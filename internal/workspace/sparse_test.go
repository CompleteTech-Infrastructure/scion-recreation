package workspace

import (
	"context"
	"bytes"
	"testing"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
)

func TestSparseLiteralMembershipAndPruning(t *testing.T) {
	paths := []model.Path{testPath(t, []byte("a/b")), testPath(t, []byte("a-")), testPath(t, []byte{'x', '/', 0xff}), testPath(t, []byte("*.go"))}
	s, err := CompileSparseSelection(1, false, paths)
	if err != nil { t.Fatal(err) }
	for _, tc := range []struct { path string; selected, descend bool }{
		{"a", false, true}, {"a/b", true, true}, {"a/b/c", true, true},
		{"ab", false, false}, {"a/bc", false, false}, {"a-", true, true},
		{"x", false, true}, {"x/\xff", true, true}, {"x/\xfe", false, false},
		{"*.go", true, true}, {"main.go", false, false}, {"A/b", false, false},
	} {
		p := testPath(t, []byte(tc.path))
		if s.Selects(p) != tc.selected || s.MayContain(p) != tc.descend {
			t.Fatalf("path %q: selected=%v descend=%v", tc.path, s.Selects(p), s.MayContain(p))
		}
	}
	paths[0] = testPath(t, []byte("changed"))
	if !s.Selects(testPath(t, []byte("a/b"))) || s.Selects(paths[0]) { t.Fatal("selection aliases caller slice") }
}

func TestSparseValidationAndEmptyAll(t *testing.T) {
	p := testPath(t, []byte("a"))
	for _, tc := range []struct { version uint16; all bool; paths []model.Path }{
		{0, false, nil}, {2, false, nil}, {1, true, []model.Path{p}},
		{1, false, []model.Path{{}}}, {1, false, make([]model.Path, MaxPaths+1)},
	} {
		if s, err := CompileSparseSelection(tc.version, tc.all, tc.paths); s != nil || err != ErrSparseSelection { t.Fatal("invalid selection accepted") }
	}
	for _, all := range []bool{false, true} {
		s, err := CompileSparseSelection(1, all, nil)
		if err != nil || s.Empty() == all || s.Selects(p) != all || s.MayContain(p) != all { t.Fatalf("all=%v: %v", all, err) }
		if s.Selects(model.Path{}) || s.MayContain(model.Path{}) { t.Fatal("zero path accepted") }
	}
	var s *SparseSelection
	if !s.Empty() || s.Selects(p) || s.MayContain(p) { t.Fatal("nil selection did not deny") }
}

func TestSparseAggregateBoundaryAndDuplicates(t *testing.T) {
	// Fill the manifest-size boundary with repeated maximum-sized records
	// and one final path. Duplicates count toward admission before deduplication.
	large := testPath(t, bytes.Repeat([]byte{'x'}, 65531))
	paths := make([]model.Path, 63)
	for i := range paths { paths[i] = large }
	remaining := MaxManifestBytes - (91 + 63*(4+65531))
	paths = append(paths, testPath(t, bytes.Repeat([]byte{'y'}, remaining-4)))
	s, err := CompileSparseSelection(1, false, paths)
	if err != nil || len(s.ordered) != 2 || !s.Selects(large) { t.Fatalf("exact boundary/duplicates: %v", err) }
	paths[len(paths)-1] = testPath(t, bytes.Repeat([]byte{'y'}, remaining-3))
	if s, err := CompileSparseSelection(1, false, paths); s != nil || err != ErrSparseSelection { t.Fatal("aggregate overflow accepted") }
}

type sparsePlanCancelContext struct { context.Context; calls int }
func (c *sparsePlanCancelContext) Err() error {
	c.calls++
	if c.calls >= 3 { return context.Canceled }
	return nil
}

func TestSparseTransitionPlansOnlyLiteralMembershipChanges(t *testing.T) {
	ctx := context.Background()
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1}); blob, _ := model.NewBlobID(tid)
	row := func(path string, tag model.OperationTag) model.Operation {
		p := testPath(t, []byte(path)); var target *model.BlobID; if tag != model.Delete { target = &blob }
		op, err := model.NewOperation(p, tag, target); if err != nil { t.Fatal(err) }; return op
	}
	rows := []model.Operation{row("*.go", model.SetRegular), row("a-", model.SetRegular), row("a/b", model.SetExecutable), row("a0", model.SetSymlink), row("z/\xff", model.SetRegular)}
	old, _ := CompileSparseSelection(1, false, []model.Path{testPath(t, []byte("a")), testPath(t, []byte("a0"))})
	next, _ := CompileSparseSelection(1, false, []model.Path{testPath(t, []byte("*.go")), testPath(t, []byte("a/b")), testPath(t, []byte("z"))})
	var pathBytes uint64; for _, op := range rows { pathBytes += uint64(len(op.Path().Bytes())) }
	budget := SparseTransitionBudget{5, pathBytes, 3}
	plan, err := PlanSparseTransition(ctx, rows, old, next, budget)
	if err != nil || len(plan) != 3 || plan[0] != (SparseTransition{rows[0], true}) || plan[1] != (SparseTransition{rows[3], false}) || plan[2] != (SparseTransition{rows[4], true}) { t.Fatalf("literal transition: %+v %v", plan, err) }
	for _, which := range []string{"rows", "paths", "changes"} {
		short := budget; switch which { case "rows": short.Entries--; case "paths": short.PathBytes--; case "changes": short.Changes-- }
		if out, err := PlanSparseTransition(ctx, rows, old, next, short); err != ErrSparseBudget || out != nil { t.Fatal("transition exhaustion exposed partial plan") }
	}
	if same, err := PlanSparseTransition(ctx, rows, old, old, budget); err != nil || len(same) != 0 { t.Fatal("unchanged selection emitted intents") }
	all, _ := CompileSparseSelection(1, true, nil); empty, _ := CompileSparseSelection(1, false, nil)
	wide := budget; wide.Changes = 5
	for _, entering := range []bool{false, true} {
		before, after := all, empty; if entering { before, after = empty, all }
		out, err := PlanSparseTransition(ctx, rows, before, after, wide)
		if err != nil || len(out) != len(rows) { t.Fatal("empty/all transition incomplete") }
		for i, intent := range out { if intent.Entry != rows[i] || intent.Selected != entering { t.Fatal("transition reordered/changed canonical row") } }
	}
	// Invalid excluded data must still fail, including non-adjacent ancestor
	// conflicts. Both selections being empty must not mask malformed input.
	for _, invalid := range [][]model.Operation{{rows[1], rows[0]}, {rows[0], rows[0]}, {row("a", model.Delete)}, {row("a", model.SetRegular), row("a-", model.SetRegular), row("a/b", model.SetRegular)}, {{}}} {
		if out, err := PlanSparseTransition(ctx, invalid, empty, empty, wide); err != ErrSparseSelection || out != nil { t.Fatalf("invalid excluded snapshot accepted: %v", err) }
	}
	if out, err := PlanSparseTransition(ctx, rows, nil, next, budget); err != ErrSparseSelection || out != nil { t.Fatal("nil old selection authorized removals") }
	if out, err := PlanSparseTransition(ctx, rows, old, nil, budget); err != ErrSparseSelection || out != nil { t.Fatal("nil new selection authorized removals") }
	if out, err := PlanSparseTransition(nil, rows, old, next, budget); err != ErrSparseSelection || out != nil { t.Fatal("nil context accepted") }
	if out, err := PlanSparseTransition(ctx, nil, empty, all, budget); err != nil || len(out) != 0 { t.Fatal("empty snapshot fabricated entries") }
	cancelled, cancel := context.WithCancel(ctx); cancel()
	if out, err := PlanSparseTransition(cancelled, rows, old, next, budget); err != context.Canceled || out != nil { t.Fatal("cancelled plan accepted") }
	// The first private intent is collected at checkpoint two; cancellation
	// on the next row must discard it rather than returning a partial plan.
	mid := &sparsePlanCancelContext{Context: ctx}
	if out, err := PlanSparseTransition(mid, rows, old, next, budget); err != context.Canceled || out != nil || mid.calls != 3 { t.Fatal("mid-plan cancellation leaked earlier intent") }
	for _, invalid := range []SparseTransitionBudget{{}, {MaxPaths+1, pathBytes, 3}, {5, MaxManifestBytes+1, 3}, {5, pathBytes, 6}} {
		if out, err := PlanSparseTransition(ctx, rows, old, next, invalid); err != ErrSparseBudget || out != nil { t.Fatal("invalid transition budget accepted") }
	}
	// Output slice mutation cannot modify the immutable supplied rows.
	plan[0] = SparseTransition{}
	if rows[0].Path() != testPath(t, []byte("*.go")) { t.Fatal("output aliased input rows") }
}

func TestCanonicalSparseTransitionBindsComputedSnapshot(t *testing.T) {
	ctx := context.Background(); repo := [16]byte{8}
	blob, err := model.HashBlob(ctx, 0, bytes.NewReader(nil)); if err != nil { t.Fatal(err) }
	var encoded bytes.Buffer; if err := model.EncodeBlob(ctx, &encoded, 0, bytes.NewReader(nil)); err != nil { t.Fatal(err) }
	blobs := map[model.BlobID][]byte{blob: encoded.Bytes()}
	row := func(raw string, tag model.OperationTag) model.Operation {
		p := testPath(t, []byte(raw)); var target *model.BlobID; if tag != model.Delete { target = &blob }
		op, err := model.NewOperation(p, tag, target); if err != nil { t.Fatal(err) }; return op
	}
	source := func(change model.ChangesetInput) derived.TreeSourceFrame {
		v, err := model.NewChangeset(change); if err != nil { t.Fatal(err) }
		id, err := model.HashChangeset(ctx, v); if err != nil { t.Fatal(err) }
		var frame bytes.Buffer; if err := model.EncodeChangeset(ctx, &frame, v); err != nil { t.Fatal(err) }
		return derived.TreeSourceFrame{ID: id, Frame: frame.Bytes()}
	}
	literal := row("*.go", model.SetRegular); oldRow := row("a/b", model.SetExecutable); newRow := row("z/\xff", model.SetSymlink)
	root := source(model.ChangesetInput{RepoID: repo, Operations: []model.Operation{literal, oldRow}})
	left := source(model.ChangesetInput{RepoID: repo, Parents: []model.ChangesetID{root.ID}, Operations: []model.Operation{newRow}})
	right := source(model.ChangesetInput{RepoID: repo, Parents: []model.ChangesetID{root.ID}, Operations: []model.Operation{row("a/b", model.Delete)}})
	merge := source(model.ChangesetInput{RepoID: repo, Parents: []model.ChangesetID{left.ID, right.ID}})
	sources := []derived.TreeSourceFrame{root, left, right, merge}
	var sourceBytes uint64; for _, s := range sources { sourceBytes += uint64(len(s.Frame)) }
	old, _ := CompileSparseSelection(1, false, []model.Path{testPath(t, []byte("a"))})
	next, _ := CompileSparseSelection(1, false, []model.Path{testPath(t, []byte("z"))})
	graph := derived.TreeGraphBudget{Visits: 4096, PageBytes: 4096*derived.MaxTreePageBytes, ContextBytes: 64<<20}
	objects := derived.TreeObjectGraphBudget{Graph: graph, BlobBytes: 1<<20}
	step := derived.TreeCheckedWriteBudget{Parent: objects, Candidate: objects, Rewrite: derived.TreeChangesetBudget{Rewrite: derived.TreeRewriteBudget{Pages: 4096, ReadBytes: 4096*derived.MaxTreePageBytes, WriteBytes: 4096*derived.MaxTreePageBytes}, Operations: 4096, InputBytes: model.MaxChangesetPayload}}
	budget := CanonicalSparseBudget{Replay: derived.TreeReplayBudget{Sources: 4, SourceBytes: sourceBytes, Pages: 4096, PageBytes: 4096*derived.MaxTreePageBytes, Step: step}, Snapshot: derived.TreeEntriesBudget{Graph: graph, Entries: 3, PathBytes: 20}, Transition: SparseTransitionBudget{3, 10, 2}}
	plan, used, err := PlanCanonicalSparseTransition(ctx, repo, merge.ID, sources, blobs, old, next, budget)
	if err != nil || len(plan) != 2 || plan[0] != (SparseTransition{oldRow, false}) || plan[1] != (SparseTransition{newRow, true}) || used.Replay.Sources != 4 || used.Snapshot.Visits == 0 { t.Fatalf("computed sparse intents: %+v %+v %v", plan, used, err) }
	current := Manifest{Base: merge.ID, SparseVersion: 1, Sparse: []model.Path{testPath(t, []byte("a"))}, State: Clean}
	requested := []model.Path{testPath(t, []byte("z"))}
	manifestBytes, err := encode(current); if err != nil { t.Fatal(err) }
	bound, boundUsage, err := PlanManifestSparseTransition(ctx, repo, current, 1, false, requested, sources, blobs, budget)
	if err != nil || len(bound) != len(plan) || boundUsage != used { t.Fatal("manifest binding changed canonical planner result") }
	for i := range plan { if bound[i] != plan[i] { t.Fatal("manifest selection lost exact intent") } }
	for _, state := range []DirtyState{Dirty, Uncertain} {
		pending := current; pending.State = state; pending.DirtyPaths = []model.Path{testPath(t, []byte("a/b"))}
		if out, usage, err := PlanManifestSparseTransition(ctx, repo, pending, 1, false, requested, nil, nil, budget); err != ErrRecoveryRequired || out != nil || usage != (CanonicalSparseUsage{}) { t.Fatal("pending local state reached replay or emitted removals") }
	}
	corruptManifest := current; corruptManifest.DirtyPaths = []model.Path{testPath(t, []byte("a/b"))}
	if out, usage, err := PlanManifestSparseTransition(ctx, repo, corruptManifest, 1, false, requested, nil, nil, budget); err != ErrCorrupt || out != nil || usage != (CanonicalSparseUsage{}) { t.Fatal("invalid clean manifest reached replay") }
	for _, invalid := range []struct {
		name string
		version uint16
		all bool
		prefixes []model.Path
	}{
		{"unknown-version", 2, false, requested},
		{"all-with-prefix", 1, true, requested},
		{"invalid-prefix", 1, false, []model.Path{{}}},
	} {
		if out, usage, err := PlanManifestSparseTransition(ctx, repo, current, invalid.version, invalid.all, invalid.prefixes, sources, blobs, budget); err != ErrSparseSelection || out != nil || usage != (CanonicalSparseUsage{}) {
			t.Fatalf("%s requested syntax reached replay: plan=%+v usage=%+v err=%v", invalid.name, out, usage, err)
		}
	}
	for _, tc := range []struct {
		name string
		currentAll, requestedAll bool
		want []SparseTransition
	}{
		{"requested-all", false, true, []SparseTransition{{literal, true}, {newRow, true}}},
		{"current-all", true, false, []SparseTransition{{literal, false}, {oldRow, false}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := current
			manifest.SparseAll = tc.currentAll
			if tc.currentAll { manifest.Sparse = nil }
			prefixes := requested
			if tc.requestedAll { prefixes = nil }
			before, err := CompileSparseSelection(manifest.SparseVersion, manifest.SparseAll, manifest.Sparse)
			if err != nil { t.Fatal(err) }
			after, err := CompileSparseSelection(1, tc.requestedAll, prefixes)
			if err != nil { t.Fatal(err) }
			canonical, canonicalUsage, err := PlanCanonicalSparseTransition(ctx, repo, manifest.Base, sources, blobs, before, after, budget)
			if err != nil { t.Fatal(err) }
			bound, boundUsage, err := PlanManifestSparseTransition(ctx, repo, manifest, 1, tc.requestedAll, prefixes, sources, blobs, budget)
			if err != nil || len(bound) != len(tc.want) || len(canonical) != len(tc.want) || boundUsage != canonicalUsage || boundUsage.Replay.Sources != 4 || boundUsage.Snapshot.Visits == 0 {
				t.Fatalf("all selection binding differs: plan=%+v canonical=%+v usage=%+v err=%v", bound, canonical, boundUsage, err)
			}
			for i, intent := range tc.want {
				if bound[i] != intent || canonical[i] != intent { t.Fatalf("all selection intent %d: bound=%+v canonical=%+v want=%+v", i, bound[i], canonical[i], intent) }
			}
		})
	}
	// Base/old selection originate only in current, not a separately supplied
	// source ID or selector. Moving the manifest base changes the result.
	priorManifest := current; priorManifest.Base = root.ID
	if out, _, err := PlanManifestSparseTransition(ctx, repo, priorManifest, 1, false, requested, sources, blobs, budget); err != nil || len(out) != 1 || out[0] != (SparseTransition{oldRow, false}) { t.Fatal("manifest base binding ignored") }
	afterManifest, err := encode(current)
	if err != nil || !bytes.Equal(afterManifest, manifestBytes) || requested[0] != testPath(t, []byte("z")) { t.Fatal("planning mutated manifest or requested selection") }
	if out, _, err := PlanManifestSparseTransition(nil, repo, current, 1, false, requested, sources, blobs, budget); err != ErrSparseSelection || out != nil { t.Fatal("nil manifest planning context accepted") }
	// Selecting an earlier source uses its own map, never a later descendant.
	if out, _, err := PlanCanonicalSparseTransition(ctx, repo, root.ID, sources, blobs, old, next, budget); err != nil || len(out) != 1 || out[0] != (SparseTransition{oldRow, false}) { t.Fatal("selected revision changed during planning") }
	if out, used, err := PlanCanonicalSparseTransition(ctx, repo, merge.ID, sources, blobs, old, old, budget); err != nil || len(out) != 0 || used.Replay.Sources != 4 || used.Snapshot.Visits == 0 { t.Fatal("unchanged selection skipped canonical verification") }
	for _, which := range []string{"source bytes", "snapshot entries", "snapshot paths", "transition paths", "changes"} {
		short := budget
		switch which { case "source bytes": short.Replay.SourceBytes--; case "snapshot entries": short.Snapshot.Entries--; case "snapshot paths": short.Snapshot.PathBytes--; case "transition paths": short.Transition.PathBytes--; case "changes": short.Transition.Changes-- }
		if out, _, err := PlanCanonicalSparseTransition(ctx, repo, merge.ID, sources, blobs, old, next, short); err == nil || out != nil { t.Fatalf("%s exhaustion leaked intents", which) }
	}
	unknown := source(model.ChangesetInput{RepoID: repo, Message: []byte("absent")})
	if out, usage, err := PlanCanonicalSparseTransition(ctx, repo, unknown.ID, sources, blobs, old, next, budget); err != ErrSparseSelection || out != nil || usage != (CanonicalSparseUsage{}) { t.Fatal("unknown source reached replay") }
	bad := append([]derived.TreeSourceFrame(nil), sources...); bad[2].Frame = append([]byte(nil), bad[2].Frame...); bad[2].Frame[len(bad[2].Frame)-1] ^= 1
	if out, usage, err := PlanCanonicalSparseTransition(ctx, repo, root.ID, bad, blobs, old, old, budget); err == nil || out != nil || usage.Snapshot.Visits != 0 { t.Fatal("off-selection corruption ignored") }
	if out, _, err := PlanCanonicalSparseTransition(ctx, repo, merge.ID, []derived.TreeSourceFrame{root, left, merge}, blobs, old, next, budget); err == nil || out != nil { t.Fatal("missing additional parent ignored") }
	if out, _, err := PlanCanonicalSparseTransition(ctx, repo, merge.ID, sources, nil, old, next, budget); err == nil || out != nil { t.Fatal("missing blob accepted") }
	if out, used, err := PlanCanonicalSparseTransition(ctx, repo, merge.ID, sources, blobs, nil, next, budget); err != ErrSparseSelection || out != nil || used != (CanonicalSparseUsage{}) { t.Fatal("nil selector reached replay") }
	if out, _, err := PlanCanonicalSparseTransition(ctx, [16]byte{9}, merge.ID, sources, blobs, old, next, budget); err == nil || out != nil { t.Fatal("foreign source accepted") }
	if out, _, err := PlanCanonicalSparseTransition(nil, repo, merge.ID, sources, blobs, old, next, budget); err != ErrSparseSelection || out != nil { t.Fatal("nil context accepted") }
	cancelled, cancel := context.WithCancel(ctx); cancel()
	if out, _, err := PlanCanonicalSparseTransition(cancelled, repo, merge.ID, sources, blobs, old, next, budget); err != context.Canceled || out != nil { t.Fatal("cancellation ignored") }
}
