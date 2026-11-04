package derived

import (
	"context"
	"testing"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

func TestDerivePathHistoryStepFirstParentTransitions(t *testing.T) {
	empty, emptyRoot, _ := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	frames := map[TreePageID][]byte{emptyRoot: empty}
	path, _ := model.NewPath([]byte("file"))
	missing, _ := model.NewPath([]byte("other"))
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1}); blob, _ := model.NewBlobID(tid)
	otherTID, _ := model.NewTypedID(model.BlobKind, [32]byte{2}); otherBlob, _ := model.NewBlobID(otherTID)
	budget := PathHistoryBudget{model.MaxChangesetPayload, TreeLookupBudget{4096, 4096*MaxTreePageBytes}}
	rewrite := TreeChangesetBudget{TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}, 4096, model.MaxChangesetPayload}
	var parent *metadata.DerivedResult
	var lastSource model.Changeset
	var expectedBefore model.Operation
	var lastCurrent, lastParent metadata.DerivedResult
	for i, tc := range []struct { tag model.OperationTag; target *model.BlobID; changed, before, after bool }{
		{model.SetRegular, &blob, true, false, true},
		{model.SetRegular, &blob, false, true, true},
		{model.SetExecutable, &blob, true, true, true},
		{model.SetExecutable, &otherBlob, true, true, true},
		{model.Delete, nil, true, true, false},
		{model.SetSymlink, &blob, true, false, true},
	} {
		op, err := model.NewOperation(path, tc.tag, tc.target); if err != nil { t.Fatal(err) }
		input := model.ChangesetInput{RepoID: [16]byte{1}, Operations: []model.Operation{op}, Message: []byte{byte(i)}}
		if parent != nil {
			// A second parent is hashed ancestry, never a history/tree union.
			other, _ := model.NewTypedID(model.ChangesetKind, [32]byte{99}); second, _ := model.NewChangesetID(other)
			input.Parents = []model.ChangesetID{parent.Identity.Changeset, second}
		}
		source, err := model.NewChangeset(input); if err != nil { t.Fatal(err) }
		id, err := model.HashChangeset(context.Background(), source); if err != nil { t.Fatal(err) }
		identity := metadata.DerivedIdentity{Repository: input.RepoID, Changeset: id, Kind: "TREE", Version: 1}
		write, added, err := PrepareTreeWrite(context.Background(), identity, input, parent, frames, rewrite)
		if err != nil { t.Fatal(err) }
		for id, frame := range added { frames[id] = frame }
		step, used, err := DerivePathHistoryStep(context.Background(), source, write.Result, parent, frames, frames, path, budget)
		if err != nil || (step != nil) != tc.changed { t.Fatalf("transition %d: %v", i, err) }
		if step != nil {
			if step.Changeset != id || step.Repository != input.RepoID || step.Path != path || step.BeforePresent != tc.before || step.AfterPresent != tc.after { t.Fatal("wrong history identity or presence") }
			if parent != nil && step.FirstParent != parent.Identity.Changeset { t.Fatal("wrong first-parent history") }
			if step.Before != expectedBefore { t.Fatal("prior mode/blob or absent state lost") }
			if tc.after && step.After != op { t.Fatal("mode/blob transition lost") }
			if !tc.after && step.After != (model.Operation{}) { t.Fatal("absent after-state carried a row") }
		}
		exact := budget; exact.InputBytes = source.PayloadSize(); exact.Lookup = TreeLookupBudget{used.Pages, used.ReadBytes}
		if _, again, err := DerivePathHistoryStep(context.Background(), source, write.Result, parent, frames, frames, path, exact); err != nil || again != used { t.Fatal("exact combined lookup budget rejected") }
		exact.Lookup.ReadBytes--
		if got, _, err := DerivePathHistoryStep(context.Background(), source, write.Result, parent, frames, frames, path, exact); err != metadata.ErrResourceExhausted || got != nil { t.Fatal("history byte budget reset") }
		if got, _, err := DerivePathHistoryStep(context.Background(), source, write.Result, parent, frames, frames, missing, budget); err != nil || got != nil { t.Fatal("absent path fabricated history") }
		if parent != nil { lastParent = *parent }
		lastSource, lastCurrent = source, write.Result
		next := write.Result; parent = &next
		expectedBefore = model.Operation{}
		if tc.after { expectedBefore = op }
	}
	check := func(current metadata.DerivedResult, prior *metadata.DerivedResult, currentFrames, priorFrames map[TreePageID][]byte, limits PathHistoryBudget, want error) {
		t.Helper()
		if step, _, err := DerivePathHistoryStep(context.Background(), lastSource, current, prior, currentFrames, priorFrames, path, limits); err != want || step != nil { t.Fatalf("invalid history admitted: %v, want %v", err, want) }
	}
	check(lastCurrent, nil, frames, frames, budget, metadata.ErrFailedPrecondition)
	check(lastCurrent, &lastParent, nil, frames, budget, ErrTreePageMissing)
	check(lastCurrent, &lastParent, frames, nil, budget, ErrTreePageMissing)
	wrong := lastParent; wrong.Identity.Repository[0]++
	check(lastCurrent, &wrong, frames, frames, budget, metadata.ErrInvalidArgument)
	wrong = lastParent; wrong.Identity.Changeset = lastCurrent.Identity.Changeset
	check(lastCurrent, &wrong, frames, frames, budget, metadata.ErrInvalidArgument)
	wrong = lastCurrent; wrong.Identity.Kind = "other"
	check(wrong, &lastParent, frames, frames, budget, metadata.ErrInvalidArgument)
	wrong = lastCurrent; wrong.Identity.Changeset = lastParent.Identity.Changeset
	check(wrong, &lastParent, frames, frames, budget, metadata.ErrCorruptData)
	short := budget; short.InputBytes = lastSource.PayloadSize()-1
	check(lastCurrent, &lastParent, frames, frames, short, metadata.ErrResourceExhausted)
	short = budget; short.Lookup.Pages = 1
	check(lastCurrent, &lastParent, frames, frames, short, metadata.ErrResourceExhausted)
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if step, _, err := DerivePathHistoryStep(ctx, lastSource, lastCurrent, &lastParent, frames, frames, path, budget); err != context.Canceled || step != nil { t.Fatal("history cancellation lost") }
}

func pathHistoryChainFixture(t *testing.T) ([]model.ChangesetID, map[model.ChangesetID]PathHistoryNode, model.Path) {
	t.Helper()
	empty, emptyRoot, _ := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	frames := map[TreePageID][]byte{emptyRoot: empty}
	path, _ := model.NewPath([]byte("file"))
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1}); blob, _ := model.NewBlobID(tid)
	rewrite := TreeChangesetBudget{TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}, 4096, model.MaxChangesetPayload}
	nodes := make(map[model.ChangesetID]PathHistoryNode)
	var ids []model.ChangesetID
	var parent *metadata.DerivedResult
	for i, tag := range []model.OperationTag{model.Delete, model.SetRegular, model.SetRegular, model.SetExecutable, model.Delete, model.SetSymlink} {
		var target *model.BlobID
		if tag != model.Delete { target = &blob }
		op, err := model.NewOperation(path, tag, target); if err != nil { t.Fatal(err) }
		input := model.ChangesetInput{RepoID: [16]byte{1}, Operations: []model.Operation{op}, Message: []byte{byte(i)}}
		if parent != nil {
			other, _ := model.NewTypedID(model.ChangesetKind, [32]byte{99}); second, _ := model.NewChangesetID(other)
			input.Parents = []model.ChangesetID{parent.Identity.Changeset, second}
		}
		source, err := model.NewChangeset(input); if err != nil { t.Fatal(err) }
		id, err := model.HashChangeset(context.Background(), source); if err != nil { t.Fatal(err) }
		identity := metadata.DerivedIdentity{Repository: input.RepoID, Changeset: id, Kind: "TREE", Version: 1}
		write, added, err := PrepareTreeWrite(context.Background(), identity, input, parent, frames, rewrite); if err != nil { t.Fatal(err) }
		for id, frame := range added { frames[id] = frame }
		nodes[id] = PathHistoryNode{Source: source, Tree: write.Result, Frames: frames}
		ids = append(ids, id)
		next := write.Result; parent = &next
	}
	return ids, nodes, path
}

func TestReadFirstParentPathHistoryCompleteOrderAndBudgets(t *testing.T) {
	ids, nodes, path := pathHistoryChainFixture(t)
	budget := PathHistoryChainBudget{6, model.MaxChangesetPayload, 4, TreeLookupBudget{4096, 4096*MaxTreePageBytes}}
	rows, used, err := ReadFirstParentPathHistory(context.Background(), [16]byte{1}, ids[5], path, nodes, budget)
	if err != nil || len(rows) != 4 || used.Nodes != 6 || used.Lookup.Pages != 11 { t.Fatalf("complete first-parent chain: %+v %v", used, err) }
	for i, index := range []int{5, 4, 3, 1} {
		if rows[i].Changeset != ids[index] || rows[i].FirstParent != ids[index-1] || rows[i].Path != path { t.Fatal("history order or first-parent binding changed") }
	}
	if rows[0].BeforePresent || !rows[0].AfterPresent || rows[0].After.Tag() != model.SetSymlink { t.Fatal("re-add history lost") }
	if !rows[1].BeforePresent || rows[1].AfterPresent || rows[1].Before.Tag() != model.SetExecutable { t.Fatal("delete history lost") }
	if rows[2].Before.Tag() != model.SetRegular || rows[2].After.Tag() != model.SetExecutable { t.Fatal("mode-only history lost") }
	var payloadBytes uint64
	for _, id := range ids { payloadBytes += nodes[id].Source.PayloadSize() }
	if used.SourceBytes != payloadBytes { t.Fatal("source budget did not count every visited source") }
	exact := PathHistoryChainBudget{used.Nodes, used.SourceBytes, 4, TreeLookupBudget{used.Lookup.Pages, used.Lookup.ReadBytes}}
	if again, usage, err := ReadFirstParentPathHistory(context.Background(), [16]byte{1}, ids[5], path, nodes, exact); err != nil || len(again) != 4 || usage != used { t.Fatal("exact chain budgets rejected") }
	for _, dimension := range []string{"nodes", "source", "changes", "pages", "read"} {
		b := exact
		switch dimension { case "nodes": b.Nodes--; case "source": b.SourceBytes--; case "changes": b.Changes--; case "pages": b.Lookup.Pages--; case "read": b.Lookup.ReadBytes-- }
		if rows, _, err := ReadFirstParentPathHistory(context.Background(), [16]byte{1}, ids[5], path, nodes, b); err != metadata.ErrResourceExhausted || rows != nil { t.Fatalf("%s budget leaked incomplete history: %v", dimension, err) }
	}
	absent, _ := model.NewPath([]byte("other"))
	if rows, usage, err := ReadFirstParentPathHistory(context.Background(), [16]byte{1}, ids[5], absent, nodes, budget); err != nil || rows != nil || usage.Nodes != 6 { t.Fatal("absent path caused fabricated history or early completion") }
	if rows, usage, err := ReadFirstParentPathHistory(context.Background(), [16]byte{1}, ids[0], path, nodes, budget); err != nil || rows != nil || usage.Nodes != 1 { t.Fatal("root DELETE fabricated a transition") }
}

func TestReadFirstParentPathHistoryMissingAncestorAndSubstitution(t *testing.T) {
	ids, nodes, path := pathHistoryChainFixture(t)
	budget := PathHistoryChainBudget{6, model.MaxChangesetPayload, 6, TreeLookupBudget{4096, 4096*MaxTreePageBytes}}
	root := nodes[ids[0]]; delete(nodes, ids[0])
	// Several newest changes can be collected before discovering this missing
	// oldest prerequisite. None may be returned as complete history.
	if rows, used, err := ReadFirstParentPathHistory(context.Background(), [16]byte{1}, ids[5], path, nodes, budget); err != metadata.ErrFailedPrecondition || rows != nil || used.Nodes < 2 { t.Fatal("missing ancestor fabricated completed history") }
	nodes[ids[0]] = root
	if rows, _, err := ReadFirstParentPathHistory(context.Background(), [16]byte{2}, ids[5], path, nodes, budget); err != metadata.ErrInvalidArgument || rows != nil { t.Fatal("cross-repository history admitted") }
	latest := nodes[ids[5]]; wrong := latest; wrong.Source = nodes[ids[4]].Source; nodes[ids[5]] = wrong
	if rows, _, err := ReadFirstParentPathHistory(context.Background(), [16]byte{1}, ids[5], path, nodes, budget); err != metadata.ErrCorruptData || rows != nil { t.Fatal("source substitution admitted") }
	nodes[ids[5]] = latest
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if rows, _, err := ReadFirstParentPathHistory(ctx, [16]byte{1}, ids[5], path, nodes, budget); err != context.Canceled || rows != nil { t.Fatal("chain cancellation lost") }
}

type historyCountContext struct { context.Context; calls, cancelAt int }
func (c *historyCountContext) Err() error {
	c.calls++
	if c.cancelAt != 0 && c.calls >= c.cancelAt { return context.Canceled }
	return nil
}

func TestReadFirstParentPathHistoryCancellationAfterCollectedStep(t *testing.T) {
	ids, nodes, path := pathHistoryChainFixture(t)
	current, parent := nodes[ids[5]], nodes[ids[4]]
	budget := PathHistoryChainBudget{6, model.MaxChangesetPayload, 6, TreeLookupBudget{4096, 4096*MaxTreePageBytes}}
	// Count the context checkpoints of the exact successful first step, then
	// cancel on the next chain-loop checkpoint: one chain check precedes the
	// step and the following check occurs after its row has been appended.
	probe := &historyCountContext{Context: context.Background()}
	step, reads, err := DerivePathHistoryStep(probe, current.Source, current.Tree, &parent.Tree, current.Frames, parent.Frames, path, PathHistoryBudget{current.Source.PayloadSize(), budget.Lookup})
	if err != nil || step == nil { t.Fatal("first-step probe failed") }
	ctx := &historyCountContext{Context: context.Background(), cancelAt: probe.calls+2}
	rows, used, err := ReadFirstParentPathHistory(ctx, [16]byte{1}, ids[5], path, nodes, budget)
	if err != context.Canceled || rows != nil || used.Nodes != 1 || used.Lookup != reads || ctx.calls != ctx.cancelAt { t.Fatalf("late cancellation leaked a collected step: %+v %v", used, err) }
}

func TestReadCanonicalPathHistoryUsesReplayedMappings(t *testing.T) {
	ctx := context.Background(); repo := [16]byte{7}
	path, _ := model.NewPath([]byte("a")); absent, _ := model.NewPath([]byte("missing"))
	blob, frame := treeCanonicalBlob(t, nil); blobs := map[model.BlobID][]byte{blob: frame}
	regular, _ := model.NewOperation(path, model.SetRegular, &blob)
	executable, _ := model.NewOperation(path, model.SetExecutable, &blob)
	symlink, _ := model.NewOperation(path, model.SetSymlink, &blob)
	remove, _ := model.NewOperation(path, model.Delete, nil)
	var sources []TreeSourceFrame
	var frameBytes, payloadBytes uint64
	for _, ops := range [][]model.Operation{{remove}, {regular}, nil, {executable}, {remove}, {symlink}} {
		change := model.ChangesetInput{RepoID: repo, Operations: ops}
		if len(sources) != 0 { change.Parents = []model.ChangesetID{sources[len(sources)-1].ID} }
		source := treeReplaySource(t, change); sources = append(sources, source)
		frameBytes += uint64(len(source.Frame)); payloadBytes += uint64(len(source.Frame)-22)
	}
	start := sources[5].ID
	graph := TreeObjectGraphBudget{graphTestBudget(), 22}
	step := TreeCheckedWriteBudget{graph, graph, TreeChangesetBudget{TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}, 4096, model.MaxChangesetPayload}}
	replay := TreeReplayBudget{6, frameBytes, 4, 204, step}
	history := PathHistoryChainBudget{6, payloadBytes, 4, TreeLookupBudget{11, 516}}
	budget := CanonicalPathHistoryBudget{replay, history}
	steps, used, err := ReadCanonicalPathHistory(ctx, repo, start, path, sources, blobs, budget)
	if err != nil || len(steps) != 4 || used.Replay != (TreeReplayUsage{6, frameBytes, 4, 204}) || used.History != (PathHistoryChainUsage{6, payloadBytes, TreeLookupUsage{11, 516}}) { t.Fatalf("canonical history exact budgets: %+v %v", used, err) }
	before := []model.Operation{{}, executable, regular, {}}
	after := []model.Operation{symlink, {}, executable, regular}
	for i, sourceIndex := range []int{5, 4, 3, 1} {
		s := steps[i]
		if s.Repository != repo || s.Path != path || s.Changeset != sources[sourceIndex].ID || s.FirstParent != sources[sourceIndex-1].ID || s.Before != before[i] || s.After != after[i] || s.BeforePresent != (i == 1 || i == 2) || s.AfterPresent != (i != 1) { t.Fatalf("canonical event %d has wrong state/identity", i) }
	}
	if rows, used, err := ReadCanonicalPathHistory(ctx, repo, start, absent, sources, blobs, budget); err != nil || len(rows) != 0 || used.History.Nodes != 6 { t.Fatal("absent path did not traverse complete canonical history") }
	for _, which := range []string{"nodes", "source bytes", "changes", "lookup pages", "lookup bytes", "replay pages"} {
		short := budget
		switch which { case "nodes": short.History.Nodes--; case "source bytes": short.History.SourceBytes--; case "changes": short.History.Changes--; case "lookup pages": short.History.Lookup.Pages--; case "lookup bytes": short.History.Lookup.ReadBytes--; case "replay pages": short.Replay.Pages-- }
		if rows, _, err := ReadCanonicalPathHistory(ctx, repo, start, path, sources, blobs, short); err != metadata.ErrResourceExhausted || rows != nil { t.Fatalf("%s exhaustion returned history: %v", which, err) }
	}
	if rows, usage, err := ReadCanonicalPathHistory(ctx, repo, sources[4].ID, path, sources, blobs, budget); err != metadata.ErrInvalidArgument || rows != nil || usage != (CanonicalPathHistoryUsage{}) { t.Fatal("selected source substitution reached replay") }
	invalid := budget; invalid.History.Lookup.Pages = 0
	if rows, usage, err := ReadCanonicalPathHistory(ctx, repo, start, path, sources, blobs, invalid); err != metadata.ErrInvalidArgument || rows != nil || usage != (CanonicalPathHistoryUsage{}) { t.Fatal("invalid history budget reached replay") }
	badSources := append([]TreeSourceFrame(nil), sources...)
	badSources[5].Frame = append([]byte(nil), badSources[5].Frame...); badSources[5].Frame[len(badSources[5].Frame)-1] ^= 1
	if rows, usage, err := ReadCanonicalPathHistory(ctx, repo, start, path, badSources, blobs, budget); err == nil || rows != nil || usage.History != (PathHistoryChainUsage{}) { t.Fatal("bad source exposed history") }
	if rows, _, err := ReadCanonicalPathHistory(ctx, [16]byte{8}, start, path, sources, blobs, budget); err != metadata.ErrInvalidArgument || rows != nil { t.Fatal("foreign canonical history accepted") }
	if rows, _, err := ReadCanonicalPathHistory(nil, repo, start, path, sources, blobs, budget); err != metadata.ErrInvalidArgument || rows != nil { t.Fatal("nil context accepted") }
	// Cancel immediately after the completed replay phase. The wrapper adds
	// one initial checkpoint; the next is its first payload-admission check.
	probe := &treePhaseCancelContext{Context: ctx}
	if _, _, _, err := ReplayCanonicalTreeChain(probe, repo, sources, blobs, replay); err != nil { t.Fatal(err) }
	cancel := &treePhaseCancelContext{Context: ctx, cancelAt: probe.calls+2}
	if rows, usage, err := ReadCanonicalPathHistory(cancel, repo, start, path, sources, blobs, budget); err != context.Canceled || rows != nil || usage.Replay.Sources != 6 || usage.History != (PathHistoryChainUsage{}) { t.Fatalf("phase cancellation leaked history: %+v %v", usage, err) }
}

func TestReadCanonicalDAGPathHistorySelectsOnlyFirstParents(t *testing.T) {
	ctx := context.Background(); repo := [16]byte{4}
	blob, frame := treeCanonicalBlob(t, nil); blobs := map[model.BlobID][]byte{blob: frame}
	path, _ := model.NewPath([]byte("a"))
	regular, _ := model.NewOperation(path, model.SetRegular, &blob)
	executable, _ := model.NewOperation(path, model.SetExecutable, &blob)
	remove, _ := model.NewOperation(path, model.Delete, nil)
	root := treeReplaySource(t, model.ChangesetInput{RepoID: repo, Operations: []model.Operation{regular}})
	left := treeReplaySource(t, model.ChangesetInput{RepoID: repo, Parents: []model.ChangesetID{root.ID}, Operations: []model.Operation{executable}})
	right := treeReplaySource(t, model.ChangesetInput{RepoID: repo, Parents: []model.ChangesetID{root.ID}, Operations: []model.Operation{remove}})
	merge := treeReplaySource(t, model.ChangesetInput{RepoID: repo, Parents: []model.ChangesetID{left.ID, right.ID}})
	swapped := treeReplaySource(t, model.ChangesetInput{RepoID: repo, Parents: []model.ChangesetID{right.ID, left.ID}})
	sources := []TreeSourceFrame{root, left, right, merge, swapped}
	var frameBytes, payloadBytes uint64
	for _, s := range sources { frameBytes += uint64(len(s.Frame)); payloadBytes += uint64(len(s.Frame)-22) }
	graph := TreeObjectGraphBudget{graphTestBudget(), 22}
	step := TreeCheckedWriteBudget{graph, graph, TreeChangesetBudget{TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}, 4096, model.MaxChangesetPayload}}
	budget := CanonicalPathHistoryBudget{TreeReplayBudget{5, frameBytes, 3, 144, step}, PathHistoryChainBudget{3, payloadBytes, 2, TreeLookupBudget{5, 300}}}
	for _, target := range []TreeSourceFrame{merge, swapped} {
		rows, used, err := ReadCanonicalDAGPathHistory(ctx, repo, target.ID, path, sources, blobs, budget)
		if err != nil || len(rows) != 2 || used.Replay.Sources != 5 || used.History.Nodes != 3 || used.History.Lookup.Pages != 5 || rows[1].Changeset != root.ID || rows[1].BeforePresent || rows[1].After != regular { t.Fatalf("selected DAG history: %+v %v", used, err) }
		want := left.ID; if target.ID == swapped.ID { want = right.ID }
		if rows[0].Changeset != want || rows[0].FirstParent != root.ID || rows[0].Before != regular || !rows[0].BeforePresent { t.Fatal("history selected additional-parent branch") }
		if target.ID == merge.ID { if rows[0].After != executable || !rows[0].AfterPresent { t.Fatal("left mode transition lost") } } else if rows[0].AfterPresent { t.Fatal("right deletion lost") }
		// Full bridge retains all decoded sources, while history usage charges
		// only the selected root/branch/merge payloads.
		branch := left; if target.ID == swapped.ID { branch = right }
		wantBytes := uint64(len(root.Frame)+len(branch.Frame)+len(target.Frame)-3*22)
		if used.History.SourceBytes != wantBytes { t.Fatal("history charged unrelated branch as visited") }
	}
	rootOnly := budget; rootOnly.History.Nodes = 1; rootOnly.History.Changes = 1; rootOnly.History.Lookup = TreeLookupBudget{1, 60}
	if rows, used, err := ReadCanonicalDAGPathHistory(ctx, repo, root.ID, path, sources, blobs, rootOnly); err != nil || len(rows) != 1 || used.Replay.Sources != 5 || used.History.Nodes != 1 { t.Fatal("nonfinal root target incorrectly required all DAG nodes in walk budget") }
	short := budget; short.History.SourceBytes--
	if rows, used, err := ReadCanonicalDAGPathHistory(ctx, repo, merge.ID, path, sources, blobs, short); err != metadata.ErrResourceExhausted || rows != nil || used.History.Nodes != 0 { t.Fatal("aggregate bridge payload failed to include other branches") }
	short = budget; short.History.Nodes--
	if rows, _, err := ReadCanonicalDAGPathHistory(ctx, repo, merge.ID, path, sources, blobs, short); err != metadata.ErrResourceExhausted || rows != nil { t.Fatal("selected walk exhaustion returned partial history") }
	if rows, _, err := ReadCanonicalDAGPathHistory(ctx, repo, merge.ID, path, []TreeSourceFrame{root, left, merge}, blobs, budget); err != metadata.ErrFailedPrecondition || rows != nil { t.Fatal("missing nonzero-parent source ignored") }
	corrupt := append([]TreeSourceFrame(nil), sources...); corrupt[2].Frame = append([]byte(nil), corrupt[2].Frame...); corrupt[2].Frame[len(corrupt[2].Frame)-1] ^= 1
	if rows, used, err := ReadCanonicalDAGPathHistory(ctx, repo, merge.ID, path, corrupt, blobs, budget); err == nil || rows != nil || used.History.Nodes != 0 { t.Fatal("corrupt off-lineage source ignored") }
	unknown := treeReplaySource(t, model.ChangesetInput{RepoID: repo, Message: []byte("not supplied")})
	if rows, used, err := ReadCanonicalDAGPathHistory(ctx, repo, unknown.ID, path, sources, blobs, budget); err != metadata.ErrInvalidArgument || rows != nil || used != (CanonicalPathHistoryUsage{}) { t.Fatal("missing target reached replay") }
	cancelled, cancel := context.WithCancel(ctx); cancel()
	if rows, _, err := ReadCanonicalDAGPathHistory(cancelled, repo, merge.ID, path, sources, blobs, budget); err != context.Canceled || rows != nil { t.Fatal("DAG history ignored cancellation") }
}
