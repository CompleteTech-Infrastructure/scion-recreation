package workspace

import (
	"context"
	"bytes"
	"testing"

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
