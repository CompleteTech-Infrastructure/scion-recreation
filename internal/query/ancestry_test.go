package query

import (
	"context"
	"errors"
	"testing"

	"canopy.local/canopy/internal/model"
)

func ancestryOracle(ancestor, descendant int, parents [][]int) bool {
	if ancestor == descendant { return true }
	for _, p := range parents[descendant] {
		if ancestryOracle(ancestor, p, parents) { return true }
	}
	return false
}

func TestAncestryAllPairsOracle(t *testing.T) {
	b := graphBuilder(t, GraphBudget{Nodes: 64, References: 1000})
	parents := make([][]int, 64)
	for i := range parents {
		if i > 0 && i%7 != 0 {
			parents[i] = []int{(i-1)/2}
			if other := i/3; other != parents[i][0] { parents[i] = append(parents[i], other) }
		}
		var ids []model.ChangesetID
		for _, p := range parents[i] { ids = append(ids, graphID(uint64(p))) }
		if _, err := b.Add(context.Background(), graphID(uint64(i)), ids); err != nil { t.Fatal(err) }
	}
	for a := range parents {
		for d := range parents {
			got, work, err := b.IsAncestor(context.Background(), graphID(uint64(a)), graphID(uint64(d)), AncestryBudget{64, 1000})
			if err != nil || got != ancestryOracle(a, d, parents) { t.Fatalf("%d -> %d: %v, %v", a, d, got, err) }
			if work.Examined > work.Discovered || work.Discovered > 64 || work.ParentEdges > 1000 { t.Fatal(work) }
		}
	}
}

func TestAncestryDeepBoundsAndPruning(t *testing.T) {
	b := graphBuilder(t, GraphBudget{Nodes: 2049, References: 30000})
	for i := uint64(0); i < 2048; i++ {
		var parents []model.ChangesetID
		if i > 0 { parents = []model.ChangesetID{graphID(i-1)} }
		if _, err := b.Add(context.Background(), graphID(i), parents); err != nil { t.Fatal(err) }
	}
	if _, err := b.Add(context.Background(), graphID(9999), nil); err != nil { t.Fatal(err) }
	for _, tc := range []struct { a, d uint64; budget AncestryBudget; want bool; err error; work AncestryWork }{
		{0, 2047, AncestryBudget{2048, 2048}, true, nil, AncestryWork{2047, 2047, 2047}},
		{0, 2047, AncestryBudget{10, 2048}, false, ErrGraphBudget, AncestryWork{10, 10, 10}},
		{0, 2047, AncestryBudget{2048, 10}, false, ErrGraphBudget, AncestryWork{11, 11, 10}},
		{2047, 0, AncestryBudget{1, 1}, false, nil, AncestryWork{1, 1, 0}},
		{2047, 2047, AncestryBudget{1, 1}, true, nil, AncestryWork{1, 1, 0}},
		{9999, 2047, AncestryBudget{2048, 2048}, false, nil, AncestryWork{2047, 2047, 2047}},
		{9999, 2047, AncestryBudget{10, 10}, false, ErrGraphBudget, AncestryWork{10, 10, 10}},
	} {
		got, work, err := b.IsAncestor(context.Background(), graphID(tc.a), graphID(tc.d), tc.budget)
		if got != tc.want || !errors.Is(err, tc.err) || work != tc.work { t.Fatalf("%d -> %d: %v %+v %v", tc.a, tc.d, got, work, err) }
	}
}

// A first-parent jump must not hide a reachable ancestor on a skipped merge's
// second parent. Generation pruning alone must retain all such branches.
func TestAncestrySecondaryParentInsideFirstParentChain(t *testing.T) {
	b := graphBuilder(t, GraphBudget{Nodes: 5, References: 20})
	for i, ps := range [][]uint64{nil, nil, {0, 1}, {2}, {3}} {
		var ids []model.ChangesetID
		for _, p := range ps { ids = append(ids, graphID(p)) }
		if _, err := b.Add(context.Background(), graphID(uint64(i)), ids); err != nil { t.Fatal(err) }
	}
	got, _, err := b.IsAncestor(context.Background(), graphID(1), graphID(4), AncestryBudget{5, 20})
	if !got || err != nil { t.Fatal(got, err) }
}

type ancestryCancelContext struct {
	context.Context
	cancel context.CancelFunc
	calls int
}
func (c *ancestryCancelContext) Err() error {
	c.calls++
	if c.calls == 4 { c.cancel() }
	return c.Context.Err()
}

func TestAncestryFailuresAreNotNegativeProof(t *testing.T) {
	b := graphBuilder(t, GraphBudget{Nodes: 3, References: 10})
	for i := uint64(0); i < 3; i++ {
		var parents []model.ChangesetID
		if i > 0 { parents = []model.ChangesetID{graphID(i-1)} }
		if _, err := b.Add(context.Background(), graphID(i), parents); err != nil { t.Fatal(err) }
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mid := &ancestryCancelContext{Context: ctx, cancel: cancel}
	got, work, err := b.IsAncestor(mid, graphID(0), graphID(2), AncestryBudget{3, 10})
	if got || !errors.Is(err, context.Canceled) || work.ParentEdges != 1 { t.Fatal(got, work, err) }
	for _, tc := range []struct { ctx context.Context; a model.ChangesetID; budget AncestryBudget; err error }{
		{nil, graphID(0), AncestryBudget{3, 10}, ErrGraphInput},
		{ctx, graphID(0), AncestryBudget{3, 10}, context.Canceled},
		{context.Background(), model.ChangesetID{}, AncestryBudget{3, 10}, ErrGraphInput},
		{context.Background(), graphID(99), AncestryBudget{3, 10}, ErrAncestryUnavailable},
		{context.Background(), graphID(0), AncestryBudget{}, ErrGraphBudget},
		{context.Background(), graphID(0), AncestryBudget{1000001, 1}, ErrGraphBudget},
		{context.Background(), graphID(0), AncestryBudget{1, 16000001}, ErrGraphBudget},
	} {
		got, work, err := b.IsAncestor(tc.ctx, tc.a, graphID(2), tc.budget)
		if got || !errors.Is(err, tc.err) || work != (AncestryWork{}) { t.Fatal(got, work, err) }
	}
	if got, _, err := b.IsAncestor(context.Background(), graphID(0), graphID(99), AncestryBudget{3, 10}); got || !errors.Is(err, ErrAncestryUnavailable) { t.Fatal(got, err) }
	if got, _, err := (*GraphBuilder)(nil).IsAncestor(context.Background(), graphID(0), graphID(2), AncestryBudget{3, 10}); got || !errors.Is(err, ErrGraphInput) { t.Fatal(got, err) }
}
