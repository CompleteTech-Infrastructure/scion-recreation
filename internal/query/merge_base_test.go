package query

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"canopy.local/canopy/internal/model"
)

func mergeBaseOracle(left, right int, parents [][]int) []model.ChangesetID {
	var result []model.ChangesetID
	for a := range parents {
		if !ancestryOracle(a, left, parents) || !ancestryOracle(a, right, parents) { continue }
		best := true
		for other := range parents {
			if other != a && ancestryOracle(other, left, parents) && ancestryOracle(other, right, parents) && ancestryOracle(a, other, parents) { best = false; break }
		}
		if best { result = append(result, graphID(uint64(a))) }
	}
	return result
}

func mergeBaseGraph(t *testing.T, parents [][]int) *GraphBuilder {
	t.Helper()
	b := graphBuilder(t, GraphBudget{Nodes: uint64(len(parents)), References: 100000})
	for i, ps := range parents {
		var ids []model.ChangesetID
		for _, p := range ps { ids = append(ids, graphID(uint64(p))) }
		if _, err := b.Add(context.Background(), graphID(uint64(i)), ids); err != nil { t.Fatal(err) }
	}
	return b
}

func TestMergeBasesAllPairsOracle(t *testing.T) {
	parents := make([][]int, 32)
	for i := range parents {
		if i > 0 && i%7 != 0 {
			parents[i] = []int{(i-1)/2}
			if other := i/3; other != parents[i][0] { parents[i] = append(parents[i], other) }
		}
	}
	b := mergeBaseGraph(t, parents)
	for left := range parents {
		for right := range parents {
			got, work, err := b.MergeBases(context.Background(), graphID(uint64(left)), graphID(uint64(right)), MergeBaseBudget{32, 1000, 32})
			if err != nil || !reflect.DeepEqual(got, mergeBaseOracle(left, right, parents)) { t.Fatalf("%d/%d: %v %v", left, right, got, err) }
			if work.Nodes > 32 || work.SideVisits > 2*work.Nodes || work.CommonNodes > work.Nodes || work.ParentEdges > 1000 { t.Fatal(work) }
		}
	}
}

func TestMergeBasesCrissCrossAndBudgets(t *testing.T) {
	b := mergeBaseGraph(t, [][]int{nil, {0}, {0}, {2, 1}, {1, 2}, {3}, {4}, nil})
	budget := MergeBaseBudget{8, 100, 8}
	for _, tc := range []struct { left, right uint64; want []model.ChangesetID }{
		{3, 4, []model.ChangesetID{graphID(1), graphID(2)}},
		{4, 3, []model.ChangesetID{graphID(1), graphID(2)}},
		{5, 6, []model.ChangesetID{graphID(1), graphID(2)}},
		{3, 3, []model.ChangesetID{graphID(3)}},
		{3, 5, []model.ChangesetID{graphID(3)}},
		{0, 0, []model.ChangesetID{graphID(0)}},
		{3, 7, nil},
	} {
		for repeat := 0; repeat < 10; repeat++ {
			got, _, err := b.MergeBases(context.Background(), graphID(tc.left), graphID(tc.right), budget)
			if err != nil || !reflect.DeepEqual(got, tc.want) { t.Fatal(tc, got, err) }
		}
	}
	got, work, err := b.MergeBases(context.Background(), graphID(3), graphID(4), MergeBaseBudget{5, 10, 2})
	if err != nil || len(got) != 2 || work != (MergeBaseWork{5, 8, 3, 10}) { t.Fatal(got, work, err) }
	for _, limit := range []MergeBaseBudget{{4, 10, 2}, {5, 9, 2}, {5, 10, 1}} {
		got, _, err := b.MergeBases(context.Background(), graphID(3), graphID(4), limit)
		if got != nil || !errors.Is(err, ErrGraphBudget) { t.Fatal(limit, got, err) }
	}
	// Returned slices are independent and cannot mutate later answers.
	got[0] = graphID(99)
	again, _, err := b.MergeBases(context.Background(), graphID(3), graphID(4), budget)
	if err != nil || again[0] != graphID(1) { t.Fatal(again, err) }
}

func TestMergeBasesDeepAndCancellation(t *testing.T) {
	parents := make([][]int, 2048)
	for i := 1; i < len(parents); i++ { parents[i] = []int{i-1} }
	b := mergeBaseGraph(t, parents)
	got, work, err := b.MergeBases(context.Background(), graphID(2047), graphID(2047), MergeBaseBudget{2048, 6141, 1})
	if err != nil || !reflect.DeepEqual(got, []model.ChangesetID{graphID(2047)}) || work != (MergeBaseWork{2048, 4096, 2048, 6141}) { t.Fatal(got, work, err) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mid := &ancestryCancelContext{Context: ctx, cancel: cancel}
	got, work, err = b.MergeBases(mid, graphID(2047), graphID(2046), MergeBaseBudget{2048, 10000, 1})
	if got != nil || !errors.Is(err, context.Canceled) || work.ParentEdges != 1 { t.Fatal(got, work, err) }
}

func TestMergeBasesInvalidAndMissing(t *testing.T) {
	b := mergeBaseGraph(t, [][]int{nil})
	for _, budget := range []MergeBaseBudget{{}, {1, 0, 1}, {0, 1, 1}, {1, 1, 0}, {1, 1, 2}, {1000001, 1, 1}, {1, 16000001, 1}} {
		got, work, err := b.MergeBases(context.Background(), graphID(0), graphID(0), budget)
		if got != nil || !errors.Is(err, ErrGraphBudget) || work != (MergeBaseWork{}) { t.Fatal(got, work, err) }
	}
	for _, pair := range [][2]model.ChangesetID{{graphID(99), graphID(0)}, {graphID(0), graphID(99)}} {
		got, work, err := b.MergeBases(context.Background(), pair[0], pair[1], MergeBaseBudget{1, 1, 1})
		if got != nil || !errors.Is(err, ErrAncestryUnavailable) || work != (MergeBaseWork{}) { t.Fatal(got, work, err) }
	}
	var zero GraphBuilder
	for _, builder := range []*GraphBuilder{nil, &zero} {
		if got, _, err := builder.MergeBases(context.Background(), graphID(0), graphID(0), MergeBaseBudget{1, 1, 1}); got != nil || !errors.Is(err, ErrGraphInput) { t.Fatal(got, err) }
	}
	if got, _, err := b.MergeBases(nil, graphID(0), graphID(0), MergeBaseBudget{1, 1, 1}); got != nil || !errors.Is(err, ErrGraphInput) { t.Fatal(got, err) }
	if got, _, err := b.MergeBases(context.Background(), model.ChangesetID{}, graphID(0), MergeBaseBudget{1, 1, 1}); got != nil || !errors.Is(err, ErrGraphInput) { t.Fatal(got, err) }
}

func TestMergeBasesUnsignedFullDigestOrder(t *testing.T) {
	b := graphBuilder(t, GraphBudget{Nodes: 5, References: 20})
	var roots []model.ChangesetID
	for _, ends := range [][2]byte{{0x7f, 0xff}, {0x80, 0x00}, {0x80, 0x01}} {
		var digest [32]byte
		digest[0], digest[31] = ends[0], ends[1]
		typed, _ := model.NewTypedID(model.ChangesetKind, digest)
		id, _ := model.NewChangesetID(typed)
		if _, err := b.Add(context.Background(), id, nil); err != nil { t.Fatal(err) }
		roots = append(roots, id)
	}
	if _, err := b.Add(context.Background(), graphID(100), []model.ChangesetID{roots[2], roots[0], roots[1]}); err != nil { t.Fatal(err) }
	if _, err := b.Add(context.Background(), graphID(101), []model.ChangesetID{roots[1], roots[2], roots[0]}); err != nil { t.Fatal(err) }
	got, _, err := b.MergeBases(context.Background(), graphID(100), graphID(101), MergeBaseBudget{5, 6, 3})
	if err != nil || !reflect.DeepEqual(got, roots) { t.Fatal(got, err) }
}
