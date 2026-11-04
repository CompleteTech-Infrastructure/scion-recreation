package query

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"canopy.local/canopy/internal/model"
)

func graphID(i uint64) model.ChangesetID {
	var digest [32]byte
	binary.BigEndian.PutUint64(digest[:8], i)
	typed, _ := model.NewTypedID(model.ChangesetKind, digest)
	id, _ := model.NewChangesetID(typed)
	return id
}

func graphBuilder(t *testing.T, b GraphBudget) *GraphBuilder {
	t.Helper()
	builder, err := NewGraphBuilder(b)
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

// The oracle walks actual parent edges, not the builder's generations or jumps.
func graphOracleGeneration(i int, parents [][]int) uint64 {
	var longest uint64
	for _, p := range parents[i] {
		if g := graphOracleGeneration(p, parents); g > longest {
			longest = g
		}
	}
	return longest + 1
}

func TestGraphMetadataDAGOracle(t *testing.T) {
	ctx := context.Background()
	b := graphBuilder(t, GraphBudget{Nodes: 128, References: 4096})
	parents := make([][]int, 128)
	for i := range parents {
		if i > 0 {
			parents[i] = []int{(i - 1) / 2, i / 3}
		}
		var ids []model.ChangesetID
		for _, p := range parents[i] {
			ids = append(ids, graphID(uint64(p)))
		}
		n, err := b.Add(ctx, graphID(uint64(i)), ids)
		if err != nil {
			t.Fatal(i, err)
		}
		if n.Generation() != graphOracleGeneration(i, parents) {
			t.Fatalf("generation %d", i)
		}
		if !reflect.DeepEqual(n.Parents(), ids) {
			t.Fatalf("parents %d", i)
		}
		var want []model.ChangesetID
		for distance := 1; ; distance *= 2 {
			at, steps := i, 0
			for steps < distance && len(parents[at]) > 0 {
				at = parents[at][0]
				steps++
			}
			if steps != distance {
				break
			}
			want = append(want, graphID(uint64(at)))
		}
		if !reflect.DeepEqual(n.Jumps(), want) {
			t.Fatalf("jumps %d", i)
		}
	}
}

func TestGraphMetadataDeepChain(t *testing.T) {
	b := graphBuilder(t, GraphBudget{Nodes: 10000, References: 200000})
	for i := uint64(0); i < 10000; i++ {
		var parents []model.ChangesetID
		if i > 0 {
			parents = []model.ChangesetID{graphID(i - 1)}
		}
		n, err := b.Add(context.Background(), graphID(i), parents)
		if err != nil || n.Generation() != i+1 {
			t.Fatalf("node %d: %v", i, err)
		}
		jumps := n.Jumps()
		k := 0
		for distance := uint64(1); distance <= i; distance *= 2 {
			if k >= len(jumps) || jumps[k] != graphID(i-distance) {
				t.Fatalf("jump %d/%d", i, k)
			}
			k++
		}
		if len(jumps) != k {
			t.Fatal("extra jump")
		}
	}
}

func TestGraphMetadataAtomicFailureAndOwnership(t *testing.T) {
	ctx := context.Background()
	b := graphBuilder(t, GraphBudget{Nodes: 4, References: 8})
	for _, i := range []uint64{0, 1} {
		if _, err := b.Add(ctx, graphID(i), nil); err != nil {
			t.Fatal(err)
		}
	}
	parents := []model.ChangesetID{graphID(0), graphID(1)}
	n, err := b.Add(ctx, graphID(2), parents)
	if err != nil {
		t.Fatal(err)
	}
	parents[0] = graphID(99)
	p, j := n.Parents(), n.Jumps()
	p[0], j[0] = graphID(99), graphID(99)
	got, ok := b.Lookup(graphID(2))
	if !ok || got.ID() != graphID(2) || got.Parents()[0] != graphID(0) || got.Jumps()[0] != graphID(0) {
		t.Fatal("mutable alias")
	}
	beforeN, beforeR := b.Usage()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	cases := []struct {
		ctx     context.Context
		id      model.ChangesetID
		parents []model.ChangesetID
		err     error
	}{
		{nil, graphID(3), nil, ErrGraphInput},
		{cancelled, graphID(3), nil, context.Canceled},
		{ctx, model.ChangesetID{}, nil, ErrGraphInput},
		{ctx, graphID(3), []model.ChangesetID{graphID(3)}, ErrGraphInput},
		{ctx, graphID(3), []model.ChangesetID{graphID(99)}, ErrGraphMissingParent},
		{ctx, graphID(3), []model.ChangesetID{{}}, ErrGraphInput},
		{ctx, graphID(2), []model.ChangesetID{graphID(1), graphID(0)}, ErrGraphConflict},
		{ctx, graphID(2), nil, ErrGraphConflict},
	}
	for _, tc := range cases {
		n, err := b.Add(tc.ctx, tc.id, tc.parents)
		if !errors.Is(err, tc.err) || n.Generation() != 0 {
			t.Fatalf("got %v want %v", err, tc.err)
		}
		if nodes, refs := b.Usage(); nodes != beforeN || refs != beforeR {
			t.Fatal("failure changed state")
		}
	}
	if _, err := b.Add(ctx, graphID(2), []model.ChangesetID{graphID(0), graphID(1)}); err != nil {
		t.Fatal(err)
	}
	if nodes, refs := b.Usage(); nodes != beforeN || refs != beforeR {
		t.Fatal("replay changed state")
	}
}

func TestGraphMetadataBudgets(t *testing.T) {
	for _, budget := range []GraphBudget{{}, {1, 0}, {0, 1}, {1000001, 1}, {1, 16000001}} {
		if _, err := NewGraphBuilder(budget); !errors.Is(err, ErrGraphBudget) {
			t.Fatal(budget, err)
		}
	}
	ctx := context.Background()
	b := graphBuilder(t, GraphBudget{Nodes: 2, References: 1})
	if _, err := b.Add(ctx, graphID(0), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Add(ctx, graphID(1), []model.ChangesetID{graphID(0)}); !errors.Is(err, ErrGraphBudget) {
		t.Fatal(err)
	}
	if nodes, refs := b.Usage(); nodes != 1 || refs != 0 {
		t.Fatal("budget failure inserted node")
	}
	if _, err := b.Add(ctx, graphID(1), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Add(ctx, graphID(2), nil); !errors.Is(err, ErrGraphBudget) {
		t.Fatal(err)
	}
	if _, err := b.Add(ctx, graphID(1), nil); err != nil {
		t.Fatal("capacity blocks replay", err)
	}
	var zero GraphBuilder
	if _, err := zero.Add(ctx, graphID(0), nil); !errors.Is(err, ErrGraphInput) {
		t.Fatal(err)
	}
	if _, err := (*GraphBuilder)(nil).Add(ctx, graphID(0), nil); !errors.Is(err, ErrGraphInput) {
		t.Fatal(err)
	}
}

func TestGraphMetadataGenerationUsesEveryParent(t *testing.T) {
	ctx := context.Background()
	b := graphBuilder(t, GraphBudget{Nodes: 4, References: 20})
	for i := uint64(0); i < 3; i++ {
		var parents []model.ChangesetID
		if i > 0 {
			parents = []model.ChangesetID{graphID(i - 1)}
		}
		if _, err := b.Add(ctx, graphID(i), parents); err != nil {
			t.Fatal(err)
		}
	}
	n, err := b.Add(ctx, graphID(3), []model.ChangesetID{graphID(0), graphID(2)})
	if err != nil {
		t.Fatal(err)
	}
	if n.Generation() != 4 || !reflect.DeepEqual(n.Jumps(), []model.ChangesetID{graphID(0)}) {
		t.Fatal("generation confused with first-parent depth")
	}
}

func TestGraphMetadataCopiesShareBudget(t *testing.T) {
	ctx := context.Background()
	b := graphBuilder(t, GraphBudget{Nodes: 4, References: 2})
	if _, err := b.Add(ctx, graphID(0), nil); err != nil {
		t.Fatal(err)
	}
	alias := *b
	if _, err := alias.Add(ctx, graphID(1), []model.ChangesetID{graphID(0)}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Add(ctx, graphID(2), []model.ChangesetID{graphID(0)}); !errors.Is(err, ErrGraphBudget) {
		t.Fatal(err)
	}
	if nodes, refs := b.Usage(); nodes != 2 || refs != 2 {
		t.Fatal("copied builder split accounting")
	}
	if nodes, refs := alias.Usage(); nodes != 2 || refs != 2 {
		t.Fatal("alias accounting diverged")
	}
	if _, ok := b.Lookup(graphID(2)); ok {
		t.Fatal("over-budget insertion")
	}
}

func TestGraphMetadataRepeatedParents(t *testing.T) {
	ctx := context.Background()
	b := graphBuilder(t, GraphBudget{Nodes: 4, References: 11})
	if _, err := b.Add(ctx, graphID(0), nil); err != nil {
		t.Fatal(err)
	}
	parents := []model.ChangesetID{graphID(0), graphID(0)}
	n, err := b.Add(ctx, graphID(1), parents)
	if err != nil {
		t.Fatal(err)
	}
	if n.Generation() != 2 || !reflect.DeepEqual(n.Parents(), parents) || !reflect.DeepEqual(n.Jumps(), []model.ChangesetID{graphID(0)}) {
		t.Fatal("repeated-parent metadata changed")
	}
	if nodes, refs := b.Usage(); nodes != 2 || refs != 3 {
		t.Fatalf("usage = %d, %d; want 2, 3", nodes, refs)
	}
	if _, err := b.Add(ctx, graphID(1), parents); err != nil {
		t.Fatal("replay", err)
	}
	if _, err := b.Add(ctx, graphID(1), parents[:1]); !errors.Is(err, ErrGraphConflict) {
		t.Fatal("deduplicated replay", err)
	}
	if nodes, refs := b.Usage(); nodes != 2 || refs != 3 {
		t.Fatal("replay changed usage")
	}
	parents[0] = graphID(99)
	copyParents := n.Parents()
	copyParents[1] = graphID(99)
	stored, ok := b.Lookup(graphID(1))
	if !ok || !reflect.DeepEqual(stored.Parents(), []model.ChangesetID{graphID(0), graphID(0)}) {
		t.Fatal("repeated-parent storage aliases caller")
	}

	descendant, err := b.Add(ctx, graphID(2), []model.ChangesetID{graphID(1)})
	if err != nil {
		t.Fatal(err)
	}
	if descendant.Generation() != 3 || !reflect.DeepEqual(descendant.Jumps(), []model.ChangesetID{graphID(1), graphID(0)}) {
		t.Fatal("repeated-parent descendant metadata")
	}
	ordered := []model.ChangesetID{graphID(0), graphID(2), graphID(0), graphID(2)}
	mixed, err := b.Add(ctx, graphID(3), ordered)
	if err != nil {
		t.Fatal(err)
	}
	if mixed.Generation() != 4 || !reflect.DeepEqual(mixed.Parents(), ordered) || !reflect.DeepEqual(mixed.Jumps(), []model.ChangesetID{graphID(0)}) {
		t.Fatal("repeated-parent order or first-parent meaning changed")
	}
	if nodes, refs := b.Usage(); nodes != 4 || refs != 11 {
		t.Fatalf("usage = %d, %d; want 4, 11", nodes, refs)
	}
	if _, err := b.Add(ctx, graphID(3), ordered); err != nil {
		t.Fatal("replay at capacity", err)
	}
	if _, err := b.Add(ctx, graphID(3), []model.ChangesetID{graphID(2), graphID(0), graphID(0), graphID(2)}); !errors.Is(err, ErrGraphConflict) {
		t.Fatal("reordered replay", err)
	}
	if nodes, refs := b.Usage(); nodes != 4 || refs != 11 {
		t.Fatal("mixed replay changed usage")
	}
}

func TestGraphMetadataRepeatedParentsReferenceBudget(t *testing.T) {
	ctx := context.Background()
	b := graphBuilder(t, GraphBudget{Nodes: 2, References: 2})
	if _, err := b.Add(ctx, graphID(0), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Add(ctx, graphID(1), []model.ChangesetID{graphID(0), graphID(0)}); !errors.Is(err, ErrGraphBudget) {
		t.Fatal("repeated references must each consume budget", err)
	}
	if nodes, refs := b.Usage(); nodes != 1 || refs != 0 {
		t.Fatal("failed repeated-parent insertion changed usage")
	}
	if _, ok := b.Lookup(graphID(1)); ok {
		t.Fatal("over-budget node retained")
	}
}
