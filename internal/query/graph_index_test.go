package query

import (
	"bytes"
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

func canonicalGraphFrame(t *testing.T, repo [16]byte, parents []model.ChangesetID, message string) (model.ChangesetID, []byte) {
	t.Helper()
	author, err := model.NewMetadata([]byte("graph-test"), 0, 0)
	if err != nil { t.Fatal(err) }
	value, err := model.NewChangeset(model.ChangesetInput{RepoID: repo, Parents: parents, Author: author, Message: []byte(message)})
	if err != nil { t.Fatal(err) }
	id, err := model.HashChangeset(context.Background(), value)
	if err != nil { t.Fatal(err) }
	var frame bytes.Buffer
	if err := model.EncodeChangeset(context.Background(), &frame, value); err != nil { t.Fatal(err) }
	return id, frame.Bytes()
}

func TestCanonicalGraphAdmissionAndQueries(t *testing.T) {
	ctx := context.Background()
	repo := [16]byte{1}
	g, err := NewCanonicalGraph(repo, GraphBudget{Nodes: 4, References: 16}, 4096)
	if err != nil { t.Fatal(err) }
	root, rootFrame := canonicalGraphFrame(t, repo, nil, "root")
	left, leftFrame := canonicalGraphFrame(t, repo, []model.ChangesetID{root}, "left")
	right, rightFrame := canonicalGraphFrame(t, repo, []model.ChangesetID{root}, "right")
	merge, mergeFrame := canonicalGraphFrame(t, repo, []model.ChangesetID{right, left}, "merge")
	if _, err := g.AddFrame(ctx, left, leftFrame); !errors.Is(err, ErrGraphMissingParent) { t.Fatal(err) }
	if n, refs := g.Usage(); n != 0 || refs != 0 { t.Fatal("missing-parent admission mutated state") }
	alias := *g
	for _, item := range []struct { id model.ChangesetID; frame []byte }{{root, rootFrame}, {left, leftFrame}, {right, rightFrame}, {merge, mergeFrame}} {
		if _, err := alias.AddFrame(ctx, item.id, item.frame); err != nil { t.Fatal(err) }
	}
	n, ok := g.Lookup(merge)
	if !ok || n.Generation() != 3 || !reflect.DeepEqual(n.Parents(), []model.ChangesetID{right, left}) { t.Fatal(n, ok) }
	if nodes, _ := g.Usage(); nodes != 4 { t.Fatal("copied wrapper lost accounting") }
	if _, err := g.AddFrame(ctx, root, rootFrame); err != nil { t.Fatal("verified replay at capacity", err) }
	got, _, err := g.IsAncestor(ctx, left, merge, AncestryBudget{4, 20})
	if err != nil || !got { t.Fatal(got, err) }
	bases, _, err := g.MergeBases(ctx, left, right, MergeBaseBudget{4, 20, 4})
	if err != nil || !reflect.DeepEqual(bases, []model.ChangesetID{root}) { t.Fatal(bases, err) }
	parents, jumps := n.Parents(), n.Jumps()
	parents[0], jumps[0] = graphID(99), graphID(99)
	mergeFrame[len(mergeFrame)-1] ^= 1
	stored, _ := g.Lookup(merge)
	if stored.Parents()[0] != right || stored.Jumps()[0] != right { t.Fatal("admitted metadata alias") }
}

func TestCanonicalGraphRejectsWithoutMutation(t *testing.T) {
	ctx := context.Background()
	repo := [16]byte{1}
	g, err := NewCanonicalGraph(repo, GraphBudget{Nodes: 4, References: 16}, 4096)
	if err != nil { t.Fatal(err) }
	root, frame := canonicalGraphFrame(t, repo, nil, "root")
	if _, err := g.AddFrame(ctx, root, frame); err != nil { t.Fatal(err) }
	wrongRepo, otherFrame := canonicalGraphFrame(t, [16]byte{2}, nil, "root")
	corrupt := append([]byte(nil), frame...); corrupt[len(corrupt)-1] ^= 1
	trailing := append(append([]byte(nil), frame...), 0)
	for _, tc := range []struct { id model.ChangesetID; frame []byte }{
		{root, corrupt}, {root, trailing}, {root, frame[:len(frame)-1]}, {root, nil},
		{graphID(999), frame}, {model.ChangesetID{}, frame}, {wrongRepo, otherFrame},
	} {
		n, err := g.AddFrame(ctx, tc.id, tc.frame)
		if err == nil || n.Generation() != 0 { t.Fatal("invalid frame admitted", n, err) }
		if nodes, refs := g.Usage(); nodes != 1 || refs != 0 { t.Fatal("failure mutated graph") }
	}
	limited, err := NewCanonicalGraph(repo, GraphBudget{Nodes: 1, References: 1}, uint64(len(frame)-23))
	if err != nil { t.Fatal(err) }
	if _, err := limited.AddFrame(ctx, root, frame); !errors.Is(err, ErrGraphBudget) { t.Fatal(err) }
	exact, err := NewCanonicalGraph(repo, GraphBudget{Nodes: 1, References: 1}, uint64(len(frame)-22))
	if err != nil { t.Fatal(err) }
	if _, err := exact.AddFrame(ctx, root, frame); err != nil { t.Fatal(err) }
	cancelled, cancel := context.WithCancel(ctx); cancel()
	if _, err := g.AddFrame(cancelled, root, frame); !errors.Is(err, context.Canceled) { t.Fatal(err) }
	if _, err := g.AddFrame(nil, root, frame); !errors.Is(err, ErrGraphInput) { t.Fatal(err) }
	if _, ok := g.Lookup(wrongRepo); ok { t.Fatal("cross-repository node retained") }
}

func TestCanonicalGraphConstructionAndZero(t *testing.T) {
	for _, payload := range []uint64{0, model.MaxChangesetPayload+1} {
		if g, err := NewCanonicalGraph([16]byte{}, GraphBudget{Nodes: 1, References: 1}, payload); g != nil || !errors.Is(err, ErrGraphBudget) { t.Fatal(g, err) }
	}
	if g, err := NewCanonicalGraph([16]byte{}, GraphBudget{}, 100); g != nil || !errors.Is(err, ErrGraphBudget) { t.Fatal(g, err) }
	var zero CanonicalGraph
	for _, g := range []*CanonicalGraph{nil, &zero} {
		if _, err := g.AddFrame(context.Background(), graphID(0), nil); !errors.Is(err, ErrGraphInput) { t.Fatal(err) }
		if _, ok := g.Lookup(graphID(0)); ok { t.Fatal("zero lookup") }
		if n, refs := g.Usage(); n != 0 || refs != 0 { t.Fatal(n, refs) }
		if yes, _, err := g.IsAncestor(context.Background(), graphID(0), graphID(0), AncestryBudget{1, 1}); yes || !errors.Is(err, ErrGraphInput) { t.Fatal(yes, err) }
		if bases, _, err := g.MergeBases(context.Background(), graphID(0), graphID(0), MergeBaseBudget{1, 1, 1}); bases != nil || !errors.Is(err, ErrGraphInput) { t.Fatal(bases, err) }
	}
}

func TestCanonicalGraphParentAndRetentionFailures(t *testing.T) {
	ctx := context.Background()
	repo := [16]byte{1}
	root, rootFrame := canonicalGraphFrame(t, repo, nil, "root")
	child, childFrame := canonicalGraphFrame(t, repo, []model.ChangesetID{root}, "child")
	duplicate, duplicateFrame := canonicalGraphFrame(t, repo, []model.ChangesetID{root, root}, "duplicate")
	for _, budget := range []GraphBudget{{Nodes: 1, References: 2}, {Nodes: 2, References: 1}} {
		g, err := NewCanonicalGraph(repo, budget, 4096)
		if err != nil { t.Fatal(err) }
		if _, err := g.AddFrame(ctx, root, rootFrame); err != nil { t.Fatal(err) }
		if _, err := g.AddFrame(ctx, child, childFrame); !errors.Is(err, ErrGraphBudget) { t.Fatal(err) }
		if nodes, refs := g.Usage(); nodes != 1 || refs != 0 { t.Fatal("retention failure changed state") }
	}
	g, err := NewCanonicalGraph(repo, GraphBudget{Nodes: 3, References: 10}, 4096)
	if err != nil { t.Fatal(err) }
	if _, err := g.AddFrame(ctx, root, rootFrame); err != nil { t.Fatal(err) }
	node, err := g.AddFrame(ctx, duplicate, duplicateFrame)
	if err != nil { t.Fatal(err) }
	if !reflect.DeepEqual(node.Parents(), []model.ChangesetID{root, root}) || node.Generation() != 2 || !reflect.DeepEqual(node.Jumps(), []model.ChangesetID{root}) {
		t.Fatal("canonical repeated-parent sequence was not preserved", node)
	}
	if nodes, refs := g.Usage(); nodes != 2 || refs != 3 { t.Fatal("repeated parents must each consume reference budget", nodes, refs) }
	if _, err := g.AddFrame(ctx, duplicate, duplicateFrame); err != nil { t.Fatal(err) }
	if nodes, refs := g.Usage(); nodes != 2 || refs != 3 { t.Fatal("replay changed retained usage", nodes, refs) }
	descendant, descendantFrame := canonicalGraphFrame(t, repo, []model.ChangesetID{duplicate}, "descendant")
	if _, err := g.AddFrame(ctx, descendant, descendantFrame); err != nil { t.Fatal(err) }
	if yes, _, err := g.IsAncestor(ctx, root, descendant, AncestryBudget{3, 8}); err != nil || !yes {
		t.Fatal("repeated-parent history was not queryable", yes, err)
	}
	if bases, _, err := g.MergeBases(ctx, duplicate, descendant, MergeBaseBudget{3, 32, 3}); err != nil || !reflect.DeepEqual(bases, []model.ChangesetID{duplicate}) {
		t.Fatal("merge bases must not duplicate repeated parents", bases, err)
	}
}
