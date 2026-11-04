package query

import (
	"bytes"
	"context"
	"sort"

	"canopy.local/canopy/internal/model"
)

// MergeBaseBudget bounds retained union nodes, examined parent references across
// all phases, and result IDs. All limits are mandatory local algorithm limits.
type MergeBaseBudget struct { Nodes, ParentEdges, Results uint64 }

// MergeBaseWork reports unique retained nodes, popped (side,node) pairs, common
// nodes processed and parent references examined (including elimination).
// Counts are internal metadata, not safe for unauthorized disclosure.
type MergeBaseWork struct { Nodes, SideVisits, CommonNodes, ParentEdges uint64 }

// MergeBases returns ALL best common ancestors of exact endpoints in ascending
// unsigned canonical typed-ID byte order. An ancestor is best iff it is not a
// strict ancestor of another common ancestor. Reflexive ancestry is included.
// Unrelated inputs return an empty result with nil error. Every error returns a
// nil result; exhaustion never silently truncates or selects one arbitrary base.
//
// This operates only on GraphBuilder's closed, single-owner in-process graph.
// It does not verify objects, authorize disclosure, fetch missing records, or
// implement a durable evaluator/RPC. Callers must authorize inputs and graph;
// the builder must not be mutated concurrently. Sorting is bounded by Results;
// cancellation is checked before and after this bounded standard-library sort.
func (b *GraphBuilder) MergeBases(ctx context.Context, left, right model.ChangesetID, budget MergeBaseBudget) ([]model.ChangesetID, MergeBaseWork, error) {
	var work MergeBaseWork
	if ctx == nil || b == nil || b.state == nil || left.Validate() != nil || right.Validate() != nil {
		return nil, work, ErrGraphInput
	}
	if err := ctx.Err(); err != nil { return nil, work, err }
	if budget.Nodes == 0 || budget.Nodes > 1000000 || budget.ParentEdges == 0 || budget.ParentEdges > 16000000 || budget.Results == 0 || budget.Results > budget.Nodes {
		return nil, work, ErrGraphBudget
	}
	if _, ok := b.state.nodes[left]; !ok { return nil, work, ErrAncestryUnavailable }
	if _, ok := b.state.nodes[right]; !ok { return nil, work, ErrAncestryUnavailable }
	// Bits 1/2 mark reachability from left/right; bit 4 marks a non-best
	// common ancestor. Every parent of a common ancestor is also common.
	marks := make(map[model.ChangesetID]byte)
	for side, start := range []model.ChangesetID{left, right} {
		bit := byte(1 << side)
		queue := []model.ChangesetID{start}
		if marks[start] == 0 {
			if work.Nodes == budget.Nodes { return nil, work, ErrGraphBudget }
			work.Nodes++
		}
		marks[start] |= bit
		for head := 0; head < len(queue); head++ {
			if err := ctx.Err(); err != nil { return nil, work, err }
			work.SideVisits++
			n := b.state.nodes[queue[head]]
			for _, parent := range n.parents {
				if err := ctx.Err(); err != nil { return nil, work, err }
				if work.ParentEdges == budget.ParentEdges { return nil, work, ErrGraphBudget }
				work.ParentEdges++
				if marks[parent]&bit != 0 { continue }
				if marks[parent] == 0 {
					if work.Nodes == budget.Nodes { return nil, work, ErrGraphBudget }
					work.Nodes++
				}
				marks[parent] |= bit
				queue = append(queue, parent)
			}
		}
	}
	// Common ancestors are parent-closed, so marking direct parents of
	// every common node eliminates every non-best common ancestor without
	// quadratic pairwise reachability queries or recursion.
	for id, mark := range marks {
		if err := ctx.Err(); err != nil { return nil, work, err }
		if mark&3 != 3 { continue }
		work.CommonNodes++
		for _, parent := range b.state.nodes[id].parents {
			if err := ctx.Err(); err != nil { return nil, work, err }
			if work.ParentEdges == budget.ParentEdges { return nil, work, ErrGraphBudget }
			work.ParentEdges++
			marks[parent] |= 4
		}
	}
	var result []model.ChangesetID
	for id, mark := range marks {
		if err := ctx.Err(); err != nil { return nil, work, err }
		if mark != 3 { continue }
		if uint64(len(result)) == budget.Results { return nil, work, ErrGraphBudget }
		result = append(result, id)
	}
	if err := ctx.Err(); err != nil { return nil, work, err }
	sort.Slice(result, func(i, j int) bool {
		// All IDs have the same validated canonical version and changeset
		// kind prefix, so digest order is exactly full typed-ID byte order.
		a, z := result[i].TypedID().Digest(), result[j].TypedID().Digest()
		return bytes.Compare(a[:], z[:]) < 0
	})
	if err := ctx.Err(); err != nil { return nil, work, err }
	return result, work, nil
}
