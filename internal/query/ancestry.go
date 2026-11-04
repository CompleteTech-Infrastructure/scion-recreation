package query

import (
	"context"
	"errors"

	"canopy.local/canopy/internal/model"
)

var ErrAncestryUnavailable = errors.New("ancestry metadata unavailable")

// AncestryBudget bounds unique discovered nodes (including the descendant) and
// examined parent references. Positive explicit limits are mandatory; these are
// local algorithm limits, not RPC policy or authorization grants.
type AncestryBudget struct { Nodes, ParentEdges uint64 }

// AncestryWork counts actual work, including on failure. Discovered bounds the
// queue/set, Examined counts popped records, and ParentEdges counts examined
// references even when already seen or generation-pruned. These internal counts
// must not be exposed across authorization boundaries without policy checks.
type AncestryWork struct { Discovered, Examined, ParentEdges uint64 }

// IsAncestor computes reflexive ancestry in the builder's closed graph, using
// indexed generations to prune impossible branches. All parents participate;
// first-parent jumps cannot safely skip merge nodes for a negative DAG answer.
// No object fetch, whole-log fallback, recursion, or durable-provider behavior is
// hidden here. The caller must authorize the graph and both requested identities
// before use. Do not mutate the single-owner builder while this method runs.
//
// A false result is definitive ONLY when err is nil. Exhaustion, cancellation,
// or absent metadata returns an error, never a successful negative answer.
func (b *GraphBuilder) IsAncestor(ctx context.Context, ancestor, descendant model.ChangesetID, budget AncestryBudget) (bool, AncestryWork, error) {
	var work AncestryWork
	if ctx == nil || b == nil || b.state == nil || ancestor.Validate() != nil || descendant.Validate() != nil {
		return false, work, ErrGraphInput
	}
	if err := ctx.Err(); err != nil { return false, work, err }
	if budget.Nodes == 0 || budget.Nodes > 1000000 || budget.ParentEdges == 0 || budget.ParentEdges > 16000000 {
		return false, work, ErrGraphBudget
	}
	target, ok := b.state.nodes[ancestor]
	if !ok { return false, work, ErrAncestryUnavailable }
	_, ok = b.state.nodes[descendant]
	if !ok { return false, work, ErrAncestryUnavailable }
	queue := []model.ChangesetID{descendant}
	seen := map[model.ChangesetID]struct{}{descendant: {}}
	work.Discovered = 1
	for head := 0; head < len(queue); head++ {
		if err := ctx.Err(); err != nil { return false, work, err }
		n := b.state.nodes[queue[head]]
		work.Examined++
		if n.id == ancestor { return true, work, nil }
		if n.generation <= target.generation { continue }
		for _, parentID := range n.parents {
			if err := ctx.Err(); err != nil { return false, work, err }
			if work.ParentEdges == budget.ParentEdges { return false, work, ErrGraphBudget }
			work.ParentEdges++
			if parentID == ancestor { return true, work, nil }
			if _, exists := seen[parentID]; exists { continue }
			parent := b.state.nodes[parentID]
			if parent.generation <= target.generation { continue }
			if work.Discovered == budget.Nodes { return false, work, ErrGraphBudget }
			seen[parentID] = struct{}{}
			queue = append(queue, parentID)
			work.Discovered++
		}
	}
	// Both endpoint records were looked up before traversal, including when
	// the descendant is too shallow. Never infer absence from a missing ID.
	if err := ctx.Err(); err != nil { return false, work, err }
	return false, work, nil
}
