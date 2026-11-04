package query

import (
	"bytes"
	"context"
	"errors"

	"canopy.local/canopy/internal/model"
)

var (
	ErrGraphInput = errors.New("invalid graph metadata input")
	ErrGraphMissingParent = errors.New("graph parent metadata unavailable")
	ErrGraphConflict = errors.New("graph identity has different ordered parents")
	ErrGraphBudget = errors.New("graph metadata budget exceeded")
)

// GraphBudget bounds all retained records and ID references (parents plus jumps).
// Both limits must be positive. These are local algorithm limits, not wire policy.
type GraphBudget struct { Nodes, References uint64 }

// GraphNode owns its metadata. Generation is 1 for roots and one plus the
// maximum parent generation otherwise. Jumps follow ONLY the first parent;
// jump k is the ancestor 2^k first-parent edges away. They do not prove general
// DAG reachability or replace traversal of the other ordered parents.
type GraphNode struct {
	id model.ChangesetID
	generation uint64
	parents []model.ChangesetID
	jumps []model.ChangesetID
}

func (n GraphNode) ID() model.ChangesetID { return n.id }
func (n GraphNode) Generation() uint64 { return n.generation }
func (n GraphNode) Parents() []model.ChangesetID {
	return append([]model.ChangesetID(nil), n.parents...)
}
func (n GraphNode) Jumps() []model.ChangesetID {
	return append([]model.ChangesetID(nil), n.jumps...)
}

// GraphBuilder incrementally computes bounded metadata from a topological
// stream. It is not a durable index, evaluator, object verifier or authorization
// boundary. Callers must verify canonical changesets and ordered parents before
// insertion and authorize any disclosure. There is no fallback object fetch.
// It is intended for one owner; concurrent calls require external coordination.
// Construct with NewGraphBuilder; the zero value rejects additions.
type GraphBuilder struct { state *graphState }

// Shared state keeps reference accounting coherent even if a builder is copied.
type graphState struct {
	budget GraphBudget
	references uint64
	nodes map[model.ChangesetID]GraphNode
}

func NewGraphBuilder(b GraphBudget) (*GraphBuilder, error) {
	if b.Nodes == 0 || b.Nodes > 1000000 || b.References == 0 || b.References > 16000000 {
		return nil, ErrGraphBudget
	}
	return &GraphBuilder{state: &graphState{budget: b, nodes: make(map[model.ChangesetID]GraphNode)}}, nil
}

// Add requires every parent already present. This prevents cycles without a
// recursive walk. Repeating the same ID and ordered parents is idempotent;
// changing their order or contents conflicts. Errors never insert partial data.
func (builder *GraphBuilder) Add(ctx context.Context, id model.ChangesetID, parents []model.ChangesetID) (GraphNode, error) {
	if ctx == nil || builder == nil || builder.state == nil || id.Validate() != nil {
		return GraphNode{}, ErrGraphInput
	}
	b := builder.state
	if err := ctx.Err(); err != nil { return GraphNode{}, err }
	if uint64(len(parents)) > model.MaxParents { return GraphNode{}, ErrGraphBudget }
	if old, ok := b.nodes[id]; ok {
		if len(old.parents) != len(parents) { return GraphNode{}, ErrGraphConflict }
		for i, p := range parents {
			if old.parents[i] != p { return GraphNode{}, ErrGraphConflict }
		}
		return old, nil
	}
	if uint64(len(b.nodes)) >= b.budget.Nodes { return GraphNode{}, ErrGraphBudget }
	seen := make(map[model.ChangesetID]struct{}, len(parents))
	n := GraphNode{id: id, generation: 1}
	for _, p := range parents {
		if err := ctx.Err(); err != nil { return GraphNode{}, err }
		if p.Validate() != nil || p == id { return GraphNode{}, ErrGraphInput }
		if _, duplicate := seen[p]; duplicate { return GraphNode{}, ErrGraphInput }
		seen[p] = struct{}{}
		parent, ok := b.nodes[p]
		if !ok { return GraphNode{}, ErrGraphMissingParent }
		// Generation cannot overflow: every ancestor was inserted earlier and
		// the builder admits at most one million records.
		if parent.generation >= n.generation { n.generation = parent.generation + 1 }
	}
	if len(parents) != 0 {
		n.jumps = append(n.jumps, parents[0])
		for k := 1; ; k++ {
			mid := b.nodes[n.jumps[k-1]]
			if k-1 >= len(mid.jumps) { break }
			n.jumps = append(n.jumps, mid.jumps[k-1])
		}
	}
	cost := uint64(len(parents) + len(n.jumps))
	if cost > b.budget.References - b.references { return GraphNode{}, ErrGraphBudget }
	n.parents = append([]model.ChangesetID(nil), parents...)
	if err := ctx.Err(); err != nil { return GraphNode{}, err }
	b.nodes[id] = n
	b.references += cost
	return n, nil
}

// Lookup performs no network access and conveys no permission to disclose a node.
func (b *GraphBuilder) Lookup(id model.ChangesetID) (GraphNode, bool) {
	if b == nil || b.state == nil { return GraphNode{}, false }
	n, ok := b.state.nodes[id]
	return n, ok
}

func (b *GraphBuilder) Usage() (nodes, references uint64) {
	if b == nil || b.state == nil { return 0, 0 }
	return uint64(len(b.state.nodes)), b.state.references
}

// CanonicalGraph owns a repository-bound graph whose nodes can only be admitted
// through canonical changeset-frame verification. The private graph cannot be
// populated via raw GraphBuilder.Add. It is still an in-process, single-owner
// index, not proof of durable publication, final-tree validity or authorization.
// The zero value is invalid. Copies share the same graph and accounting.
type CanonicalGraph struct {
	repository [16]byte
	payloadBytes uint64
	graph *GraphBuilder
}

// NewCanonicalGraph sets explicit retained graph and per-frame payload limits.
// PayloadBytes caps canonical payload, excluding the 22-byte frame header. It
// is not a peak-memory limit: decoding and Snapshot make bounded owned copies.
func NewCanonicalGraph(repository [16]byte, budget GraphBudget, payloadBytes uint64) (*CanonicalGraph, error) {
	if payloadBytes == 0 || payloadBytes > model.MaxChangesetPayload { return nil, ErrGraphBudget }
	graph, err := NewGraphBuilder(budget)
	if err != nil { return nil, err }
	return &CanonicalGraph{repository: repository, payloadBytes: payloadBytes, graph: graph}, nil
}

// AddFrame verifies complete framing, digest, canonical syntax and repository
// binding before atomically adding ordered-parent metadata. All parents must
// already have passed the same admission path. Even replays verify the supplied
// frame; knowing an existing digest does not allow skipping byte verification.
// Inputs must not be mutated during this call. No reader/network fallback exists.
func (g *CanonicalGraph) AddFrame(ctx context.Context, expected model.ChangesetID, frame []byte) (GraphNode, error) {
	if ctx == nil || g == nil || g.graph == nil { return GraphNode{}, ErrGraphInput }
	if err := ctx.Err(); err != nil { return GraphNode{}, err }
	if uint64(len(frame)) > g.payloadBytes+22 { return GraphNode{}, ErrGraphBudget }
	value, err := model.DecodeChangeset(ctx, bytes.NewReader(frame), expected, g.payloadBytes)
	if err != nil { return GraphNode{}, err }
	snapshot := value.Snapshot()
	if snapshot.RepoID != g.repository { return GraphNode{}, ErrGraphInput }
	return g.graph.Add(ctx, expected, snapshot.Parents)
}

// Lookup returns immutable verified-frame metadata, not a grant to disclose it.
func (g *CanonicalGraph) Lookup(id model.ChangesetID) (GraphNode, bool) {
	if g == nil || g.graph == nil { return GraphNode{}, false }
	return g.graph.Lookup(id)
}
func (g *CanonicalGraph) Usage() (nodes, references uint64) {
	if g == nil || g.graph == nil { return 0, 0 }
	return g.graph.Usage()
}

// IsAncestor forwards the bounded query only over this repository-bound graph.
// Callers must independently authorize both endpoints and the graph scope.
func (g *CanonicalGraph) IsAncestor(ctx context.Context, ancestor, descendant model.ChangesetID, budget AncestryBudget) (bool, AncestryWork, error) {
	if g == nil || g.graph == nil { return false, AncestryWork{}, ErrGraphInput }
	return g.graph.IsAncestor(ctx, ancestor, descendant, budget)
}

// MergeBases forwards the all-best query with the same authorization obligation.
func (g *CanonicalGraph) MergeBases(ctx context.Context, left, right model.ChangesetID, budget MergeBaseBudget) ([]model.ChangesetID, MergeBaseWork, error) {
	if g == nil || g.graph == nil { return nil, MergeBaseWork{}, ErrGraphInput }
	return g.graph.MergeBases(ctx, left, right, budget)
}
