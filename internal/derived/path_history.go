package derived

import (
	"bytes"
	"context"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

// PathHistoryBudget admits canonical source payload bytes and cumulative
// before/after lookup page reads. Source validation/hash/snapshot passes are
// separate from page I/O, not a measured RSS or interruptible CPU guarantee.
type PathHistoryBudget struct {
	InputBytes uint64
	Lookup TreeLookupBudget
}

// PathHistoryStep is one PRIVATE exact-path state transition, not a public
// history entry or durable index record. Missing sides are explicit; mode and
// typed blob identity remain distinct. No author/message metadata is copied.
type PathHistoryStep struct {
	Repository [16]byte
	Changeset, FirstParent model.ChangesetID
	Path model.Path
	Before, After model.Operation
	BeforePresent, AfterPresent bool
}

// DerivePathHistoryStep compares the source's complete tree to parent zero's
// complete tree. The supplied TREE-v1 mappings MUST be authoritative and their
// graphs validated/retained. Hash/repository/parent identity checks here cannot
// establish mapping provenance, source publication or graph retention.
// Additional parents remain ancestry, not tree-history inputs or copy sources.
//
// A nil step with nil error means unchanged exact leaf state. Missing parent
// mappings/pages fail; they never fabricate an absent ancestor. Root changesets
// have a genuinely absent before-state. Errors return no partial step. The two
// lookups share one read budget. Input frames must not change concurrently.
// This is not chain traversal, pagination, persistence, authorization or a
// rename/copy detector. Results, usage and errors must remain private.
func DerivePathHistoryStep(ctx context.Context, source model.Changeset, current metadata.DerivedResult, parent *metadata.DerivedResult, currentFrames, parentFrames map[TreePageID][]byte, path model.Path, budget PathHistoryBudget) (*PathHistoryStep, TreeLookupUsage, error) {
	var used TreeLookupUsage
	bad := func(err error) (*PathHistoryStep, TreeLookupUsage, error) { return nil, used, err }
	if ctx == nil || path.Validate() != nil || current.Identity.Validate() != nil || current.Value.Validate() != nil || current.Identity.Kind != "TREE" || current.Identity.Version != 1 ||
		budget.InputBytes == 0 || budget.InputBytes > model.MaxChangesetPayload || budget.Lookup.Pages == 0 || budget.Lookup.Pages > 4096 || budget.Lookup.ReadBytes == 0 || budget.Lookup.ReadBytes > 4096*MaxTreePageBytes { return bad(metadata.ErrInvalidArgument) }
	if err := ctx.Err(); err != nil { return bad(err) }
	if source.PayloadSize() > budget.InputBytes { return bad(metadata.ErrResourceExhausted) }
	id, err := model.HashChangeset(ctx, source)
	if err != nil { return bad(err) }
	if id != current.Identity.Changeset { return bad(metadata.ErrCorruptData) }
	input := source.Snapshot()
	if input.RepoID != current.Identity.Repository { return bad(metadata.ErrInvalidArgument) }
	step := &PathHistoryStep{Repository: input.RepoID, Changeset: id, Path: path}
	lookup := func(result metadata.DerivedResult, frames map[TreePageID][]byte) (model.Operation, bool, error) {
		if used.Pages == budget.Lookup.Pages || used.ReadBytes == budget.Lookup.ReadBytes { return model.Operation{}, false, metadata.ErrResourceExhausted }
		root, err := ParseTreePageID(result.Value.Bytes())
		if err != nil { return model.Operation{}, false, metadata.ErrInvalidArgument }
		row, usage, err := LookupTreeLeaf(ctx, root, frames, path, TreeLookupBudget{budget.Lookup.Pages-used.Pages, budget.Lookup.ReadBytes-used.ReadBytes})
		used.Pages += usage.Pages; used.ReadBytes += usage.ReadBytes
		if err == ErrTreeLeafAbsent { return model.Operation{}, false, nil }
		return row, err == nil, err
	}
	if len(input.Parents) == 0 {
		if parent != nil { return bad(metadata.ErrInvalidArgument) }
	} else {
		if parent == nil { return bad(metadata.ErrFailedPrecondition) }
		want := metadata.DerivedIdentity{Repository: input.RepoID, Changeset: input.Parents[0], Kind: "TREE", Version: 1}
		if parent.Identity != want || parent.Value.Validate() != nil { return bad(metadata.ErrInvalidArgument) }
		step.FirstParent = input.Parents[0]
		step.Before, step.BeforePresent, err = lookup(*parent, parentFrames)
		if err != nil { return bad(err) }
	}
	step.After, step.AfterPresent, err = lookup(current, currentFrames)
	if err != nil { return bad(err) }
	if err := ctx.Err(); err != nil { return bad(err) }
	if step.BeforePresent == step.AfterPresent && (!step.BeforePresent || step.Before == step.After) { return nil, used, nil }
	return step, used, nil
}

// PathHistoryNode supplies private immutable source data and a caller-trusted
// complete TREE mapping/retained frame graph. This is not a provider interface
// or a validity receipt; neither this wrapper nor a map entry proves provenance.
type PathHistoryNode struct {
	Source model.Changeset
	Tree metadata.DerivedResult
	Frames map[TreePageID][]byte
}

// PathHistoryChainBudget bounds a complete non-resumable first-parent walk.
// SourceBytes charges canonical payload once per visited changeset, not every
// validation/hash/snapshot pass or heap allocation. Lookup I/O is cumulative,
// including repeated reads of a shared tree as consecutive before/after states.
type PathHistoryChainBudget struct {
	Nodes, SourceBytes, Changes uint64
	Lookup TreeLookupBudget
}
type PathHistoryChainUsage struct {
	Nodes, SourceBytes uint64
	Lookup TreeLookupUsage
}

// ReadFirstParentPathHistory returns PRIVATE changed steps newest first, only
// after reaching a parentless source. It continues through absent/no-op paths:
// a deletion does not erase earlier history and a re-add does not invent it.
// Missing ancestors, cycles, corruption, cancellation or any exhausted budget
// return no partial steps. Unrelated supplied nodes and additional parents are
// not traversed. All supplied maps/frame bytes must remain unchanged during use.
//
// This is bounded computation over supplied trusted mappings, not a durable
// index, stable pagination/cursor, resumable job or authorized public history.
// Large valid chains can exhaust these limits. Never represent that as an empty
// or complete history, or expose private work/error distinctions to readers.
func ReadFirstParentPathHistory(ctx context.Context, repository [16]byte, start model.ChangesetID, path model.Path, nodes map[model.ChangesetID]PathHistoryNode, budget PathHistoryChainBudget) ([]PathHistoryStep, PathHistoryChainUsage, error) {
	var used PathHistoryChainUsage
	bad := func(err error) ([]PathHistoryStep, PathHistoryChainUsage, error) { return nil, used, err }
	if ctx == nil || start.Validate() != nil || path.Validate() != nil || budget.Nodes == 0 || budget.Nodes > 4096 || budget.Changes == 0 || budget.Changes > budget.Nodes ||
		budget.SourceBytes == 0 || budget.SourceBytes > model.MaxChangesetPayload || budget.Lookup.Pages == 0 || budget.Lookup.Pages > 4096 || budget.Lookup.ReadBytes == 0 || budget.Lookup.ReadBytes > 4096*MaxTreePageBytes { return bad(metadata.ErrInvalidArgument) }
	seen := make(map[model.ChangesetID]bool)
	var steps []PathHistoryStep
	cursor := start
	for {
		if err := ctx.Err(); err != nil { return bad(err) }
		if seen[cursor] { return bad(metadata.ErrCorruptData) }
		if used.Nodes == budget.Nodes { return bad(metadata.ErrResourceExhausted) }
		used.Nodes++
		seen[cursor] = true
		node, ok := nodes[cursor]
		if !ok { return bad(metadata.ErrFailedPrecondition) }
		if node.Tree.Identity.Repository != repository || node.Tree.Identity.Changeset != cursor { return bad(metadata.ErrInvalidArgument) }
		size := node.Source.PayloadSize()
		if size == 0 { return bad(metadata.ErrInvalidArgument) }
		if size > budget.SourceBytes-used.SourceBytes { return bad(metadata.ErrResourceExhausted) }
		used.SourceBytes += size
		input := node.Source.Snapshot()
		var parent *metadata.DerivedResult
		var parentFrames map[TreePageID][]byte
		if len(input.Parents) != 0 {
			prior, ok := nodes[input.Parents[0]]
			if !ok { return bad(metadata.ErrFailedPrecondition) }
			parent, parentFrames = &prior.Tree, prior.Frames
		}
		if used.Lookup.Pages == budget.Lookup.Pages || used.Lookup.ReadBytes == budget.Lookup.ReadBytes { return bad(metadata.ErrResourceExhausted) }
		remaining := TreeLookupBudget{budget.Lookup.Pages-used.Lookup.Pages, budget.Lookup.ReadBytes-used.Lookup.ReadBytes}
		step, reads, err := DerivePathHistoryStep(ctx, node.Source, node.Tree, parent, node.Frames, parentFrames, path, PathHistoryBudget{size, remaining})
		used.Lookup.Pages += reads.Pages; used.Lookup.ReadBytes += reads.ReadBytes
		if err != nil { return bad(err) }
		if step != nil {
			if uint64(len(steps)) == budget.Changes { return bad(metadata.ErrResourceExhausted) }
			steps = append(steps, *step)
		}
		if len(input.Parents) == 0 {
			if err := ctx.Err(); err != nil { return bad(err) }
			return steps, used, nil
		}
		cursor = input.Parents[0]
	}
}

// CanonicalPathHistoryBudget admits two separate phases: complete checked tree
// replay, then a cumulative bounded history walk. History.SourceBytes also caps
// aggregate retained decoded payload during the bridge. Re-decoding and owned
// model copies add bounded passes; these fields are not peak-memory guarantees.
type CanonicalPathHistoryBudget struct {
	Replay TreeReplayBudget
	History PathHistoryChainBudget
}
type CanonicalPathHistoryUsage struct {
	Replay TreeReplayUsage
	History PathHistoryChainUsage
}

// ReadCanonicalPathHistory derives private exact-path history from a complete
// root-to-start canonical first-parent chain. Tree mappings come only from this
// call's checked replay, never from caller-supplied mapping assertions. Both the
// selected start ID and repository are bound explicitly. Steps are newest first;
// absent/no-op states do not truncate earlier history. Any failure returns nil.
//
// Supplied byte integrity is not publication, durable retention or permission.
// Additional parents are ancestry only and still require external membership/
// publication checks. There is no provider, public delivery, pagination, resume,
// rename/copy detection or durable index. All inputs must remain stable. Usage
// and error distinctions are private and cannot bypass authorization filtering.
func ReadCanonicalPathHistory(ctx context.Context, repository [16]byte, start model.ChangesetID, path model.Path, sources []TreeSourceFrame, blobs map[model.BlobID][]byte, budget CanonicalPathHistoryBudget) ([]PathHistoryStep, CanonicalPathHistoryUsage, error) {
	return readCanonicalPathHistory(ctx, repository, start, path, sources, blobs, budget, false)
}

// ReadCanonicalDAGPathHistory verifies the complete supplied topological DAG,
// including every parent's repository membership, then reads only the selected
// target's first-parent history. The target may occur anywhere in the input;
// unrelated branches are verified but never unioned into that history. Every
// mapping comes from checked replay in this call. Missing ancestry fails.
//
// Replay budgets cover the whole supplied DAG. History.Nodes/Changes/Lookup
// cover only the selected walk; History.SourceBytes additionally caps retained
// decoded payload across ALL supplied sources before bridge allocation. These
// are separate phases, not a single work quantum or peak-memory measurement.
// Publication, retention and authorization remain external. Outputs are private,
// non-resumable and all-or-nothing, with the same limits as the chain API.
func ReadCanonicalDAGPathHistory(ctx context.Context, repository [16]byte, start model.ChangesetID, path model.Path, sources []TreeSourceFrame, blobs map[model.BlobID][]byte, budget CanonicalPathHistoryBudget) ([]PathHistoryStep, CanonicalPathHistoryUsage, error) {
	return readCanonicalPathHistory(ctx, repository, start, path, sources, blobs, budget, true)
}

func readCanonicalPathHistory(ctx context.Context, repository [16]byte, start model.ChangesetID, path model.Path, sources []TreeSourceFrame, blobs map[model.BlobID][]byte, budget CanonicalPathHistoryBudget, completeDAG bool) ([]PathHistoryStep, CanonicalPathHistoryUsage, error) {
	var used CanonicalPathHistoryUsage
	bad := func(err error) ([]PathHistoryStep, CanonicalPathHistoryUsage, error) { return nil, used, err }
	h := budget.History
	if ctx == nil || start.Validate() != nil || path.Validate() != nil || h.Nodes == 0 || h.Nodes > 4096 || h.Changes == 0 || h.Changes > h.Nodes || h.SourceBytes == 0 || h.SourceBytes > model.MaxChangesetPayload || h.Lookup.Pages == 0 || h.Lookup.Pages > 4096 || h.Lookup.ReadBytes == 0 || h.Lookup.ReadBytes > 4096*MaxTreePageBytes { return bad(metadata.ErrInvalidArgument) }
	if err := ctx.Err(); err != nil { return bad(err) }
	if len(sources) == 0 { return bad(metadata.ErrInvalidArgument) }
	if completeDAG {
		if len(sources) > 64 { return bad(metadata.ErrResourceExhausted) }
		found := false
		for _, source := range sources { if source.ID == start { found = true; break } }
		if !found { return bad(metadata.ErrInvalidArgument) }
	} else {
		if sources[len(sources)-1].ID != start { return bad(metadata.ErrInvalidArgument) }
		if uint64(len(sources)) > h.Nodes { return bad(metadata.ErrResourceExhausted) }
	}
	replayFn := ReplayCanonicalTreeChain
	if completeDAG { replayFn = ReplayCanonicalTreeDAG }
	writes, pages, replay, err := replayFn(ctx, repository, sources, blobs, budget.Replay)
	used.Replay = replay
	if err != nil { return bad(err) }
	// Replay has verified exact frame lengths. Reserve aggregate owned source
	// payload before allocating the decoded bridge; headers are not payload.
	var payload uint64
	for _, source := range sources {
		if err := ctx.Err(); err != nil { return bad(err) }
		n := uint64(len(source.Frame)-22)
		if n > h.SourceBytes-payload { return bad(metadata.ErrResourceExhausted) }
		payload += n
	}
	nodes := make(map[model.ChangesetID]PathHistoryNode, len(sources))
	for i, source := range sources {
		value, err := model.DecodeChangeset(ctx, bytes.NewReader(source.Frame), source.ID, budget.Replay.Step.Rewrite.InputBytes)
		if err != nil { return bad(err) }
		nodes[source.ID] = PathHistoryNode{Source: value, Tree: writes[i].Result, Frames: pages}
	}
	steps, history, err := ReadFirstParentPathHistory(ctx, repository, start, path, nodes, h)
	used.History = history
	if err != nil { return bad(err) }
	if err := ctx.Err(); err != nil { return bad(err) }
	return steps, used, nil
}
