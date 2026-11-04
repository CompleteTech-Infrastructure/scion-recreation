package derived

import (
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
