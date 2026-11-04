package edit

import (
	"bytes"
	"context"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

// PrepareCanonicalFileReplay applies a declared non-root change relative to an
// explicitly selected actual parent onto an exact target, at one file path.
// Parent membership is canonical-source verified; wrong bases fail rather than
// silently changing the delta. Merge changes require explicit parent identity;
// no RPC parent-number convention or default mainline is inferred.
//
// Opaque three-way comparison uses parent as base, target as left and change
// as right. Unchanged deltas preserve the target; concurrent changes return
// exact private conflicts. Successful results prepare one canonical SET/blob or
// DELETE, including redundant operations. No partial candidate escapes on error.
//
// This is PRIVATE exact-file replay, not whole-changeset cherry-pick, sequence
// rebase, root replay, text patch alignment or durable operation publication.
// Directory-at-path means file-absence; full file/directory interactions remain
// separate. Publication, retention, permission and explicit resolution are not
// established. No existing history or refs are rewritten. Inputs must stay stable.
// Full DAG verification and phase budgets are inherited from the merge helper;
// one additional admitted source decode/Snapshot checks parent membership. Usage
// records replay/lookups, not that extra pass or total CPU/memory consumption.
func PrepareCanonicalFileReplay(ctx context.Context, repository [16]byte, change, parent, target model.ChangesetID, path model.Path, sources []derived.TreeSourceFrame, blobs map[model.BlobID][]byte, budget TreeFileMergeBudget) (PreparedFileOperation, *FileConflict, TreeFileMergeUsage, error) {
	var zero PreparedFileOperation
	var usage TreeFileMergeUsage
	if ctx == nil || change.Validate() != nil || parent.Validate() != nil || target.Validate() != nil || path.Validate() != nil { return zero, nil, usage, ErrFileState }
	if err := ctx.Err(); err != nil { return zero, nil, usage, err }
	if budget.Replay.Sources == 0 || budget.Replay.Sources > 64 || budget.Replay.SourceBytes == 0 || budget.Replay.SourceBytes > model.MaxChangesetPayload+64*22 || budget.Replay.Step.Rewrite.InputBytes == 0 || budget.Replay.Step.Rewrite.InputBytes > model.MaxChangesetPayload { return zero, nil, usage, metadata.ErrInvalidArgument }
	if uint64(len(sources)) > budget.Replay.Sources { return zero, nil, usage, metadata.ErrResourceExhausted }
	// Admit the full supplied source batch before the extra parent-selection
	// decode, so it cannot spend work against an exhausted source-byte budget.
	var sourceBytes uint64
	for _, source := range sources {
		if err := ctx.Err(); err != nil { return zero, nil, usage, err }
		if source.ID.Validate() != nil { return zero, nil, usage, metadata.ErrInvalidArgument }
		n := uint64(len(source.Frame))
		if n > budget.Replay.Step.Rewrite.InputBytes+22 || n > budget.Replay.SourceBytes-sourceBytes { return zero, nil, usage, metadata.ErrResourceExhausted }
		sourceBytes += n
	}
	found := false
	for _, source := range sources {
		if err := ctx.Err(); err != nil { return zero, nil, usage, err }
		if source.ID != change { continue }
		if uint64(len(source.Frame)) > budget.Replay.Step.Rewrite.InputBytes+22 { return zero, nil, usage, metadata.ErrResourceExhausted }
		value, err := model.DecodeChangeset(ctx, bytes.NewReader(source.Frame), change, budget.Replay.Step.Rewrite.InputBytes)
		if err != nil { return zero, nil, usage, err }
		input := value.Snapshot()
		if input.RepoID != repository { return zero, nil, usage, metadata.ErrInvalidArgument }
		for _, id := range input.Parents { if id == parent { found = true; break } }
		if !found { return zero, nil, usage, metadata.ErrFailedPrecondition }
		break
	}
	if !found { return zero, nil, usage, metadata.ErrNotFound }
	version, conflict, used, err := MergeCanonicalTreeFile(ctx, repository, [3]model.ChangesetID{parent,target,change}, path, sources, blobs, budget)
	usage = used
	if err != nil { return zero, nil, usage, err }
	if conflict != nil { return zero, conflict, usage, nil }
	operation, err := PrepareFileOperation(ctx, path, version, budget.Payload)
	if err != nil { return zero, nil, usage, err }
	return operation, nil, usage, nil
}
