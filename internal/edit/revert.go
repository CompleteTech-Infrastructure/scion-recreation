package edit

import (
	"bytes"
	"context"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

// PrepareCanonicalFileRevert computes a PRIVATE inverse at one exact file path
// onto an exact target revision. parent must explicitly identify an actual
// parent of change, even for single-parent changes. For merge changes this is
// the declared mainline identity; no parent-number wire convention is inferred.
// Root changes have no declared parent and are unsupported by this primitive.
//
// The inverse uses change as merge base, target as left and the declared parent
// as right. Opaque three-way file equality preserves unrelated target changes
// and exposes exact conflicts rather than overwriting concurrent edits. On a
// conflict no operation/blob is returned. A conflict-free result is encoded as
// one SET/blob or DELETE candidate, including no-op/redundant operations.
//
// Entire supplied DAG/source/blob verification, independent phase budgets and
// directory-as-file-absence rules are those of MergeCanonicalTreeFile. One
// additional bounded canonical source decode/Snapshot establishes actual parent
// membership before replay; this is an extra pass, not a measured RSS guarantee.
// Inputs must stay stable. This does not authorize reverting, infer ancestry or
// base policy, resolve conflicts, handle whole-tree/file-directory interactions,
// publish a changeset, mutate refs or rewrite history. It is not an RPC adapter.
func PrepareCanonicalFileRevert(ctx context.Context, repository [16]byte, change, parent, target model.ChangesetID, path model.Path, sources []derived.TreeSourceFrame, blobs map[model.BlobID][]byte, budget TreeFileMergeBudget) (PreparedFileOperation, *FileConflict, TreeFileMergeUsage, error) {
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
	version, conflict, used, err := MergeCanonicalTreeFile(ctx, repository, [3]model.ChangesetID{change,target,parent}, path, sources, blobs, budget)
	usage = used
	if err != nil { return zero, nil, usage, err }
	if conflict != nil { return zero, conflict, usage, nil }
	operation, err := PrepareFileOperation(ctx, path, version, budget.Payload)
	if err != nil { return zero, nil, usage, err }
	return operation, nil, usage, nil
}
