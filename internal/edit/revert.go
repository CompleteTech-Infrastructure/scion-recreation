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
	if err := validateCanonicalRevertParent(ctx, repository, change, parent, sources, budget.Replay); err != nil { return zero, nil, usage, err }
	version, conflict, used, err := MergeCanonicalTreeFile(ctx, repository, [3]model.ChangesetID{change,target,parent}, path, sources, blobs, budget)
	usage = used
	if err != nil { return zero, nil, usage, err }
	if conflict != nil { return zero, conflict, usage, nil }
	operation, err := PrepareFileOperation(ctx, path, version, budget.Payload)
	if err != nil { return zero, nil, usage, err }
	return operation, nil, usage, nil
}

// PrepareCanonicalTextFileRevert explicitly selects bounded text processing
// for an inverse from change to its declared actual parent onto exact target.
// Disjoint regular/executable text edits compose with target edits; opaque
// equality and deletion/addition/type/symlink rules retain exact file semantics.
// NUL rejection is only a guard, not a classifier. The caller selects text.
//
// Text limits are admitted before the additional parent decode. Full supplied
// DAG/source/blob verification and actual parent membership remain mandatory.
// Usage reports replay/lookups, not the extra decode or text/encoding passes.
// Independent phase bounds are not a measured memory limit. This PRIVATE helper
// returns one candidate or exact conflict, not a whole-tree inverse, root revert,
// RPC mainline adapter, authorization, publication or history/ref mutation.
// Directory-at-path means file absence. Inputs must remain stable.
func PrepareCanonicalTextFileRevert(ctx context.Context, repository [16]byte, change, parent, target model.ChangesetID, path model.Path, sources []derived.TreeSourceFrame, blobs map[model.BlobID][]byte, budget TreeTextFileMergeBudget) (PreparedFileOperation, *FileConflict, TreeFileMergeUsage, error) {
	var zero PreparedFileOperation
	var usage TreeFileMergeUsage
	if ctx == nil || change.Validate() != nil || parent.Validate() != nil || target.Validate() != nil || path.Validate() != nil { return zero, nil, usage, ErrFileState }
	if err := ctx.Err(); err != nil { return zero, nil, usage, err }
	b := budget.Text
	if b.Bytes == 0 || b.Bytes > 64<<20 || b.Lines == 0 || b.Lines > 1000000 || b.Cells == 0 || b.Cells > 4000000 || b.Hunks == 0 || b.Hunks > 1000000 { return zero, nil, usage, ErrTextLimit }
	if err := validateCanonicalRevertParent(ctx, repository, change, parent, sources, budget.Replay); err != nil { return zero, nil, usage, err }
	version, conflict, used, err := MergeCanonicalTreeTextFile(ctx, repository, [3]model.ChangesetID{change,target,parent}, path, sources, blobs, budget)
	usage = used
	if err != nil { return zero, nil, usage, err }
	if conflict != nil { return zero, conflict, usage, nil }
	operation, err := PrepareFileOperation(ctx, path, version, b.Bytes)
	if err != nil { return zero, nil, usage, err }
	return operation, nil, usage, nil
}

// Caller validates context and typed identities. Admit the entire source batch
// before the bounded parent-membership decode; preserve opaque API ordering.
func validateCanonicalRevertParent(ctx context.Context, repository [16]byte, change, parent model.ChangesetID, sources []derived.TreeSourceFrame, budget derived.TreeReplayBudget) error {
	if budget.Sources == 0 || budget.Sources > 64 || budget.SourceBytes == 0 || budget.SourceBytes > model.MaxChangesetPayload+64*22 || budget.Step.Rewrite.InputBytes == 0 || budget.Step.Rewrite.InputBytes > model.MaxChangesetPayload { return metadata.ErrInvalidArgument }
	if uint64(len(sources)) > budget.Sources { return metadata.ErrResourceExhausted }
	// Admit the full supplied source batch before the extra parent-selection
	// decode, so it cannot spend work against an exhausted source-byte budget.
	var sourceBytes uint64
	for _, source := range sources {
		if err := ctx.Err(); err != nil { return err }
		if source.ID.Validate() != nil { return metadata.ErrInvalidArgument }
		n := uint64(len(source.Frame))
		if n > budget.Step.Rewrite.InputBytes+22 || n > budget.SourceBytes-sourceBytes { return metadata.ErrResourceExhausted }
		sourceBytes += n
	}
	found := false
	for _, source := range sources {
		if err := ctx.Err(); err != nil { return err }
		if source.ID != change { continue }
		if uint64(len(source.Frame)) > budget.Step.Rewrite.InputBytes+22 { return metadata.ErrResourceExhausted }
		value, err := model.DecodeChangeset(ctx, bytes.NewReader(source.Frame), change, budget.Step.Rewrite.InputBytes)
		if err != nil { return err }
		input := value.Snapshot()
		if input.RepoID != repository { return metadata.ErrInvalidArgument }
		for _, id := range input.Parents { if id == parent { found = true; break } }
		if !found { return metadata.ErrFailedPrecondition }
		break
	}
	if !found { return metadata.ErrNotFound }
	return nil
}
