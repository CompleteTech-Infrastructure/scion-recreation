package search

import (
	"bytes"
	"context"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

// PathSnapshot is a PRIVATE immutable exact-revision file-path snapshot. It is
// not an authorized search result, persistent index or freshness watermark.
// Rebuilding another revision creates another value; it cannot mutate this one.
// Repository membership is checked by canonical replay, not publication or ACLs.
type PathSnapshot struct {
	repository [16]byte
	source model.ChangesetID
	rows []model.Operation
	lengths []uint64
}
type PathSnapshotBudget struct {
	Replay derived.TreeReplayBudget
	Snapshot derived.TreeEntriesBudget
}
type PathSnapshotUsage struct {
	Replay derived.TreeReplayUsage
	Snapshot derived.TreeGraphUsage
}

// BuildCanonicalPathSnapshot verifies every source/parent/blob in the supplied
// topological DAG, then enumerates the selected computed tree. Deletes and
// first-parent merge semantics therefore come from canonical tree computation,
// not event arrival order. Full replay/enumeration have separate bounded quanta.
// Inputs must be stable during the call. Any failure returns no snapshot.
// Durable outbox consumption, incremental updates, revision watermarks, indexing
// services and permission-aware delivery remain separate requirements.
func BuildCanonicalPathSnapshot(ctx context.Context, repository [16]byte, source model.ChangesetID, sources []derived.TreeSourceFrame, blobs map[model.BlobID][]byte, budget PathSnapshotBudget) (*PathSnapshot, PathSnapshotUsage, error) {
	var used PathSnapshotUsage
	bad := func(err error) (*PathSnapshot, PathSnapshotUsage, error) { return nil, used, err }
	if ctx == nil || source.Validate() != nil || len(sources) == 0 { return bad(metadata.ErrInvalidArgument) }
	if err := ctx.Err(); err != nil { return bad(err) }
	if len(sources) > 64 { return bad(metadata.ErrResourceExhausted) }
	found := false
	for _, input := range sources { if input.ID == source { found = true; break } }
	if !found { return bad(metadata.ErrInvalidArgument) }
	writes, pages, replay, err := derived.ReplayCanonicalTreeDAG(ctx, repository, sources, blobs, budget.Replay)
	used.Replay = replay
	if err != nil { return bad(err) }
	var root derived.TreePageID
	for _, write := range writes {
		if write.Result.Identity.Changeset != source { continue }
		root, err = derived.ParseTreePageID(write.Result.Value.Bytes())
		if err != nil { return bad(err) }
		break
	}
	rows, usage, err := derived.ReadTreeEntries(ctx, root, pages, budget.Snapshot)
	used.Snapshot = usage
	if err != nil { return bad(err) }
	if err := ctx.Err(); err != nil { return bad(err) }
	// Cache lengths without adding a public model accessor. This extra pass
	// copies each admitted path once; enumeration already bounds their sum.
	lengths := make([]uint64, len(rows))
	for i, row := range rows {
		if err := ctx.Err(); err != nil { return bad(err) }
		lengths[i] = uint64(len(row.Path().Bytes()))
	}
	if err := ctx.Err(); err != nil { return bad(err) }
	return &PathSnapshot{repository: repository, source: source, rows: rows, lengths: lengths}, used, nil
}

// PathPrefixBudget bounds a full private scan, not a public search protocol.
// Bytes reserves path length plus prefix length per row before copying/comparing;
// it is a conservative work bound, not measured allocation or RSS. Matches is
// an all-or-nothing output bound, never silent truncation or pagination.
type PathPrefixBudget struct { Paths, Bytes, Matches uint64 }
type PathPrefixUsage struct { Paths, Bytes uint64 }

// Prefix matches a literal raw-byte prefix (not a directory/glob/regex query).
// Empty prefix selects all files; case and non-UTF8 bytes remain literal. Rows
// retain canonical ordering and explicit regular/executable/symlink modes.
// The expected repository/source must match this snapshot exactly. This guards
// against accidental stale-revision use, not authorization or current freshness.
// Output, timing, counts and errors must stay private until separately authorized.
func (s *PathSnapshot) Prefix(ctx context.Context, repository [16]byte, source model.ChangesetID, prefix []byte, budget PathPrefixBudget) ([]model.Operation, PathPrefixUsage, error) {
	var used PathPrefixUsage
	bad := func(err error) ([]model.Operation, PathPrefixUsage, error) { return nil, used, err }
	if ctx == nil || s == nil || s.source.Validate() != nil || repository != s.repository || source != s.source || len(prefix) > 65535 ||
		budget.Paths == 0 || budget.Paths > 4096 || budget.Bytes == 0 || budget.Bytes > 64<<20 || budget.Matches == 0 || budget.Matches > 4096 { return bad(metadata.ErrInvalidArgument) }
	if err := ctx.Err(); err != nil { return bad(err) }
	var out []model.Operation
	for i, row := range s.rows {
		if err := ctx.Err(); err != nil { return bad(err) }
		// Reserve before Path.Bytes makes its owned copy.
		cost := s.lengths[i] + uint64(len(prefix))
		if used.Paths == budget.Paths || cost > budget.Bytes-used.Bytes { return bad(metadata.ErrResourceExhausted) }
		used.Paths++; used.Bytes += cost
		if !bytes.HasPrefix(row.Path().Bytes(), prefix) { continue }
		if uint64(len(out)) == budget.Matches { return bad(metadata.ErrResourceExhausted) }
		out = append(out, row)
	}
	if err := ctx.Err(); err != nil { return bad(err) }
	return out, used, nil
}
