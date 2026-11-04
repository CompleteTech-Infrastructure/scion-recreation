package derived

import (
	"context"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

// ExactCopyBudget admits a private snapshot's rows and combined raw path bytes.
// Positive limits are required, capped at 4096 rows and 64 MiB. It does not
// measure process memory; map/slice overhead and temporary path copies remain.
type ExactCopyBudget struct { Entries, PathBytes uint64 }

// ExactCopyIndex is an immutable, single-snapshot exact-content lookup. It is
// PRIVATE algorithmic state, not an authorized index or durable derived result.
// A source ID is caller-supplied attribution, not proof of publication or that
// the supplied rows are its complete tree. Callers must establish those facts.
// Similarity, rename inference, history ranking and pagination are not provided.
type ExactCopyIndex struct {
	source model.ChangesetID
	paths map[model.BlobID][]model.Path
}

// NewExactCopyIndex requires strictly raw-byte-sorted canonical SET rows from
// one complete, caller-validated snapshot. It does not validate tree topology or
// fetch blobs. Modes do not change exact blob identity; symlinks are not followed.
// No original mutable input slice is retained. Errors return no partial index.
// Inputs must not mutate during construction. Current authorization must be
// enforced separately for every query/output; known blob IDs grant no access.
func NewExactCopyIndex(ctx context.Context, source model.ChangesetID, rows []model.Operation, budget ExactCopyBudget) (*ExactCopyIndex, error) {
	if ctx == nil { return nil, metadata.ErrInvalidArgument }
	if err := ctx.Err(); err != nil { return nil, err }
	if source.Validate() != nil || budget.Entries == 0 || budget.Entries > 4096 || budget.PathBytes == 0 || budget.PathBytes > 64<<20 { return nil, metadata.ErrInvalidArgument }
	if uint64(len(rows)) > budget.Entries { return nil, metadata.ErrResourceExhausted }
	var pathBytes uint64
	for i, row := range rows {
		if err := ctx.Err(); err != nil { return nil, err }
		id, present := row.Target()
		if row.Path().Validate() != nil || !present || id.Validate() != nil || (i > 0 && rows[i-1].Path().Compare(row.Path()) >= 0) { return nil, metadata.ErrInvalidArgument }
		n := uint64(len(row.Path().Bytes()))
		if n > budget.PathBytes-pathBytes { return nil, metadata.ErrResourceExhausted }
		pathBytes += n
	}
	index := &ExactCopyIndex{source: source, paths: make(map[model.BlobID][]model.Path)}
	for _, row := range rows {
		if err := ctx.Err(); err != nil { return nil, err }
		id, _ := row.Target()
		index.paths[id] = append(index.paths[id], row.Path())
	}
	if err := ctx.Err(); err != nil { return nil, err }
	return index, nil
}

// ExactCopyMatches owns its Paths slice; each Path is an immutable canonical
// value. Paths are deterministically raw-byte sorted within one source snapshot.
// These are exact identity matches, not proven copies/renames or ranked similarity.
type ExactCopyMatches struct { Source model.ChangesetID; Paths []model.Path }

// Lookup returns all exact matches or an error, never a truncated candidate set.
// maxResults must be 1..4096. The source path itself is included if present;
// callers apply query-specific exclusions and mode policy after lookup. Empty
// Paths means no supplied row matched, not a public nonexistence assertion.
//
// Every result, count, error distinction and timing signal is PRIVATE. Callers
// must authorize source and candidate paths before disclosure, including equal
// content at denied paths. No policy/filter callback or cross-boundary fallback
// exists here. Concurrent lookups are safe after successful construction.
func (index *ExactCopyIndex) Lookup(ctx context.Context, blob model.BlobID, maxResults uint64) (ExactCopyMatches, error) {
	var zero ExactCopyMatches
	if ctx == nil { return zero, metadata.ErrInvalidArgument }
	if err := ctx.Err(); err != nil { return zero, err }
	if index == nil || index.paths == nil || index.source.Validate() != nil || blob.Validate() != nil || maxResults == 0 || maxResults > 4096 { return zero, metadata.ErrInvalidArgument }
	paths := index.paths[blob]
	if uint64(len(paths)) > maxResults { return zero, metadata.ErrResourceExhausted }
	out := ExactCopyMatches{Source: index.source}
	for _, path := range paths {
		if err := ctx.Err(); err != nil { return zero, err }
		out.Paths = append(out.Paths, path)
	}
	if err := ctx.Err(); err != nil { return zero, err }
	return out, nil
}
