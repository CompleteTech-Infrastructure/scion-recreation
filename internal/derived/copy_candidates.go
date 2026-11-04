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
	targets map[model.Path]model.BlobID
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
	index := &ExactCopyIndex{source: source, paths: make(map[model.BlobID][]model.Path), targets: make(map[model.Path]model.BlobID)}
	for _, row := range rows {
		if err := ctx.Err(); err != nil { return nil, err }
		id, _ := row.Target()
		index.paths[id] = append(index.paths[id], row.Path())
		index.targets[row.Path()] = id
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

// NewTreeExactCopyIndex builds a private exact index from a complete verified
// page enumeration. identity is the expected TREE-v1 repository/source key;
// tree must match it exactly and identify the supplied graph root. The caller
// must obtain tree from an authoritative complete mapping and supply retained
// frames. Matching caller-supplied fields is NOT provenance or durability proof.
//
// This checks page framing/context/topology and completeness under explicit
// enumeration budgets, but not source changeset bytes or file blobs. It neither
// authenticates nor authorizes anything. All rows, usage and subsequent index
// results remain private. Unreachable frames are ignored, input maps/frames must
// not mutate, and errors return nil index. Enumeration PathBytes charges assembly
// plus owned paths; index admission then checks the retained raw path bytes under
// that same numeric cap, not a cumulative allocator/RSS budget. No resume exists.
func NewTreeExactCopyIndex(ctx context.Context, identity metadata.DerivedIdentity, tree metadata.DerivedResult, frames map[TreePageID][]byte, budget TreeEntriesBudget) (*ExactCopyIndex, TreeGraphUsage, error) {
	var usage TreeGraphUsage
	if ctx == nil { return nil, usage, metadata.ErrInvalidArgument }
	if err := ctx.Err(); err != nil { return nil, usage, err }
	if identity.Validate() != nil || identity.Kind != "TREE" || identity.Version != 1 || tree.Identity != identity || tree.Value.Validate() != nil { return nil, usage, metadata.ErrInvalidArgument }
	root, err := ParseTreePageID(tree.Value.Bytes())
	if err != nil { return nil, usage, err }
	rows, usage, err := ReadTreeEntries(ctx, root, frames, budget)
	if err != nil { return nil, usage, err }
	index, err := NewExactCopyIndex(ctx, identity.Changeset, rows, ExactCopyBudget{Entries: budget.Entries, PathBytes: budget.PathBytes})
	return index, usage, err
}

// CopiesOfPath selects the source blob identity from this same private snapshot
// and returns every other indexed path with that exact identity in raw-byte
// order. The source itself is excluded BEFORE result-budget admission; no list
// is truncated. Modes may differ. These are identity matches, not proof of
// copying/renaming, similarity ranking or historical relationships.
//
// maxResults must be 1..4096. A missing source row returns ErrNotFound rather
// than an empty match set; this distinction and all candidate paths/counts/timing
// are PRIVATE and require current source/candidate authorization before use.
// A successful empty set only means this index has no alternative path. Source
// provenance/completeness and authorization remain external prerequisites.
// Constructor retains a bounded second map of <=4096 immutable path/ID pairs;
// these maps share immutable values and permit concurrent read-only lookups.
func (index *ExactCopyIndex) CopiesOfPath(ctx context.Context, sourcePath model.Path, maxResults uint64) (ExactCopyMatches, error) {
	var zero ExactCopyMatches
	if ctx == nil { return zero, metadata.ErrInvalidArgument }
	if err := ctx.Err(); err != nil { return zero, err }
	if index == nil || index.paths == nil || index.targets == nil || index.source.Validate() != nil || sourcePath.Validate() != nil || maxResults == 0 || maxResults > 4096 { return zero, metadata.ErrInvalidArgument }
	blob, present := index.targets[sourcePath]
	if !present { return zero, metadata.ErrNotFound }
	paths := index.paths[blob]
	// Constructor guarantees one occurrence of sourcePath in this bucket.
	if uint64(len(paths)-1) > maxResults { return zero, metadata.ErrResourceExhausted }
	out := ExactCopyMatches{Source: index.source}
	for _, path := range paths {
		if err := ctx.Err(); err != nil { return zero, err }
		if path == sourcePath { continue }
		out.Paths = append(out.Paths, path)
	}
	if err := ctx.Err(); err != nil { return zero, err }
	return out, nil
}

// CanonicalCopyUsage exposes private phase accounting, not successful validation
// or an authorization signal. Replay and enumeration have independent budgets;
// total work is their sum, including each admitted replay step's phase limits.
type CanonicalCopyUsage struct { Replay TreeReplayUsage; Enumeration TreeGraphUsage }

// NewCanonicalExactCopyIndex derives the selected source's tree from a complete
// supplied canonical DAG, then builds an immutable exact-content index. Every
// supplied source (including sources after target and other roots) must pass
// replay, canonical blob verification and same-repository ancestry closure.
// The target may occur anywhere in the topological input. Parent zero alone
// supplies each tree's base; nonzero parents are verified but never unioned.
// No caller-supplied mapping or page graph can substitute for that computation.
//
// This establishes local input-to-tree binding, NOT authoritative publication,
// retention, authorization, similarity or proof of copying. All usage, errors,
// counts and index results remain PRIVATE. Missing target returns ErrNotFound
// only after full replay succeeds. Inputs must remain stable. Errors return no
// index; replay's bounded intermediate pages are not retained by the result.
// Budgets are logical admission rather than an allocator/RSS guarantee.
func NewCanonicalExactCopyIndex(ctx context.Context, repository [16]byte, target model.ChangesetID, sources []TreeSourceFrame, blobs map[model.BlobID][]byte, replayBudget TreeReplayBudget, entriesBudget TreeEntriesBudget) (*ExactCopyIndex, CanonicalCopyUsage, error) {
	var usage CanonicalCopyUsage
	if ctx == nil || target.Validate() != nil { return nil, usage, metadata.ErrInvalidArgument }
	if err := ctx.Err(); err != nil { return nil, usage, err }
	writes, pages, used, err := ReplayCanonicalTreeDAG(ctx, repository, sources, blobs, replayBudget)
	usage.Replay = used
	if err != nil { return nil, usage, err }
	for _, write := range writes {
		if err := ctx.Err(); err != nil { return nil, usage, err }
		if write.Result.Identity.Changeset != target { continue }
		identity := metadata.DerivedIdentity{Repository: repository, Changeset: target, Kind: "TREE", Version: 1}
		index, enumerated, err := NewTreeExactCopyIndex(ctx, identity, write.Result, pages, entriesBudget)
		usage.Enumeration = enumerated
		return index, usage, err
	}
	if err := ctx.Err(); err != nil { return nil, usage, err }
	return nil, usage, metadata.ErrNotFound
}
