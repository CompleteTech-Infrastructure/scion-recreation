package workspace

import (
	"bytes"
	"context"
	"errors"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/query"
	storage "canopy.local/canopy/internal/storage/metadata"
)

var ErrStatusInput = errors.New("invalid workspace status snapshot")
var ErrStatusLimit = errors.New("workspace status snapshot budget exhausted")

// ObservedFile is one stable, complete file observation. Payload is exact file
// content or symlink target bytes, never followed or normalized. Tag is one of
// the canonical SET modes; directories are not observations. The caller owns
// filesystem race detection and must not mutate inputs during status creation.
type ObservedFile struct {
	Path model.Path
	Tag model.OperationTag
	Payload []byte
}

// CanonicalStatusBudget gives replay, complete base enumeration and status
// comparison separate admission quanta. Total work is their sum, including all
// replay step limits. It is not one cumulative allocation or CPU-time budget.
type CanonicalStatusBudget struct {
	Replay derived.TreeReplayBudget
	Snapshot derived.TreeEntriesBudget
	Compare StatusBudget
}
type CanonicalStatusUsage struct { Replay derived.TreeReplayUsage; Snapshot derived.TreeGraphUsage }

// CompareCanonicalStatus derives binding.Base from the complete supplied
// topologically ordered canonical DAG and verified blobs before comparing
// observed workspace bytes. Every source, including unrelated/later sources and
// nonzero parents, must verify. Parent zero alone supplies each tree's base.
// A missing requested source fails only after successful complete replay.
//
// This removes caller-asserted base rows, NOT the need for stable complete
// filesystem observations, trusted manifest provenance, source publication,
// authorization, or durable clean-state reconciliation. No storage is mutated.
// All outputs/errors/usage are private. Inputs must remain stable. A failure in
// any phase returns nil deltas; usage is attempted work, not verified freshness.
func CompareCanonicalStatus(ctx context.Context, repository [16]byte, binding Manifest, sources []derived.TreeSourceFrame, blobs map[model.BlobID][]byte, observed []ObservedFile, budget CanonicalStatusBudget) ([]query.FileDelta, CanonicalStatusUsage, error) {
	var used CanonicalStatusUsage
	bad := func(err error) ([]query.FileDelta, CanonicalStatusUsage, error) { return nil, used, err }
	// Validate comparison/selection admission before expensive canonical work.
	if _, err := CompareStatusSnapshot(ctx, binding, binding.Base, nil, nil, budget.Compare); err != nil { return bad(err) }
	if uint64(len(observed)) > budget.Compare.Entries { return bad(ErrStatusLimit) }
	writes, pages, replay, err := derived.ReplayCanonicalTreeDAG(ctx, repository, sources, blobs, budget.Replay)
	used.Replay = replay
	if err != nil { return bad(err) }
	for _, write := range writes {
		if err := ctx.Err(); err != nil { return bad(err) }
		if write.Result.Identity.Changeset != binding.Base { continue }
		root, err := derived.ParseTreePageID(write.Result.Value.Bytes())
		if err != nil { return bad(err) }
		rows, snapshot, err := derived.ReadTreeEntries(ctx, root, pages, budget.Snapshot)
		used.Snapshot = snapshot
		if err != nil { return bad(err) }
		deltas, err := CompareStatusSnapshot(ctx, binding, binding.Base, rows, observed, budget.Compare)
		if err != nil { return bad(err) }
		return deltas, used, nil
	}
	if err := ctx.Err(); err != nil { return bad(err) }
	return bad(storage.ErrNotFound)
}

// StatusBudget bounds combined input rows/path bytes, selected payload bytes
// hashed, and output changes. Rows/changes cap at 8192; byte caps are 64 MiB.
// Path copies, hashing and comparison are separate bounded passes, not an RSS
// bound. Unselected content is not hashed or charged against PayloadBytes.
type StatusBudget struct { Entries, PathBytes, PayloadBytes, Changes uint64 }

// CompareStatusSnapshot computes exact content/mode/add/delete status for the
// manifest's literal sparse selection. baseSource must equal binding.Base;
// callers must establish that base is that revision's complete canonical tree
// and observed covers EVERY selected current file, including unchanged files.
// Both inputs must be strictly raw-path sorted, unique, and valid leaf sets.
// Missing selected observations mean deletion, never "not scanned yet".
//
// This private helper does not read a filesystem, validate a WatchScan token,
// infer status from dirty hints/stat equality, authorize paths, or mark Clean.
// Clean/Dirty/Uncertain and DirtyPaths do not suppress comparison. A complete
// stable content scan is required even after ignored/lost watcher events.
// A zero delta list is equality of these supplied snapshots, not evidence of
// current filesystem cleanliness/durability. Errors return no partial deltas.
// Exact blob identity handles binary/empty files and symlink payloads without
// text classification. Rename/copy inference and local text patches are separate.
func CompareStatusSnapshot(ctx context.Context, binding Manifest, baseSource model.ChangesetID, base []model.Operation, observed []ObservedFile, budget StatusBudget) ([]query.FileDelta, error) {
	if ctx == nil { return nil, ErrStatusInput }
	if err := ctx.Err(); err != nil { return nil, err }
	if binding.Base.Validate() != nil || baseSource != binding.Base { return nil, ErrStatusInput }
	if budget.Entries == 0 || budget.Entries > 8192 || budget.PathBytes == 0 || budget.PathBytes > 64<<20 || budget.PayloadBytes == 0 || budget.PayloadBytes > 64<<20 || budget.Changes == 0 || budget.Changes > budget.Entries { return nil, ErrStatusLimit }
	if uint64(len(base)) > budget.Entries || uint64(len(observed)) > budget.Entries-uint64(len(base)) { return nil, ErrStatusLimit }
	selection, err := CompileSparseSelection(binding.SparseVersion, binding.SparseAll, binding.Sparse)
	if err != nil { return nil, err }
	var pathBytes, payloadBytes uint64
	// Raw sorting does not make ancestors adjacent: a, a-, a/b is sorted.
	// Each side gets its own bounded set, covering excluded paths as well.
	seen := make(map[string]struct{})
	chargePath := func(path model.Path) error {
		if path.Validate() != nil { return ErrStatusInput }
		raw := path.Bytes()
		n := uint64(len(raw))
		if n > budget.PathBytes-pathBytes { return ErrStatusLimit }
		pathBytes += n
		for i, b := range raw {
			if i%(32<<10) == 0 { if err := ctx.Err(); err != nil { return err } }
			if b == '/' { if _, exists := seen[string(raw[:i])]; exists { return ErrStatusInput } }
		}
		seen[string(raw)] = struct{}{}
		return nil
	}
	var before []model.Operation
	for i, row := range base {
		if err := ctx.Err(); err != nil { return nil, err }
		if err := chargePath(row.Path()); err != nil { return nil, err }
		id, present := row.Target()
		if !present || id.Validate() != nil || (i > 0 && base[i-1].Path().Compare(row.Path()) >= 0) { return nil, ErrStatusInput }
		if selection.Selects(row.Path()) { before = append(before, row) }
	}
	clear(seen)
	// Admit all selected payloads before hashing any. Unselected observations
	// still require valid ordered paths/modes and charge row/path scan bounds.
	for i, row := range observed {
		if err := ctx.Err(); err != nil { return nil, err }
		if err := chargePath(row.Path); err != nil { return nil, err }
		if row.Tag < model.SetRegular || row.Tag > model.SetSymlink || (i > 0 && observed[i-1].Path.Compare(row.Path) >= 0) { return nil, ErrStatusInput }
		if !selection.Selects(row.Path) { continue }
		n := uint64(len(row.Payload))
		if n > budget.PayloadBytes-payloadBytes { return nil, ErrStatusLimit }
		payloadBytes += n
	}
	var after []model.Operation
	for _, row := range observed {
		if err := ctx.Err(); err != nil { return nil, err }
		if !selection.Selects(row.Path) { continue }
		id, err := model.HashBlob(ctx, uint64(len(row.Payload)), bytes.NewReader(row.Payload))
		if err != nil { return nil, err }
		op, err := model.NewOperation(row.Path, row.Tag, &id)
		if err != nil { return nil, err }
		after = append(after, op)
	}
	return query.DiffFileEntries(ctx, before, after, query.FileDiffBudget{Entries: budget.Entries, PathBytes: budget.PathBytes, Changes: budget.Changes})
}
