package workspace

import (
	"context"
	"errors"
	"sort"
	"strings"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
)

var ErrSparseSelection = errors.New("invalid sparse selection")

// SparseSelection is the immutable literal-prefix selection already defined by
// Manifest sparse version 1. It is not a glob parser, exclusion language, access
// grant, checkout plan or permission projection. Callers must intersect results
// with current authorized visibility before fetching or materializing anything.
// No filesystem or repository traversal is performed here.
type SparseSelection struct {
	all bool
	prefixes map[string]struct{}
	ordered []string
}

// CompileSparseSelection accepts exactly manifest v1 semantics: all selects the
// root, an empty prefix list selects nothing, and every other entry selects its
// exact byte path and descendants. Special-looking bytes remain literal. Unknown
// versions and ambiguous all-plus-prefix input fail closed. Count and aggregate
// encoding bounds match the sparse portion of a minimal manifest record.
func CompileSparseSelection(version uint16, all bool, prefixes []model.Path) (*SparseSelection, error) {
	if version != 1 || len(prefixes) > MaxPaths || all && len(prefixes) != 0 {
		return nil, ErrSparseSelection
	}
	// Fixed manifest framing and fields, with no dirty path hints.
	n := 44 + model.TypedIDSize + 4 + 8
	for _, p := range prefixes {
		if p.Validate() != nil {
			return nil, ErrSparseSelection
		}
		n += 4 + len(p.Bytes())
		if n > MaxManifestBytes {
			return nil, ErrSparseSelection
		}
	}
	s := &SparseSelection{all: all, prefixes: make(map[string]struct{}, len(prefixes))}
	for _, p := range prefixes {
		key := string(p.Bytes())
		if _, exists := s.prefixes[key]; !exists {
			s.prefixes[key] = struct{}{}
			s.ordered = append(s.ordered, key)
		}
	}
	sort.Strings(s.ordered)
	return s, nil
}

// Empty permits pruning the root without listing it. A nil selection fails
// closed. A valid all selection is nonempty even if the actual tree is empty.
func (s *SparseSelection) Empty() bool {
	return s == nil || !s.all && len(s.ordered) == 0
}

func (s *SparseSelection) selects(path string) bool {
	if s.all {
		return true
	}
	if _, ok := s.prefixes[path]; ok {
		return true
	}
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			if _, ok := s.prefixes[path[:i]]; ok {
				return true
			}
		}
	}
	return false
}

// Selects reports only literal sparse membership of a canonical non-root path.
// Ancestors of a selected prefix are not themselves selected leaf content.
func (s *SparseSelection) Selects(path model.Path) bool {
	return s != nil && path.Validate() == nil && s.selects(string(path.Bytes()))
}

// MayContain reports whether a canonical directory path is selected or could
// contain a selected descendant. False permits subtree pruning without listing
// it. True proves neither existence nor authorization and must not cause hidden
// names or unrelated leaf contents to be materialized. Use Empty for the root.
func (s *SparseSelection) MayContain(directory model.Path) bool {
	if s == nil || directory.Validate() != nil {
		return false
	}
	path := string(directory.Bytes())
	if s.selects(path) {
		return true
	}
	prefix := path + "/"
	i := sort.SearchStrings(s.ordered, prefix)
	return i < len(s.ordered) && strings.HasPrefix(s.ordered[i], prefix)
}

var ErrSparseBudget = errors.New("sparse transition budget exhausted")

// SparseTransitionBudget caps admitted snapshot rows, aggregate raw path bytes
// and emitted selection changes. Bounds are local planning limits, not measured
// heap usage; temporary path copies and the bounded seen-path table remain.
type SparseTransitionBudget struct { Entries, PathBytes, Changes uint64 }

// SparseTransition is a PRIVATE same-revision selection intent. Entry is the
// exact immutable canonical SET row. Selected=true enters the new selection;
// false leaves it. Neither value authorizes a fetch, overwrite or deletion.
type SparseTransition struct { Entry model.Operation; Selected bool }

// PlanSparseTransition computes changes between two manifest-v1 selections
// over one complete, already-authorized canonical file snapshot. Rows must be
// strictly raw-path sorted, unique and prefix-free. It validates every supplied
// row, even if both selections exclude it, and emits only membership changes
// in the same raw-path order. Unchanged selected rows produce no action.
//
// This does not traverse a tree, infer current local content, compare revisions,
// apply permissions or touch files/manifest state. Callers must separately
// establish snapshot completeness/source binding, current visibility and dirty
// file reconciliation before any materialization or removal. Missing supplied
// rows cannot prove that local files are absent. No include/exclude syntax or
// glob rules beyond existing literal-prefix manifest v1 semantics are invented.
// Errors/cancellation return nil, never a partial plan. Inputs must stay stable.
func PlanSparseTransition(ctx context.Context, rows []model.Operation, previous, next *SparseSelection, budget SparseTransitionBudget) ([]SparseTransition, error) {
	if ctx == nil || previous == nil || next == nil { return nil, ErrSparseSelection }
	if err := ctx.Err(); err != nil { return nil, err }
	if budget.Entries == 0 || budget.Entries > MaxPaths || budget.PathBytes == 0 || budget.PathBytes > MaxManifestBytes || budget.Changes == 0 || budget.Changes > budget.Entries { return nil, ErrSparseBudget }
	if uint64(len(rows)) > budget.Entries { return nil, ErrSparseBudget }
	seen := make(map[string]struct{}, len(rows))
	var pathBytes uint64
	var plan []SparseTransition
	for i, row := range rows {
		if err := ctx.Err(); err != nil { return nil, err }
		id, present := row.Target()
		if row.Path().Validate() != nil || !present || id.Validate() != nil || (i > 0 && rows[i-1].Path().Compare(row.Path()) >= 0) { return nil, ErrSparseSelection }
		raw := string(row.Path().Bytes())
		if uint64(len(raw)) > budget.PathBytes-pathBytes { return nil, ErrSparseBudget }
		pathBytes += uint64(len(raw))
		// Earlier lexicographic siblings can intervene between a file and
		// its descendant (a, a-, a/b); adjacent-only checks are insufficient.
		for j := 0; j < len(raw); j++ {
			if raw[j] == '/' { if _, fileAncestor := seen[raw[:j]]; fileAncestor { return nil, ErrSparseSelection } }
		}
		seen[raw] = struct{}{}
		was, selected := previous.selects(raw), next.selects(raw)
		if was == selected { continue }
		if uint64(len(plan)) == budget.Changes { return nil, ErrSparseBudget }
		plan = append(plan, SparseTransition{Entry: row, Selected: selected})
	}
	if err := ctx.Err(); err != nil { return nil, err }
	return plan, nil
}

// CanonicalSparseBudget admits complete DAG replay, whole selected-tree
// enumeration, and transition planning as separate bounded phases. It is not
// sparse traversal or a measured memory ceiling; excluded paths are still read
// privately during verification/enumeration. Total admitted work is their sum.
type CanonicalSparseBudget struct {
	Replay derived.TreeReplayBudget
	Snapshot derived.TreeEntriesBudget
	Transition SparseTransitionBudget
}
type CanonicalSparseUsage struct {
	Replay derived.TreeReplayUsage
	Snapshot derived.TreeGraphUsage
}

// PlanCanonicalSparseTransition derives the selected revision from a complete
// supplied canonical DAG, enumerates its file map, then plans a literal sparse
// selection change at THAT SAME revision. No caller-provided row/source or tree
// mapping assertion is used. Every DAG parent and referenced blob/page passes
// checked replay, including off-selection ancestry. Missing inputs fail closed.
//
// Output remains a PRIVATE intent, never permission to fetch/delete/overwrite.
// Source publication, retained storage, current visibility, local dirty-state
// reconciliation and durable checkout/manifest updates remain external. This
// performs no filesystem action and does not optimize subtree traversal. Inputs
// must remain stable. Any failure returns nil, never partial intents.
func PlanCanonicalSparseTransition(ctx context.Context, repository [16]byte, source model.ChangesetID, sources []derived.TreeSourceFrame, blobs map[model.BlobID][]byte, previous, next *SparseSelection, budget CanonicalSparseBudget) ([]SparseTransition, CanonicalSparseUsage, error) {
	var used CanonicalSparseUsage
	bad := func(err error) ([]SparseTransition, CanonicalSparseUsage, error) { return nil, used, err }
	if ctx == nil || source.Validate() != nil || previous == nil || next == nil || len(sources) == 0 { return bad(ErrSparseSelection) }
	if err := ctx.Err(); err != nil { return bad(err) }
	if len(sources) > 64 { return bad(ErrSparseBudget) }
	if _, err := PlanSparseTransition(ctx, nil, previous, next, budget.Transition); err != nil { return bad(err) }
	found := false
	for _, input := range sources { if input.ID == source { found = true; break } }
	if !found { return bad(ErrSparseSelection) }
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
	rows, snapshot, err := derived.ReadTreeEntries(ctx, root, pages, budget.Snapshot)
	used.Snapshot = snapshot
	if err != nil { return bad(err) }
	plan, err := PlanSparseTransition(ctx, rows, previous, next, budget.Transition)
	if err != nil { return bad(err) }
	if err := ctx.Err(); err != nil { return bad(err) }
	return plan, used, nil
}

// PlanManifestSparseTransition binds the current base and old selection to one
// structurally valid Clean manifest, then plans the requested versioned literal
// selection at that same base. Dirty/Uncertain state requires reconciliation,
// not an inferred removal plan. Invalid requested syntax also fails before any
// canonical replay. Only private intents/usage are returned; the manifest and
// files are never changed, and no new Clean state is manufactured.
//
// The caller must obtain the manifest from authoritative local metadata and
// reconcile actual filesystem state before trusting its Clean claim. A supplied
// struct cannot prove absence of concurrent edits, current authorization or
// durability. Locks, durable dirty-before-content journaling and safe checkout
// remain mandatory external steps. Do not treat this plan as commit permission.
func PlanManifestSparseTransition(ctx context.Context, repository [16]byte, current Manifest, version uint16, all bool, prefixes []model.Path, sources []derived.TreeSourceFrame, blobs map[model.BlobID][]byte, budget CanonicalSparseBudget) ([]SparseTransition, CanonicalSparseUsage, error) {
	bad := func(err error) ([]SparseTransition, CanonicalSparseUsage, error) { return nil, CanonicalSparseUsage{}, err }
	if ctx == nil { return bad(ErrSparseSelection) }
	if err := ctx.Err(); err != nil { return bad(err) }
	// Reuse the manifest's exact structural/encoded-size contract. The
	// temporary encoding is bounded by MaxManifestBytes, not retained.
	if _, err := encode(current); err != nil { return bad(err) }
	if current.State != Clean { return bad(ErrRecoveryRequired) }
	previous, err := CompileSparseSelection(current.SparseVersion, current.SparseAll, current.Sparse)
	if err != nil { return bad(err) }
	next, err := CompileSparseSelection(version, all, prefixes)
	if err != nil { return bad(err) }
	return PlanCanonicalSparseTransition(ctx, repository, current.Base, sources, blobs, previous, next, budget)
}
