package edit

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"strings"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

var (
	ErrFileState  = errors.New("invalid file conflict state")
	ErrFileBudget = errors.New("file conflict byte budget exhausted")
)

// FileVersion is an immutable, explicitly absent or present file. Its zero
// value is invalid, not deletion. It models control-v1 ConflictSide locally;
// it is not a wire decoder, a verified blob or an authorization assertion.
// Binary bytes and symlink target bytes are opaque; no normalization occurs.
type FileVersion struct {
	state   uint8
	mode    model.OperationTag
	content string
}

func AbsentFile() FileVersion { return FileVersion{state: 1} }

// PresentFile owns a copy of content. A nonnil empty slice explicitly represents
// an empty file; nil is missing required content. The caller admits memory
// before constructing values; this helper additionally caps each file at 64 MiB.
func PresentFile(mode model.OperationTag, content []byte) (FileVersion, error) {
	if mode < model.SetRegular || mode > model.SetSymlink || content == nil {
		return FileVersion{}, ErrFileState
	}
	if uint64(len(content)) > 64<<20 {
		return FileVersion{}, ErrFileBudget
	}
	return FileVersion{state: 2, mode: mode, content: string(content)}, nil
}

func (v FileVersion) Validate() error {
	if v.state == 1 && v.mode == model.Delete && v.content == "" {
		return nil
	}
	if v.state == 2 && v.mode >= model.SetRegular && v.mode <= model.SetSymlink && uint64(len(v.content)) <= 64<<20 {
		return nil
	}
	return ErrFileState
}

// Content returns a caller-owned copy for present files, including present-empty.
// Invalid and absent values return false; callers must Validate to distinguish.
func (v FileVersion) Content() ([]byte, bool) {
	if v.Validate() != nil || v.state != 2 {
		return nil, false
	}
	return append([]byte{}, v.content...), true
}
func (v FileVersion) Mode() (model.OperationTag, bool) {
	return v.mode, v.Validate() == nil && v.state == 2
}
func (v FileVersion) IsAbsent() bool { return v.Validate() == nil && v.state == 1 }

// FileConflict preserves all exact input states. It contains no path, diagnostic
// payload or authority claim. Service code must authorize every side and linked
// identity before serializing it; this local value must never bypass filtering.
type FileConflict struct {
	Base, Left, Right FileVersion
}

// MergeFileVersions resolves only provably identical/unchanged whole-file cases.
// Different concurrent byte/type/mode edits return an explicit conflict and the
// invalid zero result. This includes delete/modify, distinct additions, binary
// and symlink changes. Mode and bytes are considered together: a mode change on
// one side plus content change on the other is conservatively a conflict here.
// It does NOT run text merge, choose a base, resolve a conflict, authorize output,
// emit a canonical operation, or publish. Partial EDT-02 only; #97/service wiring
// remains separate. maxBytes admits the sum of all three content lengths, capped
// at 64 MiB; zero admits only empty/absent states. Returned values are immutable.
func MergeFileVersions(ctx context.Context, base, left, right FileVersion, maxBytes uint64) (FileVersion, *FileConflict, error) {
	if ctx == nil {
		return FileVersion{}, nil, ErrFileState
	}
	if err := ctx.Err(); err != nil {
		return FileVersion{}, nil, err
	}
	if maxBytes > 64<<20 {
		return FileVersion{}, nil, ErrFileBudget
	}
	var used uint64
	for _, v := range []FileVersion{base, left, right} {
		if err := v.Validate(); err != nil {
			return FileVersion{}, nil, err
		}
		if uint64(len(v.content)) > maxBytes-used {
			return FileVersion{}, nil, ErrFileBudget
		}
		used += uint64(len(v.content))
	}
	var result FileVersion
	switch {
	case left == right:
		result = left
	case left == base:
		result = right
	case right == base:
		result = left
	}
	if err := ctx.Err(); err != nil {
		return FileVersion{}, nil, err
	}
	if result.Validate() != nil {
		return FileVersion{}, &FileConflict{base, left, right}, nil
	}
	return result, nil, nil
}

// MergeTextFileVersions composes file-state handling with bounded text merging.
// Callers explicitly select this operation for text: NUL rejection is only a
// guard, not a comprehensive classifier. Use MergeFileVersions for opaque binary
// and symlink data. This is not authorization, base selection or publication.
//
// Identical/unchanged whole-file cases resolve first without parsing content.
// Competing edits merge as text only when ALL three states are present regular
// or executable files. Delete/modify, distinct additions and symlink/type cases
// retain exact structured conflicts. Modes use ordinary three-way equality:
// equal side modes win; otherwise the side different from base wins. An
// unresolved mode or text overlap keeps all three exact FileConflict states.
// Byte admission always applies; line/cell/hunk work limits are consumed only
// when text analysis runs. Bytes is not a peak-memory ceiling. Byte admission
// failures return ErrFileBudget; invalid text limits or exhausted text work
// return ErrTextLimit. No result escapes on error.
func MergeTextFileVersions(ctx context.Context, base, left, right FileVersion, budget ThreeWayTextBudget) (FileVersion, *FileConflict, error) {
	if ctx == nil { return FileVersion{}, nil, ErrFileState }
	if err := ctx.Err(); err != nil { return FileVersion{}, nil, err }
	if budget.Bytes == 0 || budget.Bytes > 64<<20 || budget.Lines == 0 || budget.Lines > 1000000 || budget.Cells == 0 || budget.Cells > 4000000 || budget.Hunks == 0 || budget.Hunks > 1000000 {
		return FileVersion{}, nil, ErrTextLimit
	}
	resolved, conflict, err := MergeFileVersions(ctx, base, left, right, budget.Bytes)
	if err != nil || conflict == nil { return resolved, conflict, err }
	for _, v := range []FileVersion{base, left, right} {
		if v.state != 2 || (v.mode != model.SetRegular && v.mode != model.SetExecutable) {
			return FileVersion{}, conflict, nil
		}
	}
	var mode model.OperationTag
	switch {
	case left.mode == right.mode:
		mode = left.mode
	case left.mode == base.mode:
		mode = right.mode
	case right.mode == base.mode:
		mode = left.mode
	default:
		return FileVersion{}, conflict, nil
	}
	// Combined byte admission already succeeded above. Conversions own local
	// bounded copies; returned content is independently owned by PresentFile.
	content, overlap, err := MergeText(ctx, []byte(base.content), []byte(left.content), []byte(right.content), budget)
	if err != nil { return FileVersion{}, nil, err }
	if overlap != nil { return FileVersion{}, conflict, nil }
	resolved, err = PresentFile(mode, content)
	if err != nil { return FileVersion{}, nil, err }
	if err := ctx.Err(); err != nil { return FileVersion{}, nil, err }
	return resolved, nil, nil
}

// CanonicalFileSide is a private input descriptor, not a trusted file state.
// Present=false requires zero Mode/ID and nil Frame. Present=true requires a
// regular/executable/symlink mode, typed blob ID and complete canonical frame.
// Present-empty has a verified empty blob frame, never an absent descriptor.
// Mode and presence are NOT authenticated by a blob digest: callers must bind
// these descriptors to the correct authorized tree/source independently.
type CanonicalFileSide struct {
	Present bool
	Mode model.OperationTag
	ID model.BlobID
	Frame []byte
}

// MergeCanonicalFileVersions verifies every present side before applying the
// opaque whole-file equality rules of MergeFileVersions. Sides are ordered base,
// left, right. Matching IDs never skip validation. Binary and symlink payloads
// remain opaque; concurrent changes yield exact FileConflict states, not text
// merging or arbitrary winners. This does not authorize, choose a base, fetch
// blobs, decode envelopes, establish retention or publish anything.
//
// maxBytes admits combined decoded payloads, capped at 64 MiB; zero allows only
// absent/empty content. Canonical headers are excluded. Owned staging and file
// copies are bounded but this is not a peak-memory ceiling. Frames must not
// mutate during the call. Any verification error yields zero result/no conflict.
func MergeCanonicalFileVersions(ctx context.Context, sides [3]CanonicalFileSide, maxBytes uint64) (FileVersion, *FileConflict, error) {
	versions, err := verifyCanonicalFileSides(ctx, sides, maxBytes)
	if err != nil { return FileVersion{}, nil, err }
	return MergeFileVersions(ctx, versions[0], versions[1], versions[2], maxBytes)
}

// MergeCanonicalTextFileVersions verifies every present canonical blob before
// applying MergeTextFileVersions, including its whole-file equality fast paths.
// Callers explicitly choose text processing: only concurrent present regular/
// executable edits enter text analysis; delete/modify, additions and symlink/
// type cases keep existing exact conflicts. NUL rejection is not a classifier;
// opaque equality fast paths intentionally preserve binary and symlink bytes.
//
// Descriptor presence/mode, source/tree binding, correct base and authorization
// remain caller prerequisites, as for CanonicalFileSide. No output is published.
// Bytes admits combined decoded payloads, excluding headers, and bounds text
// output separately. Copying/staging is bounded but not a peak-memory guarantee.
// All budgets must be valid before decoding; work limits are charged only when
// text analysis runs. Errors return zero result/no conflict, never unverified
// content. Inputs must not mutate during the call.
func MergeCanonicalTextFileVersions(ctx context.Context, sides [3]CanonicalFileSide, budget ThreeWayTextBudget) (FileVersion, *FileConflict, error) {
	if ctx == nil { return FileVersion{}, nil, ErrFileState }
	if err := ctx.Err(); err != nil { return FileVersion{}, nil, err }
	if budget.Bytes == 0 || budget.Bytes > 64<<20 || budget.Lines == 0 || budget.Lines > 1000000 || budget.Cells == 0 || budget.Cells > 4000000 || budget.Hunks == 0 || budget.Hunks > 1000000 {
		return FileVersion{}, nil, ErrTextLimit
	}
	versions, err := verifyCanonicalFileSides(ctx, sides, budget.Bytes)
	if err != nil { return FileVersion{}, nil, err }
	return MergeTextFileVersions(ctx, versions[0], versions[1], versions[2], budget)
}

// Shared verification must finish before either merge path can expose states.
func verifyCanonicalFileSides(ctx context.Context, sides [3]CanonicalFileSide, maxBytes uint64) ([3]FileVersion, error) {
	if ctx == nil { return [3]FileVersion{}, ErrFileState }
	if err := ctx.Err(); err != nil { return [3]FileVersion{}, err }
	if maxBytes > 64<<20 { return [3]FileVersion{}, ErrFileBudget }
	frameAllowance := maxBytes
	for _, side := range sides {
		if !side.Present {
			if side.Mode != model.Delete || side.ID != (model.BlobID{}) || side.Frame != nil { return [3]FileVersion{}, ErrFileState }
			continue
		}
		if side.Mode < model.SetRegular || side.Mode > model.SetSymlink || side.ID.Validate() != nil { return [3]FileVersion{}, ErrFileState }
		frameAllowance += 22
	}
	for _, side := range sides {
		if uint64(len(side.Frame)) > frameAllowance { return [3]FileVersion{}, ErrFileBudget }
		frameAllowance -= uint64(len(side.Frame))
	}
	versions := [3]FileVersion{AbsentFile(), AbsentFile(), AbsentFile()}
	remaining := maxBytes
	for i, side := range sides {
		if !side.Present { continue }
		var content bytes.Buffer
		n, err := model.DecodeBlob(ctx, bytes.NewReader(side.Frame), side.ID, &content, remaining)
		if err != nil { return [3]FileVersion{}, err }
		remaining -= n
		payload := content.Bytes()
		if payload == nil { payload = []byte{} }
		versions[i], err = PresentFile(side.Mode, payload)
		if err != nil { return [3]FileVersion{}, err }
	}
	return versions, nil
}

// PreparedFileOperation is PRIVATE candidate content, not a durable upload,
// authorized operation, published changeset or conflict-resolution receipt.
// DELETE has nil BlobFrame; SET has a complete canonical frame whose identity
// equals Operation.Target, including present-empty. BlobFrame is caller-owned.
type PreparedFileOperation struct {
	Operation model.Operation
	BlobFrame []byte
}

// PrepareFileOperation encodes one explicitly resolved file state at an exact
// canonical path. Absence becomes DELETE; present mode and bytes become SET
// plus a newly hashed canonical blob frame. It does not infer whether the path
// changed, select/resolve conflicts or verify that this state came from a merge.
// The caller must validate the whole changeset/tree, authorize every input and
// output, durably upload bytes, obtain receipts and publish separately.
//
// maxPayload caps decoded content (0..64 MiB); zero admits absent/empty states.
// A present frame adds 22 bytes of canonical header. Hashing and encoding make
// two bounded streaming passes over immutable content. Output allocation is not
// a reservation/RSS guarantee. Errors return no operation or frame.
func PrepareFileOperation(ctx context.Context, path model.Path, version FileVersion, maxPayload uint64) (PreparedFileOperation, error) {
	var zero PreparedFileOperation
	if ctx == nil { return zero, ErrFileState }
	if err := ctx.Err(); err != nil { return zero, err }
	if path.Validate() != nil || version.Validate() != nil { return zero, ErrFileState }
	if maxPayload > 64<<20 || uint64(len(version.content)) > maxPayload { return zero, ErrFileBudget }
	if version.IsAbsent() {
		op, err := model.NewOperation(path, model.Delete, nil)
		if err != nil { return zero, err }
		if err := ctx.Err(); err != nil { return zero, err }
		return PreparedFileOperation{Operation: op}, nil
	}
	length := uint64(len(version.content))
	id, err := model.HashBlob(ctx, length, strings.NewReader(version.content))
	if err != nil { return zero, err }
	var frame bytes.Buffer
	if err := model.EncodeBlob(ctx, &frame, length, strings.NewReader(version.content)); err != nil { return zero, err }
	op, err := model.NewOperation(path, version.mode, &id)
	if err != nil { return zero, err }
	if err := ctx.Err(); err != nil { return zero, err }
	return PreparedFileOperation{Operation: op, BlobFrame: frame.Bytes()}, nil
}

// ResolvedFileEntry binds an explicit resolved state to one canonical path.
// This is private input, not proof that a conflict was resolved or authorized.
type ResolvedFileEntry struct { Path model.Path; Version FileVersion }

// FilePreparationBudget bounds the entire batch, not each entry. Entries and
// PathBytes must be positive and at most 4096 and 64 MiB respectively. Payload
// may be zero and is capped at 64 MiB. Frames may be zero and is capped at
// 64 MiB + 4096*22, including each present entry's canonical header. Repeated
// content counts separately: no implicit deduplication bypasses admission.
type FilePreparationBudget struct { Entries, PathBytes, Payload, Frames uint64 }

// PrepareFileOperations requires strictly raw-byte-sorted unique paths and
// preflights all descriptors and aggregate sizes before hashing/encoding any
// blob. Each result corresponds to its input, preserving SET/DELETE and modes.
// Empty input succeeds with nil results; any error returns nil results, never
// a usable prefix. Output frame slices are owned independently of each other.
//
// Simultaneously present file/descendant paths are intrinsically impossible
// and rejected before encoding. DELETE ancestors do not block SET descendants.
// This does NOT validate the entire delta against a parent tree (including
// retained descendants), complete changeset canonicality, authorization,
// conflict resolution, upload/durability or publication. The caller must perform
// those checks before using these PRIVATE candidates. Aggregate retained output
// is bounded but temporary copies/allocator overhead are not a measured RSS cap.
// Inputs must not mutate during the call. No partial resume state is returned.
func PrepareFileOperations(ctx context.Context, entries []ResolvedFileEntry, budget FilePreparationBudget) ([]PreparedFileOperation, error) {
	if ctx == nil { return nil, ErrFileState }
	if err := ctx.Err(); err != nil { return nil, err }
	if budget.Entries == 0 || budget.Entries > 4096 || budget.PathBytes == 0 || budget.PathBytes > 64<<20 || budget.Payload > 64<<20 || budget.Frames > (64<<20)+4096*22 { return nil, ErrFileBudget }
	if uint64(len(entries)) > budget.Entries { return nil, ErrFileBudget }
	var paths, payload, frames uint64
	for i, entry := range entries {
		if err := ctx.Err(); err != nil { return nil, err }
		if entry.Path.Validate() != nil || entry.Version.Validate() != nil || (i > 0 && entries[i-1].Path.Compare(entry.Path) >= 0) { return nil, ErrFileState }
		n := uint64(len(entry.Path.Bytes()))
		if n > budget.PathBytes-paths { return nil, ErrFileBudget }; paths += n
		n = uint64(len(entry.Version.content))
		if n > budget.Payload-payload { return nil, ErrFileBudget }; payload += n
		if !entry.Version.IsAbsent() {
			n += 22
			if n > budget.Frames-frames { return nil, ErrFileBudget }; frames += n
		}
	}
	// Sorted input keeps the present-only subsequence sorted. Checking only
	// adjacent rows is insufficient: "a-" sorts between "a" and "a/b".
	// Path copies are bounded by admitted PathBytes; each search uses one
	// temporary slash-prefix, not a copy of every ancestor component.
	var present []string
	for _, entry := range entries {
		if err := ctx.Err(); err != nil { return nil, err }
		if !entry.Version.IsAbsent() { present = append(present, string(entry.Path.Bytes())) }
	}
	for _, path := range present {
		if err := ctx.Err(); err != nil { return nil, err }
		prefix := path + "/"
		i := sort.SearchStrings(present, prefix)
		if i < len(present) && strings.HasPrefix(present[i], prefix) { return nil, ErrFileState }
	}
	var out []PreparedFileOperation
	for _, entry := range entries {
		candidate, err := PrepareFileOperation(ctx, entry.Path, entry.Version, uint64(len(entry.Version.content)))
		if err != nil { return nil, err }
		out = append(out, candidate)
	}
	if err := ctx.Err(); err != nil { return nil, err }
	return out, nil
}

// FileMergeEntry contains one exact path's already established base/left/right
// states. Source identity, base selection, completeness and permission are caller
// prerequisites; this descriptor is not a verified tree or authorization proof.
type FileMergeEntry struct { Path model.Path; Base, Left, Right FileVersion }

// PathFileConflict owns immutable exact sides plus their canonical path.
// Every path/side remains private until independently authorized for disclosure.
type PathFileConflict struct { Path model.Path; Sides FileConflict }

// FileMergeBudget admits shared entries, raw path bytes and combined content
// bytes across ALL three states of ALL entries. Limits are 4096 entries and
// 64 MiB per byte counter. Entries/PathBytes must be positive; Payload may be zero.
type FileMergeBudget struct { Entries, PathBytes, Payload uint64 }

// MergeFileEntries applies opaque whole-file equality to strictly raw-byte-
// sorted unique file triples. It preflights the entire input under one budget.
// If any path conflicts, it returns ALL path-qualified conflicts and no resolved
// candidates; callers cannot mistake a resolved prefix for a complete result.
// With no conflicts it returns one resolved entry per input, including unchanged
// or absent states. Any error returns neither candidates nor conflicts.
//
// This is independent-path merging, not whole-tree merging: file/descendant
// interactions, renames, multiple-base selection, text alignment, source/blob
// verification, authorization and publication are separate mandatory concerns.
// Conflicts do not authorize winner selection. Input states are immutable, but
// the input slice must not change concurrently. Results own their slices. Bounds
// count logical bytes, not allocated memory; no resume state is provided.
func MergeFileEntries(ctx context.Context, entries []FileMergeEntry, budget FileMergeBudget) ([]ResolvedFileEntry, []PathFileConflict, error) {
	if ctx == nil { return nil, nil, ErrFileState }
	if err := ctx.Err(); err != nil { return nil, nil, err }
	if budget.Entries == 0 || budget.Entries > 4096 || budget.PathBytes == 0 || budget.PathBytes > 64<<20 || budget.Payload > 64<<20 { return nil, nil, ErrFileBudget }
	if uint64(len(entries)) > budget.Entries { return nil, nil, ErrFileBudget }
	var paths, payload uint64
	for i, entry := range entries {
		if err := ctx.Err(); err != nil { return nil, nil, err }
		if entry.Path.Validate() != nil || (i > 0 && entries[i-1].Path.Compare(entry.Path) >= 0) { return nil, nil, ErrFileState }
		n := uint64(len(entry.Path.Bytes()))
		if n > budget.PathBytes-paths { return nil, nil, ErrFileBudget }; paths += n
		for _, version := range [3]FileVersion{entry.Base, entry.Left, entry.Right} {
			if version.Validate() != nil { return nil, nil, ErrFileState }
			n := uint64(len(version.content))
			if n > budget.Payload-payload { return nil, nil, ErrFileBudget }; payload += n
		}
	}
	var resolved []ResolvedFileEntry
	var conflicts []PathFileConflict
	for _, entry := range entries {
		version, conflict, err := MergeFileVersions(ctx, entry.Base, entry.Left, entry.Right, budget.Payload)
		if err != nil { return nil, nil, err }
		if conflict != nil {
			conflicts = append(conflicts, PathFileConflict{entry.Path, *conflict})
		} else {
			resolved = append(resolved, ResolvedFileEntry{entry.Path, version})
		}
	}
	if err := ctx.Err(); err != nil { return nil, nil, err }
	if len(conflicts) != 0 { return nil, conflicts, nil }
	return resolved, nil, nil
}

// CanonicalFileMergeEntry supplies untrusted base/left/right blob descriptors at
// one exact path. Mode/presence and source/base binding remain caller assertions.
type CanonicalFileMergeEntry struct { Path model.Path; Sides [3]CanonicalFileSide }

// MergeCanonicalFileEntries verifies ALL present blobs before exposing any
// resolved state or conflict, then applies MergeFileEntries' opaque equality
// rules. Matching IDs do not skip verification. Entries must have strictly
// sorted unique paths; FileMergeBudget is shared across the entire batch,
// including every repeated payload. Canonical frames additionally admit 22
// header bytes per present side (at most 3*4096 headers). Empty/absent states
// remain distinct, and zero payload budget permits them both.
//
// No result escapes on malformed data, exhaustion or cancellation, even if an
// earlier entry would conflict or resolve. This is private independent-path
// processing, not complete tree/source verification, text merging, rename or
// multi-base policy, authorization, durable upload or publication. Input frames
// and slices must not mutate during the call. Limits are logical admission,
// not an allocator/RSS guarantee; bounded staging copies remain necessary.
func MergeCanonicalFileEntries(ctx context.Context, entries []CanonicalFileMergeEntry, budget FileMergeBudget) ([]ResolvedFileEntry, []PathFileConflict, error) {
	if ctx == nil { return nil, nil, ErrFileState }
	if err := ctx.Err(); err != nil { return nil, nil, err }
	if budget.Entries == 0 || budget.Entries > 4096 || budget.PathBytes == 0 || budget.PathBytes > 64<<20 || budget.Payload > 64<<20 { return nil, nil, ErrFileBudget }
	if uint64(len(entries)) > budget.Entries { return nil, nil, ErrFileBudget }
	var paths, frames, headers uint64
	for i, entry := range entries {
		if err := ctx.Err(); err != nil { return nil, nil, err }
		if entry.Path.Validate() != nil || (i > 0 && entries[i-1].Path.Compare(entry.Path) >= 0) { return nil, nil, ErrFileState }
		n := uint64(len(entry.Path.Bytes()))
		if n > budget.PathBytes-paths { return nil, nil, ErrFileBudget }; paths += n
		for _, side := range entry.Sides {
			if !side.Present {
				if side.Mode != model.Delete || side.ID != (model.BlobID{}) || side.Frame != nil { return nil, nil, ErrFileState }
				continue
			}
			if side.Mode < model.SetRegular || side.Mode > model.SetSymlink || side.ID.Validate() != nil { return nil, nil, ErrFileState }
			headers += 22
			// The hard maximum prevents overflow before the tighter shared check.
			n := uint64(len(side.Frame))
			if n > (64<<20)+3*4096*22-frames { return nil, nil, ErrFileBudget }; frames += n
		}
	}
	if frames > budget.Payload+headers { return nil, nil, ErrFileBudget }
	remaining := budget.Payload
	var verified []FileMergeEntry
	for _, entry := range entries {
		versions, err := verifyCanonicalFileSides(ctx, entry.Sides, remaining)
		if err != nil { return nil, nil, err }
		for _, v := range versions { remaining -= uint64(len(v.content)) }
		verified = append(verified, FileMergeEntry{entry.Path, versions[0], versions[1], versions[2]})
	}
	return MergeFileEntries(ctx, verified, budget)
}

// TreeFileMergeBudget bounds private replay, each of three exact-path lookups,
// and combined decoded merge content separately. Work includes all phases;
// Payload is 0..64 MiB and excludes canonical headers, as for file merging.
type TreeFileMergeBudget struct {
	Replay derived.TreeReplayBudget
	Lookup [3]derived.TreeLookupBudget
	Payload uint64
}
type TreeFileMergeUsage struct { Replay derived.TreeReplayUsage; Lookup [3]derived.TreeLookupUsage }

// MergeCanonicalTreeFile derives base/left/right file states at one exact path
// from selected canonical sources in a complete supplied DAG. Every supplied
// source and required blob must pass replay before lookup or merging, including
// sources unrelated to the selected revisions. All three selected IDs must be
// present; even identical sides undergo lookup and canonical blob verification.
// Base is explicitly caller-selected: no ancestry/base-selection policy is
// inferred. Opaque whole-file equality resolves only identical/unchanged states.
//
// This is private single-file computation, NOT whole-tree merge: a directory at
// path is file-absence, and file/directory interactions require separate handling.
// Source-byte binding is established in-call; authoritative publication,
// retention, permission, text merging, renames, resolution and publication are
// not. Inputs must stay stable. Errors expose neither result nor conflict;
// private usage may describe work before failure. Returned states are immutable.
func MergeCanonicalTreeFile(ctx context.Context, repository [16]byte, selected [3]model.ChangesetID, path model.Path, sources []derived.TreeSourceFrame, blobs map[model.BlobID][]byte, budget TreeFileMergeBudget) (FileVersion, *FileConflict, TreeFileMergeUsage, error) {
	sides, usage, err := canonicalTreeFileSides(ctx, repository, selected, path, sources, blobs, budget)
	if err != nil { return FileVersion{}, nil, usage, err }
	version, conflict, err := MergeCanonicalFileVersions(ctx, sides, budget.Payload)
	if err != nil { return FileVersion{}, nil, usage, err }
	return version, conflict, usage, nil
}

// TreeTextFileMergeBudget replaces opaque payload admission with the existing
// text byte/line/cell/hunk limits. Replay and three lookups remain independent.
type TreeTextFileMergeBudget struct {
	Replay derived.TreeReplayBudget
	Lookup [3]derived.TreeLookupBudget
	Text ThreeWayTextBudget
}

// MergeCanonicalTreeTextFile explicitly selects text processing for the same
// source-bound exact-file computation as MergeCanonicalTreeFile. All supplied
// DAG sources are verified before any equality fast path or text analysis.
// Competing edits enter text analysis only for present regular/executable sides;
// deletion, addition and symlink/type cases retain exact structured conflicts.
// Whole-file equality fast paths preserve opaque bytes; NUL rejection in text
// analysis is a guard, not a classifier. Callers choose text and a valid base.
//
// Directory-as-file-absence, private output, stable inputs and all publication,
// retention/authorization/whole-tree exclusions of MergeCanonicalTreeFile apply.
// Text limits are validated before replay. Bytes admits combined input payload
// and bounds output separately; work budgets are not a peak-memory guarantee.
func MergeCanonicalTreeTextFile(ctx context.Context, repository [16]byte, selected [3]model.ChangesetID, path model.Path, sources []derived.TreeSourceFrame, blobs map[model.BlobID][]byte, budget TreeTextFileMergeBudget) (FileVersion, *FileConflict, TreeFileMergeUsage, error) {
	var zero TreeFileMergeUsage
	if ctx == nil { return FileVersion{}, nil, zero, ErrFileState }
	if err := ctx.Err(); err != nil { return FileVersion{}, nil, zero, err }
	b := budget.Text
	if b.Bytes == 0 || b.Bytes > 64<<20 || b.Lines == 0 || b.Lines > 1000000 || b.Cells == 0 || b.Cells > 4000000 || b.Hunks == 0 || b.Hunks > 1000000 { return FileVersion{}, nil, zero, ErrTextLimit }
	sides, usage, err := canonicalTreeFileSides(ctx, repository, selected, path, sources, blobs, TreeFileMergeBudget{budget.Replay,budget.Lookup,b.Bytes})
	if err != nil { return FileVersion{}, nil, usage, err }
	version, conflict, err := MergeCanonicalTextFileVersions(ctx, sides, b)
	if err != nil { return FileVersion{}, nil, usage, err }
	return version, conflict, usage, nil
}

// Side derivation is shared, but content verification/merge remains mandatory
// in both entry points. Descriptors must never escape as trusted public states.
func canonicalTreeFileSides(ctx context.Context, repository [16]byte, selected [3]model.ChangesetID, path model.Path, sources []derived.TreeSourceFrame, blobs map[model.BlobID][]byte, budget TreeFileMergeBudget) ([3]CanonicalFileSide, TreeFileMergeUsage, error) {
	var usage TreeFileMergeUsage
	bad := func(err error) ([3]CanonicalFileSide, TreeFileMergeUsage, error) { return [3]CanonicalFileSide{}, usage, err }
	if ctx == nil || path.Validate() != nil { return bad(ErrFileState) }
	if err := ctx.Err(); err != nil { return bad(err) }
	if budget.Payload > 64<<20 { return bad(ErrFileBudget) }
	for i, id := range selected {
		if id.Validate() != nil { return bad(ErrFileState) }
		b := budget.Lookup[i]
		if b.Pages == 0 || b.Pages > 4096 || b.ReadBytes == 0 || b.ReadBytes > 4096*derived.MaxTreePageBytes { return bad(metadata.ErrInvalidArgument) }
	}
	writes, pages, replayed, err := derived.ReplayCanonicalTreeDAG(ctx, repository, sources, blobs, budget.Replay)
	usage.Replay = replayed
	if err != nil { return bad(err) }
	var sides [3]CanonicalFileSide
	for i, id := range selected {
		var found bool
		for _, write := range writes {
			if err := ctx.Err(); err != nil { return bad(err) }
			if write.Result.Identity.Changeset != id { continue }
			found = true
			root, err := derived.ParseTreePageID(write.Result.Value.Bytes())
			if err != nil { return bad(err) }
			row, used, err := derived.LookupTreeLeaf(ctx, root, pages, path, budget.Lookup[i])
			usage.Lookup[i] = used
			if errors.Is(err, derived.ErrTreeLeafAbsent) { break }
			if err != nil { return bad(err) }
			blob, ok := row.Target()
			if !ok { return bad(ErrFileState) }
			frame, ok := blobs[blob]
			if !ok { return bad(metadata.ErrFailedPrecondition) }
			sides[i] = CanonicalFileSide{true,row.Tag(),blob,frame}
			break
		}
		if !found { return bad(metadata.ErrNotFound) }
	}
	if err := ctx.Err(); err != nil { return bad(err) }
	return sides, usage, nil
}

// ResolveFileEntries applies an explicitly complete set of exact-path manual
// resolutions to MergeFileEntries' opaque independent-file conflicts. A valid
// resolution may contain newly edited bytes or explicit absence; it need not
// choose an existing side. Exactly one resolution is required per actual
// conflict, in raw-path order, with no extras or duplicates. Automatic winners
// are preserved rather than overridden. Missing/extra/mismatched resolutions
// fail closed with ErrFileState; no unresolved or partial result escapes.
//
// FileMergeBudget admits the original three states AND every manual resolution
// payload together. Entries/PathBytes bound the original batch; resolution paths
// must exactly match its conflict subset, and at most Entries resolutions exist.
// Repeated payloads count separately. This is private syntax/composition, not
// evidence of user approval, source identity, base policy, permissions or complete
// tree validity. Manual delete/file/directory interactions, canonical operation
// preparation, durable publication and authorization remain caller obligations.
func ResolveFileEntries(ctx context.Context, entries []FileMergeEntry, resolutions []ResolvedFileEntry, budget FileMergeBudget) ([]ResolvedFileEntry, error) {
	if ctx == nil { return nil, ErrFileState }
	if err := ctx.Err(); err != nil { return nil, err }
	if len(resolutions) > len(entries) { return nil, ErrFileState }
	resolved, conflicts, err := MergeFileEntries(ctx, entries, budget)
	if err != nil { return nil, err }
	if len(resolutions) != len(conflicts) { return nil, ErrFileState }
	if len(conflicts) == 0 { return resolved, nil }
	// Original input admission succeeded, so summing its lengths cannot exceed
	// Payload. Reserve all explicit states before constructing any output.
	remaining := budget.Payload
	for _, entry := range entries {
		if err := ctx.Err(); err != nil { return nil, err }
		for _, v := range [3]FileVersion{entry.Base,entry.Left,entry.Right} { remaining -= uint64(len(v.content)) }
	}
	for i, resolution := range resolutions {
		if err := ctx.Err(); err != nil { return nil, err }
		if resolution.Path != conflicts[i].Path || resolution.Version.Validate() != nil { return nil, ErrFileState }
		n := uint64(len(resolution.Version.content))
		if n > remaining { return nil, ErrFileBudget }; remaining -= n
	}
	var out []ResolvedFileEntry
	at := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil { return nil, err }
		if at < len(resolutions) && entry.Path == resolutions[at].Path {
			out = append(out, resolutions[at]); at++
			continue
		}
		version, conflict, err := MergeFileVersions(ctx, entry.Base, entry.Left, entry.Right, budget.Payload)
		if err != nil { return nil, err }
		if conflict != nil { return nil, ErrFileState }
		out = append(out, ResolvedFileEntry{entry.Path,version})
	}
	if err := ctx.Err(); err != nil { return nil, err }
	return out, nil
}

// TreeFilesMergeBudget admits one complete DAG replay, three independent tree
// enumerations, then a shared union-path/content merge. Enumeration PathBytes
// retains its two-copy accounting; Merge.PathBytes charges each union path once.
// Repeated revisions/content still consume their respective three phase limits.
type TreeFilesMergeBudget struct {
	Replay derived.TreeReplayBudget
	Enumeration [3]derived.TreeEntriesBudget
	Merge FileMergeBudget
}
type TreeFilesMergeUsage struct { Replay derived.TreeReplayUsage; Enumeration [3]derived.TreeGraphUsage }

// MergeCanonicalTreeFiles derives complete file-leaf sets for explicit base,
// left and right revisions from one verified supplied canonical DAG. It unions
// raw paths and compares all independent file triples, verifying their canonical
// blobs under one shared merge budget. Every path conflict is returned together,
// with no resolved prefix; failures return neither result nor conflict slices.
// Unchanged and absent winners remain in results; this is not a minimal delta.
// Empty trees succeed with nil entries; missing source mappings are errors.
//
// This is PRIVATE independent-path analysis, NOT a complete valid tree merge.
// In particular, independent winners can have incompatible file/descendant
// paths. Full-tree structural validation and explicit conflict resolution must
// precede any candidate use. Directories are implicit, symlinks remain leaves.
// Base/ancestry policy, renames, text alignment, authorized disclosure, retention
// and publication remain outside this helper. No source is fetched or mutated.
// All supplied sources, including unselected branches, must verify. Inputs must
// remain stable. Retained enumeration/union/decoded content has explicit phase
// bounds, not a measured total memory ceiling; no partial resume is provided.
func MergeCanonicalTreeFiles(ctx context.Context, repository [16]byte, selected [3]model.ChangesetID, sources []derived.TreeSourceFrame, blobs map[model.BlobID][]byte, budget TreeFilesMergeBudget) ([]ResolvedFileEntry, []PathFileConflict, TreeFilesMergeUsage, error) {
	var usage TreeFilesMergeUsage
	bad := func(err error) ([]ResolvedFileEntry, []PathFileConflict, TreeFilesMergeUsage, error) { return nil,nil,usage,err }
	if ctx == nil { return bad(ErrFileState) }
	if err := ctx.Err(); err != nil { return bad(err) }
	m := budget.Merge
	if m.Entries == 0 || m.Entries > 4096 || m.PathBytes == 0 || m.PathBytes > 64<<20 || m.Payload > 64<<20 { return bad(ErrFileBudget) }
	for i,id := range selected {
		if id.Validate() != nil { return bad(ErrFileState) }
		b := budget.Enumeration[i]; g := b.Graph
		if b.Entries == 0 || b.Entries > 4096 || b.PathBytes == 0 || b.PathBytes > 64<<20 || g.Visits == 0 || g.Visits > 4096 || g.PageBytes == 0 || g.PageBytes > 4096*derived.MaxTreePageBytes || g.ContextBytes == 0 || g.ContextBytes > 64<<20 { return bad(metadata.ErrInvalidArgument) }
	}
	writes,pages,replayed,err := derived.ReplayCanonicalTreeDAG(ctx,repository,sources,blobs,budget.Replay)
	usage.Replay = replayed
	if err != nil { return bad(err) }
	var rows [3][]model.Operation
	for i,id := range selected {
		found := false
		for _, write := range writes {
			if err := ctx.Err(); err != nil { return bad(err) }
			if write.Result.Identity.Changeset != id { continue }
			found = true
			root, err := derived.ParseTreePageID(write.Result.Value.Bytes()); if err != nil { return bad(err) }
			rows[i],usage.Enumeration[i],err = derived.ReadTreeEntries(ctx,root,pages,budget.Enumeration[i])
			if err != nil { return bad(err) }; break
		}
		if !found { return bad(metadata.ErrNotFound) }
	}
	var at [3]int
	var entries []CanonicalFileMergeEntry
	var pathBytes uint64
	for {
		if err := ctx.Err(); err != nil { return bad(err) }
		var path model.Path; found := false
		for i := range rows {
			if at[i] == len(rows[i]) { continue }
			p := rows[i][at[i]].Path()
			if !found || p.Compare(path) < 0 { path,found = p,true }
		}
		if !found { break }
		if uint64(len(entries)) == m.Entries { return bad(ErrFileBudget) }
		n := uint64(len(path.Bytes()))
		if n > m.PathBytes-pathBytes { return bad(ErrFileBudget) }; pathBytes += n
		entry := CanonicalFileMergeEntry{Path:path}
		for i := range rows {
			if at[i] == len(rows[i]) || rows[i][at[i]].Path() != path { continue }
			row := rows[i][at[i]]; at[i]++
			id, ok := row.Target(); if !ok { return bad(ErrFileState) }
			frame, ok := blobs[id]; if !ok { return bad(metadata.ErrNotFound) }
			entry.Sides[i] = CanonicalFileSide{Present:true,Mode:row.Tag(),ID:id,Frame:frame}
		}
		entries = append(entries,entry)
	}
	resolved,conflicts,err := MergeCanonicalFileEntries(ctx,entries,m)
	if err != nil { return bad(err) }
	if err := ctx.Err(); err != nil { return bad(err) }
	return resolved,conflicts,usage,nil
}
