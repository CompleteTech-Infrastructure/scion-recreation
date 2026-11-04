package edit

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"canopy.local/canopy/internal/model"
)

var (
	ErrFileState = errors.New("invalid file conflict state")
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
