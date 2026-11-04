package edit

import (
	"context"
	"errors"

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
