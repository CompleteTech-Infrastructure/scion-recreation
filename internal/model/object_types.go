// Package model defines immutable canonical v1 values. It does not encode object
// payloads, verify content digests, establish publication, or grant object access.
package model

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	CanonicalVersion    uint16 = 1
	TypedIDSize                = 35
	MaxBlobPayload      uint64 = 1 << 40
	MaxChangesetPayload uint64 = 64 << 20
	MaxParents          uint64 = 1024
	MaxOperations       uint64 = 1000000
	MaxPathBytes        uint64 = 65535
	MaxPathComponents          = 1024
	MaxIdentityBytes    uint64 = 65536
	MaxMessageBytes     uint64 = 16 << 20
	MaxEncodingBytes    uint64 = 256
)

type ObjectKind byte

const (
	BlobKind      ObjectKind = 1
	ChangesetKind ObjectKind = 2
)

func (k ObjectKind) Validate() error {
	if k != BlobKind && k != ChangesetKind {
		return errors.New("unknown canonical object kind")
	}
	return nil
}

// TypedID is comparable and owns its binary identity. Its zero value is invalid.
// Derived tree/page identities are not canonical object IDs; no such kind is
// registered here. An ID alone is neither content verification nor permission.
type TypedID struct{ raw [TypedIDSize]byte }

// NewTypedID wraps a digest computed over uncompressed canonical bytes elsewhere.
// It cannot verify those bytes and must not be used to hash storage envelopes.
func NewTypedID(kind ObjectKind, digest [32]byte) (TypedID, error) {
	if err := kind.Validate(); err != nil {
		return TypedID{}, err
	}
	var id TypedID
	binary.BigEndian.PutUint16(id.raw[:2], CanonicalVersion)
	id.raw[2] = byte(kind)
	copy(id.raw[3:], digest[:])
	return id, nil
}
func ParseTypedID(b []byte) (TypedID, error) {
	if len(b) != TypedIDSize {
		return TypedID{}, errors.New("typed ID must be exactly 35 bytes")
	}
	var id TypedID
	copy(id.raw[:], b)
	if err := id.Validate(); err != nil {
		return TypedID{}, err
	}
	return id, nil
}
func ParseTypedIDText(s string) (TypedID, error) {
	if len(s) != 76 || s[:9] != "canopy:1:" || s[11] != ':' {
		return TypedID{}, errors.New("noncanonical typed ID text")
	}
	for i := 9; i < len(s); i++ {
		if i == 11 {
			continue
		}
		if !((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')) {
			return TypedID{}, errors.New("noncanonical typed ID hex")
		}
	}
	var raw [TypedIDSize]byte
	raw[1] = 1
	if _, err := hex.Decode(raw[2:3], []byte(s[9:11])); err != nil {
		return TypedID{}, err
	}
	if _, err := hex.Decode(raw[3:], []byte(s[12:])); err != nil {
		return TypedID{}, err
	}
	return ParseTypedID(raw[:])
}
func (id TypedID) Version() uint16  { return binary.BigEndian.Uint16(id.raw[:2]) }
func (id TypedID) Kind() ObjectKind { return ObjectKind(id.raw[2]) }
func (id TypedID) Digest() [32]byte { var d [32]byte; copy(d[:], id.raw[3:]); return d }
func (id TypedID) Validate() error {
	if id.Version() != CanonicalVersion {
		return errors.New("unknown canonical object version")
	}
	return id.Kind().Validate()
}
func (id TypedID) MarshalBinary() ([]byte, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return append([]byte(nil), id.raw[:]...), nil
}
func (id TypedID) MarshalText() ([]byte, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("canopy:1:%02x:%x", byte(id.Kind()), id.raw[3:])), nil
}
func (id TypedID) String() string {
	b, err := id.MarshalText()
	if err != nil {
		return "<invalid canonical ID>"
	}
	return string(b)
}

type BlobID struct{ id TypedID }
type ChangesetID struct{ id TypedID }

func NewBlobID(id TypedID) (BlobID, error) {
	if err := id.Validate(); err != nil {
		return BlobID{}, err
	}
	if id.Kind() != BlobKind {
		return BlobID{}, errors.New("expected blob ID")
	}
	return BlobID{id}, nil
}
func NewChangesetID(id TypedID) (ChangesetID, error) {
	if err := id.Validate(); err != nil {
		return ChangesetID{}, err
	}
	if id.Kind() != ChangesetKind {
		return ChangesetID{}, errors.New("expected changeset ID")
	}
	return ChangesetID{id}, nil
}
func ParseBlobID(b []byte) (BlobID, error) {
	id, err := ParseTypedID(b)
	if err != nil {
		return BlobID{}, err
	}
	return NewBlobID(id)
}
func ParseChangesetID(b []byte) (ChangesetID, error) {
	id, err := ParseTypedID(b)
	if err != nil {
		return ChangesetID{}, err
	}
	return NewChangesetID(id)
}
func ParseBlobIDText(s string) (BlobID, error) {
	id, err := ParseTypedIDText(s)
	if err != nil {
		return BlobID{}, err
	}
	return NewBlobID(id)
}
func ParseChangesetIDText(s string) (ChangesetID, error) {
	id, err := ParseTypedIDText(s)
	if err != nil {
		return ChangesetID{}, err
	}
	return NewChangesetID(id)
}
func (id BlobID) TypedID() TypedID      { return id.id }
func (id ChangesetID) TypedID() TypedID { return id.id }
func (id BlobID) Validate() error       { _, err := NewBlobID(id.id); return err }
func (id ChangesetID) Validate() error  { _, err := NewChangesetID(id.id); return err }

// ValidatePayloadLength does not read or allocate payload bytes. Blob consumers
// must stream the declared length with their own byte/work/deadline budgets.
func ValidatePayloadLength(kind ObjectKind, length uint64) error {
	if err := kind.Validate(); err != nil {
		return err
	}
	limit := MaxBlobPayload
	if kind == ChangesetKind {
		limit = MaxChangesetPayload
	}
	if length > limit {
		return errors.New("canonical payload exceeds limit")
	}
	return nil
}

// ValidateObjectHeader checks header metadata against an expected TID. A codec
// must separately check magic, exact framing, EOF and the computed digest.
func ValidateObjectHeader(version uint16, kind ObjectKind, length uint64, expected TypedID) error {
	if version != CanonicalVersion {
		return errors.New("unknown canonical object version")
	}
	if err := ValidatePayloadLength(kind, length); err != nil {
		return err
	}
	if err := expected.Validate(); err != nil {
		return err
	}
	if version != expected.Version() || kind != expected.Kind() {
		return errors.New("object header and typed ID mismatch")
	}
	return nil
}

// ValidateByteLength checks a decoded unsigned length before conversion or allocation.
// remaining excludes the already-consumed length prefix.
func ValidateByteLength(length, maximum, remaining uint64) error {
	if length > maximum || length > remaining {
		return errors.New("byte length exceeds limit or remaining bytes")
	}
	return nil
}

// ValidateCount checks a count before multiplication or allocation. minimum is
// the minimum encoded bytes per entry; variable entries still need field checks.
func ValidateCount(count, maximum, minimum, remaining uint64) error {
	if minimum == 0 || count > maximum || count > remaining/minimum {
		return errors.New("count exceeds limit or remaining bytes")
	}
	return nil
}
func CheckedSize(total, addition, limit uint64) (uint64, error) {
	if total > limit || addition > limit-total {
		return 0, errors.New("canonical size exceeds limit or overflows")
	}
	return total + addition, nil
}
func ParsePresence(marker byte) (bool, error) {
	switch marker {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errors.New("invalid optional field presence")
	}
}

// Path owns uninterpreted bytes. Only '/' is a separator. Its zero value is invalid.
type Path struct{ raw string }

func ValidatePath(raw []byte) error { return validatePath(raw) }

// Index the same bytes directly for owned strings and caller slices, without
// copying a path during validation.
func validatePath[T ~string | ~[]byte](raw T) error {
	if len(raw) == 0 || uint64(len(raw)) > MaxPathBytes {
		return errors.New("invalid path length")
	}
	components, start := 1, 0
	for i := 0; i <= len(raw); i++ {
		if i < len(raw) && raw[i] == 0 {
			return errors.New("NUL in path")
		}
		if i == len(raw) || raw[i] == '/' {
			n := i - start
			if n == 0 || (n == 1 && raw[start] == '.') || (n == 2 && raw[start] == '.' && raw[start+1] == '.') {
				return errors.New("invalid path component")
			}
			if i < len(raw) {
				components++
				if components > MaxPathComponents {
					return errors.New("too many path components")
				}
			}
			start = i + 1
		}
	}
	return nil
}
func NewPath(raw []byte) (Path, error) {
	if err := ValidatePath(raw); err != nil {
		return Path{}, err
	}
	return Path{string(raw)}, nil
}
func (p Path) Validate() error { return validatePath(p.raw) }
func (p Path) Bytes() []byte   { return []byte(p.raw) }
func (p Path) Compare(q Path) int {
	if p.raw < q.raw {
		return -1
	}
	if p.raw > q.raw {
		return 1
	}
	return 0
}

// Metadata identities and declared times are exact, not parsed or normalized.
type Metadata struct {
	identity string
	seconds  int64
	offset   int16
}

func NewMetadata(identity []byte, seconds int64, offset int16) (Metadata, error) {
	if uint64(len(identity)) > MaxIdentityBytes {
		return Metadata{}, errors.New("identity exceeds limit")
	}
	if offset < -1439 || offset > 1439 {
		return Metadata{}, errors.New("invalid timestamp offset")
	}
	return Metadata{string(identity), seconds, offset}, nil
}
func (m Metadata) Identity() []byte     { return []byte(m.identity) }
func (m Metadata) UnixSeconds() int64   { return m.seconds }
func (m Metadata) OffsetMinutes() int16 { return m.offset }

type OperationTag byte

const (
	Delete        OperationTag = 0
	SetRegular    OperationTag = 1
	SetExecutable OperationTag = 2
	SetSymlink    OperationTag = 3
)

type Operation struct {
	path   Path
	tag    OperationTag
	target BlobID
}

func NewOperation(path Path, tag OperationTag, target *BlobID) (Operation, error) {
	if err := path.Validate(); err != nil {
		return Operation{}, err
	}
	if tag > SetSymlink {
		return Operation{}, errors.New("unknown operation tag")
	}
	if tag == Delete {
		if target != nil {
			return Operation{}, errors.New("DELETE must not have target")
		}
		return Operation{path: path, tag: tag}, nil
	}
	if target == nil {
		return Operation{}, errors.New("SET requires blob target")
	}
	if err := target.Validate(); err != nil {
		return Operation{}, err
	}
	return Operation{path, tag, *target}, nil
}
func (o Operation) Path() Path        { return o.path }
func (o Operation) Tag() OperationTag { return o.tag }
func (o Operation) Target() (BlobID, bool) {
	return o.target, o.tag >= SetRegular && o.tag <= SetSymlink
}
func (o Operation) Mode() (uint32, bool) {
	switch o.tag {
	case SetRegular:
		return 0100644, true
	case SetExecutable:
		return 0100755, true
	case SetSymlink:
		return 0120000, true
	default:
		return 0, false
	}
}

// ChangesetInput is mutable caller-owned input. Nil Committer/Encoding mean
// absent; a nonnil empty Encoding means present-empty. Operations are supplied
// in canonical order; no constructor sorts, deduplicates or supplies defaults.
type ChangesetInput struct {
	RepoID     [16]byte
	Parents    []ChangesetID
	Author     Metadata
	Committer  *Metadata
	Message    []byte
	Encoding   []byte
	Operations []Operation
}

// Changeset owns its collections. Tree application, parent repository checks,
// durable publication and authorization are separate consumers' obligations.
// The zero value is not a constructed changeset; use NewChangeset.
type Changeset struct {
	value       ChangesetInput
	payloadSize uint64
}

// ValidateChangeset preflights the complete final payload before any cloning.
// It validates local value syntax, not the resulting parent-derived tree.
func ValidateChangeset(v ChangesetInput) (uint64, error) {
	if uint64(len(v.Parents)) > MaxParents || uint64(len(v.Operations)) > MaxOperations {
		return 0, errors.New("changeset count exceeds limit")
	}
	if uint64(len(v.Message)) > MaxMessageBytes || uint64(len(v.Encoding)) > MaxEncodingBytes {
		return 0, errors.New("changeset field exceeds limit")
	}
	size := uint64(16 + 4 + 4 + 8 + 2 + 1 + 4 + 1 + 4)
	add := func(n uint64) error { var err error; size, err = CheckedSize(size, n, MaxChangesetPayload); return err }
	metadata := func(m Metadata) error {
		if uint64(len(m.identity)) > MaxIdentityBytes || m.offset < -1439 || m.offset > 1439 {
			return errors.New("invalid metadata")
		}
		return add(uint64(len(m.identity)))
	}
	if err := add(uint64(len(v.Parents)) * TypedIDSize); err != nil {
		return 0, err
	}
	for _, p := range v.Parents {
		if err := p.Validate(); err != nil {
			return 0, err
		}
	}
	if err := metadata(v.Author); err != nil {
		return 0, err
	}
	if v.Committer != nil {
		if err := add(4 + 8 + 2); err != nil {
			return 0, err
		}
		if err := metadata(*v.Committer); err != nil {
			return 0, err
		}
	}
	if err := add(uint64(len(v.Message))); err != nil {
		return 0, err
	}
	if v.Encoding != nil {
		if err := add(4 + uint64(len(v.Encoding))); err != nil {
			return 0, err
		}
	}
	for i, o := range v.Operations {
		if err := o.path.Validate(); err != nil {
			return 0, err
		}
		if i > 0 && v.Operations[i-1].path.Compare(o.path) >= 0 {
			return 0, errors.New("operations must have strictly increasing raw paths")
		}
		if o.tag > SetSymlink {
			return 0, errors.New("unknown operation tag")
		}
		n := uint64(4 + len(o.path.raw) + 1)
		if o.tag == Delete {
			if o.target != (BlobID{}) {
				return 0, errors.New("DELETE must not have target")
			}
		} else {
			if err := o.target.Validate(); err != nil {
				return 0, err
			}
			n += TypedIDSize
		}
		if err := add(n); err != nil {
			return 0, err
		}
	}
	return size, nil
}
func cloneChangeset(v ChangesetInput) ChangesetInput {
	v.Parents = append([]ChangesetID(nil), v.Parents...)
	v.Operations = append([]Operation(nil), v.Operations...)
	v.Message = append([]byte(nil), v.Message...)
	if v.Encoding != nil {
		v.Encoding = append([]byte{}, v.Encoding...)
	}
	if v.Committer != nil {
		m := *v.Committer
		v.Committer = &m
	}
	return v
}
func NewChangeset(v ChangesetInput) (Changeset, error) {
	n, err := ValidateChangeset(v)
	if err != nil {
		return Changeset{}, err
	}
	return Changeset{cloneChangeset(v), n}, nil
}
func (v Changeset) Snapshot() ChangesetInput { return cloneChangeset(v.value) }
func (v Changeset) PayloadSize() uint64      { return v.payloadSize }

// Validate rejects an unconstructed zero value as well as inconsistent state.
func (v Changeset) Validate() error {
	n, err := ValidateChangeset(v.value)
	if err != nil {
		return err
	}
	if n != v.payloadSize {
		return errors.New("unconstructed or inconsistent changeset")
	}
	return nil
}
