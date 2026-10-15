package model

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"sort"
	"strings"
)

// DecodeBlob verifies one complete canonical blob frame with constant streaming
// memory. maxPayload is the caller's byte/work admission budget (zero allows an
// empty blob). dst must be private staging: bytes written before success are
// unverified and MUST be discarded on error. Every failure returns zero.
// Neither an expected ID nor successful decoding grants access or publication.
// Cancellation is checked around I/O; blocking readers/writers must implement
// their own deadlines to interrupt an in-progress call.
func DecodeBlob(ctx context.Context, src io.Reader, expected BlobID, dst io.Writer, maxPayload uint64) (uint64, error) {
	if dst == nil {
		return 0, errors.New("nil blob staging writer")
	}
	if err := expected.Validate(); err != nil {
		return 0, err
	}
	d, err := decodeStart(ctx, src, expected.TypedID(), maxPayload)
	if err != nil {
		return 0, err
	}
	length := d.remaining
	var buffer [32768]byte
	for d.remaining > 0 {
		n := min(d.remaining, uint64(len(buffer)))
		b := buffer[:int(n)]
		if err := d.read(b); err != nil {
			return 0, err
		}
		written, err := dst.Write(b)
		if err != nil {
			return 0, err
		}
		if written != len(b) {
			return 0, io.ErrShortWrite
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
	}
	if err := d.finish(expected.TypedID()); err != nil {
		return 0, err
	}
	return length, nil
}

// DecodeChangeset verifies exact framing, digest and local canonical syntax.
// maxPayload is an explicit caller budget, additionally capped by v1 limits.
// Parent publication/repository membership and the final parent-derived tree
// require separate validation. No constructed changeset escapes on failure.
func DecodeChangeset(ctx context.Context, src io.Reader, expected ChangesetID, maxPayload uint64) (Changeset, error) {
	if err := expected.Validate(); err != nil {
		return Changeset{}, err
	}
	d, err := decodeStart(ctx, src, expected.TypedID(), maxPayload)
	if err != nil {
		return Changeset{}, err
	}
	v, err := d.changeset()
	if err != nil {
		return Changeset{}, err
	}
	if err := d.finish(expected.TypedID()); err != nil {
		return Changeset{}, err
	}
	value, err := NewChangeset(v)
	if err != nil {
		return Changeset{}, err
	}
	if err := ctx.Err(); err != nil {
		return Changeset{}, err
	}
	return value, nil
}

type decodeReader struct {
	ctx       context.Context
	src       io.Reader
	digest    hash.Hash
	remaining uint64
	eof       bool
}

func decodeStart(ctx context.Context, src io.Reader, expected TypedID, budget uint64) (*decodeReader, error) {
	if ctx == nil || src == nil {
		return nil, errors.New("nil decoder context or reader")
	}
	d := &decodeReader{ctx: ctx, src: src, digest: sha256.New(), remaining: 22}
	var header [22]byte
	if err := d.read(header[:]); err != nil {
		return nil, err
	}
	if string(header[:11]) != "CANOPY\x00OBJ\x00" {
		return nil, errors.New("invalid canonical magic")
	}
	d.remaining = binary.BigEndian.Uint64(header[14:])
	if err := ValidateObjectHeader(binary.BigEndian.Uint16(header[11:13]), ObjectKind(header[13]), d.remaining, expected); err != nil {
		return nil, err
	}
	if d.remaining > budget {
		return nil, errors.New("canonical payload exceeds caller budget")
	}
	return d, nil
}

// read never suppresses a source error returned together with the last bytes.
// EOF with final data is valid; any other error invalidates the whole result.
func (d *decodeReader) read(b []byte) error {
	if uint64(len(b)) > d.remaining {
		return io.ErrUnexpectedEOF
	}
	for idle := 0; len(b) > 0; {
		if err := d.ctx.Err(); err != nil {
			return err
		}
		if d.eof {
			return io.ErrUnexpectedEOF
		}
		n, err := d.src.Read(b)
		if n < 0 || n > len(b) {
			return errors.New("invalid reader count")
		}
		if cancel := d.ctx.Err(); cancel != nil {
			return cancel
		}
		d.digest.Write(b[:n])
		d.remaining -= uint64(n)
		b = b[n:]
		if err != nil {
			if err != io.EOF {
				return err
			}
			d.eof = true
			if len(b) != 0 {
				return io.ErrUnexpectedEOF
			}
		}
		if n == 0 {
			idle++
			if idle == 100 {
				return io.ErrNoProgress
			}
		} else {
			idle = 0
		}
	}
	return d.ctx.Err()
}

func (d *decodeReader) finish(expected TypedID) error {
	if d.remaining != 0 {
		return errors.New("trailing canonical payload bytes")
	}
	var extra [1]byte
	for idle := 0; !d.eof; idle++ {
		if err := d.ctx.Err(); err != nil {
			return err
		}
		n, err := d.src.Read(extra[:])
		if n != 0 {
			return errors.New("trailing canonical frame bytes or invalid reader count")
		}
		if err == io.EOF {
			d.eof = true
		} else if err != nil {
			return err
		} else if idle == 99 {
			return io.ErrNoProgress
		}
	}
	var actual [32]byte
	copy(actual[:], d.digest.Sum(nil))
	if actual != expected.Digest() {
		return errors.New("canonical digest mismatch")
	}
	return d.ctx.Err()
}

func (d *decodeReader) number(n int) (uint64, error) {
	var word [8]byte
	if err := d.read(word[8-n:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(word[:]), nil
}
func (d *decodeReader) bytes(maximum uint64) ([]byte, error) {
	n, err := d.number(4)
	if err != nil {
		return nil, err
	}
	if err := ValidateByteLength(n, maximum, d.remaining); err != nil {
		return nil, err
	}
	b := make([]byte, int(n)) // All callers have maxima <= 16 MiB, including on 32-bit hosts.
	if err := d.read(b); err != nil {
		return nil, err
	}
	return b, nil
}
func (d *decodeReader) presence() (bool, error) {
	n, err := d.number(1)
	if err != nil {
		return false, err
	}
	return ParsePresence(byte(n))
}
func (d *decodeReader) metadata() (Metadata, error) {
	b, err := d.bytes(MaxIdentityBytes)
	if err != nil {
		return Metadata{}, err
	}
	seconds, err := d.number(8)
	if err != nil {
		return Metadata{}, err
	}
	offset, err := d.number(2)
	if err != nil {
		return Metadata{}, err
	}
	return NewMetadata(b, int64(seconds), int16(offset))
}
func (d *decodeReader) id() (TypedID, error) {
	var raw [TypedIDSize]byte
	if err := d.read(raw[:]); err != nil {
		return TypedID{}, err
	}
	return ParseTypedID(raw[:])
}

func (d *decodeReader) changeset() (ChangesetInput, error) {
	var v ChangesetInput
	if err := d.read(v.RepoID[:]); err != nil {
		return v, err
	}
	count, err := d.number(4)
	if err != nil {
		return v, err
	}
	if err := ValidateCount(count, MaxParents, TypedIDSize, d.remaining); err != nil {
		return v, err
	}
	for i := uint64(0); i < count; i++ {
		id, err := d.id()
		if err != nil {
			return v, err
		}
		parent, err := NewChangesetID(id)
		if err != nil {
			return v, err
		}
		v.Parents = append(v.Parents, parent)
	}
	if v.Author, err = d.metadata(); err != nil {
		return v, err
	}
	present, err := d.presence()
	if err != nil {
		return v, err
	}
	if present {
		m, err := d.metadata()
		if err != nil {
			return v, err
		}
		v.Committer = &m
	}
	if v.Message, err = d.bytes(MaxMessageBytes); err != nil {
		return v, err
	}
	if present, err = d.presence(); err != nil {
		return v, err
	}
	if present {
		if v.Encoding, err = d.bytes(MaxEncodingBytes); err != nil {
			return v, err
		}
	}
	count, err = d.number(4)
	if err != nil {
		return v, err
	}
	if err := ValidateCount(count, MaxOperations, 6, d.remaining); err != nil {
		return v, err
	}
	var sets []string
	for i := uint64(0); i < count; i++ {
		raw, err := d.bytes(MaxPathBytes)
		if err != nil {
			return v, err
		}
		path, err := NewPath(raw)
		if err != nil {
			return v, err
		}
		tag, err := d.number(1)
		if err != nil {
			return v, err
		}
		var target *BlobID
		if tag >= uint64(SetRegular) && tag <= uint64(SetSymlink) {
			id, err := d.id()
			if err != nil {
				return v, err
			}
			blob, err := NewBlobID(id)
			if err != nil {
				return v, err
			}
			target = &blob
			sets = append(sets, string(raw))
		}
		op, err := NewOperation(path, OperationTag(tag), target)
		if err != nil {
			return v, err
		}
		if len(v.Operations) > 0 && v.Operations[len(v.Operations)-1].Path().Compare(path) >= 0 {
			return v, errors.New("noncanonical operation order")
		}
		v.Operations = append(v.Operations, op)
	}
	// Sorted SETs permit bounded binary searches for unavoidable leaf conflicts.
	// DELETE/SET replacements are allowed; parent-dependent conflicts are external.
	for _, path := range sets {
		if err := d.ctx.Err(); err != nil {
			return v, err
		}
		prefix := path + "/"
		i := sort.SearchStrings(sets, prefix)
		if i < len(sets) && strings.HasPrefix(sets[i], prefix) {
			return v, errors.New("conflicting SET leaf paths")
		}
	}
	return v, nil
}
