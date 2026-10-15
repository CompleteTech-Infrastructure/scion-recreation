package model

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// EncodeBlob writes one uncompressed canonical v1 frame, requiring exactly
// length bytes followed by EOF. It uses bounded scratch space even at the v1
// maximum. On any error the caller must discard all output. Cancellation is
// checked between I/O calls; callers must make blocking readers/writers honor
// their own deadlines. This function does not spawn goroutines to interrupt I/O.
func EncodeBlob(ctx context.Context, w io.Writer, length uint64, r io.Reader) error {
	if err := ValidatePayloadLength(BlobKind, length); err != nil {
		return err
	}
	if ctx == nil || w == nil || r == nil {
		return errors.New("nil encoder argument")
	}
	e := encodeWriter{ctx: ctx, w: w}
	e.header(BlobKind, length)
	if e.err != nil {
		return e.err
	}
	var buf [32 << 10]byte
	remaining, idle := length, 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// The final one-byte probe rejects excess data without consuming an
		// unbounded stream, including for a declared empty blob.
		want := uint64(len(buf))
		if remaining == 0 {
			want = 1
		} else if remaining < want {
			want = remaining
		}
		n, err := r.Read(buf[:int(want)])
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if n < 0 || n > int(want) {
			return errors.New("invalid blob reader count")
		}
		if remaining == 0 {
			if n != 0 {
				return errors.New("blob has excess data")
			}
			if err == io.EOF {
				return ctx.Err()
			}
		} else {
			if n != 0 {
				e.bytes(buf[:n])
				if e.err != nil {
					return e.err
				}
				remaining -= uint64(n)
			}
			if err == io.EOF {
				if remaining != 0 {
					return io.ErrUnexpectedEOF
				}
				return ctx.Err()
			}
		}
		if err != nil {
			return err
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
}

// HashBlob returns an ID only after the complete canonical frame and exact
// input length have succeeded. Every failure returns the invalid zero BlobID;
// no hash state or partial digest escapes to the caller.
func HashBlob(ctx context.Context, length uint64, r io.Reader) (BlobID, error) {
	if err := ValidatePayloadLength(BlobKind, length); err != nil {
		return BlobID{}, err
	}
	h := sha256.New()
	if err := EncodeBlob(ctx, h, length, r); err != nil {
		return BlobID{}, err
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	id, err := NewTypedID(BlobKind, digest)
	if err != nil {
		return BlobID{}, err
	}
	return NewBlobID(id)
}

// EncodeChangeset writes the complete canonical frame after preflighting all
// fields and the exact payload size. It retains parent order and duplicates,
// option presence and raw bytes. Operations must already be strictly sorted;
// this encoder neither normalizes input nor applies the simultaneous delta.
// On error discard all output. Blocking I/O needs caller-supplied deadlines.
func EncodeChangeset(ctx context.Context, w io.Writer, value Changeset) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if ctx == nil || w == nil {
		return errors.New("nil encoder argument")
	}
	e := encodeWriter{ctx: ctx, w: w}
	v := value.value // immutable owned data; do not clone the payload to encode it
	e.header(ChangesetKind, value.payloadSize)
	e.bytes(v.RepoID[:])
	e.integer(uint64(len(v.Parents)), 4)
	for _, parent := range v.Parents {
		e.bytes(parent.id.raw[:])
	}
	e.metadata(v.Author)
	if v.Committer == nil {
		e.integer(0, 1)
	} else {
		e.integer(1, 1)
		e.metadata(*v.Committer)
	}
	e.integer(uint64(len(v.Message)), 4)
	e.bytes(v.Message)
	if v.Encoding == nil {
		e.integer(0, 1)
	} else {
		e.integer(1, 1)
		e.integer(uint64(len(v.Encoding)), 4)
		e.bytes(v.Encoding)
	}
	e.integer(uint64(len(v.Operations)), 4)
	for _, op := range v.Operations {
		e.integer(uint64(len(op.path.raw)), 4)
		e.text(op.path.raw)
		e.integer(uint64(op.tag), 1)
		if op.tag != Delete {
			e.bytes(op.target.id.raw[:])
		}
		if e.err != nil {
			break
		}
	}
	if e.err != nil {
		return e.err
	}
	return ctx.Err()
}

// HashChangeset hashes uncompressed canonical bytes, not a storage envelope.
// It returns the invalid zero ChangesetID on every failure.
func HashChangeset(ctx context.Context, value Changeset) (ChangesetID, error) {
	if err := value.Validate(); err != nil {
		return ChangesetID{}, err
	}
	h := sha256.New()
	if err := EncodeChangeset(ctx, h, value); err != nil {
		return ChangesetID{}, err
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	id, err := NewTypedID(ChangesetKind, digest)
	if err != nil {
		return ChangesetID{}, err
	}
	return NewChangesetID(id)
}

type encodeWriter struct {
	ctx context.Context
	w   io.Writer
	err error
}

func (e *encodeWriter) bytes(b []byte) {
	for len(b) != 0 && e.err == nil {
		if e.err = e.ctx.Err(); e.err != nil {
			return
		}
		next := len(b)
		if next > 32<<10 {
			next = 32 << 10
		}
		n, err := e.w.Write(b[:next])
		switch {
		case err != nil:
			e.err = err
		case n != next:
			e.err = io.ErrShortWrite
		default:
			e.err = e.ctx.Err()
		}
		b = b[next:]
	}
}

func (e *encodeWriter) text(s string) {
	for len(s) != 0 && e.err == nil {
		n := len(s)
		if n > 32<<10 {
			n = 32 << 10
		}
		e.bytes([]byte(s[:n]))
		s = s[n:]
	}
}

func (e *encodeWriter) integer(n uint64, width int) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	e.bytes(b[8-width:])
}

func (e *encodeWriter) metadata(m Metadata) {
	e.integer(uint64(len(m.identity)), 4)
	e.text(m.identity)
	e.integer(uint64(m.seconds), 8)
	e.integer(uint64(uint16(m.offset)), 2)
}

func (e *encodeWriter) header(kind ObjectKind, length uint64) {
	var b [22]byte
	copy(b[:11], "CANOPY\x00OBJ\x00")
	binary.BigEndian.PutUint16(b[11:13], CanonicalVersion)
	b[13] = byte(kind)
	binary.BigEndian.PutUint64(b[14:], length)
	e.bytes(b[:])
}
