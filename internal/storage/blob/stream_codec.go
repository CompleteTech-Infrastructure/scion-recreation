//go:build darwin || linux

package blob

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/model"
)

// DecodeBlobEnvelope validates a whole-object delivery into PRIVATE, UNVERIFIED
// staging. It is not an upload parser: objects-v1 uploads accept RAW only. spec
// is normalized metadata, not protobuf enum numbers or the local CBLOB header.
// The caller must authenticate/authorize first, own an admitted request, reserve
// physical staging capacity, and discard all staging bytes on ANY error. Only a
// nil error permits the caller to accept the staged frame; this function does
// not activate storage, issue completion tokens, or authorize delivery.
//
// IAM-10 enforces RAW/single-member GZIP, exact input/output lengths, whole-frame
// caps, expansion ratio, cancellation, and per-request resource accounting. Its
// fixed copy buffer plus the gzip window and this 22-byte header/hash state do
// not grow with blob size. The staging writer must not buffer without a bound.
// The permit remains caller-owned until processing and cleanup finish. Readers
// and writers must provide deadlines for blocking I/O; no goroutine is spawned.
//
// This primitive validates blobs only. Changeset semantic validation and wiring
// into durable storage/services are separate integration work, not acceptance
// implied by successful decoding here.
func DecodeBlobEnvelope(ctx context.Context, permit *authz.AdmissionPermit, dst io.Writer, src io.Reader, id model.BlobID, spec authz.AdmissionObject) (uint64, error) {
	if ctx == nil || permit == nil || dst == nil || src == nil || id.Validate() != nil || spec.Kind != model.BlobKind || !spec.Whole {
		return 0, ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := model.ValidatePayloadLength(spec.Kind, spec.PayloadBytes); err != nil {
		return 0, errors.Join(ErrResourceExhausted, err)
	}
	frame := spec.PayloadBytes + 22 // validated format maximum prevents overflow
	// Admission is finite bookkeeping, not physical disk allocation. Reserve
	// before copying; whole delivery must not omit staging as an upload would not.
	if err := permit.Reserve(authz.AdmissionCost{authz.AdmissionStagingBytes: frame}); err != nil {
		return 0, err
	}
	checked := &blobFrameWriter{dst: dst, id: id, payload: spec.PayloadBytes, digest: sha256.New()}
	n, err := permit.CopyObject(ctx, checked, src, spec)
	if err != nil {
		return 0, err
	}
	if n != frame || checked.headerBytes != len(checked.header) {
		return 0, ErrCorruptData
	}
	var digest [32]byte
	copy(digest[:], checked.digest.Sum(nil))
	if digest != id.TypedID().Digest() {
		return 0, ErrCorruptData
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return spec.PayloadBytes, nil
}

type blobFrameWriter struct {
	dst io.Writer
	id model.BlobID
	payload uint64
	header [22]byte
	headerBytes int
	digest hash.Hash
}

func (w *blobFrameWriter) Write(p []byte) (int, error) {
	if w.headerBytes < len(w.header) {
		w.headerBytes += copy(w.header[w.headerBytes:], p)
		if w.headerBytes == len(w.header) {
			length := binary.BigEndian.Uint64(w.header[14:])
			if string(w.header[:11]) != "CANOPY\x00OBJ\x00" || length != w.payload {
				return 0, ErrCorruptData
			}
			if err := model.ValidateObjectHeader(binary.BigEndian.Uint16(w.header[11:13]), model.ObjectKind(w.header[13]), length, w.id.TypedID()); err != nil {
				return 0, errors.Join(ErrCorruptData, err)
			}
		}
	}
	// Only full successful writes can lead to acceptance. CopyObject rejects
	// invalid/short writer counts and preserves all writer errors.
	w.digest.Write(p)
	return w.dst.Write(p)
}
