package metadata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"hash"

	"canopy.local/canopy/internal/model"
	"github.com/jackc/pgx/v5"
)

// PostgresIntentAuthorization is additive to the connection foundation. Actual
// publication, lookup and status implementations must require this interface,
// recompute the intent from their own typed arguments, and never fall back to
// legacy string-only authorization. No such Port implementation is added here.
// FinalizeIntent checks cancellation and expiry under the same transaction's
// policy/session guards immediately before commit; it is not a physical WAL
// commit-time bound. Each method must reject an unbound or zero intent.
type PostgresIntentAuthorization interface {
	PostgresAuthorization
	AuthorizeIntent(context.Context, Scope, OperationIntent) error
	RecheckIntent(context.Context, pgx.Tx, Scope, OperationIntent) error
	FinalizeIntent(context.Context, pgx.Tx, Scope, OperationIntent) error
}

type IntentKind uint16

const (
	IntentPublication IntentKind = iota + 1
	IntentPublicationLookup
	IntentPublicationStatus
	MaxMutationKeyBytes      = 1024
	MaxPublicationEventBytes = 128
	metadataIntentDomain     = "CANOPY\x00INTERNAL-METADATA-INTENT\x00V1\x00"
)

// OperationIntent is an owned operation identity, NOT authentication, a path
// descriptor, a durable-object receipt, a policy lease or permission to look up
// or deliver any object. Principal/session/current policy are separately bound
// by the concrete authority. A known digest is never bearer permission.
type OperationIntent struct {
	kind            IntentKind
	repository      [16]byte
	id              model.ChangesetID
	key             string
	event           EventID
	canonicalHash   [32]byte
	canonicalLength uint64
	digest          [32]byte
}

func (i OperationIntent) Kind() IntentKind             { return i.kind }
func (i OperationIntent) Repository() [16]byte         { return i.repository }
func (i OperationIntent) Changeset() model.ChangesetID { return i.id }
func (i OperationIntent) MutationKey() string          { return i.key }
func (i OperationIntent) Event() EventID               { return i.event }
func (i OperationIntent) CanonicalSHA256() [32]byte    { return i.canonicalHash }
func (i OperationIntent) CanonicalLength() uint64      { return i.canonicalLength }
func (i OperationIntent) Digest() [32]byte             { return i.digest }

func (i OperationIntent) Validate() error {
	switch i.kind {
	case IntentPublication:
		if i.id.Validate() == nil && validMutationKey(i.key) && len(i.event) > 0 && len(i.event) <= MaxPublicationEventBytes && i.canonicalLength >= 38 && i.canonicalLength <= model.MaxChangesetPayload+22 {
			return nil
		}
	case IntentPublicationLookup:
		if i.id.Validate() == nil && i.key == "" && i.event == "" && i.canonicalLength == 0 {
			return nil
		}
	case IntentPublicationStatus:
		if i.id == (model.ChangesetID{}) && validMutationKey(i.key) && i.event == "" && i.canonicalLength == 0 {
			return nil
		}
	}
	return ErrInvalidArgument
}

func validMutationKey(key string) bool { return len(key) > 0 && len(key) <= MaxMutationKeyBytes }
func intentContext(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidArgument
	}
	return ctx.Err()
}
func intentPrefix(kind IntentKind, repo [16]byte) []byte {
	b := binary.BigEndian.AppendUint16([]byte(metadataIntentDomain), uint16(kind))
	return append(b, repo[:]...)
}
func intentString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

// canonicalIntentHash retains only the canonical header and repository prefix,
// never a full object snapshot. Canonical-v1 puts its repository at bytes22:38.
// The typed immutable encoder validates syntax and bounds before streaming.
type canonicalIntentHash struct {
	h      hash.Hash
	n      uint64
	prefix [38]byte
}

func (w *canonicalIntentHash) Write(p []byte) (int, error) {
	if w.n > model.MaxChangesetPayload+22 || uint64(len(p)) > model.MaxChangesetPayload+22-w.n {
		return 0, ErrResourceExhausted
	}
	if w.n < uint64(len(w.prefix)) {
		copy(w.prefix[w.n:], p)
	}
	n, err := w.h.Write(p)
	w.n += uint64(n)
	return n, err
}

func publicationIntent(ctx context.Context, s Scope, r PublishRequest) (OperationIntent, error) {
	var zero OperationIntent
	if err := intentContext(ctx); err != nil {
		return zero, err
	}
	// Scalar ceilings precede canonical work and transcript allocation. These
	// match the accepted metadata-v1 SQL keys, not a new public RPC envelope.
	if !validMutationKey(r.Mutation.Key) || len(r.Event) == 0 || len(r.Event) > MaxPublicationEventBytes || r.ID.Validate() != nil {
		return zero, ErrInvalidArgument
	}
	w := canonicalIntentHash{h: sha256.New()}
	if err := model.EncodeChangeset(ctx, &w, r.Changeset); err != nil {
		if e := ctx.Err(); e != nil {
			return zero, e
		}
		return zero, ErrInvalidArgument
	}
	var canonical [32]byte
	copy(canonical[:], w.h.Sum(nil))
	if w.n != r.Changeset.PayloadSize()+22 || !bytes.Equal(w.prefix[22:38], s.Repository[:]) || canonical != r.ID.TypedID().Digest() {
		return zero, ErrInvalidArgument
	}
	rawID, err := r.ID.TypedID().MarshalBinary()
	if err != nil {
		return zero, ErrInvalidArgument
	}
	b := intentPrefix(IntentPublication, s.Repository)
	b = intentString(b, r.Mutation.Key)
	b = intentString(b, string(r.Event))
	b = append(b, rawID...)
	b = append(b, canonical[:]...)
	b = binary.BigEndian.AppendUint64(b, w.n)
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	return OperationIntent{kind: IntentPublication, repository: s.Repository, id: r.ID, key: r.Mutation.Key, event: r.Event, canonicalHash: canonical, canonicalLength: w.n, digest: sha256.Sum256(b)}, nil
}

// PublicationRequestDigest computes the service-side immutable retry digest.
// The asserted RequestDigest is deliberately excluded. This pure operation
// checks the actual canonical content ID and repository, but authorizes nothing.
func PublicationRequestDigest(ctx context.Context, s Scope, r PublishRequest) ([32]byte, error) {
	i, err := publicationIntent(ctx, s, r)
	if err != nil {
		return [32]byte{}, err
	}
	return i.digest, nil
}

// NewPublicationIntent is for the backend's actual request boundary: unlike the
// preparation helper it also rejects an asserted mutation digest mismatch.
func NewPublicationIntent(ctx context.Context, s Scope, r PublishRequest) (OperationIntent, error) {
	i, err := publicationIntent(ctx, s, r)
	if err != nil {
		return OperationIntent{}, err
	}
	if i.digest != r.Mutation.RequestDigest {
		return OperationIntent{}, ErrInvalidArgument
	}
	return i, nil
}

// Lookup identifies disclosure of the exact Publication tuple, not delivery of
// raw Changeset bytes. Its concrete descriptor must prove all metadata rights.
func NewPublicationLookupIntent(ctx context.Context, s Scope, id model.ChangesetID) (OperationIntent, error) {
	if err := intentContext(ctx); err != nil {
		return OperationIntent{}, err
	}
	raw, err := id.TypedID().MarshalBinary()
	if id.Validate() != nil || err != nil {
		return OperationIntent{}, ErrInvalidArgument
	}
	b := append(intentPrefix(IntentPublicationLookup, s.Repository), raw...)
	if err = ctx.Err(); err != nil {
		return OperationIntent{}, err
	}
	return OperationIntent{kind: IntentPublicationLookup, repository: s.Repository, id: id, digest: sha256.Sum256(b)}, nil
}

// Status identifies the authenticated principal's mutation key. The provider
// must separately bind that exact principal and reauthorize current policy.
func NewPublicationStatusIntent(ctx context.Context, s Scope, key string) (OperationIntent, error) {
	if err := intentContext(ctx); err != nil {
		return OperationIntent{}, err
	}
	if !validMutationKey(key) {
		return OperationIntent{}, ErrInvalidArgument
	}
	b := intentString(intentPrefix(IntentPublicationStatus, s.Repository), key)
	if err := ctx.Err(); err != nil {
		return OperationIntent{}, err
	}
	return OperationIntent{kind: IntentPublicationStatus, repository: s.Repository, key: key, digest: sha256.Sum256(b)}, nil
}
