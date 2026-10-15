// Package metadata defines the authority's metadata transaction port, not a
// database implementation. Validation here proves neither authorization, content
// hashing, durable storage nor database lock-freedom.
package metadata

import (
	"context"
	"errors"
	"math"

	"canopy.local/canopy/internal/model"
)

var (
	ErrInvalidArgument    = errors.New("invalid metadata argument")
	ErrUnauthenticated    = errors.New("unauthenticated")
	ErrPermissionDenied   = errors.New("permission denied")
	ErrNotFound           = errors.New("metadata not available")
	ErrConflict           = errors.New("metadata conflict")
	ErrFailedPrecondition = errors.New("metadata precondition failed")
	ErrResourceExhausted  = errors.New("metadata resource exhausted")
	ErrUnavailable        = errors.New("metadata unavailable")
	ErrDeadlineExceeded   = errors.New("metadata deadline exceeded")
	ErrCorruptData        = errors.New("corrupt metadata")
	ErrOutcomeUnknown     = errors.New("metadata write outcome unknown")
)

// Scope is a requested binding to protected authenticated state, never proof of
// authority. Every Port method MUST authenticate context, compare principal,
// session, repository and current policy, and authorize the specific operation
// BEFORE lookup/delivery, including replay, status, refs, derived data and outbox.
// PolicyVersion is explicit; zero is valid. Credentials must not be logged here.
type Scope struct {
	Repository         [16]byte
	Principal, Session string
	PolicyVersion      uint64
}

// Mutation is scoped by repository, authenticated principal and operation kind.
// Key is opaque, nonempty and retained for the implementation's declared retry
// window. RequestDigest binds the COMPLETE versioned canonical operation intent,
// including publication Event or ref expectations; it is not a client assertion
// to trust. Services compute/verify it. Same key/different digest is ErrConflict.
// A fresh key for existing identical content cannot duplicate publication effects.
type Mutation struct {
	Key           string
	RequestDigest [32]byte
}

func (m Mutation) Validate() error {
	if m.Key == "" {
		return ErrInvalidArgument
	}
	return nil
}
func CheckReplay(stored, requested Mutation) error {
	if stored.Validate() != nil {
		return ErrCorruptData
	}
	if requested.Validate() != nil {
		return ErrInvalidArgument
	}
	if stored != requested {
		return ErrConflict
	}
	return nil
}

// PublicationID and EventID are opaque identities, not ordering counters.
// (Repository, EventID) permanently binds exactly one immutable Publication;
// acknowledging delivery never releases that binding for reuse.
type PublicationID string
type EventID string

type Publication struct {
	Repository [16]byte
	Changeset  model.ChangesetID
	ID         PublicationID
	Event      EventID
}

type PublishRequest struct {
	Mutation  Mutation
	ID        model.ChangesetID
	Changeset model.Changeset
	// Event is binding for a NEW publication only. Exact replay or identical
	// content returns the original publication/event without reserving this Event.
	Event EventID
}

// Validate checks request grammar/repository only. Event uniqueness requires
// stored state and MUST be enforced atomically by Publish, not by this helper.
func (r PublishRequest) Validate(s Scope) error {
	if r.Mutation.Validate() != nil || r.ID.Validate() != nil || r.Changeset.Validate() != nil || r.Event == "" {
		return ErrInvalidArgument
	}
	if r.Changeset.Snapshot().RepoID != s.Repository {
		return ErrInvalidArgument
	}
	return nil
}

type WriteState uint8

const (
	WritePending WriteState = iota + 1
	WriteCommitted
	WriteFailed
	WriteUnknown
)

// Status must not turn uncertainty into success. A committed result is the exact
// original tuple; failed carries a permanent typed cause. Pending/unknown carry
// no success tuple. Not found is ErrNotFound, never assumed safe to duplicate.
type PublicationStatus struct {
	State   WriteState
	Result  Publication
	Failure error
}

// Validate checks the result union, not whether a database committed it.
func (s PublicationStatus) Validate() error {
	empty := s.Result == (Publication{})
	switch s.State {
	case WriteCommitted:
		if !empty && s.Result.Changeset.Validate() == nil && s.Result.ID != "" && s.Result.Event != "" && s.Failure == nil {
			return nil
		}
	case WritePending, WriteUnknown:
		if empty && s.Failure == nil {
			return nil
		}
	case WriteFailed:
		if empty && s.Failure != nil && !errors.Is(s.Failure, ErrUnavailable) && !errors.Is(s.Failure, ErrDeadlineExceeded) && !errors.Is(s.Failure, ErrOutcomeUnknown) {
			for _, cause := range []error{ErrInvalidArgument, ErrUnauthenticated, ErrPermissionDenied, ErrNotFound, ErrConflict, ErrFailedPrecondition, ErrResourceExhausted, ErrCorruptData} {
				if errors.Is(s.Failure, cause) {
					return nil
				}
			}
		}
	}
	return ErrInvalidArgument
}

// RefExpectation is explicit: its zero value is INVALID, not unconditional CAS.
// There is no deletion/reset operation; generations cannot be recycled via ABA.
type RefValue struct {
	Target     model.ChangesetID
	Generation uint64
}
type RefExpectation struct {
	specified, exists bool
	value             RefValue
}

func AbsentRef() RefExpectation             { return RefExpectation{specified: true} }
func ExistingRef(v RefValue) RefExpectation { return RefExpectation{true, true, v} }

// NextRef is a pure transition check, not atomic storage. Implementations compare
// BOTH target and generation and install the result in one scoped transaction.
// Initial generation is zero; overflow fails rather than wrapping. No-op target
// updates still advance generation. A duplicate mutation replays before this step.
func NextRef(expected RefExpectation, actual *RefValue, target model.ChangesetID) (RefValue, error) {
	if !expected.specified || target.Validate() != nil || (expected.exists && expected.value.Target.Validate() != nil) {
		return RefValue{}, ErrInvalidArgument
	}
	if actual != nil && actual.Target.Validate() != nil {
		return RefValue{}, ErrCorruptData
	}
	if expected.exists != (actual != nil) {
		return RefValue{}, ErrConflict
	}
	if actual == nil {
		return RefValue{Target: target}, nil
	}
	if *actual != expected.value {
		return RefValue{}, ErrConflict
	}
	if actual.Generation == math.MaxUint64 {
		return RefValue{}, ErrResourceExhausted
	}
	return RefValue{target, actual.Generation + 1}, nil
}

type RefCAS struct {
	Name     string // exact opaque name bytes; nonempty, never normalized
	Expected RefExpectation
	Target   model.ChangesetID
	Mutation Mutation
}

func (r RefCAS) Validate() error {
	if r.Name == "" || r.Mutation.Validate() != nil || r.Target.Validate() != nil || !r.Expected.specified ||
		(r.Expected.exists && r.Expected.value.Target.Validate() != nil) {
		return ErrInvalidArgument
	}
	return nil
}

// Derived identities are versioned metadata keys, NOT new canonical object kinds.
// Kind names the registered deterministic algorithm and its parent/input contract.
// Version changes yield different keys, even if the output bytes are identical.
type DerivedIdentity struct {
	Repository [16]byte
	Changeset  model.ChangesetID
	Kind       string
	Version    uint32
}

func (k DerivedIdentity) Validate() error {
	if k.Changeset.Validate() != nil || k.Kind == "" || k.Version == 0 {
		return ErrInvalidArgument
	}
	return nil
}

// DerivedValueID owns a full frozen TREE-v1 page identity, separate from canonical
// TIDs. No other derived output format is currently registered; an extension must
// explicitly preserve its format/kind/version. Parsing verifies identity syntax,
// not page bytes, content hashing, graph validity, durability or authorization.
type DerivedValueID struct{ raw [39]byte }

func NewDerivedValueID(raw []byte) (DerivedValueID, error) {
	var id DerivedValueID
	if len(raw) != len(id.raw) {
		return id, ErrInvalidArgument
	}
	copy(id.raw[:], raw)
	if err := id.Validate(); err != nil {
		return DerivedValueID{}, err
	}
	return id, nil
}
func (id DerivedValueID) Validate() error {
	prefix := [7]byte{0x43, 0x54, 0x50, 0, 0, 1, 1}
	for i, b := range prefix {
		if id.raw[i] != b {
			return ErrInvalidArgument
		}
	}
	return nil
}
func (id DerivedValueID) Bytes() []byte { return append([]byte(nil), id.raw[:]...) }

// Result identity binds the output format/version through Identity.Kind/Version.
type DerivedResult struct {
	Identity DerivedIdentity
	Value    DerivedValueID
}

func CompareDerived(stored, incoming DerivedResult) error {
	if stored.Identity.Validate() != nil || stored.Value.Validate() != nil {
		return ErrCorruptData
	}
	if incoming.Identity.Validate() != nil || incoming.Value.Validate() != nil {
		return ErrInvalidArgument
	}
	if stored.Identity != incoming.Identity {
		return ErrConflict
	}
	if stored.Value != incoming.Value {
		return ErrCorruptData
	}
	return nil
}

// Parents lists exact immutable required parent results in algorithm-declared
// order. PutDerived verifies the source is published and all required parents
// exist in this repository matching the algorithm's declared kinds/versions/input contract, atomically.
// Missing prerequisites fail ErrFailedPrecondition; it cannot invent root data.
// Replays must compare parents as well as output; no rebinding a completed key.
// Same-key output/parent disagreement is ErrCorruptData: preserve both candidates
// in protected evidence and quarantine the mapping, never overwrite or serve it.
type DerivedWrite struct {
	Result  DerivedResult
	Parents []DerivedResult
}

func (w DerivedWrite) Validate() error {
	k := w.Result.Identity
	if k.Validate() != nil || w.Result.Value.Validate() != nil || uint64(len(w.Parents)) > model.MaxParents {
		return ErrInvalidArgument
	}
	for _, p := range w.Parents {
		if p.Value.Validate() != nil || p.Identity.Validate() != nil || p.Identity.Repository != k.Repository {
			return ErrInvalidArgument
		}
	}
	return nil
}

// CompareDerivedWrite checks the complete immutable binding, including ordered
// causal inputs. Persistence/quarantine remain atomic backend obligations.
func CompareDerivedWrite(stored, incoming DerivedWrite) error {
	if stored.Validate() != nil {
		return ErrCorruptData
	}
	if incoming.Validate() != nil {
		return ErrInvalidArgument
	}
	if err := CompareDerived(stored.Result, incoming.Result); err != nil {
		return err
	}
	if len(stored.Parents) != len(incoming.Parents) {
		return ErrCorruptData
	}
	for i, p := range stored.Parents {
		if p != incoming.Parents[i] {
			return ErrCorruptData
		}
	}
	return nil
}

// Outbox delivery is at least once. IDs are stable opaque identities, not a
// global ordering counter. Consumers deduplicate by (Publication.Repository, ID),
// never ID alone; ID MUST equal Publication.Event. This pair identifies exactly
// that immutable publication even after ack. Failed/unacked delivery is retained
// within declared bounded capacity/retention, never silently discarded.
type OutboxItem struct {
	ID          EventID
	Publication Publication
}
type OutboxPage struct {
	Items      []OutboxItem
	NextCursor string
}
type OutboxQuery struct {
	Cursor string
	Limit  uint32
}

func (q OutboxQuery) Validate() error {
	if q.Limit == 0 || q.Limit > 256 {
		return ErrInvalidArgument
	}
	return nil
}

// Port implementations MUST enforce finite byte/work/queue limits and deadlines
// before allocation/admission, return errors matching these sentinels (errors.Is),
// and expose only redacted errors under a consistent hidden/missing policy.
// Scope and request strings/slices have no authority. Caller-owned collections
// must be snapshotted before retention; returned collections must not alias state.
// No repository-wide mutex/transaction, global ingestion sequencer or mandatory
// numeric publication order is permitted. Independent detached publications and
// distinct ref keys can progress independently; small metadata transactions and
// per-ref CAS are allowed. This says nothing about database internals' lock-freedom.
//
// Success requires the implementation's explicitly documented persistent commit
// point. An ambiguous commit/cancellation MUST return ErrOutcomeUnknown (possibly
// joined with ErrUnavailable/ErrDeadlineExceeded); caller retries the SAME mutation
// and never infers rollback. No partial result on error. Local conformance tests
// of this interface do not establish these backend guarantees.
type Port interface {
	// Publish preflights verified canonical bytes/digest, durable blobs and final
	// tree validity outside the short transaction, with retention protecting them
	// through commit. It revalidates durable same-repository published parents in
	// the transaction; IDs/durable-object handles alone grant no authority.
	// Atomically insert immutable publication + mutation result + ONE outbox item.
	// Resolve the mutation key first: same key/intent returns the exact original
	// tuple; different intent under one key fails ErrConflict before content reuse.
	// With a fresh key, same content returns the original publication/event without
	// binding or checking the proposed Event.
	// For a NEW publication, bind (scope.Repository, request.Event) to its immutable
	// Publication in that same transaction. If already bound to a DIFFERENT
	// publication, return ErrConflict with no partial effects: no new publication,
	// mutation result or outbox item, and no alteration of the existing binding.
	// The same EventID may independently bind a publication in another repository.
	// Collision/corrupt existing canonical bytes fails ErrCorruptData.
	// No ref read/update or global sequence allocation is a publication prerequisite.
	// No cross-store transaction is assumed; blob/preflight retention, crash safety,
	// idempotency retention and persistent atomicity need backend-specific evidence.
	Publish(context.Context, Scope, PublishRequest) (Publication, error)
	GetPublication(context.Context, Scope, model.ChangesetID) (Publication, error)
	GetPublicationStatus(context.Context, Scope, string) (PublicationStatus, error)
	// CASRef separately compares only (repo,name,target,generation), verifies the
	// new target is durably published in repo, and atomically stores mutation result
	// with the ref. Same key/intent replays original result even after later updates.
	CASRef(context.Context, Scope, RefCAS) (RefValue, error)
	GetRef(context.Context, Scope, string) (RefValue, error)
	// PutDerived verifies complete output bytes/graph as durable and retained before
	// visibility, transferring retention atomically with the mapping. Missing or
	// partial output cannot become a success; uncertain storage is ErrUnavailable,
	// never a negative result. Work tokens/negative results require separate typed
	// backend protocols and cannot be smuggled through a successful DerivedResult.
	// PutDerived inserts complete successes only (including the typed empty-root ID);
	// pending work never exposes output. Existing-key parents/output disagreement is
	// ErrCorruptData and MUST quarantine the mapping with protected evidence.
	PutDerived(context.Context, Scope, DerivedWrite) (DerivedResult, error)
	GetDerived(context.Context, Scope, DerivedIdentity) (DerivedResult, error)
	// Listing is bounded, repository-scoped, with opaque stable pagination, no
	// mutable offsets or global-watermark requirement. Ack is authorized, idempotent
	// and scoped by repo+event; it never erases publication, idempotency results or
	// the permanent event binding. Ack cannot reassign an event to another publication.
	ListOutbox(context.Context, Scope, OutboxQuery) (OutboxPage, error)
	AckOutbox(context.Context, Scope, EventID) error
}
