package metadata_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

func intentRequest(t *testing.T) (metadata.Scope, metadata.PublishRequest) {
	t.Helper()
	s := metadata.Scope{Repository: [16]byte{1}, Principal: "principal", Session: "session", PolicyVersion: 0}
	c, err := model.NewChangeset(model.ChangesetInput{RepoID: s.Repository, Message: []byte{0xff, 0}})
	if err != nil {
		t.Fatal(err)
	}
	id, err := model.HashChangeset(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	r := metadata.PublishRequest{Mutation: metadata.Mutation{Key: "mutation\x00\xff"}, ID: id, Changeset: c, Event: "event/\xff"}
	r.Mutation.RequestDigest, err = metadata.PublicationRequestDigest(context.Background(), s, r)
	if err != nil {
		t.Fatal(err)
	}
	return s, r
}

func TestMetadataIntentIndependentLiterals(t *testing.T) {
	s, r := intentRequest(t)
	// Independently framed Python struct/hashlib literals, not generated from
	// the production intent encoder. The canonical body has no optional values.
	canonical, _ := hex.DecodeString("43414e4f5059004f424a00000102000000000000002e010000000000000000000000000000000000000000000000000000000000000000000000000002ff000000000000")
	var encoded bytes.Buffer
	if err := model.EncodeChangeset(context.Background(), &encoded, r.Changeset); err != nil || !bytes.Equal(encoded.Bytes(), canonical) {
		t.Fatal("canonical literal", err)
	}
	i, err := metadata.NewPublicationIntent(context.Background(), s, r)
	if err != nil || i.Validate() != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", i.Digest()); got != "4717c5024436ca7370b852f0bafde2ff1ed5b84ef73e7936c88356af135b5ec9" {
		t.Fatal(got)
	}
	if i.Kind() != metadata.IntentPublication || i.Repository() != s.Repository || i.Changeset() != r.ID || i.MutationKey() != r.Mutation.Key || i.Event() != r.Event || i.CanonicalLength() != 68 || i.CanonicalSHA256() != sha256.Sum256(canonical) {
		t.Fatal("owned exact fields")
	}
	lookup, err := metadata.NewPublicationLookupIntent(context.Background(), s, r.ID)
	if err != nil || lookup.Validate() != nil || fmt.Sprintf("%x", lookup.Digest()) != "1571cefa14d867103db270b0fb710ecbe32dc418e53dff203d7e87a939a298e6" {
		t.Fatal("lookup literal", err)
	}
	status, err := metadata.NewPublicationStatusIntent(context.Background(), s, r.Mutation.Key)
	if err != nil || status.Validate() != nil || fmt.Sprintf("%x", status.Digest()) != "f1e76556fd7a72e60d4465eb50cea133d82bafb78fd52197ecb8dc01f6457b13" {
		t.Fatal("status literal", err)
	}
	if status.Kind() != metadata.IntentPublicationStatus || status.MutationKey() != r.Mutation.Key || lookup.Kind() != metadata.IntentPublicationLookup || lookup.Changeset() != r.ID || lookup.CanonicalLength() != 0 || status.CanonicalLength() != 0 {
		t.Fatal("purpose fields")
	}
	if (metadata.OperationIntent{}).Validate() == nil {
		t.Fatal("zero intent accepted")
	}
}

func TestMetadataIntentBindsEveryActualRequestField(t *testing.T) {
	s, r := intentRequest(t)
	original := r.Mutation.RequestDigest
	for _, field := range []string{"key", "event", "message", "encoding", "parents", "repository"} {
		t.Run(field, func(t *testing.T) {
			x, scope := r, s
			input := x.Changeset.Snapshot()
			switch field {
			case "key":
				x.Mutation.Key += "x"
			case "event":
				x.Event += "x"
			case "message":
				input.Message = append(input.Message, 1)
			case "encoding":
				input.Encoding = []byte{}
			case "parents":
				input.Parents = []model.ChangesetID{r.ID, r.ID}
			case "repository":
				scope.Repository[0]++
				input.RepoID = scope.Repository
			}
			var err error
			x.Changeset, err = model.NewChangeset(input)
			if err != nil {
				t.Fatal(err)
			}
			x.ID, err = model.HashChangeset(context.Background(), x.Changeset)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := metadata.PublicationRequestDigest(context.Background(), scope, x)
			if err != nil || digest == original {
				t.Fatal("field omitted", err)
			}
			if got, err := metadata.NewPublicationIntent(context.Background(), scope, x); err != metadata.ErrInvalidArgument || got != (metadata.OperationIntent{}) {
				t.Fatal("asserted digest trusted", err)
			}
			x.Mutation.RequestDigest = digest
			if _, err := metadata.NewPublicationIntent(context.Background(), scope, x); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Reauthentication must not alter immutable retry identity. None of these
	// caller expectations authenticates or authorizes a request by itself.
	s.Principal, s.Session, s.PolicyVersion = "new-principal", "new-session", ^uint64(0)
	if d, err := metadata.PublicationRequestDigest(context.Background(), s, r); err != nil || d != original {
		t.Fatal("authentication mixed into mutation identity", err)
	}
	lookup1, _ := metadata.NewPublicationLookupIntent(context.Background(), s, r.ID)
	s.Repository[1]++
	lookup2, _ := metadata.NewPublicationLookupIntent(context.Background(), s, r.ID)
	if lookup1.Digest() == lookup2.Digest() {
		t.Fatal("lookup repository omitted")
	}
	a, _ := metadata.NewPublicationStatusIntent(context.Background(), s, "a\x00b")
	b, _ := metadata.NewPublicationStatusIntent(context.Background(), s, "a\x00b\x00")
	if a.Digest() == b.Digest() {
		t.Fatal("status framing omitted")
	}
}

func TestMetadataIntentRejectsMismatchBoundsAndCancellation(t *testing.T) {
	s, r := intentRequest(t)
	for _, field := range []string{"zero-id", "wrong-id", "zero-value", "wrong-repository", "empty-key", "large-key", "empty-event", "large-event", "wrong-digest"} {
		t.Run(field, func(t *testing.T) {
			x, scope := r, s
			switch field {
			case "zero-id":
				x.ID = model.ChangesetID{}
			case "wrong-id":
				id, _ := model.NewTypedID(model.ChangesetKind, [32]byte{9})
				x.ID, _ = model.NewChangesetID(id)
			case "zero-value":
				x.Changeset = model.Changeset{}
			case "wrong-repository":
				scope.Repository[0]++
			case "empty-key":
				x.Mutation.Key = ""
			case "large-key":
				x.Mutation.Key = string(bytes.Repeat([]byte{0xff}, metadata.MaxMutationKeyBytes+1))
			case "empty-event":
				x.Event = ""
			case "large-event":
				x.Event = metadata.EventID(bytes.Repeat([]byte{0xff}, metadata.MaxPublicationEventBytes+1))
			case "wrong-digest":
				x.Mutation.RequestDigest[0]++
			}
			got, err := metadata.NewPublicationIntent(context.Background(), scope, x)
			if err != metadata.ErrInvalidArgument || got != (metadata.OperationIntent{}) {
				t.Fatal("invalid boundary", err)
			}
		})
	}
	r.Mutation.Key = string(bytes.Repeat([]byte{0xff}, metadata.MaxMutationKeyBytes))
	r.Event = metadata.EventID(bytes.Repeat([]byte{0xff}, metadata.MaxPublicationEventBytes))
	r.Mutation.RequestDigest, _ = metadata.PublicationRequestDigest(context.Background(), s, r)
	if _, err := metadata.NewPublicationIntent(context.Background(), s, r); err != nil {
		t.Fatal("inclusive maxima", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if got, err := metadata.NewPublicationIntent(ctx, s, r); err == nil || got != (metadata.OperationIntent{}) {
			t.Fatal("context", err)
		}
		if got, err := metadata.NewPublicationLookupIntent(ctx, s, r.ID); err == nil || got != (metadata.OperationIntent{}) {
			t.Fatal("lookup context", err)
		}
		if got, err := metadata.NewPublicationStatusIntent(ctx, s, "key"); err == nil || got != (metadata.OperationIntent{}) {
			t.Fatal("status context", err)
		}
	}
	if got, err := metadata.NewPublicationLookupIntent(context.Background(), s, model.ChangesetID{}); err == nil || got != (metadata.OperationIntent{}) {
		t.Fatal("invalid lookup")
	}
	for _, key := range []string{"", string(bytes.Repeat([]byte{1}, 1025))} {
		if got, err := metadata.NewPublicationStatusIntent(context.Background(), s, key); err == nil || got != (metadata.OperationIntent{}) {
			t.Fatal("invalid status")
		}
	}
}

type cancelIntentContext struct {
	context.Context
	cancel context.CancelFunc
	calls  atomic.Int32
}

func (c *cancelIntentContext) Err() error {
	if c.calls.Add(1) == 50 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestMetadataIntentStreamingCancellationAndIndependentOracle(t *testing.T) {
	s, r := intentRequest(t)
	for n := 0; n < 128; n++ {
		input := r.Changeset.Snapshot()
		input.Message = bytes.Repeat([]byte{byte(n)}, n)
		r.Changeset, _ = model.NewChangeset(input)
		r.ID, _ = model.HashChangeset(context.Background(), r.Changeset)
		var canonical bytes.Buffer
		if err := model.EncodeChangeset(context.Background(), &canonical, r.Changeset); err != nil {
			t.Fatal(err)
		}
		var literal bytes.Buffer
		literal.WriteString("CANOPY\x00INTERNAL-METADATA-INTENT\x00V1\x00")
		binary.Write(&literal, binary.BigEndian, uint16(1))
		literal.Write(s.Repository[:])
		for _, field := range []string{r.Mutation.Key, string(r.Event)} {
			binary.Write(&literal, binary.BigEndian, uint32(len(field)))
			literal.WriteString(field)
		}
		id, _ := r.ID.TypedID().MarshalBinary()
		literal.Write(id)
		h := sha256.Sum256(canonical.Bytes())
		literal.Write(h[:])
		binary.Write(&literal, binary.BigEndian, uint64(canonical.Len()))
		want := sha256.Sum256(literal.Bytes())
		if got, err := metadata.PublicationRequestDigest(context.Background(), s, r); err != nil || got != want {
			t.Fatal(n, err)
		}
	}
	input := r.Changeset.Snapshot()
	input.Message = bytes.Repeat([]byte{7}, 4<<20)
	r.Changeset, _ = model.NewChangeset(input)
	r.ID, _ = model.HashChangeset(context.Background(), r.Changeset)
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelIntentContext{Context: base, cancel: cancel}
	if got, err := metadata.PublicationRequestDigest(ctx, s, r); !errors.Is(err, context.Canceled) || got != ([32]byte{}) || ctx.calls.Load() < 50 {
		t.Fatal("stream cancellation", err)
	}
}
