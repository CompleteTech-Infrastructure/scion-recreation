package metadata_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"testing"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

func repoA() [16]byte { return [16]byte{1} }

func expectError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want errors.Is(_, %v)", got, want)
	}
}

func changesetA(t *testing.T) model.ChangesetID {
	t.Helper()
	id, err := model.ParseChangesetIDText("canopy:1:02:f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func changesetB(t *testing.T) model.ChangesetID {
	t.Helper()
	id, err := model.ParseChangesetIDText("canopy:1:02:438a09a6c4a38f09730804074b557ff0dedc2c9f221dbaa2ee748e1d51ee9f42")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func treeValue(t *testing.T, literal string) metadata.DerivedValueID {
	t.Helper()
	raw, err := hex.DecodeString(literal)
	if err != nil {
		t.Fatal(err)
	}
	id, err := metadata.NewDerivedValueID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestCheckReplayContract(t *testing.T) {
	first := metadata.Mutation{Key: "publish/1", RequestDigest: [32]byte{1}}
	if err := metadata.CheckReplay(first, first); err != nil {
		t.Fatalf("same key and intent should replay: %v", err)
	}
	changedKey := first
	changedKey.Key = "publish/2"
	expectError(t, metadata.CheckReplay(first, changedKey), metadata.ErrConflict)
	changedIntent := first
	changedIntent.RequestDigest[31] = 2
	expectError(t, metadata.CheckReplay(first, changedIntent), metadata.ErrConflict)
	empty := metadata.Mutation{RequestDigest: first.RequestDigest}
	expectError(t, metadata.CheckReplay(empty, first), metadata.ErrCorruptData)
	expectError(t, metadata.CheckReplay(first, empty), metadata.ErrInvalidArgument)
}

func TestPublishRequestValidationAndImmutability(t *testing.T) {
	repo := repoA()
	input := model.ChangesetInput{RepoID: repo, Message: []byte("source")}
	change, err := model.NewChangeset(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Message[0] = 'X'
	request := metadata.PublishRequest{
		Mutation:  metadata.Mutation{Key: "retry-1", RequestDigest: [32]byte{7}},
		ID:        changesetA(t),
		Changeset: change,
		Event:     metadata.EventID("event-1"),
	}
	// ID is the accepted fixed typed-ID fixture, independent of this synthetic
	// Changeset. Validate checks typed syntax/repository binding, not ID-to-bytes
	// hashing; canonical verification remains a preflight/backend obligation.
	if err := request.Validate(metadata.Scope{Repository: repo}); err != nil {
		t.Fatalf("locally well-formed detached request rejected: %v", err)
	}
	if got := string(request.Changeset.Snapshot().Message); got != "source" {
		t.Fatalf("constructed canonical value aliased caller input: %q", got)
	}

	wrongRepo := request
	wrongRepo.Changeset, err = model.NewChangeset(model.ChangesetInput{RepoID: [16]byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	expectError(t, wrongRepo.Validate(metadata.Scope{Repository: repo}), metadata.ErrInvalidArgument)
	bad := request
	bad.Mutation.Key = ""
	expectError(t, bad.Validate(metadata.Scope{Repository: repo}), metadata.ErrInvalidArgument)
	bad = request
	bad.ID = model.ChangesetID{}
	expectError(t, bad.Validate(metadata.Scope{Repository: repo}), metadata.ErrInvalidArgument)
	bad = request
	bad.Event = ""
	expectError(t, bad.Validate(metadata.Scope{Repository: repo}), metadata.ErrInvalidArgument)
	bad = request
	bad.Changeset = model.Changeset{}
	expectError(t, bad.Validate(metadata.Scope{Repository: repo}), metadata.ErrInvalidArgument)
}

func TestDistinctCanonicalPublishRequestsMayShareEventAtValidationBoundary(t *testing.T) {
	// These are the accepted canonical-v1 root_A_message_ff and
	// encoding_present_empty fixtures. Event uniqueness depends on stored state,
	// so request validation must not pretend to establish it.
	repo := [16]byte{}
	author, err := model.NewMetadata([]byte("A"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		id       string
		input    model.ChangesetInput
		mutation metadata.Mutation
	}{
		{"canopy:1:02:f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee", model.ChangesetInput{RepoID: repo, Author: author, Message: []byte{0xff}}, metadata.Mutation{Key: "publish-root", RequestDigest: [32]byte{1}}},
		{"canopy:1:02:7da5e70435d6596a98808bafb53908a594f2cdc921426b99dd31b69831770060", model.ChangesetInput{RepoID: repo, Author: author, Encoding: []byte{}}, metadata.Mutation{Key: "publish-empty-encoding", RequestDigest: [32]byte{2}}},
	}
	requests := make([]metadata.PublishRequest, len(fixtures))
	for i, fixture := range fixtures {
		change, err := model.NewChangeset(fixture.input)
		if err != nil {
			t.Fatal(err)
		}
		id, err := model.ParseChangesetIDText(fixture.id)
		if err != nil {
			t.Fatal(err)
		}
		requests[i] = metadata.PublishRequest{Mutation: fixture.mutation, ID: id, Changeset: change, Event: "same-event"}
		if err := requests[i].Validate(metadata.Scope{Repository: repo}); err != nil {
			t.Fatalf("canonical fixture request %d rejected by stateless validation: %v", i, err)
		}
	}
	if requests[0].ID == requests[1].ID || requests[0].Mutation == requests[1].Mutation {
		t.Fatal("canonical fixture requests must have distinct publication and mutation identities")
	}
	if requests[0].Event != requests[1].Event || requests[0].Changeset.Snapshot().RepoID != requests[1].Changeset.Snapshot().RepoID {
		t.Fatal("fixture requests must share EventID and repository")
	}
	first, second := requests[0].Changeset.Snapshot(), requests[1].Changeset.Snapshot()
	if !bytes.Equal(first.Message, []byte{0xff}) || first.Encoding != nil || second.Encoding == nil || len(second.Encoding) != 0 {
		t.Fatal("fixtures do not preserve the accepted message and present-empty encoding values")
	}
}

func TestNextRefContract(t *testing.T) {
	a, b := changesetA(t), changesetB(t)
	created, err := metadata.NextRef(metadata.AbsentRef(), nil, a)
	if err != nil || created.Target != a || created.Generation != 0 {
		t.Fatalf("absent ref should create generation zero: %+v, %v", created, err)
	}
	genZero := metadata.RefValue{Target: a, Generation: 0}
	updated, err := metadata.NextRef(metadata.ExistingRef(genZero), &genZero, b)
	if err != nil || updated.Target != b || updated.Generation != 1 {
		t.Fatalf("existing generation zero should advance: %+v, %v", updated, err)
	}
	noop, err := metadata.NextRef(metadata.ExistingRef(genZero), &genZero, a)
	if err != nil || noop.Target != a || noop.Generation != 1 {
		t.Fatalf("no-op target update still advances generation: %+v, %v", noop, err)
	}
	staleTarget := metadata.RefValue{Target: b, Generation: 0}
	_, err = metadata.NextRef(metadata.ExistingRef(genZero), &staleTarget, a)
	expectError(t, err, metadata.ErrConflict)
	_, err = metadata.NextRef(metadata.ExistingRef(genZero), nil, b)
	expectError(t, err, metadata.ErrConflict)
	_, err = metadata.NextRef(metadata.AbsentRef(), &genZero, b)
	expectError(t, err, metadata.ErrConflict)
	_, err = metadata.NextRef(metadata.AbsentRef(), nil, model.ChangesetID{})
	expectError(t, err, metadata.ErrInvalidArgument)
	_, err = metadata.NextRef(metadata.ExistingRef(metadata.RefValue{}), &genZero, b)
	expectError(t, err, metadata.ErrInvalidArgument)
	aba := metadata.RefValue{Target: a, Generation: 2}
	_, err = metadata.NextRef(metadata.ExistingRef(genZero), &aba, b)
	expectError(t, err, metadata.ErrConflict)
	max := metadata.RefValue{Target: a, Generation: math.MaxUint64}
	_, err = metadata.NextRef(metadata.ExistingRef(max), &max, b)
	expectError(t, err, metadata.ErrResourceExhausted)
	_, err = metadata.NextRef(metadata.RefExpectation{}, nil, a)
	expectError(t, err, metadata.ErrInvalidArgument)
	corrupt := metadata.RefValue{}
	_, err = metadata.NextRef(metadata.ExistingRef(genZero), &corrupt, b)
	expectError(t, err, metadata.ErrCorruptData)
	cas := metadata.RefCAS{Name: "refs/main", Expected: metadata.AbsentRef(), Target: a, Mutation: metadata.Mutation{Key: "ref-1"}}
	if err := cas.Validate(); err != nil {
		t.Fatalf("scoped absent-ref CAS request rejected: %v", err)
	}
	cas.Name = ""
	expectError(t, cas.Validate(), metadata.ErrInvalidArgument)
	cas.Name, cas.Expected = "refs/main", metadata.RefExpectation{}
	expectError(t, cas.Validate(), metadata.ErrInvalidArgument)
}

func TestOutboxQueryBounds(t *testing.T) {
	for _, limit := range []uint32{1, 256} {
		if err := (metadata.OutboxQuery{Limit: limit}).Validate(); err != nil {
			t.Fatalf("valid bounded page %d rejected: %v", limit, err)
		}
	}
	expectError(t, (metadata.OutboxQuery{Limit: 257}).Validate(), metadata.ErrInvalidArgument)
	expectError(t, (metadata.OutboxQuery{}).Validate(), metadata.ErrInvalidArgument)
}

func TestCompareDerivedContract(t *testing.T) {
	// These independent literals exercise the frozen TREE-v1 type prefix and full
	// 32-byte digest. Parsing validates identity syntax, not page bytes or hashing.
	base := metadata.DerivedResult{
		Identity: metadata.DerivedIdentity{Repository: repoA(), Changeset: changesetA(t), Kind: "tree-index", Version: 1},
		Value:    treeValue(t, "43545000000101120fd69aec6d6bc30c93019e2849ab05d1245e26985f70fc07ee6daa41ae4028"),
	}
	if err := metadata.CompareDerived(base, base); err != nil {
		t.Fatalf("same identity and output should be idempotent: %v", err)
	}
	changedValue := base
	changedValue.Value = treeValue(t, "435450000001011111111111111111111111111111111111111111111111111111111111111111")
	expectError(t, metadata.CompareDerived(base, changedValue), metadata.ErrCorruptData)
	variants := []metadata.DerivedIdentity{
		{Repository: [16]byte{2}, Changeset: changesetA(t), Kind: "tree-index", Version: 1},
		{Repository: repoA(), Changeset: changesetB(t), Kind: "tree-index", Version: 1},
		{Repository: repoA(), Changeset: changesetA(t), Kind: "other-index", Version: 1},
		{Repository: repoA(), Changeset: changesetA(t), Kind: "tree-index", Version: 2},
	}
	for _, identity := range variants {
		expectError(t, metadata.CompareDerived(base, metadata.DerivedResult{Identity: identity, Value: base.Value}), metadata.ErrConflict)
	}
	expectError(t, metadata.CompareDerived(base, metadata.DerivedResult{}), metadata.ErrInvalidArgument)
	expectError(t, metadata.CompareDerived(metadata.DerivedResult{Identity: base.Identity}, base), metadata.ErrCorruptData)
	expectError(t, metadata.CompareDerived(base, metadata.DerivedResult{Identity: base.Identity}), metadata.ErrInvalidArgument)

	rootRaw, err := hex.DecodeString("43545000000101120fd69aec6d6bc30c93019e2849ab05d1245e26985f70fc07ee6daa41ae4028")
	if err != nil {
		t.Fatal(err)
	}
	rootValue, err := metadata.NewDerivedValueID(rootRaw)
	if err != nil {
		t.Fatalf("accepted empty-root TREE-v1 identity rejected: %v", err)
	}
	original := append([]byte(nil), rootRaw...)
	rootRaw[38] ^= 1
	if !bytes.Equal(rootValue.Bytes(), original) {
		t.Fatal("derived identity aliases constructor input")
	}
	owned := rootValue.Bytes()
	owned[0] ^= 1
	if !bytes.Equal(rootValue.Bytes(), original) {
		t.Fatal("Bytes must return an owned copy")
	}
	badPrefix := append([]byte(nil), original...)
	badPrefix[0] ^= 1
	for _, raw := range [][]byte{
		original[:38],
		badPrefix,
		mustHex(t, "000102f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee"),
	} {
		if _, err := metadata.NewDerivedValueID(raw); err == nil {
			t.Fatalf("accepted malformed, truncated, or canonical-TID value %x", raw)
		}
	}
}

func TestPublicationStatusResultUnion(t *testing.T) {
	publication := metadata.Publication{Repository: repoA(), Changeset: changesetA(t), ID: "pub-1", Event: "evt-1"}
	valid := []metadata.PublicationStatus{
		{State: metadata.WriteCommitted, Result: publication},
		{State: metadata.WritePending},
		{State: metadata.WriteUnknown},
		{State: metadata.WriteFailed, Failure: metadata.ErrConflict},
	}
	for _, status := range valid {
		if err := status.Validate(); err != nil {
			t.Fatalf("valid status rejected: %+v: %v", status, err)
		}
	}
	invalid := []metadata.PublicationStatus{
		{State: metadata.WriteCommitted, Result: publication, Failure: metadata.ErrConflict},
		{State: metadata.WriteCommitted, Result: metadata.Publication{Changeset: changesetA(t), Event: "evt-1"}},
		{State: metadata.WritePending, Result: publication},
		{State: metadata.WriteFailed, Failure: metadata.ErrUnavailable},
		{State: metadata.WriteFailed, Failure: metadata.ErrOutcomeUnknown},
		{State: metadata.WriteFailed, Failure: errors.New("untyped failure")},
		{State: metadata.WriteFailed, Failure: errors.Join(metadata.ErrConflict, metadata.ErrUnavailable)},
	}
	for _, status := range invalid {
		expectError(t, status.Validate(), metadata.ErrInvalidArgument)
	}
}

func TestDerivedWriteParentScope(t *testing.T) {
	identity := metadata.DerivedIdentity{Repository: repoA(), Changeset: changesetA(t), Kind: "tree-index", Version: 1}
	parent := metadata.DerivedResult{Identity: metadata.DerivedIdentity{Repository: repoA(), Changeset: changesetB(t), Kind: "parent-index", Version: 7}, Value: treeValue(t, "435450000001011111111111111111111111111111111111111111111111111111111111111111")}
	write := metadata.DerivedWrite{Result: metadata.DerivedResult{Identity: identity, Value: treeValue(t, "43545000000101120fd69aec6d6bc30c93019e2849ab05d1245e26985f70fc07ee6daa41ae4028")}, Parents: []metadata.DerivedResult{parent}}
	if err := write.Validate(); err != nil {
		t.Fatalf("same-repository parent with algorithm-declared distinct kind/version rejected: %v", err)
	}
	bad := write
	bad.Parents = []metadata.DerivedResult{{Identity: metadata.DerivedIdentity{Repository: [16]byte{2}, Changeset: changesetB(t), Kind: parent.Identity.Kind, Version: parent.Identity.Version}, Value: parent.Value}}
	expectError(t, bad.Validate(), metadata.ErrInvalidArgument)
	bad.Parents = []metadata.DerivedResult{{Identity: metadata.DerivedIdentity{Repository: repoA(), Changeset: changesetB(t), Kind: parent.Identity.Kind, Version: parent.Identity.Version}}}
	expectError(t, bad.Validate(), metadata.ErrInvalidArgument)
	tooMany := make([]metadata.DerivedResult, int(model.MaxParents)+1)
	for i := range tooMany {
		tooMany[i] = parent
	}
	write.Parents = tooMany
	expectError(t, write.Validate(), metadata.ErrInvalidArgument)
	write.Parents = []metadata.DerivedResult{parent}
	write.Result.Value = metadata.DerivedValueID{}
	expectError(t, write.Validate(), metadata.ErrInvalidArgument)
}

func TestCompareDerivedWriteCausalInputs(t *testing.T) {
	root := treeValue(t, "43545000000101120fd69aec6d6bc30c93019e2849ab05d1245e26985f70fc07ee6daa41ae4028")
	other := treeValue(t, "435450000001011111111111111111111111111111111111111111111111111111111111111111")
	result := metadata.DerivedResult{Identity: metadata.DerivedIdentity{Repository: repoA(), Changeset: changesetA(t), Kind: "tree-index", Version: 1}, Value: root}
	parents := []metadata.DerivedResult{
		{Identity: metadata.DerivedIdentity{Repository: repoA(), Changeset: changesetA(t), Kind: "root-index", Version: 2}, Value: root},
		{Identity: metadata.DerivedIdentity{Repository: repoA(), Changeset: changesetB(t), Kind: "parent-index", Version: 7}, Value: other},
	}
	stored := metadata.DerivedWrite{Result: result, Parents: parents}
	if err := metadata.CompareDerivedWrite(stored, stored); err != nil {
		t.Fatalf("identical derived result and ordered inputs rejected: %v", err)
	}
	reordered := metadata.DerivedWrite{Result: result, Parents: []metadata.DerivedResult{parents[1], parents[0]}}
	expectError(t, metadata.CompareDerivedWrite(stored, reordered), metadata.ErrCorruptData)
	changedParent := metadata.DerivedWrite{Result: result, Parents: []metadata.DerivedResult{parents[0], {Identity: parents[1].Identity, Value: root}}}
	expectError(t, metadata.CompareDerivedWrite(stored, changedParent), metadata.ErrCorruptData)
	changedOutput := metadata.DerivedWrite{Result: metadata.DerivedResult{Identity: result.Identity, Value: other}, Parents: parents}
	expectError(t, metadata.CompareDerivedWrite(stored, changedOutput), metadata.ErrCorruptData)
	changedKey := metadata.DerivedWrite{Result: metadata.DerivedResult{Identity: metadata.DerivedIdentity{Repository: repoA(), Changeset: changesetB(t), Kind: "tree-index", Version: 1}, Value: root}, Parents: parents}
	expectError(t, metadata.CompareDerivedWrite(stored, changedKey), metadata.ErrConflict)
	badStored := metadata.DerivedWrite{Result: result, Parents: []metadata.DerivedResult{{Identity: parents[0].Identity}}}
	expectError(t, metadata.CompareDerivedWrite(badStored, stored), metadata.ErrCorruptData)
	badIncoming := metadata.DerivedWrite{Result: result, Parents: []metadata.DerivedResult{{Identity: parents[0].Identity}}}
	expectError(t, metadata.CompareDerivedWrite(stored, badIncoming), metadata.ErrInvalidArgument)
}

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPortHasDetachedPublishSurface(t *testing.T) {
	port := reflect.TypeOf((*metadata.Port)(nil)).Elem()
	publish, ok := port.MethodByName("Publish")
	if !ok {
		t.Fatal("metadata port lacks publication operation")
	}
	cas, ok := port.MethodByName("CASRef")
	if !ok {
		t.Fatal("metadata port lacks separate scoped ref CAS operation")
	}
	ctx := reflect.TypeOf((*context.Context)(nil)).Elem()
	errType := reflect.TypeOf((*error)(nil)).Elem()
	if publish.Type.NumIn() != 3 || publish.Type.In(0) != ctx || publish.Type.In(1) != reflect.TypeOf(metadata.Scope{}) || publish.Type.In(2) != reflect.TypeOf(metadata.PublishRequest{}) {
		t.Fatalf("Publish requires an unexpected input (such as ref/global sequence): %v", publish.Type)
	}
	if cas.Type.NumIn() != 3 || cas.Type.In(1) != reflect.TypeOf(metadata.Scope{}) || cas.Type.In(2) != reflect.TypeOf(metadata.RefCAS{}) {
		t.Fatalf("ref CAS must remain scoped and separate: %v", cas.Type)
	}
	if publish.Type.NumOut() != 2 || publish.Type.Out(0) != reflect.TypeOf(metadata.Publication{}) || publish.Type.Out(1) != errType {
		t.Fatalf("Publish must return a typed publication and error: %v", publish.Type)
	}
	list, ok := port.MethodByName("ListOutbox")
	if !ok || list.Type.NumIn() != 3 || list.Type.In(1) != reflect.TypeOf(metadata.Scope{}) || list.Type.In(2) != reflect.TypeOf(metadata.OutboxQuery{}) || list.Type.NumOut() != 2 || list.Type.Out(0) != reflect.TypeOf(metadata.OutboxPage{}) || list.Type.Out(1) != errType {
		t.Fatalf("outbox listing must be scoped, bounded and typed: %v", list.Type)
	}
	ack, ok := port.MethodByName("AckOutbox")
	if !ok || ack.Type.NumIn() != 3 || ack.Type.In(1) != reflect.TypeOf(metadata.Scope{}) || ack.Type.In(2) != reflect.TypeOf(metadata.EventID("")) || ack.Type.NumOut() != 1 || ack.Type.Out(0) != errType {
		t.Fatalf("outbox acknowledgement must be scoped by event ID: %v", ack.Type)
	}
	request := reflect.TypeOf(metadata.PublishRequest{})
	if _, ok := request.FieldByName("Ref"); ok {
		t.Fatal("detached publication request must not carry a ref update")
	}
	for _, name := range []string{"Sequence", "GlobalSequence", "IngestionSequence"} {
		if _, ok := request.FieldByName(name); ok {
			t.Fatalf("publication request must not require global sequence field %q", name)
		}
	}
}
