package conformance_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"canopy.local/canopy/internal/model"
)

// Expected frames and digests are frozen independently of the product. The
// accepted literals are copied from OBJ-01-A; the additional seeded fixtures
// were serialized with Python struct/hashlib, never with model methods.
type codecFixtures struct {
	SchemaVersion int           `json:"schema_version"`
	Literals      []codecVector `json:"accepted_literals"`
	Seeded        []codecVector `json:"seeded_cases"`
}

type codecVector struct {
	Name        string       `json:"name"`
	Kind        byte         `json:"kind"`
	Preimage    string       `json:"preimage"`
	Digest      string       `json:"digest"`
	TypedID     string       `json:"typed_id"`
	BlobHex     string       `json:"blob_hex"`
	Input       *oracleInput `json:"input"`
	Seed        uint32       `json:"seed"`
	Description string       `json:"description"`
}

type oracleMetadata struct {
	Identity string `json:"identity_hex"`
	Seconds  int64  `json:"seconds"`
	Offset   int16  `json:"offset"`
}

type oracleOperation struct {
	Path   string  `json:"path_hex"`
	Tag    byte    `json:"tag"`
	Target *string `json:"target_hex"`
	Mode   uint32  `json:"mode"`
}

type oracleInput struct {
	Repo       string            `json:"repo_hex"`
	Parents    []string          `json:"parents"`
	Author     oracleMetadata    `json:"author"`
	Committer  *oracleMetadata   `json:"committer"`
	Message    string            `json:"message_hex"`
	Encoding   *string           `json:"encoding_hex"`
	Operations []oracleOperation `json:"operations"`
}

func codecHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadCodecFixtures(t *testing.T) codecFixtures {
	t.Helper()
	b, err := os.ReadFile("testdata/canonical_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f codecFixtures
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.SchemaVersion != 1 || len(f.Literals) != 19 || len(f.Seeded) != 4 {
		t.Fatalf("fixture inventory changed: version=%d literals=%d seeded=%d", f.SchemaVersion, len(f.Literals), len(f.Seeded))
	}
	seen := make(map[string]bool)
	for _, v := range append(append([]codecVector{}, f.Literals...), f.Seeded...) {
		if v.Name == "" || seen[v.Name] {
			t.Fatalf("empty or duplicate fixture name %q", v.Name)
		}
		seen[v.Name] = true
	}
	return f
}

func literalCodecVector(t *testing.T, name string) codecVector {
	t.Helper()
	for _, v := range loadCodecFixtures(t).Literals {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("missing accepted literal %q", name)
	return codecVector{}
}

// This test-only reference serializer operates on primitive fixture fields.
// It deliberately does not call any model method, including validation, hashing,
// encoding, decoding, or constant definitions. It also serializes invalid inputs
// so syntax-negative tests can carry a correct independent digest.
func oracleFrame(kind byte, payload []byte) []byte {
	b := append([]byte("CANOPY\x00OBJ\x00"), 0, 1, kind)
	b = binary.BigEndian.AppendUint64(b, uint64(len(payload)))
	return append(b, payload...)
}

func oracleChangeset(t *testing.T, v oracleInput) []byte {
	t.Helper()
	b := codecHex(t, v.Repo)
	b = binary.BigEndian.AppendUint32(b, uint32(len(v.Parents)))
	for _, p := range v.Parents {
		b = append(b, codecHex(t, p)...)
	}
	field := func(s string) {
		x := codecHex(t, s)
		b = binary.BigEndian.AppendUint32(b, uint32(len(x)))
		b = append(b, x...)
	}
	metadata := func(m oracleMetadata) {
		field(m.Identity)
		b = binary.BigEndian.AppendUint64(b, uint64(m.Seconds))
		b = binary.BigEndian.AppendUint16(b, uint16(m.Offset))
	}
	metadata(v.Author)
	if v.Committer == nil {
		b = append(b, 0)
	} else {
		b = append(b, 1)
		metadata(*v.Committer)
	}
	field(v.Message)
	if v.Encoding == nil {
		b = append(b, 0)
	} else {
		b = append(b, 1)
		field(*v.Encoding)
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(v.Operations)))
	for _, op := range v.Operations {
		field(op.Path)
		b = append(b, op.Tag)
		if op.Target != nil {
			b = append(b, codecHex(t, *op.Target)...)
		}
	}
	return oracleFrame(2, b)
}

func productChangeset(t *testing.T, v oracleInput) model.Changeset {
	t.Helper()
	var in model.ChangesetInput
	repo := codecHex(t, v.Repo)
	if len(repo) != len(in.RepoID) {
		t.Fatal("fixture repository must be 16 bytes")
	}
	copy(in.RepoID[:], repo)
	for _, raw := range v.Parents {
		p, err := model.ParseChangesetID(codecHex(t, raw))
		if err != nil {
			t.Fatal(err)
		}
		in.Parents = append(in.Parents, p)
	}
	metadata := func(m oracleMetadata) model.Metadata {
		got, err := model.NewMetadata(codecHex(t, m.Identity), m.Seconds, m.Offset)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	in.Author = metadata(v.Author)
	if v.Committer != nil {
		m := metadata(*v.Committer)
		in.Committer = &m
	}
	in.Message = codecHex(t, v.Message)
	if v.Encoding != nil {
		in.Encoding = append([]byte{}, codecHex(t, *v.Encoding)...)
	}
	for _, op := range v.Operations {
		p, err := model.NewPath(codecHex(t, op.Path))
		if err != nil {
			t.Fatal(err)
		}
		var target *model.BlobID
		if op.Target != nil {
			id, err := model.ParseBlobID(codecHex(t, *op.Target))
			if err != nil {
				t.Fatal(err)
			}
			target = &id
		}
		o, err := model.NewOperation(p, model.OperationTag(op.Tag), target)
		if err != nil {
			t.Fatal(err)
		}
		in.Operations = append(in.Operations, o)
	}
	got, err := model.NewChangeset(in)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func compareCodecChangeset(t *testing.T, got model.Changeset, want oracleInput) {
	t.Helper()
	s := got.Snapshot()
	if hex.EncodeToString(s.RepoID[:]) != want.Repo || len(s.Parents) != len(want.Parents) || len(s.Operations) != len(want.Operations) {
		t.Fatal("repository, parent count, or operation count changed")
	}
	for i, p := range s.Parents {
		raw, err := p.TypedID().MarshalBinary()
		if err != nil || hex.EncodeToString(raw) != want.Parents[i] {
			t.Fatalf("parent sequence changed at %d: %x err=%v", i, raw, err)
		}
	}
	metadata := func(g model.Metadata, w oracleMetadata) {
		if hex.EncodeToString(g.Identity()) != w.Identity || g.UnixSeconds() != w.Seconds || g.OffsetMinutes() != w.Offset {
			t.Fatal("exact metadata bytes, seconds, or offset changed")
		}
	}
	metadata(s.Author, want.Author)
	if (s.Committer == nil) != (want.Committer == nil) {
		t.Fatal("committer presence changed")
	}
	if want.Committer != nil {
		metadata(*s.Committer, *want.Committer)
	}
	if hex.EncodeToString(s.Message) != want.Message || (s.Encoding == nil) != (want.Encoding == nil) {
		t.Fatal("message bytes or encoding presence changed")
	}
	if want.Encoding != nil && hex.EncodeToString(s.Encoding) != *want.Encoding {
		t.Fatal("encoding bytes changed")
	}
	for i, w := range want.Operations {
		o := s.Operations[i]
		mode, hasMode := o.Mode()
		target, hasTarget := o.Target()
		if hex.EncodeToString(o.Path().Bytes()) != w.Path || byte(o.Tag()) != w.Tag || hasMode != (w.Tag != 0) || mode != w.Mode || hasTarget != (w.Target != nil) {
			t.Fatalf("raw path, tag, mode, or target presence changed at operation %d", i)
		}
		if w.Target != nil {
			raw, err := target.TypedID().MarshalBinary()
			if err != nil || hex.EncodeToString(raw) != *w.Target {
				t.Fatalf("target changed at operation %d", i)
			}
		}
	}
}

func checkCodecVector(t *testing.T, v codecVector) {
	t.Helper()
	want := codecHex(t, v.Preimage)
	wantID := codecHex(t, v.TypedID)
	sum := sha256.Sum256(want)
	if len(want) < 22 || want[13] != v.Kind || binary.BigEndian.Uint64(want[14:22]) != uint64(len(want)-22) || hex.EncodeToString(sum[:]) != v.Digest || v.TypedID != fmt.Sprintf("0001%02x%s", v.Kind, v.Digest) {
		t.Fatal("independent fixture frame/digest/identity is inconsistent")
	}
	var out bytes.Buffer
	if v.Kind == 1 {
		payload := codecHex(t, v.BlobHex)
		if !bytes.Equal(oracleFrame(1, payload), want) {
			t.Fatal("reference blob frame disagrees with fixed fixture")
		}
		if err := model.EncodeBlob(context.Background(), &out, uint64(len(payload)), bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
		id, err := model.HashBlob(context.Background(), uint64(len(payload)), bytes.NewReader(payload))
		raw, marshalErr := id.TypedID().MarshalBinary()
		if err != nil || marshalErr != nil || id.TypedID().Digest() != sum || !bytes.Equal(raw, wantID) {
			t.Fatalf("blob hash: id=%v err=%v", id, err)
		}
		decodeCodecVector(t, v, want, wantID)
	} else {
		if v.Kind != 2 || v.Input == nil || !bytes.Equal(oracleChangeset(t, *v.Input), want) {
			t.Fatal("reference changeset frame disagrees with fixed fixture")
		}
		value := productChangeset(t, *v.Input)
		if err := model.EncodeChangeset(context.Background(), &out, value); err != nil {
			t.Fatal(err)
		}
		id, err := model.HashChangeset(context.Background(), value)
		raw, marshalErr := id.TypedID().MarshalBinary()
		if err != nil || marshalErr != nil || id.TypedID().Digest() != sum || !bytes.Equal(raw, wantID) {
			t.Fatalf("changeset hash: id=%v err=%v", id, err)
		}
		decodeCodecVector(t, v, want, wantID)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("encoder bytes disagree with independent fixed frame\ngot  %x\nwant %x", out.Bytes(), want)
	}
}

func decodeCodecVector(t *testing.T, v codecVector, frame, expected []byte) {
	t.Helper()
	budget := uint64(len(frame) - 22)
	if v.Kind == 1 {
		id, err := model.ParseBlobID(expected)
		if err != nil {
			t.Fatal(err)
		}
		var stage bytes.Buffer
		n, err := model.DecodeBlob(context.Background(), bytes.NewReader(frame), id, &stage, budget)
		if err != nil || n != budget || !bytes.Equal(stage.Bytes(), codecHex(t, v.BlobHex)) {
			t.Fatalf("literal blob decode: n=%d bytes=%x err=%v", n, stage.Bytes(), err)
		}
		return
	}
	id, err := model.ParseChangesetID(expected)
	if err != nil {
		t.Fatal(err)
	}
	got, err := model.DecodeChangeset(context.Background(), bytes.NewReader(frame), id, budget)
	if err != nil {
		t.Fatal(err)
	}
	compareCodecChangeset(t, got, *v.Input)
}

func TestObjectConformanceLiterals(t *testing.T) {
	for _, v := range loadCodecFixtures(t).Literals {
		t.Run(v.Name, func(t *testing.T) { checkCodecVector(t, v) })
	}
}

// The LCG is specified in the fixture description. It is local and stable across
// Go versions; no product random source, serializer, hash, or decoder is used.
func seededCodecInput(t *testing.T, seed uint32) oracleInput {
	t.Helper()
	state := seed
	generate := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			state = state*1664525 + 1013904223
			b[i] = byte(state >> 24)
		}
		return hex.EncodeToString(b)
	}
	v := oracleInput{Repo: generate(16), Author: oracleMetadata{Identity: generate(7), Seconds: -1700000000 - int64(seed), Offset: int16(-1439 + int(seed%2879))}, Message: generate(11)}
	a := literalCodecVector(t, "root_A_message_ff").TypedID
	b := literalCodecVector(t, "nonutf8_ff_executable_parent_A").TypedID
	v.Parents = []string{a, b, a}
	if seed&1 != 0 {
		v.Parents = []string{b, a, b}
		v.Committer = &oracleMetadata{}
	}
	if seed&2 != 0 {
		empty := ""
		v.Encoding = &empty
	}
	target := literalCodecVector(t, "blob_x").TypedID
	paths := []string{"41", "61", "65cc81", "7a2fff", "c3a9", "ff"}
	tags := []byte{1, 2, 3, 0, 1, 2}
	modes := []uint32{0100644, 0100755, 0120000, 0, 0100644, 0100755}
	for i, path := range paths {
		op := oracleOperation{Path: path, Tag: tags[i], Mode: modes[i]}
		if op.Tag != 0 {
			op.Target = &target
		}
		v.Operations = append(v.Operations, op)
	}
	return v
}

func TestObjectConformanceSeeded(t *testing.T) {
	for _, v := range loadCodecFixtures(t).Seeded {
		t.Run(v.Name, func(t *testing.T) {
			if v.Seed < 0xd0100000 || v.Seed > 0xd0100003 || v.Description == "" || v.Input == nil || !reflect.DeepEqual(seededCodecInput(t, v.Seed), *v.Input) {
				t.Fatal("seeded input disagrees with independent frozen input")
			}
			checkCodecVector(t, v)
		})
	}
}

// gzip is only a fixture adapter. No product gzip, transport envelope, or storage
// codec support is implied. Bound compressed input and expansion and require one
// complete member, verified checksum, and no trailing/concatenated data.
func fixtureGunzip(compressed []byte, compressedLimit, expandedLimit int) ([]byte, error) {
	if len(compressed) > compressedLimit || expandedLimit < 0 {
		return nil, errors.New("fixture compressed/expanded byte budget")
	}
	src := bytes.NewReader(compressed)
	z, err := gzip.NewReader(src)
	if err != nil {
		return nil, err
	}
	z.Multistream(false)
	frame, readErr := io.ReadAll(io.LimitReader(z, int64(expandedLimit)+1))
	closeErr := z.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(frame) > expandedLimit || src.Len() != 0 {
		return nil, errors.New("fixture expansion or single-member boundary")
	}
	return frame, nil
}

func fixtureGzip(t *testing.T, frame []byte, level int) []byte {
	t.Helper()
	var compressed bytes.Buffer
	z, err := gzip.NewWriterLevel(&compressed, level)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := z.Write(frame); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func TestObjectConformanceCompression(t *testing.T) {
	for _, name := range []string{"blob_x", "root_A_message_ff"} {
		t.Run(name, func(t *testing.T) {
			v := literalCodecVector(t, name)
			frame := codecHex(t, v.Preimage)
			a, b := fixtureGzip(t, frame, gzip.NoCompression), fixtureGzip(t, frame, gzip.BestCompression)
			if bytes.Equal(a, b) {
				t.Fatal("metamorphic compressed representations must differ")
			}
			for _, representation := range [][]byte{a, b} {
				expanded, err := fixtureGunzip(representation, 4096, len(frame))
				if err != nil || !bytes.Equal(expanded, frame) {
					t.Fatalf("bounded fixture decompression: err=%v", err)
				}
				decodeCodecVector(t, v, expanded, codecHex(t, v.TypedID))
			}
		})
	}
}

func TestObjectConformanceCompressionAdapterRejects(t *testing.T) {
	frame := codecHex(t, literalCodecVector(t, "root_A_message_ff").Preimage)
	compressed := fixtureGzip(t, frame, gzip.BestCompression)
	corrupt := append([]byte{}, compressed...)
	corrupt[len(corrupt)-8] ^= 1
	cases := []struct {
		name                           string
		data                           []byte
		compressedLimit, expandedLimit int
	}{
		{"compressed_budget", compressed, len(compressed) - 1, len(frame)},
		{"expansion_budget", compressed, 4096, len(frame) - 1},
		{"truncated", compressed[:len(compressed)-1], 4096, len(frame)},
		{"corrupt_checksum", corrupt, 4096, len(frame)},
		{"trailing", append(append([]byte{}, compressed...), 0), 4096, len(frame)},
		{"concatenated", append(append([]byte{}, compressed...), compressed...), 4096, 2 * len(frame)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := fixtureGunzip(tc.data, tc.compressedLimit, tc.expandedLimit); err == nil || got != nil {
				t.Fatalf("invalid fixture compression accepted: bytes=%d err=%v", len(got), err)
			}
		})
	}
}

// For negative syntax tests only, wrap independently mutated bytes in their
// matching SHA-256 identity. A rejection then exercises syntax rather than only
// an accidental checksum mismatch. Positive identities always come from JSON.
func negativeBlobID(t *testing.T, frame []byte) model.BlobID {
	t.Helper()
	sum := sha256.Sum256(frame)
	id, err := model.ParseBlobID(append([]byte{0, 1, 1}, sum[:]...))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func negativeChangesetID(t *testing.T, frame []byte) model.ChangesetID {
	t.Helper()
	sum := sha256.Sum256(frame)
	id, err := model.ParseChangesetID(append([]byte{0, 1, 2}, sum[:]...))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestObjectConformanceBlobRejects(t *testing.T) {
	v := literalCodecVector(t, "blob_x")
	frame := codecHex(t, v.Preimage)
	id, err := model.ParseBlobID(codecHex(t, v.TypedID))
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(at int, value byte) []byte {
		b := append([]byte{}, frame...)
		b[at] = value
		return b
	}
	length := func(n uint64) []byte {
		b := append([]byte{}, frame...)
		binary.BigEndian.PutUint64(b[14:22], n)
		return b
	}
	wrong := codecHex(t, v.TypedID)
	wrong[len(wrong)-1] ^= 1
	wrongID, err := model.ParseBlobID(wrong)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		frame  []byte
		id     model.BlobID
		budget uint64
	}{
		{"magic", mutate(0, 'X'), id, 1},
		{"unknown_version", mutate(12, 2), id, 1},
		{"unknown_kind", mutate(13, 9), id, 1},
		{"kind_identity_mismatch", mutate(13, 2), id, 1},
		{"corrupt_payload", mutate(22, 'y'), id, 1},
		{"wrong_digest_identity", frame, wrongID, 1},
		{"invalid_zero_identity", frame, model.BlobID{}, 1},
		{"short_declared_length", length(0), id, 1},
		{"long_declared_length", length(2), id, 2},
		{"overflow_length", length(^uint64(0)), id, 1},
		{"trailing_bytes", append(append([]byte{}, frame...), 0), id, 1},
		{"caller_budget", frame, id, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if n, err := model.DecodeBlob(context.Background(), bytes.NewReader(tc.frame), tc.id, io.Discard, tc.budget); err == nil || n != 0 {
				t.Fatalf("malformed blob verified: n=%d err=%v", n, err)
			}
		})
	}
	t.Run("every_truncation", func(t *testing.T) {
		for cut := 0; cut < len(frame); cut++ {
			if n, err := model.DecodeBlob(context.Background(), bytes.NewReader(frame[:cut]), id, io.Discard, 1); err == nil || n != 0 {
				t.Fatalf("truncation at %d verified: n=%d err=%v", cut, n, err)
			}
		}
	})
}

func TestObjectConformanceChangesetRejects(t *testing.T) {
	base := *literalCodecVector(t, "metadata_absent").Input
	blob := literalCodecVector(t, "blob_x").TypedID
	parent := literalCodecVector(t, "root_A_message_ff").TypedID
	makeInput := func(change func(*oracleInput)) []byte {
		v := base
		change(&v)
		return oracleChangeset(t, v)
	}
	field32 := func(name string, at int, n uint32) []byte {
		b := codecHex(t, literalCodecVector(t, name).Preimage)
		binary.BigEndian.PutUint32(b[at:at+4], n)
		return b
	}
	marker := func(at int) []byte {
		b := oracleChangeset(t, base)
		b[at] = 2
		return b
	}
	withOps := func(ops ...oracleOperation) []byte {
		return makeInput(func(v *oracleInput) { v.Operations = ops })
	}
	cases := []struct {
		name  string
		frame []byte
	}{
		{"parent_count_limit", field32("metadata_absent", 38, ^uint32(0))},
		{"parent_count_remaining", field32("metadata_absent", 38, 1)},
		{"identity_length_limit", field32("metadata_absent", 42, 65537)},
		{"identity_length_remaining", field32("metadata_absent", 42, 64)},
		{"message_length_limit", field32("metadata_absent", 58, (16<<20)+1)},
		{"message_length_remaining", field32("metadata_absent", 58, 64)},
		{"encoding_length_limit", field32("encoding_present_empty", 63, 257)},
		{"encoding_length_remaining", field32("encoding_present_empty", 63, 64)},
		{"operation_count_limit", field32("metadata_absent", 63, ^uint32(0))},
		{"operation_count_remaining", field32("metadata_absent", 63, 1)},
		{"path_length_limit", field32("mode_regular", 67, 65536)},
		{"path_length_remaining", field32("mode_regular", 67, 64)},
		{"committer_presence_marker", marker(57)},
		{"encoding_presence_marker", marker(62)},
		{"author_offset_positive", makeInput(func(v *oracleInput) { v.Author.Offset = 1440 })},
		{"author_offset_negative", makeInput(func(v *oracleInput) { v.Author.Offset = -1440 })},
		{"committer_offset", makeInput(func(v *oracleInput) { v.Committer = &oracleMetadata{Offset: 1440} })},
		{"parent_wrong_kind", makeInput(func(v *oracleInput) { v.Parents = []string{blob} })},
		{"parent_unknown_version", makeInput(func(v *oracleInput) { v.Parents = []string{"0002" + parent[4:]} })},
		{"parent_unknown_kind", makeInput(func(v *oracleInput) { v.Parents = []string{parent[:4] + "09" + parent[6:]} })},
		{"target_wrong_kind", withOps(oracleOperation{Path: "61", Tag: 1, Target: &parent})},
		{"target_unknown_version", func() []byte { s := "0002" + blob[4:]; return withOps(oracleOperation{Path: "61", Tag: 1, Target: &s}) }()},
		{"unknown_operation", withOps(oracleOperation{Path: "61", Tag: 4})},
		{"missing_set_target", withOps(oracleOperation{Path: "61", Tag: 1})},
		{"delete_with_target", withOps(oracleOperation{Path: "61", Tag: 0, Target: &blob})},
		{"duplicate_paths", withOps(oracleOperation{Path: "61"}, oracleOperation{Path: "61"})},
		{"unordered_paths", withOps(oracleOperation{Path: "62"}, oracleOperation{Path: "61"})},
		{"conflicting_set_ancestors", withOps(oracleOperation{Path: "61", Tag: 1, Target: &blob}, oracleOperation{Path: "612f62", Tag: 1, Target: &blob})},
		{"trailing_payload", oracleFrame(2, append(oracleChangeset(t, base)[22:], 0))},
	}
	for _, p := range []struct {
		name string
		raw  []byte
	}{
		{"empty", nil}, {"nul", []byte{0}}, {"leading_slash", []byte("/a")}, {"trailing_slash", []byte("a/")},
		{"empty_component", []byte("a//b")}, {"dot", []byte(".")}, {"dotdot", []byte("..")},
		{"dot_component", []byte("a/./b")}, {"dotdot_component", []byte("a/../b")},
		{"component_limit", []byte(strings.Repeat("a/", 1024) + "a")},
	} {
		cases = append(cases, struct {
			name  string
			frame []byte
		}{"path_" + p.name, withOps(oracleOperation{Path: hex.EncodeToString(p.raw)})})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := model.DecodeChangeset(context.Background(), bytes.NewReader(tc.frame), negativeChangesetID(t, tc.frame), 4096)
			if err == nil || !reflect.DeepEqual(got, model.Changeset{}) {
				t.Fatalf("noncanonical changeset escaped: value=%+v err=%v", got, err)
			}
		})
	}
}

func TestObjectConformanceChangesetFraming(t *testing.T) {
	v := literalCodecVector(t, "root_A_message_ff")
	frame := codecHex(t, v.Preimage)
	id, err := model.ParseChangesetID(codecHex(t, v.TypedID))
	if err != nil {
		t.Fatal(err)
	}
	wrong := codecHex(t, v.TypedID)
	wrong[len(wrong)-1] ^= 1
	wrongID, err := model.ParseChangesetID(wrong)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		frame  []byte
		id     model.ChangesetID
		budget uint64
	}{
		{"wrong_digest_identity", frame, wrongID, 4096},
		{"invalid_zero_identity", frame, model.ChangesetID{}, 4096},
		{"trailing_bytes", append(append([]byte{}, frame...), 0), id, 4096},
		{"caller_budget", frame, id, uint64(len(frame) - 23)},
	}
	for _, change := range []struct {
		name  string
		at    int
		value byte
	}{
		{"magic", 0, 'X'}, {"unknown_version", 12, 2}, {"unknown_kind", 13, 9}, {"kind_identity_mismatch", 13, 1}, {"corrupt_message", 62, 0},
	} {
		b := append([]byte{}, frame...)
		b[change.at] = change.value
		cases = append(cases, struct {
			name   string
			frame  []byte
			id     model.ChangesetID
			budget uint64
		}{change.name, b, id, 4096})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := model.DecodeChangeset(context.Background(), bytes.NewReader(tc.frame), tc.id, tc.budget)
			if err == nil || !reflect.DeepEqual(got, model.Changeset{}) {
				t.Fatalf("framing failure escaped: err=%v", err)
			}
		})
	}
	t.Run("every_truncation", func(t *testing.T) {
		for cut := 0; cut < len(frame); cut++ {
			got, err := model.DecodeChangeset(context.Background(), bytes.NewReader(frame[:cut]), id, 4096)
			if err == nil || !reflect.DeepEqual(got, model.Changeset{}) {
				t.Fatalf("truncation at %d escaped: err=%v", cut, err)
			}
		}
	})
}

var codecIOError = errors.New("conformance injected I/O error")

type codecErrorReader struct{ data []byte }

func (r *codecErrorReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, codecIOError
}

type codecIdleReader struct{ calls int }

func (r *codecIdleReader) Read([]byte) (int, error) { r.calls++; return 0, nil }

type codecInvalidReader struct{}

func (codecInvalidReader) Read(p []byte) (int, error) { return len(p) + 1, nil }

type codecObservedReader struct {
	r                     io.Reader
	calls, total, maximum int
	after                 func()
}

func (r *codecObservedReader) Read(p []byte) (int, error) {
	r.calls++
	if len(p) > r.maximum {
		r.maximum = len(p)
	}
	n, err := r.r.Read(p)
	r.total += n
	if r.after != nil {
		r.after()
	}
	return n, err
}

type codecWriter struct {
	w                     io.Writer
	calls, total, maximum int
	err                   error
	short                 bool
}

func (w *codecWriter) Write(p []byte) (int, error) {
	w.calls++
	if len(p) > w.maximum {
		w.maximum = len(p)
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.short {
		return len(p) - 1, nil
	}
	n, err := w.w.Write(p)
	w.total += n
	return n, err
}

func TestObjectConformanceIO(t *testing.T) {
	blob := literalCodecVector(t, "blob_x")
	bframe := codecHex(t, blob.Preimage)
	bid, err := model.ParseBlobID(codecHex(t, blob.TypedID))
	if err != nil {
		t.Fatal(err)
	}
	cs := literalCodecVector(t, "metadata_absent")
	cframe := codecHex(t, cs.Preimage)
	cid, err := model.ParseChangesetID(codecHex(t, cs.TypedID))
	if err != nil {
		t.Fatal(err)
	}
	value := productChangeset(t, *cs.Input)
	checkBlob := func(t *testing.T, ctx context.Context, r io.Reader, w io.Writer, want error) {
		t.Helper()
		n, err := model.DecodeBlob(ctx, r, bid, w, 1)
		if n != 0 || !errors.Is(err, want) {
			t.Fatalf("blob failure: n=%d err=%v want=%v", n, err, want)
		}
	}
	checkChangeset := func(t *testing.T, ctx context.Context, r io.Reader, want error) {
		t.Helper()
		got, err := model.DecodeChangeset(ctx, r, cid, 4096)
		if !reflect.DeepEqual(got, model.Changeset{}) || !errors.Is(err, want) {
			t.Fatalf("changeset failure: err=%v want=%v", err, want)
		}
	}
	cases := []struct {
		name string
		run  func(*testing.T)
	}{
		{"blob_decode_reader_error_with_data", func(t *testing.T) {
			checkBlob(t, context.Background(), &codecErrorReader{data: bframe}, io.Discard, codecIOError)
		}},
		{"changeset_decode_reader_error_with_data", func(t *testing.T) {
			checkChangeset(t, context.Background(), &codecErrorReader{data: cframe}, codecIOError)
		}},
		{"blob_decode_staging_writer_error", func(t *testing.T) {
			checkBlob(t, context.Background(), bytes.NewReader(bframe), &codecWriter{err: codecIOError}, codecIOError)
		}},
		{"blob_decode_staging_short_write", func(t *testing.T) {
			checkBlob(t, context.Background(), bytes.NewReader(bframe), &codecWriter{short: true}, io.ErrShortWrite)
		}},
		{"blob_decode_no_progress", func(t *testing.T) {
			r := &codecIdleReader{}
			checkBlob(t, context.Background(), r, io.Discard, io.ErrNoProgress)
			if r.calls != 100 {
				t.Fatalf("unbounded no-progress reads: %d", r.calls)
			}
		}},
		{"changeset_decode_no_progress", func(t *testing.T) {
			r := &codecIdleReader{}
			checkChangeset(t, context.Background(), r, io.ErrNoProgress)
			if r.calls != 100 {
				t.Fatalf("unbounded no-progress reads: %d", r.calls)
			}
		}},
		{"blob_decode_invalid_reader_count", func(t *testing.T) {
			if n, err := model.DecodeBlob(context.Background(), codecInvalidReader{}, bid, io.Discard, 1); err == nil || n != 0 {
				t.Fatalf("bad reader verified: n=%d err=%v", n, err)
			}
		}},
		{"changeset_decode_invalid_reader_count", func(t *testing.T) {
			if got, err := model.DecodeChangeset(context.Background(), codecInvalidReader{}, cid, 4096); err == nil || !reflect.DeepEqual(got, model.Changeset{}) {
				t.Fatalf("bad reader verified: err=%v", err)
			}
		}},
		{"blob_decode_precanceled", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			r := &codecObservedReader{r: bytes.NewReader(bframe)}
			checkBlob(t, ctx, r, io.Discard, context.Canceled)
			if r.calls != 0 {
				t.Fatal("precanceled decoder performed I/O")
			}
		}},
		{"changeset_decode_precanceled", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			r := &codecObservedReader{r: bytes.NewReader(cframe)}
			checkChangeset(t, ctx, r, context.Canceled)
			if r.calls != 0 {
				t.Fatal("precanceled decoder performed I/O")
			}
		}},
		{"blob_decode_cancel_during_read", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checkBlob(t, ctx, &codecObservedReader{r: bytes.NewReader(bframe), after: cancel}, io.Discard, context.Canceled)
		}},
		{"changeset_decode_cancel_during_read", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checkChangeset(t, ctx, &codecObservedReader{r: bytes.NewReader(cframe), after: cancel}, context.Canceled)
		}},
		{"blob_encode_writer_error", func(t *testing.T) {
			if err := model.EncodeBlob(context.Background(), &codecWriter{err: codecIOError}, 1, bytes.NewReader([]byte{'x'})); !errors.Is(err, codecIOError) {
				t.Fatal(err)
			}
		}},
		{"changeset_encode_writer_error", func(t *testing.T) {
			if err := model.EncodeChangeset(context.Background(), &codecWriter{err: codecIOError}, value); !errors.Is(err, codecIOError) {
				t.Fatal(err)
			}
		}},
		{"blob_encode_short_write", func(t *testing.T) {
			if err := model.EncodeBlob(context.Background(), &codecWriter{short: true}, 1, bytes.NewReader([]byte{'x'})); !errors.Is(err, io.ErrShortWrite) {
				t.Fatal(err)
			}
		}},
		{"changeset_encode_short_write", func(t *testing.T) {
			if err := model.EncodeChangeset(context.Background(), &codecWriter{short: true}, value); !errors.Is(err, io.ErrShortWrite) {
				t.Fatal(err)
			}
		}},
		{"blob_hash_reader_error", func(t *testing.T) {
			id, err := model.HashBlob(context.Background(), 1, &codecErrorReader{data: []byte{'x'}})
			if !errors.Is(err, codecIOError) || id != (model.BlobID{}) {
				t.Fatalf("partial hash: id=%v err=%v", id, err)
			}
		}},
		{"blob_hash_short_input", func(t *testing.T) {
			id, err := model.HashBlob(context.Background(), 2, bytes.NewReader([]byte{'x'}))
			if !errors.Is(err, io.ErrUnexpectedEOF) || id != (model.BlobID{}) {
				t.Fatalf("partial hash: id=%v err=%v", id, err)
			}
		}},
		{"blob_hash_excess_input", func(t *testing.T) {
			id, err := model.HashBlob(context.Background(), 0, bytes.NewReader([]byte{'x'}))
			if err == nil || id != (model.BlobID{}) {
				t.Fatalf("excess hash: id=%v err=%v", id, err)
			}
		}},
		{"blob_hash_precanceled", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			id, err := model.HashBlob(ctx, 1, bytes.NewReader([]byte{'x'}))
			if !errors.Is(err, context.Canceled) || id != (model.BlobID{}) {
				t.Fatalf("canceled hash: id=%v err=%v", id, err)
			}
		}},
		{"changeset_hash_precanceled", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			id, err := model.HashChangeset(ctx, value)
			if !errors.Is(err, context.Canceled) || id != (model.ChangesetID{}) {
				t.Fatalf("canceled hash: id=%v err=%v", id, err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

func TestObjectConformanceBoundedResources(t *testing.T) {
	t.Run("small_stream_chunk_bound", func(t *testing.T) {
		payload := make([]byte, 2*(32<<10)+17)
		for i := range payload {
			payload[i] = byte(i*17 + 3)
		}
		frame := oracleFrame(1, payload)
		r := &codecObservedReader{r: bytes.NewReader(frame)}
		w := &codecWriter{w: io.Discard}
		n, err := model.DecodeBlob(context.Background(), r, negativeBlobID(t, frame), w, uint64(len(payload)))
		if err != nil || n != uint64(len(payload)) || r.total != len(frame) || w.total != len(payload) || r.maximum > 32<<10 || w.maximum > 32<<10 {
			t.Fatalf("unbounded/incomplete decode: n=%d err=%v reader=%+v writer=%+v", n, err, r, w)
		}
		var out bytes.Buffer
		er := &codecObservedReader{r: bytes.NewReader(payload)}
		ew := &codecWriter{w: &out}
		if err := model.EncodeBlob(context.Background(), ew, uint64(len(payload)), er); err != nil || !bytes.Equal(out.Bytes(), frame) || er.maximum > 32<<10 || ew.maximum > 32<<10 {
			t.Fatalf("unbounded/incomplete encode: err=%v reader=%+v writer=%+v", err, er, ew)
		}
		t.Logf("payload=%d frame=%d max decode read/write=%d/%d max encode read/write=%d/%d", len(payload), len(frame), r.maximum, w.maximum, er.maximum, ew.maximum)
	})
	for _, tc := range []struct {
		name             string
		kind             byte
		declared, budget uint64
	}{
		{"blob_header_only_format_limit", 1, (1 << 40) + 1, 1 << 40},
		{"changeset_header_only_format_limit", 2, (64 << 20) + 1, 64 << 20},
		{"blob_header_only_caller_budget", 1, 1 << 20, 1},
		{"changeset_header_only_caller_budget", 2, 1 << 20, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := oracleFrame(tc.kind, nil)
			binary.BigEndian.PutUint64(header[14:22], tc.declared)
			r := &codecObservedReader{r: bytes.NewReader(header)}
			w := &codecWriter{w: io.Discard}
			if tc.kind == 1 {
				n, err := model.DecodeBlob(context.Background(), r, negativeBlobID(t, header), w, tc.budget)
				if err == nil || n != 0 {
					t.Fatalf("oversize blob verified: n=%d err=%v", n, err)
				}
			} else {
				got, err := model.DecodeChangeset(context.Background(), r, negativeChangesetID(t, header), tc.budget)
				if err == nil || !reflect.DeepEqual(got, model.Changeset{}) {
					t.Fatalf("oversize changeset verified: err=%v", err)
				}
			}
			if r.total != 22 || r.calls != 1 || w.calls != 0 {
				t.Fatalf("declaration caused payload I/O: reader=%+v writer=%+v", r, w)
			}
			t.Logf("input allocation=22 bytes; declared=%d; read=%d; staging writes=%d", tc.declared, r.total, w.calls)
		})
	}
}
