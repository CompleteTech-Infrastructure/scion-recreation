package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

// Frozen verbatim from accepted FND-03 canonical.md (SHA-256
// eceab23e153e7d96558858ef76448d41b34bf844315b5d37cea4f0404df4b9c2).
// Its independent script and vector-run.txt are pinned in the task evidence.
// Expected preimages, digests, TIDs and text never call model code to derive them.
var frozenVectors = []struct{ name, preimage, digest, tid, text string }{
	{"blob_empty", "43414e4f5059004f424a000001010000000000000000", "d300c179fc91e6df3575c746e504ce7edbfa118fae5cb3446df7696157cc7235", "000101d300c179fc91e6df3575c746e504ce7edbfa118fae5cb3446df7696157cc7235", "canopy:1:01:d300c179fc91e6df3575c746e504ce7edbfa118fae5cb3446df7696157cc7235"},
	{"blob_x", "43414e4f5059004f424a00000101000000000000000178", "b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052", "000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052", "canopy:1:01:b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052"},
	{"root_A_message_ff", "43414e4f5059004f424a00000102000000000000002e00000000000000000000000000000000000000000000000141000000000000000000000000000001ff0000000000", "f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee", "000102f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee", "canopy:1:02:f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee"},
	{"nonutf8_ff_executable_parent_A", "43414e4f5059004f424a0000010200000000000000790000000000000000000000000000000000000001000102f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee0000000141000000000000000000000000000000000000000100000001ff02000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052", "438a09a6c4a38f09730804074b557ff0dedc2c9f221dbaa2ee748e1d51ee9f42", "000102438a09a6c4a38f09730804074b557ff0dedc2c9f221dbaa2ee748e1d51ee9f42", "canopy:1:02:438a09a6c4a38f09730804074b557ff0dedc2c9f221dbaa2ee748e1d51ee9f42"},
	{"delete_ff_parent_B", "43414e4f5059004f424a0000010200000000000000560000000000000000000000000000000000000001000102438a09a6c4a38f09730804074b557ff0dedc2c9f221dbaa2ee748e1d51ee9f420000000141000000000000000000000000000000000000000100000001ff00", "457753f4dace3d206e1d5c10747150a56dcdace4ed1cbff8b967b7749cad0c0e", "000102457753f4dace3d206e1d5c10747150a56dcdace4ed1cbff8b967b7749cad0c0e", "canopy:1:02:457753f4dace3d206e1d5c10747150a56dcdace4ed1cbff8b967b7749cad0c0e"},
	{"noop_delete_ff_root", "43414e4f5059004f424a00000102000000000000003300000000000000000000000000000000000000000000000141000000000000000000000000000000000000000100000001ff00", "865a4926c0b0f2a725f6abf809fbb4bd0416f55e47f86f155a6a77982433f1a1", "000102865a4926c0b0f2a725f6abf809fbb4bd0416f55e47f86f155a6a77982433f1a1", "canopy:1:02:865a4926c0b0f2a725f6abf809fbb4bd0416f55e47f86f155a6a77982433f1a1"},
	{"parent_order_AB", "43414e4f5059004f424a0000010200000000000000730000000000000000000000000000000000000002000102f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee000102438a09a6c4a38f09730804074b557ff0dedc2c9f221dbaa2ee748e1d51ee9f4200000001410000000000000000000000000000000000000000", "1aabe967540700974c3eeafda5af257ad151682ed1f314bfd55eb5fb7f144a48", "0001021aabe967540700974c3eeafda5af257ad151682ed1f314bfd55eb5fb7f144a48", "canopy:1:02:1aabe967540700974c3eeafda5af257ad151682ed1f314bfd55eb5fb7f144a48"},
	{"parent_order_BA", "43414e4f5059004f424a0000010200000000000000730000000000000000000000000000000000000002000102438a09a6c4a38f09730804074b557ff0dedc2c9f221dbaa2ee748e1d51ee9f42000102f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee00000001410000000000000000000000000000000000000000", "b10bb307ff4ea79466f5901327d8ae4c26ca7c64eb3552417bbcbce02594c2bb", "000102b10bb307ff4ea79466f5901327d8ae4c26ca7c64eb3552417bbcbce02594c2bb", "canopy:1:02:b10bb307ff4ea79466f5901327d8ae4c26ca7c64eb3552417bbcbce02594c2bb"},
	{"mode_regular", "43414e4f5059004f424a000001020000000000000056000000000000000000000000000000000000000000000001410000000000000000000000000000000000000001000000016601000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052", "594def650a507241fe608a4a58210f33f64cf1c84243285278c5b0b126c120fb", "000102594def650a507241fe608a4a58210f33f64cf1c84243285278c5b0b126c120fb", "canopy:1:02:594def650a507241fe608a4a58210f33f64cf1c84243285278c5b0b126c120fb"},
	{"mode_executable", "43414e4f5059004f424a000001020000000000000056000000000000000000000000000000000000000000000001410000000000000000000000000000000000000001000000016602000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052", "192d9db24fcf992a334faddd1cf50545e1f7dd0487c0ca0198500cfa29fd2892", "000102192d9db24fcf992a334faddd1cf50545e1f7dd0487c0ca0198500cfa29fd2892", "canopy:1:02:192d9db24fcf992a334faddd1cf50545e1f7dd0487c0ca0198500cfa29fd2892"},
	{"mode_symlink", "43414e4f5059004f424a000001020000000000000056000000000000000000000000000000000000000000000001410000000000000000000000000000000000000001000000016603000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052", "30913c27f5af231c48b2ee3e9cb800d9d9066e772649a754d1a982f0f085cb6d", "00010230913c27f5af231c48b2ee3e9cb800d9d9066e772649a754d1a982f0f085cb6d", "canopy:1:02:30913c27f5af231c48b2ee3e9cb800d9d9066e772649a754d1a982f0f085cb6d"},
	{"metadata_absent", "43414e4f5059004f424a00000102000000000000002d000000000000000000000000000000000000000000000001410000000000000000000000000000000000000000", "bdee982b0f3b4bfff9ef151f81d8578a5afd3022c07ef86b7883f848c0944d89", "000102bdee982b0f3b4bfff9ef151f81d8578a5afd3022c07ef86b7883f848c0944d89", "canopy:1:02:bdee982b0f3b4bfff9ef151f81d8578a5afd3022c07ef86b7883f848c0944d89"},
	{"committer_present_empty", "43414e4f5059004f424a00000102000000000000003b0000000000000000000000000000000000000000000000014100000000000000000000010000000000000000000000000000000000000000000000", "ff4c76d67982d119dc6bcb37c173a816a889350b532f47cb68fa07cdafa7a9fc", "000102ff4c76d67982d119dc6bcb37c173a816a889350b532f47cb68fa07cdafa7a9fc", "canopy:1:02:ff4c76d67982d119dc6bcb37c173a816a889350b532f47cb68fa07cdafa7a9fc"},
	{"encoding_present_empty", "43414e4f5059004f424a00000102000000000000003100000000000000000000000000000000000000000000000141000000000000000000000000000000010000000000000000", "7da5e70435d6596a98808bafb53908a594f2cdc921426b99dd31b69831770060", "0001027da5e70435d6596a98808bafb53908a594f2cdc921426b99dd31b69831770060", "canopy:1:02:7da5e70435d6596a98808bafb53908a594f2cdc921426b99dd31b69831770060"},
	{"metadata_full_offsets", "43414e4f5059004f424a00000102000000000000004600000000000000000000000000000000000000000000000141000000006553f100014a010000000143000000006553f107fed4000000016d01000000057574662d3800000000", "5cd0226da8c40d20f5e2f43212e2782bc07ddaf2c1eb98fad0b823da454cd642", "0001025cd0226da8c40d20f5e2f43212e2782bc07ddaf2c1eb98fad0b823da454cd642", "canopy:1:02:5cd0226da8c40d20f5e2f43212e2782bc07ddaf2c1eb98fad0b823da454cd642"},
	{"path_A_upper", "43414e4f5059004f424a000001020000000000000056000000000000000000000000000000000000000000000001410000000000000000000000000000000000000001000000014101000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052", "d419c81c623636a49469b804368e2f2ead8e88ce08f15b449b51c992304b65d4", "000102d419c81c623636a49469b804368e2f2ead8e88ce08f15b449b51c992304b65d4", "canopy:1:02:d419c81c623636a49469b804368e2f2ead8e88ce08f15b449b51c992304b65d4"},
	{"path_a_lower", "43414e4f5059004f424a000001020000000000000056000000000000000000000000000000000000000000000001410000000000000000000000000000000000000001000000016101000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052", "5c6d8c08e97604286ccb52fd54b4ac60a153b8fdff26e33ede8cf49f9cdb4acb", "0001025c6d8c08e97604286ccb52fd54b4ac60a153b8fdff26e33ede8cf49f9cdb4acb", "canopy:1:02:5c6d8c08e97604286ccb52fd54b4ac60a153b8fdff26e33ede8cf49f9cdb4acb"},
	{"path_nfc_e_acute", "43414e4f5059004f424a00000102000000000000005700000000000000000000000000000000000000000000000141000000000000000000000000000000000000000100000002c3a901000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052", "96acac1b45deb2f39f0c162a6c0264c1b41d4957c92e7031ea8abca8946ab8a9", "00010296acac1b45deb2f39f0c162a6c0264c1b41d4957c92e7031ea8abca8946ab8a9", "canopy:1:02:96acac1b45deb2f39f0c162a6c0264c1b41d4957c92e7031ea8abca8946ab8a9"},
	{"path_nfd_e_acute", "43414e4f5059004f424a0000010200000000000000580000000000000000000000000000000000000000000000014100000000000000000000000000000000000000010000000365cc8101000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052", "60ec419c01dac21dc6aa04dd4db8122fc48a53594746d5c6a7c7a5b215adc271", "00010260ec419c01dac21dc6aa04dd4db8122fc48a53594746d5c6a7c7a5b215adc271", "canopy:1:02:60ec419c01dac21dc6aa04dd4db8122fc48a53594746d5c6a7c7a5b215adc271"},
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func blobX(t *testing.T) BlobID {
	t.Helper()
	id, err := ParseBlobIDText("canopy:1:01:b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052")
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func parentA(t *testing.T) ChangesetID {
	t.Helper()
	id, err := ParseChangesetIDText("canopy:1:02:f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee")
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func parentB(t *testing.T) ChangesetID {
	t.Helper()
	id, err := ParseChangesetIDText("canopy:1:02:438a09a6c4a38f09730804074b557ff0dedc2c9f221dbaa2ee748e1d51ee9f42")
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func path(t *testing.T, b []byte) Path {
	t.Helper()
	p, err := NewPath(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func metadata(t *testing.T, b []byte, s int64, o int16) Metadata {
	t.Helper()
	m, err := NewMetadata(b, s, o)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func operation(t *testing.T, p []byte, tag OperationTag) Operation {
	t.Helper()
	var id *BlobID
	if tag != Delete {
		x := blobX(t)
		id = &x
	}
	o, err := NewOperation(path(t, p), tag, id)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestObjectIDIndependentVectors(t *testing.T) {
	for _, v := range frozenVectors {
		t.Run(v.name, func(t *testing.T) {
			pre := unhex(t, v.preimage)
			want := unhex(t, v.tid)
			sum := sha256.Sum256(pre)
			if hex.EncodeToString(sum[:]) != v.digest {
				t.Fatal("frozen preimage/digest mismatch")
			}
			id, err := ParseTypedID(want)
			if err != nil {
				t.Fatal(err)
			}
			if id.Version() != 1 || byte(id.Kind()) != pre[13] || id.Digest() != sum {
				t.Fatal("wrong identity fields")
			}
			text, err := id.MarshalText()
			if err != nil || string(text) != v.text || id.String() != v.text {
				t.Fatal("text mismatch", err)
			}
			back, err := ParseTypedIDText(v.text)
			if err != nil || back != id {
				t.Fatal("text parse mismatch", err)
			}
			b, err := back.MarshalBinary()
			if err != nil || !bytes.Equal(b, want) {
				t.Fatal("binary mismatch", err)
			}
			made, err := NewTypedID(id.Kind(), sum)
			if err != nil || made != id {
				t.Fatal("digest boundary mismatch", err)
			}
			if id.Kind() == BlobKind {
				typed, err := ParseBlobID(want)
				if err != nil || typed.TypedID() != id {
					t.Fatal(err)
				}
				typed, err = ParseBlobIDText(v.text)
				if err != nil || typed.TypedID() != id {
					t.Fatal(err)
				}
			} else {
				typed, err := ParseChangesetID(want)
				if err != nil || typed.TypedID() != id {
					t.Fatal(err)
				}
				typed, err = ParseChangesetIDText(v.text)
				if err != nil || typed.TypedID() != id {
					t.Fatal(err)
				}
			}
			if err := ValidateObjectHeader(1, id.Kind(), binary.BigEndian.Uint64(pre[14:22]), id); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A test-only projection of observed immutable values, never the expected oracle.
// Product codecs are deliberately absent; frozen accepted preimages above are
// the independent expected bytes. This is not an interoperability claim.
func observedPreimage(t *testing.T, v ChangesetInput) []byte {
	t.Helper()
	var p bytes.Buffer
	write := func(x any) {
		if err := binary.Write(&p, binary.BigEndian, x); err != nil {
			t.Fatal(err)
		}
	}
	b := func(x []byte) { write(uint32(len(x))); p.Write(x) }
	id := func(x TypedID) {
		raw, err := x.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		p.Write(raw)
	}
	meta := func(m Metadata) { b(m.Identity()); write(m.UnixSeconds()); write(m.OffsetMinutes()) }
	p.Write(v.RepoID[:])
	write(uint32(len(v.Parents)))
	for _, x := range v.Parents {
		id(x.TypedID())
	}
	meta(v.Author)
	if v.Committer == nil {
		p.WriteByte(0)
	} else {
		p.WriteByte(1)
		meta(*v.Committer)
	}
	b(v.Message)
	if v.Encoding == nil {
		p.WriteByte(0)
	} else {
		p.WriteByte(1)
		b(v.Encoding)
	}
	write(uint32(len(v.Operations)))
	for _, o := range v.Operations {
		b(o.Path().Bytes())
		p.WriteByte(byte(o.Tag()))
		if target, ok := o.Target(); ok {
			id(target.TypedID())
		}
	}
	var frame bytes.Buffer
	frame.WriteString("CANOPY\x00OBJ\x00")
	_ = binary.Write(&frame, binary.BigEndian, uint16(1))
	frame.WriteByte(2)
	_ = binary.Write(&frame, binary.BigEndian, uint64(p.Len()))
	frame.Write(p.Bytes())
	return frame.Bytes()
}
func TestObjectChangesetIndependentValues(t *testing.T) {
	for _, v := range frozenVectors {
		if strings.HasPrefix(v.name, "blob_") {
			continue
		}
		t.Run(v.name, func(t *testing.T) {
			input := ChangesetInput{Author: metadata(t, []byte("A"), 0, 0)}
			switch v.name {
			case "root_A_message_ff":
				input.Message = []byte{0xff}
			case "nonutf8_ff_executable_parent_A":
				input.Parents = []ChangesetID{parentA(t)}
				input.Operations = []Operation{operation(t, []byte{0xff}, SetExecutable)}
			case "delete_ff_parent_B":
				input.Parents = []ChangesetID{parentB(t)}
				input.Operations = []Operation{operation(t, []byte{0xff}, Delete)}
			case "noop_delete_ff_root":
				input.Operations = []Operation{operation(t, []byte{0xff}, Delete)}
			case "parent_order_AB":
				input.Parents = []ChangesetID{parentA(t), parentB(t)}
			case "parent_order_BA":
				input.Parents = []ChangesetID{parentB(t), parentA(t)}
			case "mode_regular":
				input.Operations = []Operation{operation(t, []byte("f"), SetRegular)}
			case "mode_executable":
				input.Operations = []Operation{operation(t, []byte("f"), SetExecutable)}
			case "mode_symlink":
				input.Operations = []Operation{operation(t, []byte("f"), SetSymlink)}
			case "metadata_absent":
			case "committer_present_empty":
				m := metadata(t, []byte{}, 0, 0)
				input.Committer = &m
			case "encoding_present_empty":
				input.Encoding = []byte{}
			case "metadata_full_offsets":
				input.Author = metadata(t, []byte("A"), 1700000000, 330)
				m := metadata(t, []byte("C"), 1700000007, -300)
				input.Committer = &m
				input.Message = []byte("m")
				input.Encoding = []byte("utf-8")
			case "path_A_upper":
				input.Operations = []Operation{operation(t, []byte("A"), SetRegular)}
			case "path_a_lower":
				input.Operations = []Operation{operation(t, []byte("a"), SetRegular)}
			case "path_nfc_e_acute":
				input.Operations = []Operation{operation(t, []byte{0xc3, 0xa9}, SetRegular)}
			case "path_nfd_e_acute":
				input.Operations = []Operation{operation(t, []byte{0x65, 0xcc, 0x81}, SetRegular)}
			default:
				t.Fatal("unmapped frozen fixture")
			}
			cs, err := NewChangeset(input)
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.Validate(); err != nil {
				t.Fatal(err)
			}
			got := observedPreimage(t, cs.Snapshot())
			if !bytes.Equal(got, unhex(t, v.preimage)) {
				t.Fatalf("value changed: got %x", got)
			}
			if cs.PayloadSize() != uint64(len(got)-22) {
				t.Fatal("wrong preflight size")
			}
			sum := sha256.Sum256(got)
			if hex.EncodeToString(sum[:]) != v.digest {
				t.Fatal("frozen digest mismatch")
			}
		})
	}
}

func TestObjectIDRejectBinary(t *testing.T) {
	good := unhex(t, frozenVectors[0].tid)
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", nil}, {"truncated", good[:34]}, {"trailing", append(append([]byte{}, good...), 0)},
	}
	for _, pair := range []struct {
		name   string
		offset int
		value  byte
	}{{"version_zero", 1, 0}, {"version_two", 1, 2}, {"version_high", 0, 1}, {"kind_zero", 2, 0}, {"kind_page", 2, 3}, {"kind_ff", 2, 255}} {
		b := append([]byte{}, good...)
		b[pair.offset] = pair.value
		cases = append(cases, struct {
			name string
			raw  []byte
		}{pair.name, b})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseTypedID(c.raw); err == nil {
				t.Fatal("accepted invalid ID")
			}
		})
	}
}
func TestObjectIDRejectText(t *testing.T) {
	good := frozenVectors[0].text
	cases := []struct{ name, text string }{
		{"upper", strings.ToUpper(good)}, {"upper_digest", good[:12] + strings.ToUpper(good[12:])}, {"upper_kind", "canopy:1:0A:" + good[12:]}, {"space", " " + good}, {"newline", good + "\n"}, {"version_zero", strings.Replace(good, "canopy:1:", "canopy:0:", 1)}, {"version_two", strings.Replace(good, "canopy:1:", "canopy:2:", 1)}, {"version_width", strings.Replace(good, "canopy:1:", "canopy:01:", 1)}, {"kind_width", good[:9] + "1:" + good[12:]}, {"unknown_kind", good[:9] + "03:" + good[12:]}, {"zero_kind", good[:9] + "00:" + good[12:]}, {"hex_invalid", good[:75] + "g"}, {"short_digest", good[:75]}, {"trailing", good + "0"}, {"colon", good[:11] + ";" + good[12:]}, {"empty", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseTypedIDText(c.text); err == nil {
				t.Fatal("accepted noncanonical text")
			}
		})
	}
}
func TestObjectIDKindsAndHeader(t *testing.T) {
	b, c := blobX(t).TypedID(), parentA(t).TypedID()
	if _, err := NewBlobID(c); err == nil {
		t.Fatal("wrong blob kind")
	}
	if _, err := NewChangesetID(b); err == nil {
		t.Fatal("wrong parent kind")
	}
	cb, _ := c.MarshalBinary()
	bb, _ := b.MarshalBinary()
	if _, err := ParseBlobID(cb); err == nil {
		t.Fatal("wrong binary blob kind")
	}
	if _, err := ParseChangesetID(bb); err == nil {
		t.Fatal("wrong binary parent kind")
	}
	if _, err := ParseBlobIDText(c.String()); err == nil {
		t.Fatal("wrong text kind")
	}
	if _, err := ParseChangesetIDText(b.String()); err == nil {
		t.Fatal("wrong text kind")
	}
	for _, id := range []TypedID{{}, b, c} {
		if id == (TypedID{}) {
			if id.Validate() == nil {
				t.Fatal("zero valid")
			}
			if _, err := id.MarshalBinary(); err == nil {
				t.Fatal("zero emitted")
			}
			if _, err := id.MarshalText(); err == nil {
				t.Fatal("zero emitted")
			}
		}
	}
	if (BlobID{}).Validate() == nil || (ChangesetID{}).Validate() == nil {
		t.Fatal("zero typed wrapper valid")
	}
	if _, err := NewTypedID(ObjectKind(3), [32]byte{}); err == nil {
		t.Fatal("page kind accepted")
	}
	for _, tc := range []struct {
		version uint16
		kind    ObjectKind
		length  uint64
		id      TypedID
	}{{2, BlobKind, 0, b}, {1, ChangesetKind, 0, b}, {1, BlobKind, 0, c}, {1, 3, 0, b}, {1, BlobKind, MaxBlobPayload + 1, b}, {1, ChangesetKind, MaxChangesetPayload + 1, c}, {1, BlobKind, 0, TypedID{}}} {
		if err := ValidateObjectHeader(tc.version, tc.kind, tc.length, tc.id); err == nil {
			t.Fatal("bad header accepted")
		}
	}
}

func TestObjectPathBytes(t *testing.T) {
	values := [][]byte{[]byte("A"), []byte("a"), []byte("a/b"), []byte("a\\b"), []byte("%2e%2e"), {0xc3, 0xa9}, {0x65, 0xcc, 0x81}, {0xff}}
	for i, b := range values {
		p := path(t, b)
		if !bytes.Equal(p.Bytes(), b) {
			t.Fatal("normalized path")
		}
		for j, c := range values {
			q := path(t, c)
			if p.Compare(q) != bytes.Compare(b, c) {
				t.Fatalf("order %d %d", i, j)
			}
		}
	}
	for _, n := range []int{65535} {
		p := path(t, bytes.Repeat([]byte{'x'}, n))
		if len(p.Bytes()) != n {
			t.Fatal("length changed")
		}
	}
	p := path(t, []byte(strings.Repeat("x/", 1023)+"x"))
	if len(p.Bytes()) != 2047 {
		t.Fatal("components changed")
	}
}
func TestObjectPathReject(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{{"empty", nil}, {"nul", []byte{0}}, {"embedded_nul", []byte{'a', 0, 'b'}}, {"leading", []byte("/a")}, {"trailing", []byte("a/")}, {"empty_component", []byte("a//b")}, {"dot", []byte(".")}, {"dotdot", []byte("..")}, {"inner_dot", []byte("a/./b")}, {"inner_dotdot", []byte("a/../b")}, {"too_long", bytes.Repeat([]byte{'x'}, 65536)}, {"too_deep", []byte(strings.Repeat("x/", 1024) + "x")}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewPath(c.raw); err == nil {
				t.Fatal("bad path accepted")
			}
		})
	}
}
func TestObjectOperationShape(t *testing.T) {
	p := path(t, []byte("f"))
	b := blobX(t)
	for _, tc := range []struct {
		tag  OperationTag
		mode uint32
	}{{SetRegular, 0100644}, {SetExecutable, 0100755}, {SetSymlink, 0120000}} {
		tag, want := tc.tag, tc.mode
		o, err := NewOperation(p, tag, &b)
		if err != nil {
			t.Fatal(err)
		}
		mode, ok := o.Mode()
		if !ok || mode != want {
			t.Fatal("wrong mode")
		}
		target, ok := o.Target()
		if !ok || target != b {
			t.Fatal("wrong target")
		}
	}
	d, err := NewOperation(p, Delete, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Target(); ok {
		t.Fatal("delete target")
	}
	if _, ok := d.Mode(); ok {
		t.Fatal("delete mode")
	}
	for _, tc := range []struct {
		p      Path
		tag    OperationTag
		target *BlobID
	}{{p, 4, nil}, {p, SetRegular, nil}, {p, Delete, &b}, {Path{}, Delete, nil}, {p, SetRegular, &BlobID{}}} {
		if _, err := NewOperation(tc.p, tc.tag, tc.target); err == nil {
			t.Fatal("bad operation accepted")
		}
	}
}
func TestObjectOperationOrder(t *testing.T) {
	for _, v := range [][]Operation{{operation(t, []byte("b"), Delete), operation(t, []byte("a"), Delete)}, {operation(t, []byte("a"), Delete), operation(t, []byte("a"), SetRegular)}} {
		if _, err := NewChangeset(ChangesetInput{Operations: v}); err == nil {
			t.Fatal("bad ordering accepted")
		}
	}
	// Final tree validation belongs to tree application; this valid delta must
	// survive the value boundary even though its path strings share a prefix.
	ops := []Operation{operation(t, []byte("a"), Delete), operation(t, []byte("a/b"), SetRegular)}
	v, err := NewChangeset(ChangesetInput{Parents: []ChangesetID{parentA(t), parentA(t)}, Operations: ops})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Snapshot().Parents) != 2 {
		t.Fatal("deduplicated parents")
	}
}

func TestObjectBoundedLengthAndCounts(t *testing.T) {
	for _, tc := range []struct {
		max     uint64
		minimum uint64
	}{{MaxParents, 35}, {MaxOperations, 6}} {
		if err := ValidateCount(tc.max, tc.max, tc.minimum, tc.max*tc.minimum); err != nil {
			t.Fatal(err)
		}
		if ValidateCount(tc.max+1, tc.max, tc.minimum, math.MaxUint64) == nil || ValidateCount(tc.max, tc.max, tc.minimum, tc.max*tc.minimum-1) == nil {
			t.Fatal("count bound bypass")
		}
	}
	if ValidateCount(math.MaxUint64, math.MaxUint64, 2, math.MaxUint64) == nil || ValidateCount(0, 1, 0, 1) == nil {
		t.Fatal("overflow or zero minimum accepted")
	}
	for _, limit := range []uint64{MaxPathBytes, MaxIdentityBytes, MaxMessageBytes, MaxEncodingBytes, MaxChangesetPayload, MaxBlobPayload} {
		if err := ValidateByteLength(limit, limit, limit); err != nil {
			t.Fatal(err)
		}
		if ValidateByteLength(limit+1, limit, math.MaxUint64) == nil || ValidateByteLength(limit, limit, limit-1) == nil || ValidateByteLength(math.MaxUint64, limit, math.MaxUint64) == nil {
			t.Fatal("unchecked length")
		}
	}
	if n, err := CheckedSize(math.MaxUint64-1, 1, math.MaxUint64); err != nil || n != math.MaxUint64 {
		t.Fatal("wrong checked sum")
	}
	if _, err := CheckedSize(math.MaxUint64, 1, math.MaxUint64); err == nil {
		t.Fatal("overflow accepted")
	}
	if _, err := CheckedSize(2, 0, 1); err == nil {
		t.Fatal("invalid total")
	}
	for i := 0; i < 256; i++ {
		present, err := ParsePresence(byte(i))
		if i < 2 {
			if err != nil || present != (i == 1) {
				t.Fatal("valid presence failed")
			}
		} else if err == nil {
			t.Fatal("bad presence accepted")
		}
	}
}
func TestObjectBlobSizeWithoutBuffering(t *testing.T) {
	id := blobX(t).TypedID()
	if err := ValidateObjectHeader(1, BlobKind, 1<<40, id); err != nil {
		t.Fatal(err)
	}
	if allocs := testing.AllocsPerRun(100, func() {
		if ValidateObjectHeader(1, BlobKind, 1<<40, id) != nil {
			panic("limit")
		}
	}); allocs != 0 {
		t.Fatalf("blob size validation allocates: %g", allocs)
	}
	for _, n := range []uint64{1<<40 + 1, math.MaxUint64} {
		if ValidatePayloadLength(BlobKind, n) == nil {
			t.Fatal("blob limit bypass")
		}
	}
	if ValidatePayloadLength(ChangesetKind, 64<<20) != nil || ValidatePayloadLength(ChangesetKind, 64<<20+1) == nil || ValidatePayloadLength(3, 0) == nil {
		t.Fatal("payload kind/size bound")
	}
}
func TestObjectMetadataLimits(t *testing.T) {
	for _, offset := range []int16{-1439, 1439} {
		m, err := NewMetadata(bytes.Repeat([]byte{0xff}, 65536), math.MinInt64, offset)
		if err != nil || m.UnixSeconds() != math.MinInt64 || m.OffsetMinutes() != offset {
			t.Fatal("valid metadata failed", err)
		}
	}
	for _, offset := range []int16{-1440, 1440} {
		if _, err := NewMetadata(nil, 0, offset); err == nil {
			t.Fatal("bad offset")
		}
	}
	if _, err := NewMetadata(make([]byte, 65537), 0, 0); err == nil {
		t.Fatal("long identity")
	}
	if _, err := NewChangeset(ChangesetInput{Author: Metadata{offset: 1440}}); err == nil {
		t.Fatal("forged metadata")
	}
}
func TestObjectChangesetLimits(t *testing.T) {
	parents := make([]ChangesetID, 1024)
	for i := range parents {
		parents[i] = parentA(t)
	}
	if _, err := NewChangeset(ChangesetInput{Parents: parents, Message: make([]byte, 16<<20), Encoding: make([]byte, 256)}); err != nil {
		t.Fatal("max fields", err)
	}
	if _, err := NewChangeset(ChangesetInput{Parents: append(parents, parentA(t))}); err == nil {
		t.Fatal("parent limit")
	}
	if _, err := NewChangeset(ChangesetInput{Parents: []ChangesetID{{}}}); err == nil {
		t.Fatal("invalid parent")
	}
	if _, err := NewChangeset(ChangesetInput{Message: make([]byte, 16<<20+1)}); err == nil {
		t.Fatal("message limit")
	}
	if _, err := NewChangeset(ChangesetInput{Encoding: make([]byte, 257)}); err == nil {
		t.Fatal("encoding limit")
	}
	if (Changeset{}).Validate() == nil {
		t.Fatal("zero changeset valid")
	}
	for _, o := range []Operation{{path: Path{"a"}, tag: 4}, {path: Path{"a"}, tag: Delete, target: blobX(t)}, {path: Path{"a"}, tag: SetRegular}, {}} {
		if _, err := NewChangeset(ChangesetInput{Operations: []Operation{o}}); err == nil {
			t.Fatal("invalid operation")
		}
	}
}
func TestObjectAggregatePreflight(t *testing.T) {
	// 1100 ordered prefix strings share one 65,535-byte backing string. The
	// encoded size is >64 MiB while actual fixture memory is <200 KiB. A rejected
	// constructor must never clone the declared aggregate or a blob payload.
	raw := strings.Repeat("x", 65535)
	ops := make([]Operation, 1100)
	for i := range ops {
		ops[i] = Operation{path: Path{raw[:64436+i]}, tag: Delete}
	}
	input := ChangesetInput{Operations: ops}
	if _, err := NewChangeset(input); err == nil {
		t.Fatal("aggregate bound")
	}
	if n := testing.AllocsPerRun(5, func() { _, _ = NewChangeset(input) }); n > 2 {
		t.Fatalf("preflight copied before failure: %g allocations", n)
	}
	// The count-only primitive protects decoders before any operation allocation.
	if ValidateCount(1000001, MaxOperations, 6, math.MaxUint64) == nil {
		t.Fatal("operation count")
	}
}
func TestObjectImmutableAliases(t *testing.T) {
	raw := unhex(t, frozenVectors[0].tid)
	id, err := ParseTypedID(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[3] ^= 255
	b, _ := id.MarshalBinary()
	want := unhex(t, frozenVectors[0].tid)
	if !bytes.Equal(b, want) {
		t.Fatal("ID input alias")
	}
	b[3] ^= 255
	again, _ := id.MarshalBinary()
	if !bytes.Equal(again, want) {
		t.Fatal("ID alias")
	}
	pbytes := []byte{0xff, '/', 'a'}
	p := path(t, pbytes)
	pbytes[0] = 'x'
	out := p.Bytes()
	out[0] = 'x'
	if p.Bytes()[0] != 255 {
		t.Fatal("path alias")
	}
	identity := []byte{0xff}
	m := metadata(t, identity, 7, -30)
	identity[0] = 0
	mout := m.Identity()
	mout[0] = 0
	if m.Identity()[0] != 255 {
		t.Fatal("metadata alias")
	}
	committer := m
	in := ChangesetInput{Parents: []ChangesetID{parentA(t), parentB(t)}, Author: m, Committer: &committer, Message: []byte{0xff}, Encoding: []byte("opaque"), Operations: []Operation{operation(t, []byte("f"), SetSymlink)}}
	cs, err := NewChangeset(in)
	if err != nil {
		t.Fatal(err)
	}
	before := observedPreimage(t, cs.Snapshot())
	in.Parents[0] = parentB(t)
	in.Operations[0] = operation(t, []byte("z"), Delete)
	in.Message[0] = 0
	in.Encoding[0] = 0
	*in.Committer = Metadata{}
	snapshot := cs.Snapshot()
	snapshot.Parents[0] = parentB(t)
	snapshot.Operations[0] = operation(t, []byte("q"), Delete)
	snapshot.Message[0] = 0
	snapshot.Encoding[0] = 0
	*snapshot.Committer = Metadata{}
	if !bytes.Equal(before, observedPreimage(t, cs.Snapshot())) {
		t.Fatal("changeset alias")
	}
	empty, err := NewChangeset(ChangesetInput{Committer: &Metadata{}, Encoding: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	x := empty.Snapshot()
	if x.Committer == nil || x.Encoding == nil || len(x.Encoding) != 0 {
		t.Fatal("lost presence")
	}
	absent, err := NewChangeset(ChangesetInput{})
	if err != nil {
		t.Fatal(err)
	}
	x = absent.Snapshot()
	if x.Committer != nil || x.Encoding != nil {
		t.Fatal("invented presence")
	}
	if reflect.DeepEqual(empty.Snapshot(), absent.Snapshot()) {
		t.Fatal("presence conflated")
	}
	target := blobX(t)
	o, err := NewOperation(path(t, []byte("f")), SetRegular, &target)
	if err != nil {
		t.Fatal(err)
	}
	target = BlobID{}
	if got, ok := o.Target(); !ok || got != blobX(t) {
		t.Fatal("target alias")
	}
}

func TestObjectExactSizeBoundaries(t *testing.T) {
	// Exercise an exact 64 MiB encoded value without buffering that encoding.
	raw := strings.Repeat("x", 65535)
	ops := make([]Operation, 900)
	for i := range ops {
		ops[i] = Operation{path: Path{raw[:64636+i]}, tag: Delete}
	}
	base := ChangesetInput{Operations: ops}
	size, err := ValidateChangeset(base)
	if err != nil {
		t.Fatal(err)
	}
	gap := MaxChangesetPayload - size
	if gap > MaxMessageBytes {
		t.Fatal("fixture gap")
	}
	base.Message = make([]byte, int(gap))
	if got, err := ValidateChangeset(base); err != nil || got != MaxChangesetPayload {
		t.Fatal("exact payload bound", got, err)
	}
	base.Message = append(base.Message, 0)
	if _, err := NewChangeset(base); err == nil {
		t.Fatal("payload plus one accepted")
	}
	// Verify length prefixes and option markers are included in the accounting.
	for _, tc := range []struct {
		input ChangesetInput
		size  uint64
	}{{ChangesetInput{}, 44}, {ChangesetInput{Committer: &Metadata{}}, 58}, {ChangesetInput{Encoding: []byte{}}, 48}} {
		if got, err := ValidateChangeset(tc.input); err != nil || got != tc.size {
			t.Fatal(fmt.Sprint(got, err))
		}
	}
}
