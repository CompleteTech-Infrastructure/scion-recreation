package derived

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"canopy.local/canopy/internal/model"
)

type treeLiteral struct {
	Name string `json:"name"`
	IDHex string `json:"id_hex"`
	IDText string `json:"id_text"`
	FrameHex string `json:"frame_hex"`
	Claimed string `json:"claimed_id_hex"`
	Reject string `json:"expected_reject"`
	ParseAs string `json:"parse_as"`
}

func treeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil { t.Fatal(err) }
	return b
}

func treeFixture(t *testing.T) (pages, negatives, ids []treeLiteral) {
	t.Helper()
	b, err := os.ReadFile("../../tests/fixtures/tree_pages_v1.json")
	if err != nil { t.Fatal(err) }
	var fixture struct {
		Pages []treeLiteral `json:"pages"`
		Negative []treeLiteral `json:"negative_vectors"`
		IDs []treeLiteral `json:"id_rejects"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil { t.Fatal(err) }
	return fixture.Pages, fixture.Negative, fixture.IDs
}

func TestTreePageLiteralSyntax(t *testing.T) {
	pages, negatives, ids := treeFixture(t)
	if len(pages) != 1941 || len(negatives) != 35 || len(ids) != 8 { t.Fatal("fixture coverage changed") }
	for _, row := range pages {
		raw := treeHex(t, row.IDHex)
		id, err := ParseTreePageID(raw)
		if err != nil { t.Fatal(err) }
		text, err := id.MarshalText()
		if err != nil || string(text) != row.IDText { t.Fatal("text identity mismatch") }
		parsed, err := ParseTreePageIDText(row.IDText)
		if err != nil || parsed != id { t.Fatal("text parse mismatch") }
		encoded, err := id.MarshalBinary()
		if err != nil || !bytes.Equal(encoded, raw) { t.Fatal("binary identity mismatch") }
		frame := treeHex(t, row.FrameHex)
		p, err := DecodeUnlinkedTreePage(frame, id)
		if err != nil { t.Fatalf("literal %s: %v", row.IDHex, err) }
		// Reconstruct from decoded fields to catch offset/tag/link corruption.
		payload := binary.BigEndian.AppendUint16(nil, uint16(len(p.Label)))
		payload = append(payload, p.Label...)
		payload = append(payload, p.Tag)
		switch p.Tag {
		case 1, 2, 3:
			target, err := p.Blob.TypedID().MarshalBinary()
			if err != nil { t.Fatal(err) }
			payload = append(payload, target...)
		case 4:
			target, err := p.Directory.MarshalBinary()
			if err != nil { t.Fatal(err) }
			payload = append(payload, target...)
		}
		payload = binary.BigEndian.AppendUint16(payload, uint16(len(p.Children)))
		for _, child := range p.Children {
			payload = append(payload, child.Edge)
			target, err := child.ID.MarshalBinary()
			if err != nil { t.Fatal(err) }
			payload = append(payload, target...)
		}
		if !bytes.Equal(payload, frame[19:]) { t.Fatal("decoded fields differ from literal bytes") }
	}
	checked := 0
	for _, row := range negatives {
		// These ten cases need graph/context validation, explicitly NOT supplied
		// by this syntax primitive. No full corpus conformance claim is made.
		if strings.HasPrefix(row.Reject, "context_") || strings.HasPrefix(row.Reject, "graph:") { continue }
		id, err := ParseTreePageID(treeHex(t, row.Claimed))
		if err != nil { t.Fatal(err) }
		if _, err := DecodeUnlinkedTreePage(treeHex(t, row.FrameHex), id); err != ErrTreePage { t.Fatalf("accepted %s", row.Name) }
		checked++
	}
	if checked != 25 { t.Fatalf("syntax negatives: %d", checked) }
	for _, row := range ids {
		var err error
		switch {
		case row.ParseAs == "canonical_tid":
			_, err = model.ParseTypedID(treeHex(t, row.IDHex))
		case row.IDText != "":
			_, err = ParseTreePageIDText(row.IDText)
		default:
			_, err = ParseTreePageID(treeHex(t, row.IDHex))
		}
		if err == nil { t.Fatalf("accepted ID %s", row.Name) }
	}
}

func TestTreePageBoundsOwnershipAndTruncation(t *testing.T) {
	pages, _, _ := treeFixture(t)
	for _, row := range pages {
		frame := treeHex(t, row.FrameHex)
		id, err := ParseTreePageID(treeHex(t, row.IDHex))
		if err != nil { t.Fatal(err) }
		p, err := DecodeUnlinkedTreePage(frame, id)
		if err != nil { t.Fatal(err) }
		if len(p.Label) == 0 || len(p.Children) == 0 { continue }
		before := append([]byte(nil), p.Label...)
		child := p.Children[0]
		for i := range frame { frame[i] = 0 }
		if !bytes.Equal(before, p.Label) || p.Children[0] != child { t.Fatal("parsed page aliases input") }
		break
	}
	row := pages[0]
	frame := treeHex(t, row.FrameHex)
	id, _ := ParseTreePageID(treeHex(t, row.IDHex))
	for n := 0; n < len(frame); n++ {
		if _, err := DecodeUnlinkedTreePage(frame[:n], id); err != ErrTreePage { t.Fatalf("accepted truncation %d", n) }
	}
	if _, err := DecodeUnlinkedTreePage(make([]byte, MaxTreePageBytes+1), id); err != ErrTreePage { t.Fatal("accepted oversized page") }
	if _, err := DecodeUnlinkedTreePage(frame, TreePageID{}); err != ErrTreePage { t.Fatal("accepted invalid expected ID") }
	if _, err := (TreePageID{}).MarshalBinary(); err != ErrTreePage { t.Fatal("encoded zero ID") }
	// The maximum directory-terminal frame fits exactly; graph referents are
	// deliberately unvalidated here. This is a syntax-size test, not a tree.
	payload := binary.BigEndian.AppendUint16(nil, 255)
	payload = append(payload, bytes.Repeat([]byte{'a'}, 255)...)
	payload = append(payload, 4)
	payload = append(payload, id.raw[:]...)
	payload = binary.BigEndian.AppendUint16(payload, 254)
	for edge := 1; edge <= 255; edge++ {
		if edge == '/' { continue }
		payload = append(payload, byte(edge))
		payload = append(payload, id.raw[:]...)
	}
	max := append([]byte("CANOPY\x00TREE\x00\x00\x01\x01"), binary.BigEndian.AppendUint32(nil, uint32(len(payload)))...)
	max = append(max, payload...)
	digest := sha256.Sum256(max)
	expected := id
	copy(expected.raw[7:], digest[:])
	if len(max) != MaxTreePageBytes { t.Fatal("maximum fixture arithmetic") }
	if _, err := DecodeUnlinkedTreePage(max, expected); err != nil { t.Fatal(err) }
}
