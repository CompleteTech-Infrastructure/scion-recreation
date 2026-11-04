package derived

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"canopy.local/canopy/internal/model"
)

const (
	TreePageIDSize = 39
	MaxTreePageBytes = 10478
)

var ErrTreePage = errors.New("invalid derived tree page")

// TreePageID belongs to the derived namespace, never the canonical object
// registry. Identity alone proves neither graph validity nor authorization.
type TreePageID struct { raw [TreePageIDSize]byte }

func ParseTreePageID(raw []byte) (TreePageID, error) {
	if len(raw) != TreePageIDSize || string(raw[:7]) != "CTP\x00\x00\x01\x01" {
		return TreePageID{}, ErrTreePage
	}
	var id TreePageID
	copy(id.raw[:], raw)
	return id, nil
}

func ParseTreePageIDText(s string) (TreePageID, error) {
	const prefix = "canopy-tree:1:01:"
	if len(s) != len(prefix)+64 || s[:len(prefix)] != prefix {
		return TreePageID{}, ErrTreePage
	}
	for _, c := range []byte(s[len(prefix):]) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return TreePageID{}, ErrTreePage
		}
	}
	var raw [TreePageIDSize]byte
	copy(raw[:7], "CTP\x00\x00\x01\x01")
	if _, err := hex.Decode(raw[7:], []byte(s[len(prefix):])); err != nil {
		return TreePageID{}, ErrTreePage
	}
	return ParseTreePageID(raw[:])
}

func (id TreePageID) Validate() error {
	_, err := ParseTreePageID(id.raw[:])
	return err
}

func (id TreePageID) MarshalBinary() ([]byte, error) {
	if id.Validate() != nil { return nil, ErrTreePage }
	return append([]byte(nil), id.raw[:]...), nil
}

func (id TreePageID) MarshalText() ([]byte, error) {
	if id.Validate() != nil { return nil, ErrTreePage }
	return []byte("canopy-tree:1:01:" + hex.EncodeToString(id.raw[7:])), nil
}

// UnlinkedTreePage is owned parsed syntax, NOT a validated tree node. The
// caller may edit these fields; they carry no verified-state capability.
// Tag 0 is absent; 1/2/3 are regular/executable/symlink Blob; 4 is Directory.
// Directory targets and continuation Children have distinct roles.
type UnlinkedTreePage struct {
	Label []byte
	Tag byte
	Blob model.BlobID
	Directory TreePageID
	Children []TreePageChild
}

type TreePageChild struct {
	Edge byte
	ID TreePageID
}

// DecodeUnlinkedTreePage verifies bounded frame syntax and the full expected
// digest. It does not fetch links, validate anchored compression in context,
// reconstruct components/paths, reject cycles/missing/empty referents, or
// establish persistence, publication or permission. Graph ingestion MUST do
// those checks before accepting a tree. Do not expose raw pages to readers.
// Input must not be modified concurrently. Allocation/work is bounded by one
// 10,478-byte page, 255 label bytes and 254 child rows, never advertised lengths.
func DecodeUnlinkedTreePage(frame []byte, expected TreePageID) (UnlinkedTreePage, error) {
	bad := func() (UnlinkedTreePage, error) { return UnlinkedTreePage{}, ErrTreePage }
	if len(frame) < 24 || len(frame) > MaxTreePageBytes || expected.Validate() != nil ||
		string(frame[:12]) != "CANOPY\x00TREE\x00" || binary.BigEndian.Uint16(frame[12:14]) != 1 ||
		frame[14] != 1 || uint64(binary.BigEndian.Uint32(frame[15:19])) != uint64(len(frame)-19) {
		return bad()
	}
	digest := sha256.Sum256(frame)
	if !bytes.Equal(digest[:], expected.raw[7:]) { return bad() }
	b := frame[19:]
	n := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if n > 255 || n > len(b)-3 { return bad() }
	label := b[:n]
	for _, c := range label {
		if c == 0 || c == '/' { return bad() }
	}
	b = b[n:]
	p := UnlinkedTreePage{Tag: b[0]}
	b = b[1:]
	var err error
	switch p.Tag {
	case 0:
	case 1, 2, 3:
		if len(b) < model.TypedIDSize+2 { return bad() }
		p.Blob, err = model.ParseBlobID(b[:model.TypedIDSize])
		b = b[model.TypedIDSize:]
	case 4:
		if len(b) < TreePageIDSize+2 { return bad() }
		p.Directory, err = ParseTreePageID(b[:TreePageIDSize])
		b = b[TreePageIDSize:]
	default:
		return bad()
	}
	if err != nil || len(b) < 2 { return bad() }
	count := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if count > 254 || len(b) != count*(1+TreePageIDSize) { return bad() }
	p.Children = make([]TreePageChild, 0, count)
	last := -1
	for i := 0; i < count; i++ {
		edge := b[0]
		if edge == 0 || edge == '/' || int(edge) <= last { return bad() }
		id, err := ParseTreePageID(b[1:1+TreePageIDSize])
		if err != nil { return bad() }
		p.Children = append(p.Children, TreePageChild{Edge: edge, ID: id})
		last = int(edge)
		b = b[1+TreePageIDSize:]
	}
	p.Label = append([]byte(nil), label...)
	return p, nil
}
