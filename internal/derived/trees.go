package derived

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
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

// DecodeTreePageAt additionally checks this page in its supplied byte-path
// context. directoryPrefix is empty for the repository root, otherwise a
// canonical directory path WITHOUT a trailing slash. componentPrefix contains
// the bytes already consumed within its current component; its length is the
// absolute radix offset, so callers cannot supply a contradictory offset/depth.
// Context is caller-supplied, not authenticated. The result remains unlinked:
// every referent must still be fetched/validated in its own context; missing
// pages, cycles, publication, retention and authorization are not checked here.
// Inputs must not be modified concurrently. Work is bounded by canonical path
// limits plus one page. No graph traversal or filesystem operation is performed.
func DecodeTreePageAt(frame []byte, expected TreePageID, directoryPrefix, componentPrefix []byte) (UnlinkedTreePage, error) {
	bad := func() (UnlinkedTreePage, error) { return UnlinkedTreePage{}, ErrTreePage }
	if uint64(len(directoryPrefix)) > model.MaxPathBytes || uint64(len(componentPrefix)) > model.MaxPathBytes {
		return bad()
	}
	dirBytes, depth := 0, 0
	if len(directoryPrefix) != 0 {
		if err := model.ValidatePath(directoryPrefix); err != nil { return bad() }
		dirBytes = len(directoryPrefix) + 1
		depth = 1 + bytes.Count(directoryPrefix, []byte{'/'})
	}
	for _, c := range componentPrefix {
		if c == 0 || c == '/' { return bad() }
	}
	p, err := DecodeUnlinkedTreePage(frame, expected)
	if err != nil { return bad() }
	d := len(componentPrefix)
	cap := 255 - d%256
	if len(p.Label) > cap { return bad() }
	componentBytes := d + len(p.Label)
	if p.Tag == 0 && len(p.Children) == 0 {
		// The empty map is legal only as the entire repository result, not an
		// explicit empty directory or an empty continuation.
		if d != 0 || len(p.Label) != 0 || len(directoryPrefix) != 0 { return bad() }
		return p, nil
	}
	if uint64(componentBytes) > model.MaxPathBytes || uint64(dirBytes+componentBytes) > model.MaxPathBytes || depth >= model.MaxPathComponents {
		return bad()
	}
	if p.Tag == 0 && len(p.Children) == 1 && len(p.Label) != cap { return bad() }
	if p.Tag != 0 {
		if componentBytes == 0 { return bad() }
		if componentBytes <= 2 {
			component := append(append([]byte(nil), componentPrefix...), p.Label...)
			if bytes.Equal(component, []byte(".")) || bytes.Equal(component, []byte("..")) { return bad() }
		}
	}
	// Reject path/offset overruns BEFORE following the next edge. Directory
	// targets necessarily need a slash and at least one more component byte.
	if len(p.Children) != 0 && (uint64(componentBytes+1) > model.MaxPathBytes || uint64(dirBytes+componentBytes+1) > model.MaxPathBytes) { return bad() }
	if p.Tag == 4 && (depth+1 >= model.MaxPathComponents || uint64(dirBytes+componentBytes+2) > model.MaxPathBytes) { return bad() }
	// The empty root's identity is fixed by the contract. Referents with that
	// identity are forbidden without needing to fetch their bytes.
	emptyDigest := sha256.Sum256([]byte("CANOPY\x00TREE\x00\x00\x01\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00"))
	if p.Tag == 4 && bytes.Equal(p.Directory.raw[7:], emptyDigest[:]) { return bad() }
	for _, child := range p.Children {
		if bytes.Equal(child.ID.raw[7:], emptyDigest[:]) { return bad() }
	}
	return p, nil
}

// EncodeTreePageAt serializes one page exactly as the derived v1 contract and
// checks its local context with DecodeTreePageAt. It does not normalize/sort an
// invalid shape, validate referent graphs, write storage, or authorize delivery.
// Inactive union targets must be zero, not silently discarded. Output owns its
// bytes. The page and context inputs must not be modified concurrently.
func EncodeTreePageAt(page UnlinkedTreePage, directoryPrefix, componentPrefix []byte) ([]byte, TreePageID, error) {
	bad := func() ([]byte, TreePageID, error) { return nil, TreePageID{}, ErrTreePage }
	if len(page.Label) > 255 || len(page.Children) > 254 ||
		uint64(len(directoryPrefix)) > model.MaxPathBytes || uint64(len(componentPrefix)) > model.MaxPathBytes {
		return bad()
	}
	var target []byte
	var err error
	switch page.Tag {
	case 0:
		if page.Blob != (model.BlobID{}) || page.Directory != (TreePageID{}) { return bad() }
	case 1, 2, 3:
		if page.Directory != (TreePageID{}) { return bad() }
		target, err = page.Blob.TypedID().MarshalBinary()
	case 4:
		if page.Blob != (model.BlobID{}) { return bad() }
		target, err = page.Directory.MarshalBinary()
	default:
		return bad()
	}
	if err != nil { return bad() }
	// Counts are bounded above before multiplication or allocation.
	length := 2 + len(page.Label) + 1 + len(target) + 2 + len(page.Children)*(1+TreePageIDSize)
	frame := make([]byte, 19, 19+length)
	copy(frame, "CANOPY\x00TREE\x00")
	binary.BigEndian.PutUint16(frame[12:14], 1)
	frame[14] = 1
	binary.BigEndian.PutUint32(frame[15:19], uint32(length))
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(page.Label)))
	frame = append(frame, page.Label...)
	frame = append(frame, page.Tag)
	frame = append(frame, target...)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(page.Children)))
	for _, child := range page.Children {
		if child.ID.Validate() != nil { return bad() }
		frame = append(frame, child.Edge)
		frame = append(frame, child.ID.raw[:]...)
	}
	digest := sha256.Sum256(frame)
	var id TreePageID
	copy(id.raw[:7], "CTP\x00\x00\x01\x01")
	copy(id.raw[7:], digest[:])
	if _, err := DecodeTreePageAt(frame, id, directoryPrefix, componentPrefix); err != nil { return bad() }
	return frame, id, nil
}

var ErrTreePageMissing = errors.New("incomplete derived page graph")

// TreeGraphBudget bounds one non-resumable private validation attempt, not a
// whole repository. Visits/PageBytes cannot exceed the contract's work quantum.
// ContextBytes bounds cumulative walker-owned path copies, not decoder
// temporaries, input map storage, allocator overhead or total process RSS.
// The implementation additionally caps this copy counter at 64 MiB.
// A valid graph exceeding a bound returns resource exhaustion, never corruption.
type TreeGraphBudget struct { Visits, PageBytes, ContextBytes uint64 }

type TreeGraphUsage struct { Visits, Terminals, PageBytes, ContextBytes uint64 }

// CheckTreePageGraph checks ONLY the page topology reachable from root in an
// explicitly supplied private frame map. It is not a storage provider or a
// durable completion receipt: file blobs are NOT fetched/validated/retained,
// and publication/authentication/authorization are NOT established. Unreachable
// map entries are ignored. The map and its frames must not change concurrently.
// Every shared-page context is checked and charged separately. No partial root
// or success is returned on exhaustion, cancellation, missing or invalid input.
// Larger graphs need an external resumable validator; retrying this attempt
// from scratch is not a checkpoint or a route around a whole-job work budget.
func CheckTreePageGraph(ctx context.Context, root TreePageID, frames map[TreePageID][]byte, budget TreeGraphBudget) (TreeGraphUsage, error) {
	var used TreeGraphUsage
	if ctx == nil || root.Validate() != nil || budget.Visits == 0 || budget.Visits > 4096 ||
		budget.PageBytes == 0 || budget.PageBytes > 4096*MaxTreePageBytes || budget.ContextBytes == 0 || budget.ContextBytes > 64<<20 {
		return used, metadata.ErrInvalidArgument
	}
	type work struct { id TreePageID; directory, component []byte; exit bool }
	stack := []work{{id: root}}
	active := make(map[TreePageID]bool)
	chargeContext := func(n int) bool {
		if uint64(n) > budget.ContextBytes-used.ContextBytes { return false }
		used.ContextBytes += uint64(n)
		return true
	}
	for len(stack) != 0 {
		if err := ctx.Err(); err != nil { return used, err }
		w := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if w.exit { delete(active, w.id); continue }
		if used.Visits == budget.Visits { return used, metadata.ErrResourceExhausted }
		used.Visits++
		if active[w.id] { return used, ErrTreePage }
		frame, ok := frames[w.id]
		if !ok { return used, ErrTreePageMissing }
		if len(frame) > MaxTreePageBytes { return used, ErrTreePage }
		if uint64(len(frame)) > budget.PageBytes-used.PageBytes { return used, metadata.ErrResourceExhausted }
		used.PageBytes += uint64(len(frame))
		p, err := DecodeTreePageAt(frame, w.id, w.directory, w.component)
		if err != nil { return used, err }
		if p.Tag != 0 { used.Terminals++ }
		active[w.id] = true
		stack = append(stack, work{id: w.id, exit: true})
		if !chargeContext(len(w.component)+len(p.Label)) { return used, metadata.ErrResourceExhausted }
		component := make([]byte, len(w.component)+len(p.Label))
		copy(component, w.component)
		copy(component[len(w.component):], p.Label)
		// Bound queued frames as well as executed work. Context copies are
		// charged before allocation. PageBytes counts frame bytes processed,
		// not heap usage; decoder temporaries are outside ContextBytes.
		for _, child := range p.Children {
			if err := ctx.Err(); err != nil { return used, err }
			if len(stack) >= 4096 || !chargeContext(len(component)+1) { return used, metadata.ErrResourceExhausted }
			prefix := make([]byte, len(component)+1)
			copy(prefix, component)
			prefix[len(component)] = child.Edge
			stack = append(stack, work{id: child.ID, directory: w.directory, component: prefix})
		}
		if p.Tag == 4 {
			n := len(w.directory)+len(component)
			if len(w.directory) != 0 { n++ }
			if len(stack) >= 4096 || !chargeContext(n) { return used, metadata.ErrResourceExhausted }
			directory := make([]byte, 0, n)
			directory = append(directory, w.directory...)
			if len(directory) != 0 { directory = append(directory, '/') }
			directory = append(directory, component...)
			stack = append(stack, work{id: p.Directory, directory: directory})
		}
	}
	if err := ctx.Err(); err != nil { return used, err }
	return used, nil
}
