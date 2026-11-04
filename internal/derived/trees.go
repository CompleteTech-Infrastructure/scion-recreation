package derived

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"sort"

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
// ContextBytes bounds cumulative walker-owned edge/label copies and explicit
// path-buffer growth copies, not decoder temporaries, input map storage,
// zero-initialization, allocator overhead or total process RSS.
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
	return walkTreePageGraph(ctx, root, frames, budget, nil)
}

func walkTreePageGraph(ctx context.Context, root TreePageID, frames map[TreePageID][]byte, budget TreeGraphBudget, leaf func([]byte, []byte, UnlinkedTreePage) error) (TreeGraphUsage, error) {
	return walkTreePageView(ctx, root, treeFrameView{base: frames}, budget, leaf)
}

func walkTreePageView(ctx context.Context, root TreePageID, frames treeFrameView, budget TreeGraphBudget, leaf func([]byte, []byte, UnlinkedTreePage) error) (TreeGraphUsage, error) {
	var used TreeGraphUsage
	if ctx == nil || root.Validate() != nil || budget.Visits == 0 || budget.Visits > 4096 ||
		budget.PageBytes == 0 || budget.PageBytes > 4096*MaxTreePageBytes || budget.ContextBytes == 0 || budget.ContextBytes > 64<<20 {
		return used, metadata.ErrInvalidArgument
	}
	// DFS preserves every pending sibling's prefix in this one path buffer.
	// Frames store restoration offsets, not copied directory/component bytes.
	// A child appends its edge; a directory appends '/', resetting component.
	type work struct { id TreePageID; base, directoryEnd, componentStart int; edge byte; appendEdge, exit bool }
	stack := []work{{id: root}}
	active := make(map[TreePageID]bool)
	var path []byte
	appendContext := func(b []byte) bool {
		need := len(path)+len(b)
		if uint64(need) > model.MaxPathBytes { return false }
		cost := uint64(len(b))
		capacity := cap(path)
		if need > capacity {
			capacity = max(64, capacity*2, need)
			capacity = min(capacity, int(model.MaxPathBytes))
			cost += uint64(len(path)) // explicit backing-buffer growth copy
		}
		if cost > budget.ContextBytes-used.ContextBytes { return false }
		used.ContextBytes += cost
		if need > cap(path) {
			next := make([]byte, len(path), capacity)
			copy(next, path)
			path = next
		}
		path = append(path, b...)
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
		if w.base > len(path) { return used, ErrTreePage }
		path = path[:w.base]
		if w.appendEdge && !appendContext([]byte{w.edge}) { return used, metadata.ErrResourceExhausted }
		frame, ok := frames.lookup(w.id)
		if !ok { return used, ErrTreePageMissing }
		if len(frame) > MaxTreePageBytes { return used, ErrTreePage }
		if uint64(len(frame)) > budget.PageBytes-used.PageBytes { return used, metadata.ErrResourceExhausted }
		used.PageBytes += uint64(len(frame))
		p, err := DecodeTreePageAt(frame, w.id, path[:w.directoryEnd], path[w.componentStart:])
		if err != nil { return used, err }
		if p.Tag != 0 { used.Terminals++ }
		active[w.id] = true
		stack = append(stack, work{id: w.id, exit: true})
		if !appendContext(p.Label) { return used, metadata.ErrResourceExhausted }
		if leaf != nil && p.Tag >= 1 && p.Tag <= 3 {
			// Callback slices are borrowed only for this call. The internal
			// enumeration consumer copies admitted output before returning.
			if err := leaf(path[:w.directoryEnd], path[w.componentStart:], p); err != nil { return used, err }
		}
		for _, child := range p.Children {
			if err := ctx.Err(); err != nil { return used, err }
			if len(stack) >= 4096 { return used, metadata.ErrResourceExhausted }
			stack = append(stack, work{id: child.ID, base: len(path), directoryEnd: w.directoryEnd, componentStart: w.componentStart, edge: child.Edge, appendEdge: true})
		}
		if p.Tag == 4 {
			if len(stack) >= 4096 { return used, metadata.ErrResourceExhausted }
			stack = append(stack, work{id: p.Directory, base: len(path), directoryEnd: len(path), componentStart: len(path)+1, edge: '/', appendEdge: true})
		}
	}
	if err := ctx.Err(); err != nil { return used, err }
	return used, nil
}

var ErrTreeLeafAbsent = errors.New("existing tree leaf required")

type TreeRewriteBudget struct { Pages, ReadBytes, WriteBytes uint64 }

// ReplaceExistingTreeLeaf computes an exact existing-file SET using structural
// path copying. It returns a candidate root plus only newly addressed frames;
// no input frame is changed. Equal mode/target returns the original root and no
// frames. It does NOT insert/delete, normalize structural edits, or apply a
// simultaneous changeset. Directory paths are not existing file leaves.
//
// Caller MUST already have a validated retained base graph; only this path is
// checked here, never unrelated subtrees. This helper cannot establish that
// precondition. Neither old/new blobs nor storage receipts are verified here.
// Output is PRIVATE candidate data, NOT durable publication or authorization.
// No storage interface is introduced. Inputs must not change concurrently.
// Pages/read/write bytes bound this non-resumable attempt; resource exhaustion
// is not corruption. Larger jobs need a separately bounded resumable updater.
func ReplaceExistingTreeLeaf(ctx context.Context, root TreePageID, frames map[TreePageID][]byte, path model.Path, tag byte, target model.BlobID, budget TreeRewriteBudget) (TreePageID, map[TreePageID][]byte, error) {
	bad := func(err error) (TreePageID, map[TreePageID][]byte, error) { return TreePageID{}, nil, err }
	if ctx == nil || root.Validate() != nil || path.Validate() != nil || tag < 1 || tag > 3 || target.Validate() != nil ||
		budget.Pages == 0 || budget.Pages > 4096 || budget.ReadBytes == 0 || budget.ReadBytes > 4096*MaxTreePageBytes ||
		budget.WriteBytes == 0 || budget.WriteBytes > 4096*MaxTreePageBytes { return bad(metadata.ErrInvalidArgument) }
	raw := path.Bytes()
	type ancestor struct { id TreePageID; page UnlinkedTreePage; directory, prefix []byte; child int; directoryEdge bool }
	var chain []ancestor
	var readBytes, writeBytes uint64
	current := root
	start, pos, end := 0, 0, bytes.IndexByte(raw, '/')
	if end < 0 { end = len(raw) }
	for {
		if err := ctx.Err(); err != nil { return bad(err) }
		if uint64(len(chain)) >= budget.Pages { return bad(metadata.ErrResourceExhausted) }
		frame, ok := frames[current]
		if !ok { return bad(ErrTreePageMissing) }
		if len(frame) > MaxTreePageBytes { return bad(ErrTreePage) }
		if uint64(len(frame)) > budget.ReadBytes-readBytes { return bad(metadata.ErrResourceExhausted) }
		readBytes += uint64(len(frame))
		var directory []byte
		if start != 0 { directory = raw[:start-1] }
		prefix := raw[start:pos]
		page, err := DecodeTreePageAt(frame, current, directory, prefix)
		if err != nil { return bad(err) }
		if !bytes.HasPrefix(raw[pos:end], page.Label) { return bad(ErrTreeLeafAbsent) }
		chain = append(chain, ancestor{id: current, page: page, directory: directory, prefix: prefix})
		pos += len(page.Label)
		if pos == end {
			if end == len(raw) {
				if page.Tag < 1 || page.Tag > 3 { return bad(ErrTreeLeafAbsent) }
				if page.Tag == tag && page.Blob == target {
					if err := ctx.Err(); err != nil { return bad(err) }
					return root, nil, nil
				}
				break
			}
			if page.Tag != 4 { return bad(ErrTreeLeafAbsent) }
			chain[len(chain)-1].directoryEdge = true
			current = page.Directory
			start, pos = end+1, end+1
			n := bytes.IndexByte(raw[start:], '/')
			end = len(raw)
			if n >= 0 { end = start+n }
			continue
		}
		edge := raw[pos]
		i := sort.Search(len(page.Children), func(i int) bool { return page.Children[i].Edge >= edge })
		if i == len(page.Children) || page.Children[i].Edge != edge { return bad(ErrTreeLeafAbsent) }
		chain[len(chain)-1].child = i
		current = page.Children[i].ID
		pos++
	}
	// Comparing occupied identities also reads bytes. Charge external and
	// already-produced frame comparisons before scanning; length mismatch
	// needs no content scan and is immediately corruption.
	compareExisting := func(existing, wanted []byte) error {
		if len(existing) != len(wanted) { return ErrTreePage }
		n := uint64(len(existing))
		if n > budget.ReadBytes-readBytes { return metadata.ErrResourceExhausted }
		readBytes += n
		if !bytes.Equal(existing, wanted) { return ErrTreePage }
		return nil
	}
	produced := make(map[TreePageID][]byte)
	var replacement TreePageID
	for i := len(chain)-1; i >= 0; i-- {
		if err := ctx.Err(); err != nil { return bad(err) }
		c := chain[i]
		if i == len(chain)-1 { c.page.Tag, c.page.Blob = tag, target } else if c.directoryEdge {
			c.page.Directory = replacement
		} else { c.page.Children[c.child].ID = replacement }
		// File mode/target and parent references have fixed widths, so exact
		// output size equals this old frame's size, known before allocation.
		n := uint64(len(frames[c.id]))
		if n > budget.WriteBytes-writeBytes { return bad(metadata.ErrResourceExhausted) }
		writeBytes += n
		frame, id, err := EncodeTreePageAt(c.page, c.directory, c.prefix)
		if err != nil { return bad(err) }
		if existing, ok := frames[id]; ok {
			if err := compareExisting(existing, frame); err != nil { return bad(err) }
		} else if existing, ok := produced[id]; ok {
			if err := compareExisting(existing, frame); err != nil { return bad(err) }
		} else { produced[id] = frame }
		replacement = id
	}
	if err := ctx.Err(); err != nil { return bad(err) }
	return replacement, produced, nil
}

type TreeBuildBudget struct { Pages, Bytes uint64 }

// BuildSingleLeafTree constructs the canonical tree containing exactly one
// file leaf and its implicit directories. This is empty-tree/missing-suffix
// groundwork, NOT insertion into an existing tree or a changeset application.
// All outputs are private candidates; the blob identity is type-checked only,
// without content/durability/retention/publication or authorization evidence.
// Exact page count and encoded bytes are admitted before frame construction.
// Budgets bound produced pages/bytes, not total RSS or measured CPU time.
func BuildSingleLeafTree(ctx context.Context, path model.Path, tag byte, target model.BlobID, budget TreeBuildBudget) (TreePageID, map[TreePageID][]byte, error) {
	bad := func(err error) (TreePageID, map[TreePageID][]byte, error) { return TreePageID{}, nil, err }
	if ctx == nil || path.Validate() != nil || tag < 1 || tag > 3 || target.Validate() != nil ||
		budget.Pages == 0 || budget.Pages > 4096 || budget.Bytes == 0 || budget.Bytes > 4096*MaxTreePageBytes { return bad(metadata.ErrInvalidArgument) }
	if err := ctx.Err(); err != nil { return bad(err) }
	raw := path.Bytes()
	starts := []int{0}
	for i, b := range raw { if b == '/' { starts = append(starts, i+1) } }
	var pages, size uint64
	for i, start := range starts {
		if err := ctx.Err(); err != nil { return bad(err) }
		end := len(raw)
		if i+1 < len(starts) { end = starts[i+1]-1 }
		length := uint64(end-start)
		n := length/256+1
		targetBytes := uint64(TreePageIDSize)
		if i == len(starts)-1 { targetBytes = model.TypedIDSize }
		// Each unary edge consumes one component byte and adds a 40-byte
		// child row. All nodes have 24 framing/count/tag bytes.
		encoded := length + 24*n + targetBytes + 39*(n-1)
		if n > budget.Pages-pages || encoded > budget.Bytes-size { return bad(metadata.ErrResourceExhausted) }
		pages += n
		size += encoded
	}
	frames := make(map[TreePageID][]byte, int(pages))
	var root TreePageID
	for i := len(starts)-1; i >= 0; i-- {
		start, end := starts[i], len(raw)
		if i+1 < len(starts) { end = starts[i+1]-1 }
		component := raw[start:end]
		var directory []byte
		if start != 0 { directory = raw[:start-1] }
		var continuation TreePageID
		for offset := len(component)/256*256; offset >= 0; offset -= 256 {
			if err := ctx.Err(); err != nil { return bad(err) }
			last := offset+255
			var p UnlinkedTreePage
			if last >= len(component) {
				p.Label = component[offset:]
				if i == len(starts)-1 { p.Tag, p.Blob = tag, target } else { p.Tag, p.Directory = 4, root }
			} else {
				p.Label = component[offset:last]
				p.Children = []TreePageChild{{Edge: component[last], ID: continuation}}
			}
			frame, id, err := EncodeTreePageAt(p, directory, component[:offset])
			if err != nil { return bad(err) }
			if previous, ok := frames[id]; ok {
				if !bytes.Equal(previous, frame) { return bad(ErrTreePage) }
			} else { frames[id] = frame }
			continuation = id
		}
		root = continuation
	}
	if err := ctx.Err(); err != nil { return bad(err) }
	return root, frames, nil
}

// SetTreeLeaf applies one SET to a caller-validated retained base graph by
// anchored radix splitting and path copying. File ancestors/directory targets
// conflict rather than silently deleting descendants. No DELETE, pruning or
// simultaneous changeset application is supplied. Output is PRIVATE candidate
// data, never durable publication, retention or authorization; blob identities
// are type-checked only. Input maps/frames must not change concurrently.
// Pages separately caps traversed page fetches and encoded candidate pages
// (including candidates already occupied by identical bytes). Occupied-identity
// comparisons consume ReadBytes but are not additional traversal-page charges.
// ReadBytes includes every compared existing frame, and limits are cumulative
// within this non-resumable call.
func SetTreeLeaf(ctx context.Context, root TreePageID, frames map[TreePageID][]byte, path model.Path, tag byte, target model.BlobID, budget TreeRewriteBudget) (TreePageID, map[TreePageID][]byte, error) {
	return setTreeLeaf(ctx, root, treeFrameView{base: frames}, path, tag, target, &treeRewriteMeter{limit: budget})
}

func setTreeLeaf(ctx context.Context, root TreePageID, frames treeFrameView, path model.Path, tag byte, target model.BlobID, meter *treeRewriteMeter) (TreePageID, map[TreePageID][]byte, error) {
	budget := meter.limit
	bad := func(err error) (TreePageID, map[TreePageID][]byte, error) { return TreePageID{}, nil, err }
	if ctx == nil || root.Validate() != nil || path.Validate() != nil || tag < 1 || tag > 3 || target.Validate() != nil ||
		budget.Pages == 0 || budget.Pages > 4096 || budget.ReadBytes == 0 || budget.ReadBytes > 4096*MaxTreePageBytes ||
		budget.WriteBytes == 0 || budget.WriteBytes > 4096*MaxTreePageBytes { return bad(metadata.ErrInvalidArgument) }
	raw := path.Bytes()
	starts := []int{0}
	for i, b := range raw { if b == '/' { starts = append(starts, i+1) } }
	endOf := func(i int) int { if i+1 < len(starts) { return starts[i+1]-1 }; return len(raw) }
	directoryOf := func(i int) []byte { if i == 0 { return nil }; return raw[:starts[i]-1] }
	produced := make(map[TreePageID][]byte)
	compare := func(existing, wanted []byte) error {
		if len(existing) != len(wanted) { return ErrTreePage }
		if uint64(len(existing)) > budget.ReadBytes-meter.readBytes { return metadata.ErrResourceExhausted }
		meter.readBytes += uint64(len(existing))
		if !bytes.Equal(existing, wanted) { return ErrTreePage }
		return nil
	}
	emit := func(p UnlinkedTreePage, dir, prefix []byte) (TreePageID, error) {
		if err := ctx.Err(); err != nil { return TreePageID{}, err }
		n := uint64(24+len(p.Label)+40*len(p.Children))
		if p.Tag >= 1 && p.Tag <= 3 { n += model.TypedIDSize } else if p.Tag == 4 { n += TreePageIDSize }
		if meter.writePages == budget.Pages || n > budget.WriteBytes-meter.writeBytes { return TreePageID{}, metadata.ErrResourceExhausted }
		meter.writePages++
		meter.writeBytes += n
		b, id, err := EncodeTreePageAt(p, dir, prefix)
		if err != nil { return TreePageID{}, err }
		if old, ok := frames.lookup(id); ok { err = compare(old, b) } else if old, ok := produced[id]; ok { err = compare(old, b) } else { produced[id] = b }
		return id, err
	}
	// Construct only a missing suffix, retaining absolute fragment endpoints
	// in its first component rather than restarting the 255-byte schedule.
	suffix := func(first, firstOffset int) (TreePageID, error) {
		var result TreePageID
		for i := len(starts)-1; i >= first; i-- {
			component := raw[starts[i]:endOf(i)]
			begin := 0
			if i == first { begin = firstOffset }
			offset := len(component)/256*256
			if offset < begin { offset = begin }
			var continuation TreePageID
			for {
				last := offset+255-offset%256
				var p UnlinkedTreePage
				if last >= len(component) {
					p.Label = component[offset:]
					if i == len(starts)-1 { p.Tag, p.Blob = tag, target } else { p.Tag, p.Directory = 4, result }
				} else {
					p.Label = component[offset:last]
					p.Children = []TreePageChild{{Edge: component[last], ID: continuation}}
				}
				id, err := emit(p, directoryOf(i), component[:offset])
				if err != nil { return TreePageID{}, err }
				continuation = id
				if offset == begin { break }
				offset -= 256
				if offset < begin { offset = begin }
			}
			result = continuation
		}
		return result, nil
	}
	type ancestor struct { page UnlinkedTreePage; dir, prefix []byte; child int; directory bool }
	var chain []ancestor
	current := root
	ci, pos := 0, 0
	var replacement TreePageID
	for {
		if err := ctx.Err(); err != nil { return bad(err) }
		if meter.readPages == budget.Pages { return bad(metadata.ErrResourceExhausted) }
		frame, ok := frames.lookup(current)
		if !ok { return bad(ErrTreePageMissing) }
		if len(frame) > MaxTreePageBytes { return bad(ErrTreePage) }
		if uint64(len(frame)) > budget.ReadBytes-meter.readBytes { return bad(metadata.ErrResourceExhausted) }
		meter.readPages++
		meter.readBytes += uint64(len(frame))
		end, dir, prefix := endOf(ci), directoryOf(ci), raw[starts[ci]:pos]
		p, err := DecodeTreePageAt(frame, current, dir, prefix)
		if err != nil { return bad(err) }
		common := 0
		for common < len(p.Label) && pos+common < end && p.Label[common] == raw[pos+common] { common++ }
		if common < len(p.Label) {
			oldEdge := p.Label[common]
			oldPrefix := make([]byte, len(prefix)+common+1)
			copy(oldPrefix, prefix)
			copy(oldPrefix[len(prefix):], p.Label[:common+1])
			old := p
			old.Label = p.Label[common+1:]
			oldID, err := emit(old, dir, oldPrefix)
			if err != nil { return bad(err) }
			parent := UnlinkedTreePage{Label: p.Label[:common], Children: []TreePageChild{{oldEdge, oldID}}}
			pos += common
			if pos == end {
				if ci == len(starts)-1 { parent.Tag, parent.Blob = tag, target } else {
					parent.Tag = 4
					parent.Directory, err = suffix(ci+1, 0)
				}
			} else {
				newID, e := suffix(ci, pos+1-starts[ci])
				err = e
				parent.Children = append(parent.Children, TreePageChild{raw[pos], newID})
				if parent.Children[0].Edge > parent.Children[1].Edge { parent.Children[0], parent.Children[1] = parent.Children[1], parent.Children[0] }
			}
			if err != nil { return bad(err) }
			replacement, err = emit(parent, dir, prefix)
			if err != nil { return bad(err) }
			break
		}
		pos += len(p.Label)
		if pos == end {
			if ci == len(starts)-1 {
				if p.Tag == 4 { return bad(metadata.ErrConflict) }
				if p.Tag == tag && p.Blob == target {
					if err := ctx.Err(); err != nil { return bad(err) }
					return root, nil, nil
				}
				p.Tag, p.Blob = tag, target
			} else {
				if p.Tag >= 1 && p.Tag <= 3 { return bad(metadata.ErrConflict) }
				if p.Tag == 4 {
					chain = append(chain, ancestor{page: p, dir: dir, prefix: prefix, directory: true})
					current = p.Directory
					ci++
					pos = starts[ci]
					continue
				}
				p.Tag = 4
				p.Directory, err = suffix(ci+1, 0)
				if err != nil { return bad(err) }
			}
			replacement, err = emit(p, dir, prefix)
			if err != nil { return bad(err) }
			break
		}
		edge := raw[pos]
		i := sort.Search(len(p.Children), func(i int) bool { return p.Children[i].Edge >= edge })
		if i < len(p.Children) && p.Children[i].Edge == edge {
			chain = append(chain, ancestor{page: p, dir: dir, prefix: prefix, child: i})
			current = p.Children[i].ID
			pos++
			continue
		}
		if p.Tag == 0 && len(p.Children) == 0 {
			replacement, err = suffix(ci, pos-starts[ci])
		} else {
			newID, e := suffix(ci, pos+1-starts[ci])
			err = e
			p.Children = append(p.Children, TreePageChild{})
			copy(p.Children[i+1:], p.Children[i:])
			p.Children[i] = TreePageChild{edge, newID}
			if err == nil { replacement, err = emit(p, dir, prefix) }
		}
		if err != nil { return bad(err) }
		break
	}
	for i := len(chain)-1; i >= 0; i-- {
		c := chain[i]
		if c.directory { c.page.Directory = replacement } else { c.page.Children[c.child].ID = replacement }
		var err error
		replacement, err = emit(c.page, c.dir, c.prefix)
		if err != nil { return bad(err) }
	}
	if err := ctx.Err(); err != nil { return bad(err) }
	return replacement, produced, nil
}

// DeleteTreeLeaf removes only an exact file leaf, prunes empty implicit
// directories and normalizes unary radix pages at absolute fragment endpoints.
// Absent leaves and directory paths are no-ops, never recursive deletions.
// Caller MUST supply a validated retained base; unrelated subtrees and blobs
// are not validated here. Outputs are PRIVATE candidates, not storage deletion,
// GC, durable publication or authorization. Returned frames may include bounded
// intermediate pages consumed by normalization; only the returned root defines
// the candidate graph. Inputs must not change concurrently. Budget semantics
// match SetTreeLeaf, including normalization fetches and occupied comparisons.
func DeleteTreeLeaf(ctx context.Context, root TreePageID, frames map[TreePageID][]byte, path model.Path, budget TreeRewriteBudget) (TreePageID, map[TreePageID][]byte, error) {
	return deleteTreeLeaf(ctx, root, treeFrameView{base: frames}, path, &treeRewriteMeter{limit: budget})
}

func deleteTreeLeaf(ctx context.Context, root TreePageID, frames treeFrameView, path model.Path, meter *treeRewriteMeter) (TreePageID, map[TreePageID][]byte, error) {
	budget := meter.limit
	bad := func(err error) (TreePageID, map[TreePageID][]byte, error) { return TreePageID{}, nil, err }
	if ctx == nil || root.Validate() != nil || path.Validate() != nil || budget.Pages == 0 || budget.Pages > 4096 ||
		budget.ReadBytes == 0 || budget.ReadBytes > 4096*MaxTreePageBytes || budget.WriteBytes == 0 || budget.WriteBytes > 4096*MaxTreePageBytes { return bad(metadata.ErrInvalidArgument) }
	noop := func() (TreePageID, map[TreePageID][]byte, error) {
		if err := ctx.Err(); err != nil { return bad(err) }
		return root, nil, nil
	}
	produced := make(map[TreePageID][]byte)
	read := func(id TreePageID, dir, prefix []byte) (UnlinkedTreePage, error) {
		if err := ctx.Err(); err != nil { return UnlinkedTreePage{}, err }
		if meter.readPages == budget.Pages { return UnlinkedTreePage{}, metadata.ErrResourceExhausted }
		b, ok := produced[id]
		if !ok { b, ok = frames.lookup(id) }
		if !ok { return UnlinkedTreePage{}, ErrTreePageMissing }
		if len(b) > MaxTreePageBytes { return UnlinkedTreePage{}, ErrTreePage }
		if uint64(len(b)) > budget.ReadBytes-meter.readBytes { return UnlinkedTreePage{}, metadata.ErrResourceExhausted }
		meter.readPages++
		meter.readBytes += uint64(len(b))
		return DecodeTreePageAt(b, id, dir, prefix)
	}
	emit := func(p UnlinkedTreePage, dir, prefix []byte) (TreePageID, error) {
		if err := ctx.Err(); err != nil { return TreePageID{}, err }
		n := uint64(24+len(p.Label)+40*len(p.Children))
		if p.Tag >= 1 && p.Tag <= 3 { n += model.TypedIDSize } else if p.Tag == 4 { n += TreePageIDSize }
		if meter.writePages == budget.Pages || n > budget.WriteBytes-meter.writeBytes { return TreePageID{}, metadata.ErrResourceExhausted }
		meter.writePages++
		meter.writeBytes += n
		b, id, err := EncodeTreePageAt(p, dir, prefix)
		if err != nil { return TreePageID{}, err }
		old, ok := frames.lookup(id)
		if !ok { old, ok = produced[id] }
		if ok {
			if len(old) != len(b) { return TreePageID{}, ErrTreePage }
			if uint64(len(old)) > budget.ReadBytes-meter.readBytes { return TreePageID{}, metadata.ErrResourceExhausted }
			meter.readBytes += uint64(len(old))
			if !bytes.Equal(old, b) { return TreePageID{}, ErrTreePage }
		} else { produced[id] = b }
		return id, nil
	}
	normalize := func(p UnlinkedTreePage, dir, prefix []byte) (TreePageID, bool, error) {
		if p.Tag == 0 && len(p.Children) == 0 { return TreePageID{}, true, nil }
		cap := 255-len(prefix)%256
		for p.Tag == 0 && len(p.Children) == 1 && len(p.Label) < cap {
			childPrefix := make([]byte, len(prefix)+len(p.Label)+1)
			copy(childPrefix, prefix)
			copy(childPrefix[len(prefix):], p.Label)
			childPrefix[len(childPrefix)-1] = p.Children[0].Edge
			child, err := read(p.Children[0].ID, dir, childPrefix)
			if err != nil { return TreePageID{}, false, err }
			label := make([]byte, len(p.Label)+1+len(child.Label))
			copy(label, p.Label)
			label[len(p.Label)] = p.Children[0].Edge
			copy(label[len(p.Label)+1:], child.Label)
			// A validated child cannot cross this absolute anchor.
			if len(label) > cap { return TreePageID{}, false, ErrTreePage }
			p = child
			p.Label = label
		}
		id, err := emit(p, dir, prefix)
		return id, false, err
	}
	raw := path.Bytes()
	type ancestor struct { page UnlinkedTreePage; dir, prefix []byte; child int; directory bool }
	var chain []ancestor
	current := root
	start, pos, end := 0, 0, bytes.IndexByte(raw, '/')
	if end < 0 { end = len(raw) }
	var replacement TreePageID
	var empty bool
	for {
		var dir []byte
		if start != 0 { dir = raw[:start-1] }
		prefix := raw[start:pos]
		p, err := read(current, dir, prefix)
		if err != nil { return bad(err) }
		if !bytes.HasPrefix(raw[pos:end], p.Label) { return noop() }
		pos += len(p.Label)
		if pos == end {
			if end == len(raw) {
				if p.Tag < 1 || p.Tag > 3 { return noop() }
				p.Tag, p.Blob = 0, model.BlobID{}
				replacement, empty, err = normalize(p, dir, prefix)
				if err != nil { return bad(err) }
				break
			}
			if p.Tag != 4 { return noop() }
			chain = append(chain, ancestor{page: p, dir: dir, prefix: prefix, directory: true})
			current = p.Directory
			start, pos = end+1, end+1
			n := bytes.IndexByte(raw[start:], '/')
			end = len(raw)
			if n >= 0 { end = start+n }
			continue
		}
		edge := raw[pos]
		i := sort.Search(len(p.Children), func(i int) bool { return p.Children[i].Edge >= edge })
		if i == len(p.Children) || p.Children[i].Edge != edge { return noop() }
		chain = append(chain, ancestor{page: p, dir: dir, prefix: prefix, child: i})
		current = p.Children[i].ID
		pos++
	}
	for i := len(chain)-1; i >= 0; i-- {
		c := chain[i]
		if c.directory {
			if empty { c.page.Tag, c.page.Directory = 0, TreePageID{} } else { c.page.Directory = replacement }
		} else if empty {
			c.page.Children = append(c.page.Children[:c.child], c.page.Children[c.child+1:]...)
		} else { c.page.Children[c.child].ID = replacement }
		var err error
		replacement, empty, err = normalize(c.page, c.dir, c.prefix)
		if err != nil { return bad(err) }
	}
	if empty {
		var err error
		replacement, err = emit(UnlinkedTreePage{}, nil, nil)
		if err != nil { return bad(err) }
	}
	if err := ctx.Err(); err != nil { return bad(err) }
	return replacement, produced, nil
}


type treeFrameView struct { base, staged map[TreePageID][]byte }
func (v treeFrameView) lookup(id TreePageID) ([]byte, bool) {
 if b, ok := v.staged[id]; ok { return b, true }
 b, ok := v.base[id]
 return b, ok
}

type treeRewriteMeter struct {
 limit TreeRewriteBudget
 readPages, writePages, readBytes, writeBytes uint64
}

type TreeChangesetBudget struct {
	Rewrite TreeRewriteBudget
	Operations, InputBytes uint64
}

// ApplyTreeChangeset validates canonical changeset syntax, removes all exact
// DELETE leaves, then applies SETs against the parent-zero tree. This implements
// simultaneous delta semantics, not a union of additional parent trees. The
// supplied root MUST be the caller-verified retained tree of parent zero (or
// the literal empty root for no parents). Nonempty parent/repository binding,
// blob validity/retention, authorization and publication remain unverified.
//
// A private overlay and ONE shared meter cover the whole batch, without copying
// the caller's potentially large frame map or resetting budgets per operation.
// Failure returns no candidate root/frames; no caller data is changed. Returned
// frames may include bounded intermediates; only the final root defines content.
// Inputs must not change concurrently. This is not a resumable transaction or
// backend commit, and input/path validation is not an interruptible CPU bound.
func ApplyTreeChangeset(ctx context.Context, root TreePageID, frames map[TreePageID][]byte, change model.ChangesetInput, budget TreeChangesetBudget) (TreePageID, map[TreePageID][]byte, error) {
	bad := func(err error) (TreePageID, map[TreePageID][]byte, error) { return TreePageID{}, nil, err }
	b := budget.Rewrite
	if ctx == nil || root.Validate() != nil || budget.Operations == 0 || budget.Operations > 4096 ||
		budget.InputBytes == 0 || budget.InputBytes > model.MaxChangesetPayload || b.Pages == 0 || b.Pages > 4096 ||
		b.ReadBytes == 0 || b.ReadBytes > 4096*MaxTreePageBytes || b.WriteBytes == 0 || b.WriteBytes > 4096*MaxTreePageBytes { return bad(metadata.ErrInvalidArgument) }
	if err := ctx.Err(); err != nil { return bad(err) }
	if uint64(len(change.Operations)) > budget.Operations || uint64(len(change.Message)) > budget.InputBytes { return bad(metadata.ErrResourceExhausted) }
	size, err := model.ValidateChangeset(change)
	if err != nil { return bad(metadata.ErrInvalidArgument) }
	if size > budget.InputBytes { return bad(metadata.ErrResourceExhausted) }
	if len(change.Parents) == 0 {
		empty := sha256.Sum256([]byte("CANOPY\x00TREE\x00\x00\x01\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00"))
		if !bytes.Equal(root.raw[7:], empty[:]) { return bad(metadata.ErrInvalidArgument) }
	}
	view := treeFrameView{base: frames, staged: make(map[TreePageID][]byte)}
	meter := &treeRewriteMeter{limit: b}
	current := root
	for _, deletions := range []bool{true, false} {
		for _, op := range change.Operations {
			if err := ctx.Err(); err != nil { return bad(err) }
			if (op.Tag() == model.Delete) != deletions { continue }
			var added map[TreePageID][]byte
			if deletions { current, added, err = deleteTreeLeaf(ctx, current, view, op.Path(), meter) } else {
				target, ok := op.Target()
				if !ok { return bad(metadata.ErrInvalidArgument) }
				current, added, err = setTreeLeaf(ctx, current, view, op.Path(), byte(op.Tag()), target, meter)
			}
			if err != nil { return bad(err) }
			for id, frame := range added {
				if err := ctx.Err(); err != nil { return bad(err) }
				view.staged[id] = frame
			}
		}
	}
	if err := ctx.Err(); err != nil { return bad(err) }
	if len(view.staged) == 0 { return current, nil, nil }
	return current, view.staged, nil
}

// PrepareTreeWrite binds private tree computation to the frozen TREE-v1 mapping
// key and canonical source bytes. Only parent zero is a required tree input;
// additional canonical parents establish ancestry, never a union of trees.
// The parent record MUST come from an authoritative complete mapping, and frames
// MUST represent its validated retained graph (or include the literal empty
// root for a parentless source). Matching identities alone cannot prove that.
//
// The returned DerivedWrite is a PRIVATE candidate, not a completed stored
// result. Publication, parent membership, blob/page durability and retention,
// authorization, and PutDerived's atomic checks are still mandatory elsewhere.
// No storage provider is fabricated or called here. Inputs must not be mutated
// concurrently. InputBytes bounds canonical payload, not allocation/RSS or CPU;
// validation and canonical hashing add bounded passes separate from page I/O.
func PrepareTreeWrite(ctx context.Context, identity metadata.DerivedIdentity, change model.ChangesetInput, parent *metadata.DerivedResult, frames map[TreePageID][]byte, budget TreeChangesetBudget) (metadata.DerivedWrite, map[TreePageID][]byte, error) {
	root, parents, err := bindTreeInput(ctx, identity, change, parent, budget)
	if err != nil { return metadata.DerivedWrite{}, nil, err }
	return applyBoundTreeWrite(ctx, root, parents, identity, change, frames, budget)
}

func bindTreeInput(ctx context.Context, identity metadata.DerivedIdentity, change model.ChangesetInput, parent *metadata.DerivedResult, budget TreeChangesetBudget) (TreePageID, []metadata.DerivedResult, error) {
	bad := func(err error) (TreePageID, []metadata.DerivedResult, error) { return TreePageID{}, nil, err }
	b := budget.Rewrite
	if ctx == nil || identity.Validate() != nil || identity.Kind != "TREE" || identity.Version != 1 ||
		budget.Operations == 0 || budget.Operations > 4096 || budget.InputBytes == 0 || budget.InputBytes > model.MaxChangesetPayload ||
		b.Pages == 0 || b.Pages > 4096 || b.ReadBytes == 0 || b.ReadBytes > 4096*MaxTreePageBytes || b.WriteBytes == 0 || b.WriteBytes > 4096*MaxTreePageBytes { return bad(metadata.ErrInvalidArgument) }
	if err := ctx.Err(); err != nil { return bad(err) }
	if change.RepoID != identity.Repository { return bad(metadata.ErrInvalidArgument) }
	if uint64(len(change.Operations)) > budget.Operations || uint64(len(change.Message)) > budget.InputBytes { return bad(metadata.ErrResourceExhausted) }
	size, err := model.ValidateChangeset(change)
	if err != nil { return bad(metadata.ErrInvalidArgument) }
	if size > budget.InputBytes { return bad(metadata.ErrResourceExhausted) }
	value, err := model.NewChangeset(change)
	if err != nil { return bad(metadata.ErrInvalidArgument) }
	source, err := model.HashChangeset(ctx, value)
	if err != nil { return bad(err) }
	if source != identity.Changeset { return bad(metadata.ErrCorruptData) }
	var root TreePageID
	var parents []metadata.DerivedResult
	if len(change.Parents) == 0 {
		if parent != nil { return bad(metadata.ErrInvalidArgument) }
		_, root, err = EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
		if err != nil { return bad(err) }
	} else {
		if parent == nil { return bad(metadata.ErrFailedPrecondition) }
		want := metadata.DerivedIdentity{Repository: identity.Repository, Changeset: change.Parents[0], Kind: "TREE", Version: 1}
		if parent.Identity != want || parent.Value.Validate() != nil { return bad(metadata.ErrInvalidArgument) }
		root, err = ParseTreePageID(parent.Value.Bytes())
		if err != nil { return bad(metadata.ErrInvalidArgument) }
		parents = []metadata.DerivedResult{*parent}
	}
	return root, parents, nil
}

func applyBoundTreeWrite(ctx context.Context, root TreePageID, parents []metadata.DerivedResult, identity metadata.DerivedIdentity, change model.ChangesetInput, frames map[TreePageID][]byte, budget TreeChangesetBudget) (metadata.DerivedWrite, map[TreePageID][]byte, error) {
	bad := func(err error) (metadata.DerivedWrite, map[TreePageID][]byte, error) { return metadata.DerivedWrite{}, nil, err }
	root, added, err := ApplyTreeChangeset(ctx, root, frames, change, budget)
	if err != nil { return bad(err) }
	raw, err := root.MarshalBinary()
	if err != nil { return bad(err) }
	resultID, err := metadata.NewDerivedValueID(raw)
	if err != nil { return bad(err) }
	candidate := metadata.DerivedWrite{Result: metadata.DerivedResult{Identity: identity, Value: resultID}, Parents: parents}
	if err := candidate.Validate(); err != nil { return bad(err) }
	if err := ctx.Err(); err != nil { return bad(err) }
	return candidate, added, nil
}

// TreeEntriesBudget limits one complete private enumeration attempt. PathBytes
// charges both each temporary assembled path and its owned model.Path copy.
// Graph.ContextBytes separately charges walker contexts; neither is total RSS.
type TreeEntriesBudget struct {
	Graph TreeGraphBudget
	Entries, PathBytes uint64
}

// ReadTreeEntries verifies the supplied page graph and returns its file leaves
// as canonical raw-byte-sorted SET operations, including modes and typed blob
// targets. Directories are implicit; symlinks are leaves, never followed. Shared
// pages are visited in every context. Unreachable supplied frames are ignored.
//
// Results and usage counters are PRIVATE data, not an authorized projection,
// cursor or public listing. Blob bytes, publication, retention and authorization
// are not checked. Do not expose hidden paths/counts/timing through this helper.
// Errors return no partial rows. Large valid trees may exhaust this bounded
// non-resumable attempt; exhaustion never means absence or graph corruption.
// Sorting is bounded by admitted entries/paths but not interruptible mid-sort.
func ReadTreeEntries(ctx context.Context, root TreePageID, frames map[TreePageID][]byte, budget TreeEntriesBudget) ([]model.Operation, TreeGraphUsage, error) {
	if budget.Entries == 0 || budget.Entries > 4096 || budget.PathBytes == 0 || budget.PathBytes > 64<<20 {
		return nil, TreeGraphUsage{}, metadata.ErrInvalidArgument
	}
	var rows []model.Operation
	var pathBytes uint64
	used, err := walkTreePageGraph(ctx, root, frames, budget.Graph, func(directory, component []byte, page UnlinkedTreePage) error {
		if uint64(len(rows)) == budget.Entries { return metadata.ErrResourceExhausted }
		n := len(directory)+len(component)
		if len(directory) != 0 { n++ }
		if uint64(n)*2 > budget.PathBytes-pathBytes { return metadata.ErrResourceExhausted }
		pathBytes += uint64(n)*2
		raw := make([]byte, 0, n)
		raw = append(raw, directory...)
		if len(directory) != 0 { raw = append(raw, '/') }
		raw = append(raw, component...)
		path, err := model.NewPath(raw)
		if err != nil { return ErrTreePage }
		op, err := model.NewOperation(path, model.OperationTag(page.Tag), &page.Blob)
		if err != nil { return ErrTreePage }
		rows = append(rows, op)
		return nil
	})
	if err != nil { return nil, used, err }
	// Directory traversal order is not raw path order: '/' may sort before
	// or after a same-component continuation edge. Sort the bounded result.
	sort.Slice(rows, func(i, j int) bool { return rows[i].Path().Compare(rows[j].Path()) < 0 })
	for i := 1; i < len(rows); i++ {
		if err := ctx.Err(); err != nil { return nil, used, err }
		if rows[i-1].Path().Compare(rows[i].Path()) >= 0 { return nil, used, ErrTreePage }
	}
	if err := ctx.Err(); err != nil { return nil, used, err }
	return rows, used, nil
}

// TreeLookupBudget bounds page-context reads in one exact-path lookup. The
// canonical input path owns at most 65,535 bytes; its temporary copy and decoder
// temporaries are not counted as page I/O or measured process memory.
type TreeLookupBudget struct { Pages, ReadBytes uint64 }
type TreeLookupUsage struct { Pages, ReadBytes uint64 }

// LookupTreeLeaf follows only the exact raw-byte path from a caller-validated
// retained graph and returns its immutable SET row. Directory-only paths and
// absent file leaves return ErrTreeLeafAbsent; missing/corrupt traversed pages
// are errors, never absence. Symlink bytes are not fetched or followed.
//
// The base validity/retention prerequisite is NOT established here. Unrelated
// subtrees and blob content are not checked. Result, absence, error distinctions
// and counters are PRIVATE and must not be exposed as unauthorized existence
// signals. This is not a storage provider, projection or authorization check.
// Inputs must not change concurrently. Every failure returns a zero row.
func LookupTreeLeaf(ctx context.Context, root TreePageID, frames map[TreePageID][]byte, path model.Path, budget TreeLookupBudget) (model.Operation, TreeLookupUsage, error) {
	var used TreeLookupUsage
	bad := func(err error) (model.Operation, TreeLookupUsage, error) {
		if ctx != nil { if canceled := ctx.Err(); canceled != nil { err = canceled } }
		return model.Operation{}, used, err
	}
	if ctx == nil || root.Validate() != nil || path.Validate() != nil || budget.Pages == 0 || budget.Pages > 4096 || budget.ReadBytes == 0 || budget.ReadBytes > 4096*MaxTreePageBytes { return bad(metadata.ErrInvalidArgument) }
	if err := ctx.Err(); err != nil { return bad(err) }
	raw := path.Bytes()
	current := root
	start, pos, end := 0, 0, bytes.IndexByte(raw, '/')
	if end < 0 { end = len(raw) }
	for {
		if err := ctx.Err(); err != nil { return bad(err) }
		if used.Pages == budget.Pages { return bad(metadata.ErrResourceExhausted) }
		used.Pages++
		frame, ok := frames[current]
		if !ok { return bad(ErrTreePageMissing) }
		if len(frame) > MaxTreePageBytes { return bad(ErrTreePage) }
		if uint64(len(frame)) > budget.ReadBytes-used.ReadBytes { return bad(metadata.ErrResourceExhausted) }
		used.ReadBytes += uint64(len(frame))
		var directory []byte
		if start != 0 { directory = raw[:start-1] }
		page, err := DecodeTreePageAt(frame, current, directory, raw[start:pos])
		if err != nil { return bad(err) }
		if !bytes.HasPrefix(raw[pos:end], page.Label) { return bad(ErrTreeLeafAbsent) }
		pos += len(page.Label)
		if pos == end {
			if end == len(raw) {
				if page.Tag < 1 || page.Tag > 3 { return bad(ErrTreeLeafAbsent) }
				row, err := model.NewOperation(path, model.OperationTag(page.Tag), &page.Blob)
				if err != nil { return bad(ErrTreePage) }
				if err := ctx.Err(); err != nil { return bad(err) }
				return row, used, nil
			}
			if page.Tag != 4 { return bad(ErrTreeLeafAbsent) }
			current = page.Directory
			start, pos = end+1, end+1
			n := bytes.IndexByte(raw[start:], '/')
			end = len(raw)
			if n >= 0 { end = start+n }
			continue
		}
		edge := raw[pos]
		i := sort.Search(len(page.Children), func(i int) bool { return page.Children[i].Edge >= edge })
		if i == len(page.Children) || page.Children[i].Edge != edge { return bad(ErrTreeLeafAbsent) }
		current = page.Children[i].ID
		pos++
	}
}

var ErrTreeBlobMissing = errors.New("referenced canonical blob frame missing")

// TreeObjectGraphBudget adds the frozen 1 MiB per-quantum blob-byte ceiling to
// graph admission. BlobBytes charges each complete frame before decoding,
// including the 22-byte header; failure can mean fewer bytes were actually read.
// Repeated references are charged again. Supplied map/frame
// storage and decoder temporaries are not measured process-memory counters.
type TreeObjectGraphBudget struct {
	Graph TreeGraphBudget
	BlobBytes uint64
}
type TreeObjectGraphUsage struct {
	Graph TreeGraphUsage
	BlobVisits, BlobBytes uint64
}

// CheckTreeObjectGraph validates all supplied reachable page contexts AND the
// exact canonical bytes/type/digest of every file blob target. It uses existing
// graph and canonical-object decoders; blob payloads are streamed to io.Discard,
// never interpreted as paths or followed as symlinks. Every occurrence is checked
// and charged, even if a typed blob identity was already visited.
//
// This is PRIVATE integrity preflight over supplied bytes, not a storage provider,
// immutable receipt, durable/retained graph, published source or authorization.
// Caller maps/bytes must not change during the call. Errors cannot establish
// completion; partial usage is private diagnostic data only. Valid graphs with
// large blobs can exhaust this non-resumable attempt and need a separate bounded
// resumable validator, never a false corruption/absence/completion claim.
func CheckTreeObjectGraph(ctx context.Context, root TreePageID, pageFrames map[TreePageID][]byte, blobFrames map[model.BlobID][]byte, budget TreeObjectGraphBudget) (TreeObjectGraphUsage, error) {
	return checkTreeObjectView(ctx, root, treeFrameView{base: pageFrames}, blobFrames, budget)
}

func checkTreeObjectView(ctx context.Context, root TreePageID, pageFrames treeFrameView, blobFrames map[model.BlobID][]byte, budget TreeObjectGraphBudget) (TreeObjectGraphUsage, error) {
	var used TreeObjectGraphUsage
	if budget.BlobBytes == 0 || budget.BlobBytes > 1<<20 { return used, metadata.ErrInvalidArgument }
	graph, err := walkTreePageView(ctx, root, pageFrames, budget.Graph, func(_ []byte, _ []byte, page UnlinkedTreePage) error {
		if err := ctx.Err(); err != nil { return err }
		used.BlobVisits++
		frame, ok := blobFrames[page.Blob]
		if !ok { return ErrTreeBlobMissing }
		if uint64(len(frame)) > budget.BlobBytes-used.BlobBytes { return metadata.ErrResourceExhausted }
		used.BlobBytes += uint64(len(frame))
		var payloadLimit uint64
		if len(frame) >= 22 { payloadLimit = uint64(len(frame)-22) }
		_, err := model.DecodeBlob(ctx, bytes.NewReader(frame), page.Blob, io.Discard, payloadLimit)
		return err
	})
	used.Graph = graph
	return used, err
}

// TreeCheckedWriteBudget explicitly admits two graph-validation quanta plus
// one rewrite attempt. Total admitted work is bounded by their summed ceilings,
// not by a single graph quantum. Reused blobs/pages are charged in both phases.
type TreeCheckedWriteBudget struct {
	Parent, Candidate TreeObjectGraphBudget
	Rewrite TreeChangesetBudget
}
type TreeCheckedWriteUsage struct { Parent, Candidate TreeObjectGraphUsage }

// PrepareCheckedTreeWrite binds the canonical source and parent-zero mapping,
// checks all supplied parent page/blob bytes, computes the simultaneous delta,
// then checks the final reachable candidate page/blob bytes before returning.
// An overlay resolves new frames without copying the arbitrary caller map.
// The existing PrepareTreeWrite fast path remains for already-validated bases.
//
// This establishes supplied-byte integrity only while inputs remain stable.
// Mapping provenance, source/parent publication, durable retention, authorization
// and PutDerived remain separate prerequisites. No provider, storage mutation or
// transferable validity receipt is created. Errors return no write or frames;
// usage is private diagnostic data. Returned frames can include unreachable
// rewrite intermediates: only the candidate root's reachable closure is checked.
func PrepareCheckedTreeWrite(ctx context.Context, identity metadata.DerivedIdentity, change model.ChangesetInput, parent *metadata.DerivedResult, frames map[TreePageID][]byte, blobs map[model.BlobID][]byte, budget TreeCheckedWriteBudget) (metadata.DerivedWrite, map[TreePageID][]byte, TreeCheckedWriteUsage, error) {
	var used TreeCheckedWriteUsage
	bad := func(err error) (metadata.DerivedWrite, map[TreePageID][]byte, TreeCheckedWriteUsage, error) { return metadata.DerivedWrite{}, nil, used, err }
	admitted := func(b TreeObjectGraphBudget) bool {
		g := b.Graph
		return b.BlobBytes > 0 && b.BlobBytes <= 1<<20 && g.Visits > 0 && g.Visits <= 4096 && g.PageBytes > 0 && g.PageBytes <= 4096*MaxTreePageBytes && g.ContextBytes > 0 && g.ContextBytes <= 64<<20
	}
	if !admitted(budget.Parent) || !admitted(budget.Candidate) { return bad(metadata.ErrInvalidArgument) }
	root, parents, err := bindTreeInput(ctx, identity, change, parent, budget.Rewrite)
	if err != nil { return bad(err) }
	used.Parent, err = CheckTreeObjectGraph(ctx, root, frames, blobs, budget.Parent)
	if err != nil { return bad(err) }
	candidate, added, err := applyBoundTreeWrite(ctx, root, parents, identity, change, frames, budget.Rewrite)
	if err != nil { return bad(err) }
	resultRoot, err := ParseTreePageID(candidate.Result.Value.Bytes())
	if err != nil { return bad(err) }
	used.Candidate, err = checkTreeObjectView(ctx, resultRoot, treeFrameView{base: frames, staged: added}, blobs, budget.Candidate)
	if err != nil { return bad(err) }
	if err := ctx.Err(); err != nil { return bad(err) }
	return candidate, added, used, nil
}

// PrepareCanonicalTreeWrite verifies an exact canonical changeset frame before
// entering the checked parent/rewrite/candidate pipeline. Rewrite.InputBytes
// limits the source payload (the 22-byte object header is additional), and the
// complete supplied frame is admitted before decoding. Decoder/Snapshot copies
// are bounded by that payload limit, not a peak-memory or operation-count bound;
// Rewrite.Operations is enforced on the decoded changeset before tree work.
//
// Expected source identity is caller-supplied. Valid bytes do not establish
// publication, authoritative parent mapping, retention or permission to read or
// write. All PrepareCheckedTreeWrite phase budgets and private-output caveats
// still apply. Inputs must remain stable; there is no fetch or durable mutation.
func PrepareCanonicalTreeWrite(ctx context.Context, identity metadata.DerivedIdentity, sourceFrame []byte, parent *metadata.DerivedResult, frames map[TreePageID][]byte, blobs map[model.BlobID][]byte, budget TreeCheckedWriteBudget) (metadata.DerivedWrite, map[TreePageID][]byte, TreeCheckedWriteUsage, error) {
	bad := func(err error) (metadata.DerivedWrite, map[TreePageID][]byte, TreeCheckedWriteUsage, error) { return metadata.DerivedWrite{}, nil, TreeCheckedWriteUsage{}, err }
	limit := budget.Rewrite.InputBytes
	if ctx == nil || identity.Validate() != nil || identity.Kind != "TREE" || identity.Version != 1 || limit == 0 || limit > model.MaxChangesetPayload { return bad(metadata.ErrInvalidArgument) }
	if err := ctx.Err(); err != nil { return bad(err) }
	if uint64(len(sourceFrame)) > limit+22 { return bad(metadata.ErrResourceExhausted) }
	source, err := model.DecodeChangeset(ctx, bytes.NewReader(sourceFrame), identity.Changeset, limit)
	if err != nil { return bad(err) }
	return PrepareCheckedTreeWrite(ctx, identity, source.Snapshot(), parent, frames, blobs, budget)
}

// TreeSourceFrame identifies one exact canonical source. Chain replay requires
// a root then contiguous parent-zero successors; DAG replay requires topological
// order with every parent present earlier in the same supplied batch.
type TreeSourceFrame struct { ID model.ChangesetID; Frame []byte }

// TreeReplayBudget admits at most Sources independent checked-write attempts.
// Total admitted phase work is Sources times Step's phase ceilings, not one
// graph quantum. SourceBytes charges complete frames including headers once;
// Pages/PageBytes bound retained distinct pages, including empty/intermediate
// pages. Decoder/rewrite temporaries are separately bounded by Step, not RSS.
type TreeReplayBudget struct {
	Sources, SourceBytes, Pages, PageBytes uint64
	Step TreeCheckedWriteBudget
}
type TreeReplayUsage struct { Sources, SourceBytes, Pages, PageBytes uint64 }

// ReplayCanonicalTreeChain computes private mappings from a canonical root to
// the final source without caller-supplied tree mappings. Every parent-zero
// mapping comes from the immediately preceding checked computation. Additional
// canonical parents affect source identity, not the tree input; their repository
// membership/publication remains an external prerequisite. Inputs must be stable.
//
// This is bounded, non-resumable private replay, not a durable evaluator or an
// authorization boundary. It fetches nothing and publishes nothing. Outputs
// include mappings for the whole chain and owned page bytes, including possibly
// unreachable intermediate pages. Any failure returns nil mappings and pages;
// private usage describes admitted work, not proof of successful validation.
func ReplayCanonicalTreeChain(ctx context.Context, repository [16]byte, sources []TreeSourceFrame, blobs map[model.BlobID][]byte, budget TreeReplayBudget) ([]metadata.DerivedWrite, map[TreePageID][]byte, TreeReplayUsage, error) {
	return replayCanonicalTrees(ctx, repository, sources, blobs, budget, false)
}

// ReplayCanonicalTreeDAG accepts a complete, topologically ordered supplied
// canonical DAG. Every parent (including nonzero parents) must already have
// passed canonical/repository verification and checked tree computation in this
// call. Multiple roots are allowed; repeated source IDs and unknown/not-yet-seen
// parents fail. This establishes supplied ancestry closure without fetching or
// accepting caller mappings. Only parent zero contributes a source's base tree.
//
// Budget accounting, private owned outputs and all-or-nothing failure semantics
// are identical to ReplayCanonicalTreeChain. Verified supplied ancestry still
// does not establish authoritative publication, retention or authorization.
func ReplayCanonicalTreeDAG(ctx context.Context, repository [16]byte, sources []TreeSourceFrame, blobs map[model.BlobID][]byte, budget TreeReplayBudget) ([]metadata.DerivedWrite, map[TreePageID][]byte, TreeReplayUsage, error) {
	return replayCanonicalTrees(ctx, repository, sources, blobs, budget, true)
}

func replayCanonicalTrees(ctx context.Context, repository [16]byte, sources []TreeSourceFrame, blobs map[model.BlobID][]byte, budget TreeReplayBudget, completeDAG bool) ([]metadata.DerivedWrite, map[TreePageID][]byte, TreeReplayUsage, error) {
	var used TreeReplayUsage
	bad := func(err error) ([]metadata.DerivedWrite, map[TreePageID][]byte, TreeReplayUsage, error) { return nil, nil, used, err }
	if ctx == nil || budget.Sources == 0 || budget.Sources > 64 || budget.SourceBytes == 0 || budget.SourceBytes > model.MaxChangesetPayload+64*22 || budget.Pages == 0 || budget.Pages > 4096 || budget.PageBytes == 0 || budget.PageBytes > 4096*MaxTreePageBytes || budget.Step.Rewrite.InputBytes == 0 || budget.Step.Rewrite.InputBytes > model.MaxChangesetPayload { return bad(metadata.ErrInvalidArgument) }
	if err := ctx.Err(); err != nil { return bad(err) }
	if len(sources) == 0 { return bad(metadata.ErrInvalidArgument) }
	if uint64(len(sources)) > budget.Sources { return bad(metadata.ErrResourceExhausted) }
	// Reserve the complete source batch before any decoding or tree work.
	for _, source := range sources {
		if err := ctx.Err(); err != nil { return bad(err) }
		n := uint64(len(source.Frame))
		if source.ID.Validate() != nil { return bad(metadata.ErrInvalidArgument) }
		if n > budget.Step.Rewrite.InputBytes+22 || n > budget.SourceBytes-used.SourceBytes { return bad(metadata.ErrResourceExhausted) }
		used.SourceBytes += n
	}
	empty, root, err := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	if err != nil { return bad(err) }
	if uint64(len(empty)) > budget.PageBytes { return bad(metadata.ErrResourceExhausted) }
	pages := map[TreePageID][]byte{root: empty}
	used.Pages, used.PageBytes = 1, uint64(len(empty))
	writes := make([]metadata.DerivedWrite, 0, len(sources))
	var verified map[model.ChangesetID]metadata.DerivedResult
	if completeDAG { verified = make(map[model.ChangesetID]metadata.DerivedResult, len(sources)) }
	for i, source := range sources {
		if err := ctx.Err(); err != nil { return bad(err) }
		used.Sources++
		value, err := model.DecodeChangeset(ctx, bytes.NewReader(source.Frame), source.ID, budget.Step.Rewrite.InputBytes)
		if err != nil { return bad(err) }
		change := value.Snapshot()
		if change.RepoID != repository { return bad(metadata.ErrInvalidArgument) }
		var parent *metadata.DerivedResult
		if completeDAG {
			if _, duplicate := verified[source.ID]; duplicate { return bad(metadata.ErrInvalidArgument) }
			for j, id := range change.Parents {
				if err := ctx.Err(); err != nil { return bad(err) }
				prior, ok := verified[id]
				if !ok { return bad(metadata.ErrFailedPrecondition) }
				if j == 0 { parent = &prior }
			}
		} else if i == 0 {
			if len(change.Parents) != 0 { return bad(metadata.ErrFailedPrecondition) }
		} else {
			if len(change.Parents) == 0 || change.Parents[0] != sources[i-1].ID { return bad(metadata.ErrFailedPrecondition) }
			parent = &writes[i-1].Result
		}
		identity := metadata.DerivedIdentity{Repository: repository, Changeset: source.ID, Kind: "TREE", Version: 1}
		write, added, _, err := PrepareCheckedTreeWrite(ctx, identity, change, parent, pages, blobs, budget.Step)
		if err != nil { return bad(err) }
		// Stage only privately owned new frames. Existing frames were checked
		// against the occupied ID by the rewrite path before it returned.
		for id, frame := range added {
			if err := ctx.Err(); err != nil { return bad(err) }
			if _, exists := pages[id]; exists { continue }
			if used.Pages == budget.Pages || uint64(len(frame)) > budget.PageBytes-used.PageBytes { return bad(metadata.ErrResourceExhausted) }
			used.Pages++; used.PageBytes += uint64(len(frame))
			pages[id] = frame
		}
		writes = append(writes, write)
		if completeDAG { verified[source.ID] = write.Result }
	}
	if err := ctx.Err(); err != nil { return bad(err) }
	return writes, pages, used, nil
}
