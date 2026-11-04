package derived

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
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

func TestTreePageContextLiteralGraphs(t *testing.T) {
	b, err := os.ReadFile("../../tests/fixtures/tree_pages_v1.json")
	if err != nil { t.Fatal(err) }
	var f struct {
		Pages []treeLiteral `json:"pages"`
		Positive []struct { Root string `json:"root_id_hex"` } `json:"positive_vectors"`
		Negative []struct {
			treeLiteral
			Context *struct {
				Directory string `json:"directory_prefix_hex"`
				Component string `json:"component_prefix_hex"`
			} `json:"context"`
		} `json:"negative_vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil { t.Fatal(err) }
	pages := make(map[TreePageID][]byte)
	for _, row := range f.Pages {
		id, err := ParseTreePageID(treeHex(t, row.IDHex))
		if err != nil { t.Fatal(err) }
		pages[id] = treeHex(t, row.FrameHex)
	}
	type visit struct { id TreePageID; directory, component []byte }
	visits := 0
	for _, row := range f.Positive {
		root, err := ParseTreePageID(treeHex(t, row.Root))
		if err != nil { t.Fatal(err) }
		queue := []visit{{id: root}}
		for len(queue) != 0 {
			v := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			visits++
			if visits > 100000 { t.Fatal("fixture traversal exceeded test bound") }
			p, err := DecodeTreePageAt(pages[v.id], v.id, v.directory, v.component)
			if err != nil { t.Fatalf("positive context dir=%d component=%d: %v", len(v.directory), len(v.component), err) }
			encoded, encodedID, err := EncodeTreePageAt(p, v.directory, v.component)
			if err != nil || encodedID != v.id || !bytes.Equal(encoded, pages[v.id]) { t.Fatalf("literal context encoding: %v", err) }
			component := append(append([]byte(nil), v.component...), p.Label...)
			for _, child := range p.Children {
				prefix := append(append([]byte(nil), component...), child.Edge)
				queue = append(queue, visit{child.ID, v.directory, prefix})
			}
			if p.Tag == 4 {
				dir := append([]byte(nil), v.directory...)
				if len(dir) != 0 { dir = append(dir, '/') }
				dir = append(dir, component...)
				queue = append(queue, visit{id: p.Directory, directory: dir})
			}
		}
	}
	checked := 0
	for _, row := range f.Negative {
		if row.Context == nil && row.Reject != "graph:empty_directory_target" { continue }
		var dir, component []byte
		if row.Context != nil {
			dir = treeHex(t, row.Context.Directory)
			component = treeHex(t, row.Context.Component)
		}
		id, err := ParseTreePageID(treeHex(t, row.Claimed))
		if err != nil { t.Fatal(err) }
		if _, err := DecodeTreePageAt(treeHex(t, row.FrameHex), id, dir, component); err != ErrTreePage { t.Fatalf("accepted context %s", row.Name) }
		checked++
	}
	if checked != 9 { t.Fatalf("context negatives: %d", checked) }
}

func TestTreePageContextRejectsMalformedPrefixes(t *testing.T) {
	pages, _, _ := treeFixture(t)
	var frame []byte
	var id TreePageID
	for _, row := range pages {
		candidate := treeHex(t, row.FrameHex)
		if binary.BigEndian.Uint16(candidate[19:21]) == 255 {
			frame = candidate
			var err error
			id, err = ParseTreePageID(treeHex(t, row.IDHex))
			if err != nil { t.Fatal(err) }
			break
		}
	}
	if frame == nil { t.Fatal("missing 255-byte label fixture") }
	for _, tc := range []struct { directory, component []byte }{
		{nil, []byte("a")}, // cap(1)=254, so this label crosses its anchor.
		{nil, []byte("a/b")}, {nil, []byte{0}},
		{[]byte("a/"), nil}, {[]byte("."), nil}, {[]byte("a/../b"), nil},
		{bytes.Repeat([]byte{'a'}, 65536), nil}, {nil, bytes.Repeat([]byte{'a'}, 65536)},
	} {
		if _, err := DecodeTreePageAt(frame, id, tc.directory, tc.component); err != ErrTreePage { t.Fatal("accepted invalid context") }
	}
}

func TestTreePageEncoderRejectsInactiveTargetsAndInvalidShapes(t *testing.T) {
	pages, _, _ := treeFixture(t)
	var page UnlinkedTreePage
	for _, row := range pages {
		id, err := ParseTreePageID(treeHex(t, row.IDHex))
		if err != nil { t.Fatal(err) }
		p, err := DecodeTreePageAt(treeHex(t, row.FrameHex), id, nil, nil)
		if err == nil && p.Tag == 1 && len(p.Children) == 0 {
			page = p
			break
		}
	}
	if page.Tag != 1 { t.Fatal("missing independent leaf fixture") }
	frame, id, err := EncodeTreePageAt(page, nil, nil)
	if err != nil { t.Fatal(err) }
	for _, invalid := range []UnlinkedTreePage{
		{Tag: 0, Blob: page.Blob}, {Tag: 0, Directory: id},
		{Tag: 1, Label: []byte("a"), Blob: page.Blob, Directory: id},
		{Tag: 4, Label: []byte("a"), Blob: page.Blob, Directory: id},
		{Tag: 1, Label: []byte("a")}, {Tag: 4, Label: []byte("a")}, {Tag: 5},
		{Label: bytes.Repeat([]byte{'a'}, 256)}, {Children: make([]TreePageChild, 255)},
		{Tag: 1, Label: []byte("a/b"), Blob: page.Blob},
		{Tag: 1, Label: []byte("."), Blob: page.Blob},
		{Tag: 1, Label: []byte("a"), Blob: page.Blob, Children: []TreePageChild{{Edge: 'b'}}},
		{Tag: 1, Label: []byte("a"), Blob: page.Blob, Children: []TreePageChild{{Edge: 'c', ID: id}, {Edge: 'b', ID: id}}},
		{Tag: 1, Label: []byte("a"), Blob: page.Blob, Children: []TreePageChild{{Edge: 'b', ID: id}, {Edge: 'b', ID: id}}},
	} {
		got, gotID, err := EncodeTreePageAt(invalid, nil, nil)
		if err != ErrTreePage || got != nil || gotID != (TreePageID{}) { t.Fatal("invalid page produced output") }
	}
	original := append([]byte(nil), frame...)
	page.Label[0] ^= 1
	if !bytes.Equal(frame, original) { t.Fatal("encoded frame aliases label") }
	frame[0] ^= 1
	if _, err := DecodeTreePageAt(frame, id, nil, nil); err != ErrTreePage { t.Fatal("changed frame preserved verification") }
	// Empty repository has its unique canonical frame; no empty directory is
	// introduced when the identical empty syntax is supplied below a path.
	empty, emptyID, err := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	if err != nil || hex.EncodeToString(empty) != "43414e4f5059005452454500000101000000050000000000" { t.Fatal("wrong empty encoding") }
	if _, _, err := EncodeTreePageAt(UnlinkedTreePage{}, []byte("dir"), nil); err != ErrTreePage { t.Fatal("encoded empty nonroot") }
	if _, _, err := EncodeTreePageAt(UnlinkedTreePage{Tag: 4, Label: []byte("dir"), Directory: emptyID}, nil, nil); err != ErrTreePage { t.Fatal("encoded empty directory referent") }
}

func graphTestBudget() TreeGraphBudget { return TreeGraphBudget{4096, 4096*MaxTreePageBytes, 64<<20} }

func TestTreeGraphLiteralRootsAndMissing(t *testing.T) {
	b, err := os.ReadFile("../../tests/fixtures/tree_pages_v1.json")
	if err != nil { t.Fatal(err) }
	var f struct {
		Pages []treeLiteral `json:"pages"`
		Positive []struct { Name string `json:"name"`; Root string `json:"root_id_hex"` } `json:"positive_vectors"`
		Negative []struct {
			Name string `json:"name"`
			Root string `json:"graph_root_id_hex"`
			Pages []treeLiteral `json:"graph_pages"`
		} `json:"negative_vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil { t.Fatal(err) }
	makeFrames := func(rows []treeLiteral) map[TreePageID][]byte {
		frames := make(map[TreePageID][]byte)
		for _, row := range rows {
			id, err := ParseTreePageID(treeHex(t, row.IDHex))
			if err != nil { t.Fatal(err) }
			frames[id] = treeHex(t, row.FrameHex)
		}
		return frames
	}
	frames := makeFrames(f.Pages)
	for _, row := range f.Positive {
		id, err := ParseTreePageID(treeHex(t, row.Root))
		if err != nil { t.Fatal(err) }
		used, err := CheckTreePageGraph(context.Background(), id, frames, graphTestBudget())
		// This valid extreme graph needs 81,867,529 cumulative context-copy
		// bytes. Our bounded non-resumable attempt must report exhaustion,
		// not misclassify it as corrupt or claim full graph acceptance.
		if row.Name == "path-length-65535-components-1024" {
			if err != metadata.ErrResourceExhausted || used.ContextBytes > graphTestBudget().ContextBytes { t.Fatalf("large valid graph: %+v %v", used, err) }
			continue
		}
		if err != nil || used.Visits == 0 || used.PageBytes == 0 { t.Fatalf("positive graph: %+v %v", used, err) }
	}
	for _, row := range f.Negative {
		if row.Root == "" { continue }
		id, err := ParseTreePageID(treeHex(t, row.Root))
		if err != nil { t.Fatal(err) }
		want := ErrTreePage
		if row.Name == "missing-directory-referent" { want = ErrTreePageMissing }
		if _, err := CheckTreePageGraph(context.Background(), id, makeFrames(row.Pages), graphTestBudget()); err != want { t.Fatalf("%s: %v", row.Name, err) }
	}
}

type treeCancelContext struct { context.Context; calls int }
func (c *treeCancelContext) Err() error {
	c.calls++
	if c.calls >= 4 { return context.Canceled }
	return nil
}

func TestTreeGraphChargesRepeatedContextsAndBounds(t *testing.T) {
	blob, err := model.NewTypedID(model.BlobKind, [32]byte{1})
	if err != nil { t.Fatal(err) }
	bid, err := model.NewBlobID(blob)
	if err != nil { t.Fatal(err) }
	leaf, leafID, err := EncodeTreePageAt(UnlinkedTreePage{Label: []byte("x"), Tag: 1, Blob: bid}, nil, []byte("a"))
	if err != nil { t.Fatal(err) }
	root, rootID, err := EncodeTreePageAt(UnlinkedTreePage{Children: []TreePageChild{{'a', leafID}, {'b', leafID}}}, nil, nil)
	if err != nil { t.Fatal(err) }
	frames := map[TreePageID][]byte{rootID: root, leafID: leaf}
	used, err := CheckTreePageGraph(context.Background(), rootID, frames, graphTestBudget())
	if err != nil || used.Visits != 3 || used.Terminals != 2 || used.PageBytes != uint64(len(root)+2*len(leaf)) { t.Fatalf("shared contexts: %+v %v", used, err) }
	exact := TreeGraphBudget{used.Visits, used.PageBytes, used.ContextBytes}
	if _, err := CheckTreePageGraph(context.Background(), rootID, frames, exact); err != nil { t.Fatal(err) }
	for dimension := 0; dimension < 3; dimension++ {
		budget := exact
		switch dimension { case 0: budget.Visits--; case 1: budget.PageBytes--; case 2: budget.ContextBytes-- }
		if _, err := CheckTreePageGraph(context.Background(), rootID, frames, budget); err != metadata.ErrResourceExhausted { t.Fatalf("dimension %d: %v", dimension, err) }
	}
	if _, err := CheckTreePageGraph(context.Background(), rootID, frames, TreeGraphBudget{}); err != metadata.ErrInvalidArgument { t.Fatal("accepted zero budget") }
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if used, err := CheckTreePageGraph(cancelled, rootID, frames, exact); err != context.Canceled || used.Visits != 0 { t.Fatal("work after cancellation") }
	if _, err := CheckTreePageGraph(&treeCancelContext{Context: context.Background()}, rootID, frames, exact); err != context.Canceled { t.Fatal("mid-traversal cancellation lost") }
	delete(frames, leafID)
	if _, err := CheckTreePageGraph(context.Background(), rootID, frames, graphTestBudget()); err != ErrTreePageMissing { t.Fatal("missing shared page accepted") }
}

func TestTreeGraphDoesNotDeduplicateDifferentContexts(t *testing.T) {
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1})
	bid, _ := model.NewBlobID(tid)
	// The same frame means a legal z. file in one context and the forbidden
	// dot component a/. in another. The valid context is visited first.
	leaf, leafID, err := EncodeTreePageAt(UnlinkedTreePage{Label: []byte("."), Tag: 1, Blob: bid}, nil, []byte("z"))
	if err != nil { t.Fatal(err) }
	dir, dirID, err := EncodeTreePageAt(UnlinkedTreePage{Tag: 4, Directory: leafID}, nil, []byte("a"))
	if err != nil { t.Fatal(err) }
	root, rootID, err := EncodeTreePageAt(UnlinkedTreePage{Children: []TreePageChild{{'a', dirID}, {'z', leafID}}}, nil, nil)
	if err != nil { t.Fatal(err) }
	frames := map[TreePageID][]byte{rootID: root, dirID: dir, leafID: leaf}
	used, err := CheckTreePageGraph(context.Background(), rootID, frames, graphTestBudget())
	if err != ErrTreePage || used.Visits != 4 { t.Fatalf("second context bypassed: %+v %v", used, err) }
}

func TestReplaceExistingTreeLeafCopiesOnlyPath(t *testing.T) {
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1})
	oldBlob, _ := model.NewBlobID(tid)
	tid, _ = model.NewTypedID(model.BlobKind, [32]byte{2})
	newBlob, _ := model.NewBlobID(tid)
	frames := make(map[TreePageID][]byte)
	encode := func(p UnlinkedTreePage, dir, prefix string) TreePageID {
		b, id, err := EncodeTreePageAt(p, []byte(dir), []byte(prefix))
		if err != nil { t.Fatal(err) }
		frames[id] = b
		return id
	}
	fileID := encode(UnlinkedTreePage{Label: []byte("file"), Tag: 1, Blob: oldBlob}, "dir", "")
	dirID := encode(UnlinkedTreePage{Label: []byte("ir"), Tag: 4, Directory: fileID}, "", "d")
	siblingID := encode(UnlinkedTreePage{Tag: 1, Blob: oldBlob}, "", "z")
	root := encode(UnlinkedTreePage{Children: []TreePageChild{{'d', dirID}, {'z', siblingID}}}, "", "")
	if _, err := CheckTreePageGraph(context.Background(), root, frames, graphTestBudget()); err != nil { t.Fatal(err) }
	original := make(map[TreePageID][]byte)
	for id, frame := range frames { original[id] = append([]byte(nil), frame...) }
	path, _ := model.NewPath([]byte("dir/file"))
	exactBytes := uint64(len(frames[root])+len(frames[dirID])+len(frames[fileID]))
	budget := TreeRewriteBudget{3, exactBytes, exactBytes}
	next, added, err := ReplaceExistingTreeLeaf(context.Background(), root, frames, path, 2, newBlob, budget)
	if err != nil || next == root || len(added) != 3 { t.Fatalf("replace: %d %v", len(added), err) }
	for id, frame := range original { if !bytes.Equal(frame, frames[id]) { t.Fatal("base frame changed") } }
	if _, ok := added[siblingID]; ok { t.Fatal("unrelated subtree rewritten") }
	combined := make(map[TreePageID][]byte)
	for id, frame := range frames { combined[id] = frame }
	for id, frame := range added { combined[id] = frame }
	if _, err := CheckTreePageGraph(context.Background(), next, combined, graphTestBudget()); err != nil { t.Fatal(err) }
	// Reusing already-occupied candidate IDs scans each new frame again.
	// All three comparisons must be admitted, not hidden behind the path read.
	occupiedBudget := budget
	occupiedBudget.ReadBytes = 2*exactBytes
	if got, out, err := ReplaceExistingTreeLeaf(context.Background(), root, combined, path, 2, newBlob, occupiedBudget); err != nil || got != next || len(out) != 0 { t.Fatalf("exact occupied comparison budget: %v", err) }
	occupiedBudget.ReadBytes--
	if got, out, err := ReplaceExistingTreeLeaf(context.Background(), root, combined, path, 2, newBlob, occupiedBudget); err != metadata.ErrResourceExhausted || got != (TreePageID{}) || out != nil { t.Fatalf("occupied read exceeds budget by one: %v", err) }
	if _, _, err := ReplaceExistingTreeLeaf(context.Background(), root, combined, path, 2, newBlob, budget); err != metadata.ErrResourceExhausted { t.Fatal("occupied comparisons bypassed read admission") }
	page, err := DecodeTreePageAt(combined[next], next, nil, nil)
	if err != nil || page.Children[1].ID != siblingID { t.Fatal("unrelated identity lost") }
	dir := page.Children[0].ID
	page, err = DecodeTreePageAt(combined[dir], dir, nil, []byte("d"))
	if err != nil { t.Fatal(err) }
	page, err = DecodeTreePageAt(combined[page.Directory], page.Directory, []byte("dir"), nil)
	if err != nil || page.Tag != 2 || page.Blob != newBlob { t.Fatal("replacement terminal mismatch") }
	same, noFrames, err := ReplaceExistingTreeLeaf(context.Background(), next, combined, path, 2, newBlob, budget)
	if err != nil || same != next || len(noFrames) != 0 { t.Fatal("identical replacement rewrote pages") }
	// Same old frame sizes allow each budget dimension to be tested exactly.
	for dimension := 0; dimension < 3; dimension++ {
		limit := budget
		switch dimension { case 0: limit.Pages--; case 1: limit.ReadBytes--; case 2: limit.WriteBytes-- }
		id, out, err := ReplaceExistingTreeLeaf(context.Background(), root, frames, path, 2, newBlob, limit)
		if err != metadata.ErrResourceExhausted || id != (TreePageID{}) || out != nil { t.Fatalf("budget %d: %v", dimension, err) }
	}
	for _, name := range []string{"dir", "dir/missing", "z/child", "absent"} {
		p, _ := model.NewPath([]byte(name))
		if _, _, err := ReplaceExistingTreeLeaf(context.Background(), root, frames, p, 1, newBlob, budget); err != ErrTreeLeafAbsent { t.Fatalf("path %s: %v", name, err) }
	}
	if _, _, err := ReplaceExistingTreeLeaf(&treeCancelContext{Context: context.Background()}, root, frames, path, 2, newBlob, budget); err != context.Canceled { t.Fatal("cancellation lost") }
	// An occupied new identity with different bytes is corruption, not overwrite.
	frames[next] = []byte("occupied with inconsistent bytes")
	if _, out, err := ReplaceExistingTreeLeaf(context.Background(), root, frames, path, 2, newBlob, budget); err != ErrTreePage || out != nil { t.Fatal("occupied ID overwritten") }
	delete(frames, next)
	delete(frames, fileID)
	if _, _, err := ReplaceExistingTreeLeaf(context.Background(), root, frames, path, 2, newBlob, budget); err != ErrTreePageMissing { t.Fatal("missing path page accepted") }
}

func TestBuildSingleLeafMatchesLiteralRoots(t *testing.T) {
	b, err := os.ReadFile("../../tests/fixtures/tree_pages_v1.json")
	if err != nil { t.Fatal(err) }
	var f struct {
		Pages []treeLiteral `json:"pages"`
		Positive []struct {
			Name string `json:"name"`
			Root string `json:"root_id_hex"`
			PageIDs []string `json:"page_ids"`
			Entries []struct { Path string `json:"path_hex"`; Mode string `json:"mode"`; Payload string `json:"blob_payload_hex"` } `json:"entries"`
		} `json:"positive_vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil { t.Fatal(err) }
	literals := make(map[string][]byte)
	for _, p := range f.Pages { literals[p.IDHex] = treeHex(t, p.FrameHex) }
	checked := 0
	for _, row := range f.Positive {
		if len(row.Entries) != 1 { continue }
		e := row.Entries[0]
		path, err := model.NewPath(treeHex(t, e.Path))
		if err != nil { t.Fatal(err) }
		payload := treeHex(t, e.Payload)
		blob, err := model.HashBlob(context.Background(), uint64(len(payload)), bytes.NewReader(payload))
		if err != nil { t.Fatal(err) }
		var tag byte
		switch e.Mode { case "regular": tag = 1; case "executable": tag = 2; case "symlink": tag = 3; default: t.Fatal("unknown fixture mode") }
		var total uint64
		for _, id := range row.PageIDs { total += uint64(len(literals[id])) }
		budget := TreeBuildBudget{uint64(len(row.PageIDs)), total}
		root, pages, err := BuildSingleLeafTree(context.Background(), path, tag, blob, budget)
		if err != nil { t.Fatalf("%s: %v", row.Name, err) }
		expected, err := ParseTreePageID(treeHex(t, row.Root))
		if err != nil || root != expected || len(pages) != len(row.PageIDs) { t.Fatalf("%s root/count mismatch", row.Name) }
		for _, idHex := range row.PageIDs {
			id, err := ParseTreePageID(treeHex(t, idHex))
			if err != nil || !bytes.Equal(pages[id], literals[idHex]) { t.Fatalf("%s literal page mismatch", row.Name) }
		}
		// Do not claim graph-preflight success for the extreme fixture: that
		// separate helper's cumulative context-copy cap remains unchanged.
		if row.Name != "path-length-65535-components-1024" {
			if _, err := CheckTreePageGraph(context.Background(), root, pages, graphTestBudget()); err != nil { t.Fatal(err) }
		}
		for _, limit := range []TreeBuildBudget{{budget.Pages, budget.Bytes-1}, {budget.Pages-1, budget.Bytes}} {
			want := metadata.ErrResourceExhausted
			if limit.Pages == 0 { want = metadata.ErrInvalidArgument }
			id, pages, err := BuildSingleLeafTree(context.Background(), path, tag, blob, limit)
			if err != want || id != (TreePageID{}) || pages != nil { t.Fatalf("%s bound: %v", row.Name, err) }
		}
		checked++
	}
	if checked != 9 { t.Fatalf("single-leaf fixture count: %d", checked) }
}

func TestBuildSingleLeafModesAndCancellation(t *testing.T) {
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1})
	blob, _ := model.NewBlobID(tid)
	path, _ := model.NewPath([]byte{'d', '/', 0xff})
	budget := TreeBuildBudget{4096, 4096*MaxTreePageBytes}
	seen := make(map[TreePageID]bool)
	for tag := byte(1); tag <= 3; tag++ {
		root, frames, err := BuildSingleLeafTree(context.Background(), path, tag, blob, budget)
		if err != nil || seen[root] { t.Fatal("mode not preserved") }
		seen[root] = true
		if _, err := CheckTreePageGraph(context.Background(), root, frames, graphTestBudget()); err != nil { t.Fatal(err) }
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, out, err := BuildSingleLeafTree(ctx, path, 1, blob, budget); err != context.Canceled || out != nil { t.Fatal("canceled build produced output") }
	if _, out, err := BuildSingleLeafTree(&treeCancelContext{Context: context.Background()}, path, 1, blob, budget); err != context.Canceled || out != nil { t.Fatal("mid-build cancellation lost") }
	if _, _, err := BuildSingleLeafTree(context.Background(), model.Path{}, 1, blob, budget); err != metadata.ErrInvalidArgument { t.Fatal("empty path accepted") }
	if _, _, err := BuildSingleLeafTree(context.Background(), path, 4, blob, budget); err != metadata.ErrInvalidArgument { t.Fatal("directory as file accepted") }
}

func TestSetTreeLeafLiteralPermutations(t *testing.T) {
	b, err := os.ReadFile("../../tests/fixtures/tree_pages_v1.json")
	if err != nil { t.Fatal(err) }
	var f struct {
		Pages []treeLiteral `json:"pages"`
		Positive []struct {
			Name string `json:"name"`
			Root string `json:"root_id_hex"`
			PageIDs []string `json:"page_ids"`
			Entries []struct { Path string `json:"path_hex"`; Mode string `json:"mode"`; Payload string `json:"blob_payload_hex"` } `json:"entries"`
		} `json:"positive_vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil { t.Fatal(err) }
	literals := make(map[string][]byte)
	for _, p := range f.Pages { literals[p.IDHex] = treeHex(t, p.FrameHex) }
	budget := TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}
	for _, row := range f.Positive {
		for _, reverse := range []bool{false, true} {
			empty, root, err := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
			if err != nil { t.Fatal(err) }
			frames := map[TreePageID][]byte{root: empty}
			for j := range row.Entries {
				i := j
				if reverse { i = len(row.Entries)-1-j }
				e := row.Entries[i]
				path, err := model.NewPath(treeHex(t, e.Path))
				if err != nil { t.Fatal(err) }
				payload := treeHex(t, e.Payload)
				blob, err := model.HashBlob(context.Background(), uint64(len(payload)), bytes.NewReader(payload))
				if err != nil { t.Fatal(err) }
				var tag byte
				switch e.Mode { case "regular": tag = 1; case "executable": tag = 2; case "symlink": tag = 3; default: t.Fatal("unknown fixture mode") }
				next, added, err := SetTreeLeaf(context.Background(), root, frames, path, tag, blob, budget)
				if err != nil { t.Fatalf("%s entry %d reverse=%v: %v", row.Name, i, reverse, err) }
				for id, frame := range added {
					if old, ok := frames[id]; ok && !bytes.Equal(old, frame) { t.Fatal("old identity overwritten") }
					frames[id] = frame
				}
				root = next
				same, none, err := SetTreeLeaf(context.Background(), root, frames, path, tag, blob, budget)
				if err != nil || same != root || len(none) != 0 { t.Fatal("identical SET changed identity") }
			}
			expected, err := ParseTreePageID(treeHex(t, row.Root))
			if err != nil || root != expected { t.Fatalf("%s final root differs, reverse=%v", row.Name, reverse) }
			for _, text := range row.PageIDs {
				id, err := ParseTreePageID(treeHex(t, text))
				if err != nil || !bytes.Equal(frames[id], literals[text]) { t.Fatalf("%s final page differs", row.Name) }
			}
		}
	}
}

func TestSetTreeLeafConflictsAndOccupiedBudgets(t *testing.T) {
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1})
	blob, _ := model.NewBlobID(tid)
	budget := TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}
	build := TreeBuildBudget{4096, 4096*MaxTreePageBytes}
	for _, pair := range [][2]string{{"a", "a/b"}, {"a/b", "a"}} {
		basePath, _ := model.NewPath([]byte(pair[0]))
		path, _ := model.NewPath([]byte(pair[1]))
		root, frames, err := BuildSingleLeafTree(context.Background(), basePath, 1, blob, build)
		if err != nil { t.Fatal(err) }
		id, out, err := SetTreeLeaf(context.Background(), root, frames, path, 1, blob, budget)
		if err != metadata.ErrConflict || id != (TreePageID{}) || out != nil { t.Fatal("file ancestor/directory conflict lost") }
	}
	empty, root, err := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	if err != nil { t.Fatal(err) }
	frames := map[TreePageID][]byte{root: empty}
	path, _ := model.NewPath([]byte("new"))
	next, out, err := SetTreeLeaf(context.Background(), root, frames, path, 1, blob, budget)
	if err != nil || len(out) != 1 { t.Fatal(err) }
	for id, frame := range out { frames[id] = frame }
	exact := TreeRewriteBudget{1, uint64(len(empty)+len(frames[next])), uint64(len(frames[next]))}
	if got, out, err := SetTreeLeaf(context.Background(), root, frames, path, 1, blob, exact); err != nil || got != next || len(out) != 0 { t.Fatal("exact occupied read budget failed") }
	exact.ReadBytes--
	if id, out, err := SetTreeLeaf(context.Background(), root, frames, path, 1, blob, exact); err != metadata.ErrResourceExhausted || id != (TreePageID{}) || out != nil { t.Fatal("unadmitted comparison succeeded") }
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if _, out, err := SetTreeLeaf(ctx, root, frames, path, 1, blob, budget); err != context.Canceled || out != nil { t.Fatal("canceled SET returned output") }
	longPath, _ := model.NewPath(bytes.Repeat([]byte{'x'}, 1024))
	if _, out, err := SetTreeLeaf(&treeCancelContext{Context: context.Background()}, root, frames, longPath, 1, blob, budget); err != context.Canceled || out != nil { t.Fatal("mid-SET cancellation lost") }
}

func TestSetTreeLeafSplitPreservesBaseAndAdmitsWrites(t *testing.T) {
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1})
	oldBlob, _ := model.NewBlobID(tid)
	tid, _ = model.NewTypedID(model.BlobKind, [32]byte{2})
	newBlob, _ := model.NewBlobID(tid)
	budget := TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}
	path, _ := model.NewPath([]byte("abc"))
	root, frames, err := BuildSingleLeafTree(context.Background(), path, 1, oldBlob, TreeBuildBudget{4096, 4096*MaxTreePageBytes})
	if err != nil { t.Fatal(err) }
	path, _ = model.NewPath([]byte("abcz"))
	root, added, err := SetTreeLeaf(context.Background(), root, frames, path, 1, oldBlob, budget)
	if err != nil { t.Fatal(err) }
	for id, frame := range added { frames[id] = frame }
	oldPage, err := DecodeTreePageAt(frames[root], root, nil, nil)
	if err != nil || len(oldPage.Children) != 1 { t.Fatal("bad branching base") }
	untouched := oldPage.Children[0].ID
	before := make(map[TreePageID][]byte)
	for id, frame := range frames { before[id] = append([]byte(nil), frame...) }
	path, _ = model.NewPath([]byte("axy"))
	next, produced, err := SetTreeLeaf(context.Background(), root, frames, path, 1, newBlob, budget)
	if err != nil || len(produced) != 3 { t.Fatalf("split output: %d %v", len(produced), err) }
	if _, ok := produced[untouched]; ok { t.Fatal("unrelated continuation rewritten") }
	parent, err := DecodeTreePageAt(produced[next], next, nil, nil)
	if err != nil || len(parent.Children) != 2 || parent.Children[0].Edge != 'b' { t.Fatal("wrong split parent") }
	oldID := parent.Children[0].ID
	oldBranch, err := DecodeTreePageAt(produced[oldID], oldID, nil, []byte("ab"))
	if err != nil || len(oldBranch.Children) != 1 || oldBranch.Children[0].ID != untouched { t.Fatal("split lost unrelated identity") }
	var bytesWritten uint64
	for _, frame := range produced { bytesWritten += uint64(len(frame)) }
	exact := TreeRewriteBudget{3, uint64(len(frames[root])), bytesWritten}
	if got, out, err := SetTreeLeaf(context.Background(), root, frames, path, 1, newBlob, exact); err != nil || got != next || len(out) != 3 { t.Fatalf("exact split budget: %v", err) }
	for _, limit := range []TreeRewriteBudget{{2, exact.ReadBytes, exact.WriteBytes}, {3, exact.ReadBytes, exact.WriteBytes-1}} {
		if id, out, err := SetTreeLeaf(context.Background(), root, frames, path, 1, newBlob, limit); err != metadata.ErrResourceExhausted || id != (TreePageID{}) || out != nil { t.Fatal("split exceeded production budget") }
	}
	for id, original := range before { if !bytes.Equal(frames[id], original) { t.Fatal("SET mutated base input") } }
	if len(frames) != len(before) { t.Fatal("SET changed input map") }
}
