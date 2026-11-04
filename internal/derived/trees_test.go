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
		if _, err := CheckTreePageGraph(context.Background(), root, pages, graphTestBudget()); err != nil { t.Fatal(err) }
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

func TestDeleteTreeLeafLiteralHistories(t *testing.T) {
	b, err := os.ReadFile("../../tests/fixtures/tree_pages_v1.json")
	if err != nil { t.Fatal(err) }
	var f struct {
		Cases []struct {
			Name string `json:"name"`
			Initial []json.RawMessage `json:"initial_entries"`
			Final string `json:"flat_oracle_root_id_hex"`
			Histories []struct {
				Operations []struct { Op string `json:"op"`; Path string `json:"path_hex"`; Mode string `json:"mode"`; Payload string `json:"blob_payload_hex"` } `json:"operations"`
				Checkpoints []struct { Index int `json:"operation_index"`; Root string `json:"root_id_hex"` } `json:"checkpoints"`
			} `json:"histories"`
		} `json:"history_cases"`
	}
	if err := json.Unmarshal(b, &f); err != nil { t.Fatal(err) }
	if len(f.Cases) != 4 { t.Fatal("history coverage changed") }
	budget := TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}
	for _, c := range f.Cases {
		if len(c.Initial) != 0 { t.Fatal("fixture initial entries changed") }
		for _, h := range c.Histories {
			empty, root, err := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
			if err != nil { t.Fatal(err) }
			frames := map[TreePageID][]byte{root: empty}
			for i, op := range h.Operations {
				path, err := model.NewPath(treeHex(t, op.Path))
				if err != nil { t.Fatal(err) }
				var added map[TreePageID][]byte
				switch op.Op {
				case "insert":
					payload := treeHex(t, op.Payload)
					blob, e := model.HashBlob(context.Background(), uint64(len(payload)), bytes.NewReader(payload))
					if e != nil { t.Fatal(e) }
					var tag byte
					switch op.Mode { case "regular": tag = 1; case "executable": tag = 2; case "symlink": tag = 3; default: t.Fatal("unknown mode") }
					root, added, err = SetTreeLeaf(context.Background(), root, frames, path, tag, blob, budget)
				case "delete": root, added, err = DeleteTreeLeaf(context.Background(), root, frames, path, budget)
				default: t.Fatal("unknown operation")
				}
				if err != nil { t.Fatalf("%s operation %d: %v", c.Name, i+1, err) }
				for id, frame := range added {
					if old, ok := frames[id]; ok && !bytes.Equal(old, frame) { t.Fatal("input frame overwritten") }
					frames[id] = frame
				}
				for _, checkpoint := range h.Checkpoints {
					if checkpoint.Index != i+1 { continue }
					want, err := ParseTreePageID(treeHex(t, checkpoint.Root))
					if err != nil || root != want { t.Fatalf("%s checkpoint %d mismatch", c.Name, i+1) }
				}
				if _, err := CheckTreePageGraph(context.Background(), root, frames, graphTestBudget()); err != nil { t.Fatal(err) }
			}
			want, err := ParseTreePageID(treeHex(t, c.Final))
			if err != nil || root != want { t.Fatalf("%s final root mismatch", c.Name) }
		}
	}
}

func TestDeleteTreeLeafNormalizationBudgetsAndNoops(t *testing.T) {
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1})
	blob, _ := model.NewBlobID(tid)
	pathAB, _ := model.NewPath([]byte("ab"))
	pathA, _ := model.NewPath([]byte("a"))
	originalRoot, frames, err := BuildSingleLeafTree(context.Background(), pathAB, 1, blob, TreeBuildBudget{4096, 4096*MaxTreePageBytes})
	if err != nil { t.Fatal(err) }
	budget := TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}
	root, added, err := SetTreeLeaf(context.Background(), originalRoot, frames, pathA, 1, blob, budget)
	if err != nil { t.Fatal(err) }
	for id, frame := range added { frames[id] = frame }
	p, err := DecodeTreePageAt(frames[root], root, nil, nil)
	if err != nil || len(p.Children) != 1 { t.Fatal("bad prefix fixture") }
	before := make(map[TreePageID][]byte)
	for id, frame := range frames { before[id] = append([]byte(nil), frame...) }
	// Read the target, fetch its sole child for normalization, then compare
	// the normalized root against its already-occupied identity.
	exact := TreeRewriteBudget{2, uint64(len(frames[root])+len(frames[p.Children[0].ID])+len(frames[originalRoot])), uint64(len(frames[originalRoot]))}
	if got, out, err := DeleteTreeLeaf(context.Background(), root, frames, pathA, exact); err != nil || got != originalRoot || len(out) != 0 { t.Fatalf("exact normalization: %v", err) }
	for _, limit := range []TreeRewriteBudget{{1, exact.ReadBytes, exact.WriteBytes}, {2, exact.ReadBytes-1, exact.WriteBytes}, {2, exact.ReadBytes, exact.WriteBytes-1}} {
		if id, out, err := DeleteTreeLeaf(context.Background(), root, frames, pathA, limit); err != metadata.ErrResourceExhausted || id != (TreePageID{}) || out != nil { t.Fatal("normalization exceeded budget") }
	}
	for _, name := range []string{"absent", "a/child"} {
		path, _ := model.NewPath([]byte(name))
		if got, out, err := DeleteTreeLeaf(context.Background(), root, frames, path, budget); err != nil || got != root || len(out) != 0 { t.Fatal("absent deletion changed root") }
	}
	if _, out, err := DeleteTreeLeaf(&treeCancelContext{Context: context.Background()}, root, frames, pathA, budget); err != context.Canceled || out != nil { t.Fatal("mid-normalization cancellation lost") }
	for id, frame := range before { if !bytes.Equal(frames[id], frame) { t.Fatal("delete mutated input") } }
	dirPath, _ := model.NewPath([]byte("dir/file"))
	dirRoot, dirFrames, err := BuildSingleLeafTree(context.Background(), dirPath, 1, blob, TreeBuildBudget{4096, 4096*MaxTreePageBytes})
	if err != nil { t.Fatal(err) }
	directory, _ := model.NewPath([]byte("dir"))
	if got, out, err := DeleteTreeLeaf(context.Background(), dirRoot, dirFrames, directory, budget); err != nil || got != dirRoot || len(out) != 0 { t.Fatal("directory path deleted recursively") }
}

func TestApplyTreeChangesetLiteralDeltas(t *testing.T) {
	b, err := os.ReadFile("../../tests/fixtures/tree_pages_v1.json")
	if err != nil { t.Fatal(err) }
	type entry struct { Op string `json:"op"`; Path string `json:"path_hex"`; Mode string `json:"mode"`; Payload string `json:"blob_payload_hex"` }
	var f struct { Cases []struct { Name string `json:"name"`; Initial []entry `json:"initial_entries"`; Operations []entry `json:"operations"`; Root string `json:"expected_root_id_hex"`; Reject string `json:"expected_reject"` } `json:"delta_cases"` }
	if err := json.Unmarshal(b, &f); err != nil { t.Fatal(err) }
	if len(f.Cases) != 5 { t.Fatal("delta coverage changed") }
	budget := TreeChangesetBudget{TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}, 4096, model.MaxChangesetPayload}
	tid, _ := model.NewTypedID(model.ChangesetKind, [32]byte{1})
	parent, _ := model.NewChangesetID(tid)
	operation := func(e entry) model.Operation {
		path, err := model.NewPath(treeHex(t, e.Path))
		if err != nil { t.Fatal(err) }
		var tag model.OperationTag
		var target *model.BlobID
		if e.Op != "delete" {
			payload := treeHex(t, e.Payload)
			blob, err := model.HashBlob(context.Background(), uint64(len(payload)), bytes.NewReader(payload))
			if err != nil { t.Fatal(err) }
			target = &blob
			switch e.Mode { case "regular": tag = model.SetRegular; case "executable": tag = model.SetExecutable; case "symlink": tag = model.SetSymlink; default: t.Fatal("unknown mode") }
		}
		op, err := model.NewOperation(path, tag, target)
		if err != nil { t.Fatal(err) }
		return op
	}
	for _, c := range f.Cases {
		empty, root, err := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
		if err != nil { t.Fatal(err) }
		frames := map[TreePageID][]byte{root: empty}
		for _, e := range c.Initial {
			op := operation(e)
			blob, _ := op.Target()
			next, added, err := SetTreeLeaf(context.Background(), root, frames, op.Path(), byte(op.Tag()), blob, budget.Rewrite)
			if err != nil { t.Fatal(err) }
			for id, frame := range added { frames[id] = frame }
			root = next
		}
		before := make(map[TreePageID][]byte)
		for id, frame := range frames { before[id] = append([]byte(nil), frame...) }
		change := model.ChangesetInput{}
		if len(c.Initial) != 0 { change.Parents = []model.ChangesetID{parent} }
		for _, e := range c.Operations { change.Operations = append(change.Operations, operation(e)) }
		next, added, err := ApplyTreeChangeset(context.Background(), root, frames, change, budget)
		if c.Reject != "" {
			if err != metadata.ErrConflict || next != (TreePageID{}) || added != nil { t.Fatalf("%s did not reject atomically: %v", c.Name, err) }
		} else {
			want, e := ParseTreePageID(treeHex(t, c.Root))
			if err != nil || e != nil || next != want { t.Fatalf("%s final root: %v", c.Name, err) }
		}
		if len(frames) != len(before) { t.Fatal("batch changed input map") }
		for id, frame := range before { if !bytes.Equal(frames[id], frame) { t.Fatal("batch mutated input bytes") } }
	}
}

func TestApplyTreeChangesetCumulativeBudgetAndValidation(t *testing.T) {
	empty, root, err := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	if err != nil { t.Fatal(err) }
	frames := map[TreePageID][]byte{root: empty}
	pa, _ := model.NewPath([]byte("a")); pb, _ := model.NewPath([]byte("b"))
	da, _ := model.NewOperation(pa, model.Delete, nil); db, _ := model.NewOperation(pb, model.Delete, nil)
	change := model.ChangesetInput{Operations: []model.Operation{da, db}}
	budget := TreeChangesetBudget{TreeRewriteBudget{2, 48, 1}, 2, model.MaxChangesetPayload}
	if got, out, err := ApplyTreeChangeset(context.Background(), root, frames, change, budget); err != nil || got != root || len(out) != 0 { t.Fatal("exact cumulative no-op budget failed") }
	inputSize, err := model.ValidateChangeset(change)
	if err != nil { t.Fatal(err) }
	inputLimit := budget; inputLimit.InputBytes = inputSize
	if _, _, err := ApplyTreeChangeset(context.Background(), root, frames, change, inputLimit); err != nil { t.Fatal("exact input byte budget failed") }
	inputLimit.InputBytes--
	if _, out, err := ApplyTreeChangeset(context.Background(), root, frames, change, inputLimit); err != metadata.ErrResourceExhausted || out != nil { t.Fatal("input byte overflow accepted") }
	inputLimit = budget; inputLimit.Operations = 1
	if _, out, err := ApplyTreeChangeset(context.Background(), root, frames, change, inputLimit); err != metadata.ErrResourceExhausted || out != nil { t.Fatal("operation count overflow accepted") }
	for _, limit := range []TreeRewriteBudget{{1, 48, 1}, {2, 47, 1}} {
		b := budget; b.Rewrite = limit
		if got, out, err := ApplyTreeChangeset(context.Background(), root, frames, change, b); err != metadata.ErrResourceExhausted || got != (TreePageID{}) || out != nil { t.Fatal("read budget reset between operations") }
	}
	for _, ops := range [][]model.Operation{{db, da}, {da, da}, {{}}} {
		invalid := model.ChangesetInput{Operations: ops}
		if _, _, err := ApplyTreeChangeset(context.Background(), root, frames, invalid, budget); err != metadata.ErrInvalidArgument { t.Fatal("noncanonical delta accepted") }
	}
	var ops []model.Operation
	for i, path := range []model.Path{pa, pb} {
		tid, _ := model.NewTypedID(model.BlobKind, [32]byte{byte(i+1)})
		blob, _ := model.NewBlobID(tid)
		op, _ := model.NewOperation(path, model.SetRegular, &blob)
		ops = append(ops, op)
	}
	change.Operations = ops
	// First SET: one 60-byte frame. Second: two 59-byte suffixes and a
	// 104-byte branch. Reads are the 24-byte empty root then 60-byte leaf.
	budget.Rewrite = TreeRewriteBudget{4, 84, 282}
	got, out, err := ApplyTreeChangeset(context.Background(), root, frames, change, budget)
	if err != nil || got == root || len(out) != 4 { t.Fatalf("exact cumulative writes: %v", err) }
	for _, limit := range []TreeRewriteBudget{{3, 84, 282}, {4, 84, 281}} {
		b := budget; b.Rewrite = limit
		if got, out, err := ApplyTreeChangeset(context.Background(), root, frames, change, b); err != metadata.ErrResourceExhausted || got != (TreePageID{}) || out != nil { t.Fatal("write budget reset between operations") }
	}
	if _, out, err := ApplyTreeChangeset(&treeCancelContext{Context: context.Background()}, root, frames, change, budget); err != context.Canceled || out != nil { t.Fatal("batch cancellation lost") }
	if _, _, err := ApplyTreeChangeset(context.Background(), got, out, model.ChangesetInput{}, budget); err != metadata.ErrInvalidArgument { t.Fatal("parentless change accepted nonempty base") }
}

func TestApplyTreeChangesetDeleteThenSetBudgetAtomicity(t *testing.T) {
	pa, _ := model.NewPath([]byte("a")); pb, _ := model.NewPath([]byte("b"))
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1})
	blob, _ := model.NewBlobID(tid)
	root, frames, err := BuildSingleLeafTree(context.Background(), pa, 1, blob, TreeBuildBudget{1, 60})
	if err != nil { t.Fatal(err) }
	before := append([]byte(nil), frames[root]...)
	parentID, _ := model.NewTypedID(model.ChangesetKind, [32]byte{1})
	parent, _ := model.NewChangesetID(parentID)
	deleteA, _ := model.NewOperation(pa, model.Delete, nil)
	setB, _ := model.NewOperation(pb, model.SetRegular, &blob)
	change := model.ChangesetInput{Parents: []model.ChangesetID{parent}, Operations: []model.Operation{deleteA, setB}}
	// DELETE reads the 60-byte leaf and writes the 24-byte empty root.
	// SET then reads that staged empty root and writes a new 60-byte leaf.
	budget := TreeChangesetBudget{TreeRewriteBudget{2, 84, 84}, 2, model.MaxChangesetPayload}
	want, _, err := BuildSingleLeafTree(context.Background(), pb, 1, blob, TreeBuildBudget{1, 60})
	if err != nil { t.Fatal(err) }
	if got, out, err := ApplyTreeChangeset(context.Background(), root, frames, change, budget); err != nil || got != want || len(out) != 2 { t.Fatalf("exact cross-phase budget: %v", err) }
	budget.Rewrite.WriteBytes--
	if got, out, err := ApplyTreeChangeset(context.Background(), root, frames, change, budget); err != metadata.ErrResourceExhausted || got != (TreePageID{}) || out != nil { t.Fatal("failed SET exposed successful DELETE") }
	if len(frames) != 1 || !bytes.Equal(frames[root], before) { t.Fatal("cross-phase failure mutated trusted base") }
}

func treeBindingIdentity(t *testing.T, change model.ChangesetInput) metadata.DerivedIdentity {
	t.Helper()
	value, err := model.NewChangeset(change)
	if err != nil { t.Fatal(err) }
	id, err := model.HashChangeset(context.Background(), value)
	if err != nil { t.Fatal(err) }
	return metadata.DerivedIdentity{Repository: change.RepoID, Changeset: id, Kind: "TREE", Version: 1}
}

func TestPrepareTreeWriteRootAndSourceBinding(t *testing.T) {
	empty, root, err := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	if err != nil { t.Fatal(err) }
	frames := map[TreePageID][]byte{root: empty}
	change := model.ChangesetInput{RepoID: [16]byte{1}}
	identity := treeBindingIdentity(t, change)
	budget := TreeChangesetBudget{TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}, 4096, model.MaxChangesetPayload}
	candidate, out, err := PrepareTreeWrite(context.Background(), identity, change, nil, frames, budget)
	if err != nil || candidate.Validate() != nil || candidate.Result.Identity != identity || candidate.Parents != nil || out != nil { t.Fatalf("root candidate: %v", err) }
	raw, _ := root.MarshalBinary()
	if !bytes.Equal(candidate.Result.Value.Bytes(), raw) { t.Fatal("root was not the literal empty tree") }
	bad := func(key metadata.DerivedIdentity, input model.ChangesetInput, parent *metadata.DerivedResult, limits TreeChangesetBudget, want error) {
		t.Helper()
		got, out, err := PrepareTreeWrite(context.Background(), key, input, parent, frames, limits)
		if err != want || got.Result != (metadata.DerivedResult{}) || got.Parents != nil || out != nil { t.Fatalf("failed binding leaked candidate: %v, want %v", err, want) }
	}
	for _, key := range []metadata.DerivedIdentity{
		{Repository: [16]byte{2}, Changeset: identity.Changeset, Kind: "TREE", Version: 1},
		{Repository: identity.Repository, Changeset: identity.Changeset, Kind: "tree-index", Version: 1},
		{Repository: identity.Repository, Changeset: identity.Changeset, Kind: "TREE", Version: 2},
		{},
	} { bad(key, change, nil, budget, metadata.ErrInvalidArgument) }
	changed := change; changed.Message = []byte("changed")
	bad(identity, changed, nil, budget, metadata.ErrCorruptData)
	bad(identity, change, &candidate.Result, budget, metadata.ErrInvalidArgument)
	size, err := model.ValidateChangeset(change)
	if err != nil { t.Fatal(err) }
	budget.InputBytes = size
	if _, _, err := PrepareTreeWrite(context.Background(), identity, change, nil, frames, budget); err != nil { t.Fatal("exact source budget rejected") }
	budget.InputBytes--
	bad(identity, change, nil, budget, metadata.ErrResourceExhausted)
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if got, out, err := PrepareTreeWrite(ctx, identity, change, nil, frames, budget); err != context.Canceled || got.Result != (metadata.DerivedResult{}) || out != nil { t.Fatal("cancellation lost") }
}

func TestPrepareTreeWriteExactParentZeroAndPrivateDelta(t *testing.T) {
	path, _ := model.NewPath([]byte("a"))
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1})
	blob, _ := model.NewBlobID(tid)
	root, frames, err := BuildSingleLeafTree(context.Background(), path, 1, blob, TreeBuildBudget{1, 60})
	if err != nil { t.Fatal(err) }
	before := append([]byte(nil), frames[root]...)
	var ids []model.ChangesetID
	for _, n := range []byte{1, 2} {
		tid, _ := model.NewTypedID(model.ChangesetKind, [32]byte{n})
		id, _ := model.NewChangesetID(tid); ids = append(ids, id)
	}
	op, _ := model.NewOperation(path, model.Delete, nil)
	change := model.ChangesetInput{RepoID: [16]byte{1}, Parents: ids, Operations: []model.Operation{op}}
	identity := treeBindingIdentity(t, change)
	raw, _ := root.MarshalBinary(); value, _ := metadata.NewDerivedValueID(raw)
	parent := metadata.DerivedResult{Identity: metadata.DerivedIdentity{Repository: change.RepoID, Changeset: ids[0], Kind: "TREE", Version: 1}, Value: value}
	budget := TreeChangesetBudget{TreeRewriteBudget{1, 60, 24}, 1, model.MaxChangesetPayload}
	candidate, out, err := PrepareTreeWrite(context.Background(), identity, change, &parent, frames, budget)
	if err != nil || len(out) != 1 || len(candidate.Parents) != 1 || candidate.Parents[0] != parent { t.Fatalf("parent-zero computation: %v", err) }
	_, emptyRoot, _ := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	emptyRaw, _ := emptyRoot.MarshalBinary()
	if !bytes.Equal(candidate.Result.Value.Bytes(), emptyRaw) { t.Fatal("DELETE did not compute empty root") }
	// Only parent zero is a tree dependency; the second parent's identity is
	// still covered by the canonical source hash but is not a union input.
	second := parent; second.Identity.Changeset = ids[1]
	wrongRepo := parent; wrongRepo.Identity.Repository[0]++
	wrongKind := parent; wrongKind.Identity.Kind = "other"
	wrongVersion := parent; wrongVersion.Identity.Version++
	wrongValue := parent; wrongValue.Value = metadata.DerivedValueID{}
	for _, p := range []*metadata.DerivedResult{nil, &second, &wrongRepo, &wrongKind, &wrongVersion, &wrongValue} {
		want := metadata.ErrInvalidArgument
		if p == nil { want = metadata.ErrFailedPrecondition }
		got, out, err := PrepareTreeWrite(context.Background(), identity, change, p, frames, budget)
		if err != want || got.Result != (metadata.DerivedResult{}) || got.Parents != nil || out != nil { t.Fatalf("parent substitution accepted: %v", err) }
	}
	budget.Rewrite.WriteBytes--
	if got, out, err := PrepareTreeWrite(context.Background(), identity, change, &parent, frames, budget); err != metadata.ErrResourceExhausted || got.Result != (metadata.DerivedResult{}) || out != nil { t.Fatal("failed private delta exposed binding") }
	parent.Identity.Version++
	if candidate.Parents[0].Identity.Version != 1 { t.Fatal("candidate retained mutable parent pointer") }
	if len(frames) != 1 || !bytes.Equal(frames[root], before) { t.Fatal("binding mutated caller graph") }
}

func TestReadTreeEntriesLiteralMaps(t *testing.T) {
	b, err := os.ReadFile("../../tests/fixtures/tree_pages_v1.json")
	if err != nil { t.Fatal(err) }
	var f struct {
		Pages []treeLiteral `json:"pages"`
		Positive []struct {
			Name string `json:"name"`; Root string `json:"root_id_hex"`
			Entries []struct { Path string `json:"path_hex"`; Mode string `json:"mode"`; Payload string `json:"blob_payload_hex"` } `json:"entries"`
		} `json:"positive_vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil { t.Fatal(err) }
	if len(f.Positive) != 15 { t.Fatal("literal map coverage changed") }
	frames := make(map[TreePageID][]byte)
	for _, p := range f.Pages {
		id, err := ParseTreePageID(treeHex(t, p.IDHex)); if err != nil { t.Fatal(err) }
		frames[id] = treeHex(t, p.FrameHex)
	}
	budget := TreeEntriesBudget{graphTestBudget(), 4096, 64<<20}
	for _, c := range f.Positive {
		root, err := ParseTreePageID(treeHex(t, c.Root)); if err != nil { t.Fatal(err) }
		rows, _, err := ReadTreeEntries(context.Background(), root, frames, budget)
		if err != nil || len(rows) != len(c.Entries) { t.Fatalf("%s enumeration: %v", c.Name, err) }
		for i, e := range c.Entries {
			if !bytes.Equal(rows[i].Path().Bytes(), treeHex(t, e.Path)) { t.Fatalf("%s path/order mismatch", c.Name) }
			payload := treeHex(t, e.Payload)
			blob, err := model.HashBlob(context.Background(), uint64(len(payload)), bytes.NewReader(payload)); if err != nil { t.Fatal(err) }
			got, ok := rows[i].Target()
			var tag model.OperationTag
			switch e.Mode { case "regular": tag = model.SetRegular; case "executable": tag = model.SetExecutable; case "symlink": tag = model.SetSymlink; default: t.Fatal("unknown mode") }
			if !ok || got != blob || rows[i].Tag() != tag { t.Fatal("mode/target mismatch") }
		}
	}
}

func TestReadTreeEntriesBudgetsSharedPagesAndNoPartial(t *testing.T) {
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1}); blob, _ := model.NewBlobID(tid)
	leaf, leafID, err := EncodeTreePageAt(UnlinkedTreePage{Label: []byte("x"), Tag: 1, Blob: blob}, nil, []byte("a"))
	if err != nil { t.Fatal(err) }
	frame, root, err := EncodeTreePageAt(UnlinkedTreePage{Children: []TreePageChild{{Edge: 'a', ID: leafID}, {Edge: 'b', ID: leafID}}}, nil, nil)
	if err != nil { t.Fatal(err) }
	frames := map[TreePageID][]byte{root: frame, leafID: leaf}
	// Every shared context counts: root plus two visits to the same leaf.
	// Paths ax and bx each charge a two-byte assembly and owned copy.
	budget := TreeEntriesBudget{graphTestBudget(), 2, 8}
	budget.Graph.Visits = 3; budget.Graph.PageBytes = uint64(len(frame)+2*len(leaf))
	rows, used, err := ReadTreeEntries(context.Background(), root, frames, budget)
	if err != nil || len(rows) != 2 || used.Visits != 3 || string(rows[0].Path().Bytes()) != "ax" || string(rows[1].Path().Bytes()) != "bx" { t.Fatalf("shared contexts: %+v %v", used, err) }
	for _, kind := range []string{"entries", "paths", "visits", "page-bytes"} {
		b := budget
		switch kind { case "entries": b.Entries--; case "paths": b.PathBytes--; case "visits": b.Graph.Visits--; case "page-bytes": b.Graph.PageBytes-- }
		if rows, _, err := ReadTreeEntries(context.Background(), root, frames, b); err != metadata.ErrResourceExhausted || rows != nil { t.Fatalf("%s leaked partial output", kind) }
	}
	if rows, _, err := ReadTreeEntries(&treeCancelContext{Context: context.Background()}, root, frames, budget); err != context.Canceled || rows != nil { t.Fatal("enumeration cancellation lost") }
	missing := map[TreePageID][]byte{root: frame}
	if rows, _, err := ReadTreeEntries(context.Background(), root, missing, budget); err != ErrTreePageMissing || rows != nil { t.Fatal("missing referent treated as absence") }
	corrupt := append([]byte(nil), leaf...); corrupt[len(corrupt)-1] ^= 1
	if rows, _, err := ReadTreeEntries(context.Background(), root, map[TreePageID][]byte{root: frame, leafID: corrupt}, budget); err != ErrTreePage || rows != nil { t.Fatal("corrupt leaf admitted") }
	owned := rows[0].Path().Bytes(); owned[0] = 'z'
	if string(rows[0].Path().Bytes()) != "ax" { t.Fatal("returned path leaked ownership") }
}

func TestReadTreeEntriesDirectoryOrder(t *testing.T) {
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1}); blob, _ := model.NewBlobID(tid)
	empty, root, _ := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	frames := map[TreePageID][]byte{root: empty}
	// '/' sorts between '.' and '0'; neither unconditional directory-first
	// nor directory-last traversal is the required raw-byte order.
	want := []string{"a.", "a/b", "a0"}
	for _, name := range want {
		path, _ := model.NewPath([]byte(name))
		next, added, err := SetTreeLeaf(context.Background(), root, frames, path, 1, blob, TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes})
		if err != nil { t.Fatal(err) }
		for id, frame := range added { frames[id] = frame }; root = next
	}
	rows, _, err := ReadTreeEntries(context.Background(), root, frames, TreeEntriesBudget{graphTestBudget(), 3, 64})
	if err != nil || len(rows) != len(want) { t.Fatalf("directory enumeration: %v", err) }
	for i, name := range want { if string(rows[i].Path().Bytes()) != name { t.Fatal("directory/continuation ordering incorrect") } }
}

func TestReadTreeEntriesDiscardsLeafBeforeMissingReferent(t *testing.T) {
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1}); blob, _ := model.NewBlobID(tid)
	leaf, leafID, err := EncodeTreePageAt(UnlinkedTreePage{Label: []byte("x"), Tag: 1, Blob: blob}, nil, []byte("b"))
	if err != nil { t.Fatal(err) }
	_, missingID, err := EncodeTreePageAt(UnlinkedTreePage{Label: []byte("y"), Tag: 1, Blob: blob}, nil, []byte("a"))
	if err != nil { t.Fatal(err) }
	frame, root, err := EncodeTreePageAt(UnlinkedTreePage{Children: []TreePageChild{{Edge: 'a', ID: missingID}, {Edge: 'b', ID: leafID}}}, nil, nil)
	if err != nil { t.Fatal(err) }
	// The LIFO walker collects bx first, then discovers the missing ay page.
	// Visits/terminal usage confirms the failure is after a collected leaf.
	rows, used, err := ReadTreeEntries(context.Background(), root, map[TreePageID][]byte{root: frame, leafID: leaf}, TreeEntriesBudget{graphTestBudget(), 2, 8})
	if err != ErrTreePageMissing || rows != nil || used.Visits != 3 || used.Terminals != 1 { t.Fatalf("late missing referent leaked rows: %+v %v", used, err) }
}

func TestLookupTreeLeafLiteralPaths(t *testing.T) {
	b, err := os.ReadFile("../../tests/fixtures/tree_pages_v1.json"); if err != nil { t.Fatal(err) }
	var f struct {
		Pages []treeLiteral `json:"pages"`
		Positive []struct {
			Name string `json:"name"`; Root string `json:"root_id_hex"`
			Entries []struct { Path string `json:"path_hex"`; Mode string `json:"mode"`; Payload string `json:"blob_payload_hex"` } `json:"entries"`
		} `json:"positive_vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil { t.Fatal(err) }
	if len(f.Positive) != 15 { t.Fatal("lookup fixture coverage changed") }
	frames := make(map[TreePageID][]byte)
	for _, p := range f.Pages {
		id, err := ParseTreePageID(treeHex(t, p.IDHex)); if err != nil { t.Fatal(err) }
		frames[id] = treeHex(t, p.FrameHex)
	}
	budget := TreeLookupBudget{4096, 4096*MaxTreePageBytes}
	for _, c := range f.Positive {
		root, err := ParseTreePageID(treeHex(t, c.Root)); if err != nil { t.Fatal(err) }
		if len(c.Entries) == 0 {
			path, _ := model.NewPath([]byte("absent"))
			if row, used, err := LookupTreeLeaf(context.Background(), root, frames, path, budget); err != ErrTreeLeafAbsent || row != (model.Operation{}) || used.Pages != 1 || used.ReadBytes != 24 { t.Fatal("empty-root lookup") }
		}
		for _, e := range c.Entries {
			path, err := model.NewPath(treeHex(t, e.Path)); if err != nil { t.Fatal(err) }
			row, used, err := LookupTreeLeaf(context.Background(), root, frames, path, budget)
			if err != nil || row.Path().Compare(path) != 0 || used.Pages == 0 { t.Fatalf("%s lookup: %v", c.Name, err) }
			payload := treeHex(t, e.Payload)
			blob, err := model.HashBlob(context.Background(), uint64(len(payload)), bytes.NewReader(payload)); if err != nil { t.Fatal(err) }
			var tag model.OperationTag
			switch e.Mode { case "regular": tag = model.SetRegular; case "executable": tag = model.SetExecutable; case "symlink": tag = model.SetSymlink; default: t.Fatal("unknown mode") }
			got, ok := row.Target()
			if !ok || got != blob || row.Tag() != tag { t.Fatal("lookup mode/target mismatch") }
			if again, exact, err := LookupTreeLeaf(context.Background(), root, frames, path, TreeLookupBudget{used.Pages, used.ReadBytes}); err != nil || again != row || exact != used { t.Fatal("exact lookup budget rejected") }
			if got, _, err := LookupTreeLeaf(context.Background(), root, frames, path, TreeLookupBudget{used.Pages, used.ReadBytes-1}); err != metadata.ErrResourceExhausted || got != (model.Operation{}) { t.Fatal("lookup byte budget exceeded") }
		}
	}
}

func TestLookupTreeLeafPrivatePathOnlyAndFailures(t *testing.T) {
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1}); blob, _ := model.NewBlobID(tid)
	leaf, leafID, err := EncodeTreePageAt(UnlinkedTreePage{Label: []byte("x"), Tag: 3, Blob: blob}, nil, []byte("b"))
	if err != nil { t.Fatal(err) }
	_, missingID, err := EncodeTreePageAt(UnlinkedTreePage{Label: []byte("y"), Tag: 1, Blob: blob}, nil, []byte("a"))
	if err != nil { t.Fatal(err) }
	frame, root, err := EncodeTreePageAt(UnlinkedTreePage{Children: []TreePageChild{{Edge: 'a', ID: missingID}, {Edge: 'b', ID: leafID}}}, nil, nil)
	if err != nil { t.Fatal(err) }
	frames := map[TreePageID][]byte{root: frame, leafID: leaf}
	path, _ := model.NewPath([]byte("bx"))
	budget := TreeLookupBudget{2, uint64(len(frame)+len(leaf))}
	row, used, err := LookupTreeLeaf(context.Background(), root, frames, path, budget)
	// The trusted-base precondition is external: unrelated missing pages are
	// not fetched, so this success is NOT evidence of complete graph validity.
	if err != nil || row.Tag() != model.SetSymlink || used.Pages != 2 || used.ReadBytes != budget.ReadBytes { t.Fatal("point lookup traversed unrelated subtree") }
	if got, _, err := LookupTreeLeaf(context.Background(), root, frames, path, TreeLookupBudget{1, budget.ReadBytes}); err != metadata.ErrResourceExhausted || got != (model.Operation{}) { t.Fatal("lookup page budget exceeded") }
	missing, _ := model.NewPath([]byte("ay"))
	if got, _, err := LookupTreeLeaf(context.Background(), root, frames, missing, budget); err != ErrTreePageMissing || got != (model.Operation{}) { t.Fatal("missing page became absent leaf") }
	for _, name := range []string{"b", "bz", "c", "bx/child"} {
		p, _ := model.NewPath([]byte(name))
		if got, _, err := LookupTreeLeaf(context.Background(), root, frames, p, budget); err != ErrTreeLeafAbsent || got != (model.Operation{}) { t.Fatalf("unexpected presence for %s: %v", name, err) }
	}
	corrupt := append([]byte(nil), leaf...); corrupt[len(corrupt)-1] ^= 1
	if got, _, err := LookupTreeLeaf(context.Background(), root, map[TreePageID][]byte{root: frame, leafID: corrupt}, path, budget); err != ErrTreePage || got != (model.Operation{}) { t.Fatal("corrupt lookup admitted") }
	if got, _, err := LookupTreeLeaf(&treeCancelContext{Context: context.Background()}, root, frames, path, budget); err != context.Canceled || got != (model.Operation{}) { t.Fatal("mid-lookup cancellation lost") }
	dirPath, _ := model.NewPath([]byte("dir/file"))
	dirRoot, dirFrames, err := BuildSingleLeafTree(context.Background(), dirPath, 1, blob, TreeBuildBudget{2, 256}); if err != nil { t.Fatal(err) }
	dir, _ := model.NewPath([]byte("dir"))
	if got, _, err := LookupTreeLeaf(context.Background(), dirRoot, dirFrames, dir, TreeLookupBudget{2, 256}); err != ErrTreeLeafAbsent || got != (model.Operation{}) { t.Fatal("implicit directory exposed as file") }
}

func TestTreeGraphExtremeContextBufferBudget(t *testing.T) {
	b, err := os.ReadFile("../../tests/fixtures/tree_pages_v1.json"); if err != nil { t.Fatal(err) }
	var f struct {
		Pages []treeLiteral `json:"pages"`
		Positive []struct { Name string `json:"name"`; Root string `json:"root_id_hex"` } `json:"positive_vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil { t.Fatal(err) }
	frames := make(map[TreePageID][]byte)
	for _, p := range f.Pages {
		id, err := ParseTreePageID(treeHex(t, p.IDHex)); if err != nil { t.Fatal(err) }
		frames[id] = treeHex(t, p.FrameHex)
	}
	checked := 0
	for _, c := range f.Positive {
		if c.Name != "component-length-65535" && c.Name != "path-length-65535-components-1024" { continue }
		checked++
		root, err := ParseTreePageID(treeHex(t, c.Root)); if err != nil { t.Fatal(err) }
		budget := graphTestBudget(); budget.ContextBytes = 194302
		used, err := CheckTreePageGraph(context.Background(), root, frames, budget)
		if err != nil || used.ContextBytes != budget.ContextBytes { t.Fatalf("exact growth-copy budget: %+v %v", used, err) }
		budget.ContextBytes--
		if rows, used, err := ReadTreeEntries(context.Background(), root, frames, TreeEntriesBudget{budget, 1, 2*model.MaxPathBytes}); err != metadata.ErrResourceExhausted || rows != nil || used.ContextBytes > budget.ContextBytes { t.Fatal("context growth exceeded budget or leaked rows") }
	}
	if checked != 2 { t.Fatal("extreme fixture coverage changed") }
}

func TestTreeGraphRestoresSiblingPathsAfterBufferGrowth(t *testing.T) {
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1}); blob, _ := model.NewBlobID(tid)
	empty, root, _ := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	frames := map[TreePageID][]byte{root: empty}
	prefix := strings.Repeat("a", 260)
	want := []string{prefix+".x", prefix+"/child/"+strings.Repeat("b", 300), prefix+"0z"}
	for _, name := range want {
		path, _ := model.NewPath([]byte(name))
		next, added, err := SetTreeLeaf(context.Background(), root, frames, path, 1, blob, TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes})
		if err != nil { t.Fatal(err) }
		for id, frame := range added { frames[id] = frame }; root = next
	}
	before := make(map[TreePageID][]byte)
	for id, frame := range frames { before[id] = append([]byte(nil), frame...) }
	rows, _, err := ReadTreeEntries(context.Background(), root, frames, TreeEntriesBudget{graphTestBudget(), 3, 4096})
	if err != nil || len(rows) != len(want) { t.Fatalf("restored sibling enumeration: %v", err) }
	for i, name := range want { if string(rows[i].Path().Bytes()) != name { t.Fatal("shared path buffer overwrote a sibling or emitted row") } }
	for id, frame := range before { if !bytes.Equal(frames[id], frame) { t.Fatal("walker mutated input bytes") } }
}

func treeCanonicalBlob(t *testing.T, payload []byte) (model.BlobID, []byte) {
	t.Helper()
	id, err := model.HashBlob(context.Background(), uint64(len(payload)), bytes.NewReader(payload)); if err != nil { t.Fatal(err) }
	var frame bytes.Buffer
	if err := model.EncodeBlob(context.Background(), &frame, uint64(len(payload)), bytes.NewReader(payload)); err != nil { t.Fatal(err) }
	return id, frame.Bytes()
}

func TestTreeObjectGraphLiteralReferents(t *testing.T) {
	b, err := os.ReadFile("../../tests/fixtures/tree_pages_v1.json"); if err != nil { t.Fatal(err) }
	var f struct {
		Pages []treeLiteral `json:"pages"`
		Positive []struct { Root string `json:"root_id_hex"`; Entries []struct { Payload string `json:"blob_payload_hex"` } `json:"entries"` } `json:"positive_vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil { t.Fatal(err) }
	if len(f.Positive) != 15 { t.Fatal("blob referent fixture coverage changed") }
	pages := make(map[TreePageID][]byte)
	for _, p := range f.Pages { id, err := ParseTreePageID(treeHex(t, p.IDHex)); if err != nil { t.Fatal(err) }; pages[id] = treeHex(t, p.FrameHex) }
	blobs := make(map[model.BlobID][]byte)
	for _, c := range f.Positive { for _, e := range c.Entries { id, frame := treeCanonicalBlob(t, treeHex(t, e.Payload)); blobs[id] = frame } }
	for _, c := range f.Positive {
		root, err := ParseTreePageID(treeHex(t, c.Root)); if err != nil { t.Fatal(err) }
		used, err := CheckTreeObjectGraph(context.Background(), root, pages, blobs, TreeObjectGraphBudget{graphTestBudget(), 1<<20})
		if err != nil || used.BlobVisits != uint64(len(c.Entries)) { t.Fatalf("literal referent validation: %+v %v", used, err) }
		var expectedBytes uint64
		for _, e := range c.Entries { expectedBytes += 22+uint64(len(treeHex(t, e.Payload))) }
		if used.BlobBytes != expectedBytes { t.Fatal("canonical headers/repeated blobs not charged") }
	}
}

func TestTreeObjectGraphRepeatedBlobBudgetsAndIntegrity(t *testing.T) {
	blob, frame := treeCanonicalBlob(t, []byte{0, 255, '/', 'x'}) // opaque symlink/binary bytes
	pathA, _ := model.NewPath([]byte("a")); pathB, _ := model.NewPath([]byte("b"))
	root, pages, err := BuildSingleLeafTree(context.Background(), pathA, 3, blob, TreeBuildBudget{4096, 4096*MaxTreePageBytes}); if err != nil { t.Fatal(err) }
	next, added, err := SetTreeLeaf(context.Background(), root, pages, pathB, 1, blob, TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}); if err != nil { t.Fatal(err) }
	for id, p := range added { pages[id] = p }; root = next
	blobs := map[model.BlobID][]byte{blob: frame}
	budget := TreeObjectGraphBudget{graphTestBudget(), 2*uint64(len(frame))}
	used, err := CheckTreeObjectGraph(context.Background(), root, pages, blobs, budget)
	if err != nil || used.BlobVisits != 2 || used.BlobBytes != budget.BlobBytes { t.Fatalf("repeated exact blob admission: %+v %v", used, err) }
	budget.BlobBytes--
	if used, err := CheckTreeObjectGraph(context.Background(), root, pages, blobs, budget); err != metadata.ErrResourceExhausted || used.BlobVisits != 2 || used.BlobBytes != uint64(len(frame)) { t.Fatal("blob cache hit bypassed cumulative budget") }
	budget.BlobBytes = 1<<20
	otherID, other := treeCanonicalBlob(t, []byte("else")); _ = otherID
	wrongKind := append([]byte(nil), frame...); wrongKind[13] = byte(model.ChangesetKind)
	for _, invalid := range [][]byte{nil, frame[:len(frame)-1], append(append([]byte(nil), frame...), 0), wrongKind, other} {
		if _, err := CheckTreeObjectGraph(context.Background(), root, pages, map[model.BlobID][]byte{blob: invalid}, budget); err == nil { t.Fatal("invalid canonical blob referent admitted") }
	}
	if _, err := CheckTreeObjectGraph(context.Background(), root, pages, nil, budget); err != ErrTreeBlobMissing { t.Fatal("missing blob accepted") }
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if used, err := CheckTreeObjectGraph(ctx, root, pages, blobs, budget); err != context.Canceled || used.BlobVisits != 0 { t.Fatal("blob graph work after cancellation") }
}

func TestTreeObjectGraphLateMissingAndLargeValidBlob(t *testing.T) {
	good, frame := treeCanonicalBlob(t, nil)
	missing, _ := treeCanonicalBlob(t, []byte("missing"))
	pathA, _ := model.NewPath([]byte("a")); pathB, _ := model.NewPath([]byte("b"))
	root, pages, err := BuildSingleLeafTree(context.Background(), pathA, 1, missing, TreeBuildBudget{4096, 4096*MaxTreePageBytes}); if err != nil { t.Fatal(err) }
	next, added, err := SetTreeLeaf(context.Background(), root, pages, pathB, 1, good, TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}); if err != nil { t.Fatal(err) }
	for id, p := range added { pages[id] = p }; root = next
	// LIFO traversal verifies b's exact empty canonical blob, then fails at a.
	if used, err := CheckTreeObjectGraph(context.Background(), root, pages, map[model.BlobID][]byte{good: frame}, TreeObjectGraphBudget{graphTestBudget(), 22}); err != ErrTreeBlobMissing || used.BlobVisits != 2 || used.BlobBytes != 22 { t.Fatalf("late missing blob: %+v %v", used, err) }
	large, largeFrame := treeCanonicalBlob(t, bytes.Repeat([]byte{'x'}, 1<<20))
	largeRoot, largePages, err := BuildSingleLeafTree(context.Background(), pathA, 1, large, TreeBuildBudget{1, 60}); if err != nil { t.Fatal(err) }
	if used, err := CheckTreeObjectGraph(context.Background(), largeRoot, largePages, map[model.BlobID][]byte{large: largeFrame}, TreeObjectGraphBudget{graphTestBudget(), 1<<20}); err != metadata.ErrResourceExhausted || used.BlobBytes != 0 { t.Fatal("valid large blob exceeded quantum or was treated as success") }
}

type treeBlobDecodeCancelContext struct { context.Context; calls int }
func (c *treeBlobDecodeCancelContext) Err() error {
	c.calls++
	// One walker check, one callback check, three header-read checks and
	// four first-payload-chunk checks precede the next payload read.
	if c.calls >= 10 { return context.Canceled }
	return nil
}

func TestTreeObjectGraphExactQuantumAndMidDecodeCancellation(t *testing.T) {
	blob, frame := treeCanonicalBlob(t, bytes.Repeat([]byte{'x'}, (1<<20)-22))
	if len(frame) != 1<<20 { t.Fatal("canonical quantum fixture changed") }
	path, _ := model.NewPath([]byte("a"))
	root, pages, err := BuildSingleLeafTree(context.Background(), path, 1, blob, TreeBuildBudget{1, 60}); if err != nil { t.Fatal(err) }
	budget := TreeObjectGraphBudget{graphTestBudget(), 1<<20}
	blobs := map[model.BlobID][]byte{blob: frame}
	if used, err := CheckTreeObjectGraph(context.Background(), root, pages, blobs, budget); err != nil || used.BlobBytes != 1<<20 || used.BlobVisits != 1 { t.Fatalf("exact canonical blob quantum: %+v %v", used, err) }
	ctx := &treeBlobDecodeCancelContext{Context: context.Background()}
	used, err := CheckTreeObjectGraph(ctx, root, pages, blobs, budget)
	// Admission charges the entire frame before decoding; the private usage
	// counter is not evidence that all admitted bytes were read or validated.
	if err != context.Canceled || ctx.calls != 10 || used.BlobVisits != 1 || used.BlobBytes != 1<<20 || used.Graph.Visits != 1 { t.Fatalf("mid-decode cancellation lost: %+v %v", used, err) }
}

func TestPrepareCheckedTreeWriteValidatesCandidateBeforeReturn(t *testing.T) {
	empty, root, _ := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	frames := map[TreePageID][]byte{root: empty}
	path, _ := model.NewPath([]byte("a"))
	blob, blobFrame := treeCanonicalBlob(t, nil)
	op, _ := model.NewOperation(path, model.SetRegular, &blob)
	change := model.ChangesetInput{RepoID: [16]byte{1}, Operations: []model.Operation{op}}
	identity := treeBindingIdentity(t, change)
	graph := TreeObjectGraphBudget{graphTestBudget(), 22}
	budget := TreeCheckedWriteBudget{graph, graph, TreeChangesetBudget{TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}, 4096, model.MaxChangesetPayload}}
	blobs := map[model.BlobID][]byte{blob: blobFrame}
	write, added, used, err := PrepareCheckedTreeWrite(context.Background(), identity, change, nil, frames, blobs, budget)
	if err != nil || write.Result.Identity != identity || len(added) != 1 || used.Parent.BlobVisits != 0 || used.Candidate.BlobVisits != 1 || used.Candidate.BlobBytes != 22 { t.Fatalf("checked candidate: %+v %v", used, err) }
	plain, plainFrames, err := PrepareTreeWrite(context.Background(), identity, change, nil, frames, budget.Rewrite)
	if err != nil || metadata.CompareDerivedWrite(plain, write) != nil || len(plainFrames) != len(added) { t.Fatal("checked computation changed source-bound result") }
	for id, frame := range added { if !bytes.Equal(frame, plainFrames[id]) { t.Fatal("overlay changed candidate frames") } }
	for _, invalid := range []map[model.BlobID][]byte{nil, {blob: []byte("corrupt")}} {
		got, out, usage, err := PrepareCheckedTreeWrite(context.Background(), identity, change, nil, frames, invalid, budget)
		if err == nil || got.Result != (metadata.DerivedResult{}) || got.Parents != nil || out != nil || usage.Candidate.BlobVisits != 1 { t.Fatal("failed candidate validation exposed private write") }
	}
	invalidBudget := budget; invalidBudget.Candidate.Graph.Visits = 0
	if _, out, usage, err := PrepareCheckedTreeWrite(context.Background(), identity, change, nil, frames, blobs, invalidBudget); err != metadata.ErrInvalidArgument || out != nil || usage.Parent.Graph.Visits != 0 { t.Fatal("invalid later-phase budget admitted earlier work") }
	short := budget; short.Candidate.BlobBytes = 21
	if got, out, _, err := PrepareCheckedTreeWrite(context.Background(), identity, change, nil, frames, blobs, short); err != metadata.ErrResourceExhausted || got.Result != (metadata.DerivedResult{}) || out != nil { t.Fatal("candidate budget failure leaked output") }
	if len(frames) != 1 || !bytes.Equal(frames[root], empty) { t.Fatal("checked write mutated caller map") }
	changed := change; changed.Message = []byte("different")
	if got, out, usage, err := PrepareCheckedTreeWrite(context.Background(), identity, changed, nil, frames, blobs, budget); err != metadata.ErrCorruptData || got.Result != (metadata.DerivedResult{}) || out != nil || usage.Parent.Graph.Visits != 0 { t.Fatal("source mismatch reached graph work") }
}

func TestPrepareCheckedTreeWriteRejectsUnrelatedCorruptParent(t *testing.T) {
	good, goodFrame := treeCanonicalBlob(t, []byte("good")); other, otherFrame := treeCanonicalBlob(t, []byte("other"))
	pa, _ := model.NewPath([]byte("a")); pb, _ := model.NewPath([]byte("b"))
	root, frames, err := BuildSingleLeafTree(context.Background(), pa, 1, good, TreeBuildBudget{4096, 4096*MaxTreePageBytes}); if err != nil { t.Fatal(err) }
	rewrite := TreeChangesetBudget{TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}, 4096, model.MaxChangesetPayload}
	next, added, err := SetTreeLeaf(context.Background(), root, frames, pb, 1, other, rewrite.Rewrite); if err != nil { t.Fatal(err) }
	for id, frame := range added { frames[id] = frame }; root = next
	parentTID, _ := model.NewTypedID(model.ChangesetKind, [32]byte{1}); parentID, _ := model.NewChangesetID(parentTID)
	raw, _ := root.MarshalBinary(); value, _ := metadata.NewDerivedValueID(raw)
	parent := metadata.DerivedResult{Identity: metadata.DerivedIdentity{Repository: [16]byte{1}, Changeset: parentID, Kind: "TREE", Version: 1}, Value: value}
	op, _ := model.NewOperation(pa, model.SetExecutable, &good)
	change := model.ChangesetInput{RepoID: [16]byte{1}, Parents: []model.ChangesetID{parentID}, Operations: []model.Operation{op}}
	identity := treeBindingIdentity(t, change)
	graph := TreeObjectGraphBudget{graphTestBudget(), uint64(len(goodFrame)+len(otherFrame))}
	budget := TreeCheckedWriteBudget{graph, graph, rewrite}
	blobs := map[model.BlobID][]byte{good: goodFrame, other: otherFrame}
	if _, _, used, err := PrepareCheckedTreeWrite(context.Background(), identity, change, &parent, frames, blobs, budget); err != nil || used.Parent.BlobBytes != graph.BlobBytes || used.Candidate.BlobBytes != graph.BlobBytes { t.Fatal("before/after referents not independently charged") }
	// The delta touches a, but an unrelated corrupt b blob still rejects
	// the parent preflight before candidate construction/validation.
	blobs[other] = []byte("bad")
	if got, out, used, err := PrepareCheckedTreeWrite(context.Background(), identity, change, &parent, frames, blobs, budget); err == nil || got.Result != (metadata.DerivedResult{}) || out != nil || used.Candidate.Graph.Visits != 0 { t.Fatal("unrelated parent corruption was ignored") }
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if got, out, _, err := PrepareCheckedTreeWrite(ctx, identity, change, &parent, frames, blobs, budget); err != context.Canceled || got.Result != (metadata.DerivedResult{}) || out != nil { t.Fatal("checked write ignored cancellation") }
}

type treePhaseCancelContext struct { context.Context; calls, cancelAt int }
func (c *treePhaseCancelContext) Err() error {
	c.calls++
	if c.cancelAt != 0 && c.calls >= c.cancelAt { return context.Canceled }
	return nil
}

func TestPrepareCheckedTreeWriteNoopsEmptyAndPhaseCancellation(t *testing.T) {
	blob, blobFrame := treeCanonicalBlob(t, nil)
	path, _ := model.NewPath([]byte("a"))
	root, frames, err := BuildSingleLeafTree(context.Background(), path, 1, blob, TreeBuildBudget{1, 60}); if err != nil { t.Fatal(err) }
	parentTID, _ := model.NewTypedID(model.ChangesetKind, [32]byte{1}); parentID, _ := model.NewChangesetID(parentTID)
	raw, _ := root.MarshalBinary(); value, _ := metadata.NewDerivedValueID(raw)
	parent := metadata.DerivedResult{Identity: metadata.DerivedIdentity{Repository: [16]byte{1}, Changeset: parentID, Kind: "TREE", Version: 1}, Value: value}
	graph := TreeObjectGraphBudget{graphTestBudget(), 22}
	budget := TreeCheckedWriteBudget{graph, graph, TreeChangesetBudget{TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}, 4096, model.MaxChangesetPayload}}
	blobs := map[model.BlobID][]byte{blob: blobFrame}
	same, _ := model.NewOperation(path, model.SetRegular, &blob); remove, _ := model.NewOperation(path, model.Delete, nil)
	var deletion model.ChangesetInput
	var deletionID metadata.DerivedIdentity
	for i, ops := range [][]model.Operation{nil, {same}, {remove}} {
		change := model.ChangesetInput{RepoID: [16]byte{1}, Parents: []model.ChangesetID{parentID}, Operations: ops}
		identity := treeBindingIdentity(t, change)
		write, added, used, err := PrepareCheckedTreeWrite(context.Background(), identity, change, &parent, frames, blobs, budget)
		if err != nil || write.Result.Identity != identity || len(write.Parents) != 1 || write.Parents[0] != parent { t.Fatalf("checked no-op/delete: %v", err) }
		if i < 2 {
			if write.Result.Value != parent.Value || added != nil || used.Parent.BlobBytes != 22 || used.Candidate.BlobBytes != 22 { t.Fatal("no-op changed root or skipped integrity phases") }
		} else {
			_, emptyRoot, _ := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
			if !bytes.Equal(write.Result.Value.Bytes(), emptyRoot.raw[:]) || len(added) != 1 || used.Candidate.Graph.Visits != 1 || used.Candidate.BlobVisits != 0 { t.Fatal("delete-to-empty result/validation incorrect") }
			deletion, deletionID = change, identity
		}
	}
	for _, afterRewrite := range []bool{false, true} {
		// Calibrate the exact successful prefix, then cancel at the next
		// phase's first context checkpoint. No private candidate may escape.
		probe := &treePhaseCancelContext{Context: context.Background()}
		base, parents, err := bindTreeInput(probe, deletionID, deletion, &parent, budget.Rewrite); if err != nil { t.Fatal(err) }
		if _, err := CheckTreeObjectGraph(probe, base, frames, blobs, budget.Parent); err != nil { t.Fatal(err) }
		if afterRewrite { if _, _, err := applyBoundTreeWrite(probe, base, parents, deletionID, deletion, frames, budget.Rewrite); err != nil { t.Fatal(err) } }
		ctx := &treePhaseCancelContext{Context: context.Background(), cancelAt: probe.calls+1}
		got, out, used, err := PrepareCheckedTreeWrite(ctx, deletionID, deletion, &parent, frames, blobs, budget)
		if err != context.Canceled || got.Result != (metadata.DerivedResult{}) || got.Parents != nil || out != nil || used.Parent.BlobBytes != 22 || used.Candidate.Graph.Visits != 0 || ctx.calls != ctx.cancelAt { t.Fatalf("between-phase cancellation leaked output: %+v %v", used, err) }
	}
	if len(frames) != 1 { t.Fatal("checked phases mutated caller map") }
}

func TestPrepareCanonicalTreeWriteAdmitsExactSource(t *testing.T) {
	ctx := context.Background()
	empty, root, _ := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	frames := map[TreePageID][]byte{root: empty}
	blob, blobFrame := treeCanonicalBlob(t, []byte("content"))
	path, _ := model.NewPath([]byte("a")); op, _ := model.NewOperation(path, model.SetRegular, &blob)
	change := model.ChangesetInput{RepoID: [16]byte{1}, Operations: []model.Operation{op}}
	identity := treeBindingIdentity(t, change)
	value, err := model.NewChangeset(change); if err != nil { t.Fatal(err) }
	var encoded bytes.Buffer
	if err := model.EncodeChangeset(ctx, &encoded, value); err != nil { t.Fatal(err) }
	source := encoded.Bytes()
	sourceBefore := append([]byte(nil), source...)
	graph := TreeObjectGraphBudget{graphTestBudget(), 1<<20}
	budget := TreeCheckedWriteBudget{graph, graph, TreeChangesetBudget{TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}, 4096, uint64(len(source)-22)}}
	blobs := map[model.BlobID][]byte{blob: blobFrame}
	want, wantFrames, wantUsage, err := PrepareCheckedTreeWrite(ctx, identity, change, nil, frames, blobs, budget); if err != nil { t.Fatal(err) }
	got, added, used, err := PrepareCanonicalTreeWrite(ctx, identity, source, nil, frames, blobs, budget)
	if err != nil || metadata.CompareDerivedWrite(got, want) != nil || used != wantUsage || len(added) != len(wantFrames) { t.Fatalf("canonical admission changed checked result: %v", err) }
	for id, frame := range added { if !bytes.Equal(frame, wantFrames[id]) { t.Fatal("canonical admission changed page bytes") } }
	checkBad := func(name string, callContext context.Context, id metadata.DerivedIdentity, frame []byte, b TreeCheckedWriteBudget) {
		t.Helper()
		write, out, usage, err := PrepareCanonicalTreeWrite(callContext, id, frame, nil, frames, blobs, b)
		if err == nil || write.Result != (metadata.DerivedResult{}) || write.Parents != nil || out != nil || usage != (TreeCheckedWriteUsage{}) { t.Fatalf("%s reached tree work or leaked output: %+v %v", name, usage, err) }
	}
	short := budget; short.Rewrite.InputBytes--
	checkBad("one byte short", ctx, identity, source, short)
	for _, n := range []uint64{0, model.MaxChangesetPayload+1} { invalid := budget; invalid.Rewrite.InputBytes = n; checkBad("invalid payload cap", ctx, identity, source, invalid) }
	checkBad("truncated", ctx, identity, source[:len(source)-1], budget)
	// Permit the extra byte in admission so the canonical decoder itself must
	// reject trailing data rather than relying on the outer length bound.
	larger := budget; larger.Rewrite.InputBytes++
	checkBad("trailing", ctx, identity, append(append([]byte(nil), source...), 0), larger)
	corrupt := append([]byte(nil), source...); corrupt[len(corrupt)-1] ^= 1
	checkBad("digest or syntax", ctx, identity, corrupt, budget)
	wrongKind := append([]byte(nil), source...); wrongKind[13] = byte(model.BlobKind)
	checkBad("kind", ctx, identity, wrongKind, budget)
	other := change; other.Message = []byte("different")
	checkBad("expected digest", ctx, treeBindingIdentity(t, other), source, budget)
	wrongRepo := identity; wrongRepo.Repository[0]++
	checkBad("repository", ctx, wrongRepo, source, budget)
	wrongDerived := identity; wrongDerived.Version++
	checkBad("derived version", ctx, wrongDerived, source, budget)
	checkBad("nil context", nil, identity, source, budget)
	cancelled, cancel := context.WithCancel(ctx); cancel()
	checkBad("cancelled", cancelled, identity, source, budget)
	// The decoder admits both canonical operations under the payload cap, but
	// the separate rewrite operation cap must reject before any tree work.
	pathB, _ := model.NewPath([]byte("b")); opB, _ := model.NewOperation(pathB, model.SetRegular, &blob)
	two := change; two.Operations = []model.Operation{op, opB}
	twoValue, err := model.NewChangeset(two); if err != nil { t.Fatal(err) }
	var twoEncoded bytes.Buffer
	if err := model.EncodeChangeset(ctx, &twoEncoded, twoValue); err != nil { t.Fatal(err) }
	oneOperation := budget; oneOperation.Rewrite.Operations = 1; oneOperation.Rewrite.InputBytes = uint64(twoEncoded.Len()-22)
	writeLimit, outLimit, usedLimit, err := PrepareCanonicalTreeWrite(ctx, treeBindingIdentity(t, two), twoEncoded.Bytes(), nil, frames, blobs, oneOperation)
	if err != metadata.ErrResourceExhausted || writeLimit.Result != (metadata.DerivedResult{}) || writeLimit.Parents != nil || outLimit != nil || usedLimit != (TreeCheckedWriteUsage{}) { t.Fatal("decoded operation limit reached tree work") }
	// Checkpoint 1 is wrapper admission, 2-4 read the complete header,
	// and 5-6 begin/read the repository payload. Cancel after that read,
	// within decoding and before source verification or tree work completes.
	midDecode := &treePhaseCancelContext{Context: ctx, cancelAt: 6}
	writeCancel, outCancel, usedCancel, err := PrepareCanonicalTreeWrite(midDecode, identity, source, nil, frames, blobs, budget)
	if err != context.Canceled || midDecode.calls != 6 || writeCancel.Result != (metadata.DerivedResult{}) || writeCancel.Parents != nil || outCancel != nil || usedCancel != (TreeCheckedWriteUsage{}) { t.Fatal("mid-source-decode cancellation leaked output") }
	// Later candidate-integrity failure still yields no prepared write.
	write, out, usage, err := PrepareCanonicalTreeWrite(ctx, identity, source, nil, frames, nil, budget)
	if err == nil || write.Result != (metadata.DerivedResult{}) || out != nil || usage.Parent.Graph.Visits != 1 || usage.Candidate.BlobVisits != 1 { t.Fatal("canonical source skipped candidate validation") }
	if len(frames) != 1 || !bytes.Equal(frames[root], empty) || !bytes.Equal(source, sourceBefore) { t.Fatal("canonical preparation mutated input") }
}

func treeReplaySource(t *testing.T, change model.ChangesetInput) TreeSourceFrame {
	t.Helper()
	v, err := model.NewChangeset(change); if err != nil { t.Fatal(err) }
	id, err := model.HashChangeset(context.Background(), v); if err != nil { t.Fatal(err) }
	var frame bytes.Buffer
	if err := model.EncodeChangeset(context.Background(), &frame, v); err != nil { t.Fatal(err) }
	return TreeSourceFrame{id, frame.Bytes()}
}

func TestReplayCanonicalTreeChainOwnsParentMappings(t *testing.T) {
	ctx := context.Background(); repo := [16]byte{1}
	blob, blobFrame := treeCanonicalBlob(t, []byte("opaque"))
	blobs := map[model.BlobID][]byte{blob: blobFrame}
	blobBefore := append([]byte(nil), blobFrame...)
	path, _ := model.NewPath([]byte("a"))
	regular, _ := model.NewOperation(path, model.SetRegular, &blob)
	executable, _ := model.NewOperation(path, model.SetExecutable, &blob)
	remove, _ := model.NewOperation(path, model.Delete, nil)
	symlink, _ := model.NewOperation(path, model.SetSymlink, &blob)
	var sources []TreeSourceFrame
	var changes []model.ChangesetInput
	var sourceBytes uint64
	for _, ops := range [][]model.Operation{{regular}, {executable}, {remove}, {symlink}, nil} {
		change := model.ChangesetInput{RepoID: repo, Operations: ops}
		if len(sources) != 0 { change.Parents = []model.ChangesetID{sources[len(sources)-1].ID} }
		source := treeReplaySource(t, change); sources = append(sources, source); changes = append(changes, change); sourceBytes += uint64(len(source.Frame))
	}
	graph := TreeObjectGraphBudget{graphTestBudget(), 1<<20}
	step := TreeCheckedWriteBudget{graph, graph, TreeChangesetBudget{TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}, 4096, model.MaxChangesetPayload}}
	budget := TreeReplayBudget{5, sourceBytes, 4, 204, step}
	writes, pages, used, err := ReplayCanonicalTreeChain(ctx, repo, sources, blobs, budget)
	if err != nil || len(writes) != 5 || len(pages) != 4 || used != (TreeReplayUsage{5, sourceBytes, 4, 204}) { t.Fatalf("exact replay: %+v %v", used, err) }
	_, emptyRoot, _ := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	for i, tag := range []byte{1, 2, 0, 3, 3} {
		want := emptyRoot
		if tag != 0 { want, _, err = BuildSingleLeafTree(ctx, path, tag, blob, TreeBuildBudget{1, 60}); if err != nil { t.Fatal(err) } }
		if writes[i].Result.Identity != (metadata.DerivedIdentity{Repository: repo, Changeset: sources[i].ID, Kind: "TREE", Version: 1}) || !bytes.Equal(writes[i].Result.Value.Bytes(), want.raw[:]) { t.Fatal("replay changed canonical source/root association") }
		if i == 0 { if len(writes[i].Parents) != 0 { t.Fatal("root acquired parent") } } else if len(writes[i].Parents) != 1 || writes[i].Parents[0] != writes[i-1].Result { t.Fatal("replay did not derive its own parent-zero mapping") }
	}
	for _, which := range []string{"sources", "source bytes", "pages", "page bytes"} {
		short := budget
		switch which { case "sources": short.Sources--; case "source bytes": short.SourceBytes--; case "pages": short.Pages--; case "page bytes": short.PageBytes-- }
		out, frames, _, err := ReplayCanonicalTreeChain(ctx, repo, sources, blobs, short)
		if err != metadata.ErrResourceExhausted || out != nil || frames != nil { t.Fatalf("%s exhaustion leaked candidates: %v", which, err) }
	}
	for _, invalid := range []TreeReplayBudget{{}, {65, sourceBytes, 4, 204, step}, {5, sourceBytes, 0, 204, step}} {
		if out, frames, _, err := ReplayCanonicalTreeChain(ctx, repo, sources, blobs, invalid); err != metadata.ErrInvalidArgument || out != nil || frames != nil { t.Fatal("invalid replay budget accepted") }
	}
	if out, frames, _, err := ReplayCanonicalTreeChain(nil, repo, sources, blobs, budget); err != metadata.ErrInvalidArgument || out != nil || frames != nil { t.Fatal("nil replay context accepted") }
	for _, which := range []string{"input", "parent visits", "candidate blobs", "rewrite pages"} {
		invalid := budget
		switch which { case "input": invalid.Step.Rewrite.InputBytes = 0; case "parent visits": invalid.Step.Parent.Graph.Visits = 0; case "candidate blobs": invalid.Step.Candidate.BlobBytes = 0; case "rewrite pages": invalid.Step.Rewrite.Rewrite.Pages = 0 }
		if out, frames, _, err := ReplayCanonicalTreeChain(ctx, repo, sources, blobs, invalid); err != metadata.ErrInvalidArgument || out != nil || frames != nil { t.Fatalf("invalid step %s admitted output: %v", which, err) }
	}
	// The first rewrite reads the 24-byte empty root and succeeds; the
	// second must read its 60-byte parent leaf and exhaust the per-step cap.
	// A completed private first mapping must not escape the later failure.
	laterShort := budget; laterShort.Step.Rewrite.Rewrite.ReadBytes = 24
	if out, frames, usage, err := ReplayCanonicalTreeChain(ctx, repo, sources, blobs, laterShort); err != metadata.ErrResourceExhausted || out != nil || frames != nil || usage.Sources != 2 || usage.Pages != 2 || usage.PageBytes != 84 { t.Fatalf("later step exhaustion leaked prior candidate: %+v %v", usage, err) }
	badSources := append([]TreeSourceFrame(nil), sources...)
	badSources[4].Frame = append([]byte(nil), badSources[4].Frame...); badSources[4].Frame[len(badSources[4].Frame)-1] ^= 1
	out, frames, partial, err := ReplayCanonicalTreeChain(ctx, repo, badSources, blobs, budget)
	if err == nil || out != nil || frames != nil || partial.Sources != 5 { t.Fatal("late corrupt source exposed earlier private results") }
	for _, batch := range [][]TreeSourceFrame{nil, sources[1:], {sources[0], sources[2]}, {sources[0], sources[0]}} {
		if out, frames, _, err := ReplayCanonicalTreeChain(ctx, repo, batch, blobs, budget); err == nil || out != nil || frames != nil { t.Fatal("empty/non-root/disconnected/repeated-root chain accepted") }
	}
	if out, frames, _, err := ReplayCanonicalTreeChain(ctx, [16]byte{2}, sources, blobs, budget); err != metadata.ErrInvalidArgument || out != nil || frames != nil { t.Fatal("foreign repository replay accepted") }
	if out, frames, _, err := ReplayCanonicalTreeChain(ctx, repo, sources, nil, budget); err == nil || out != nil || frames != nil { t.Fatal("missing referenced blob accepted") }
	// Additional canonical parents are ancestry, never tree-union inputs.
	merge := changes[1]; merge.Parents = append(append([]model.ChangesetID(nil), merge.Parents...), sources[3].ID)
	mergeSource := treeReplaySource(t, merge)
	mergeBudget := budget; mergeBudget.SourceBytes = uint64(len(sources[0].Frame)+len(mergeSource.Frame))
	merged, _, _, err := ReplayCanonicalTreeChain(ctx, repo, []TreeSourceFrame{sources[0], mergeSource}, blobs, mergeBudget)
	if err != nil || len(merged) != 2 || merged[1].Result.Value != writes[1].Result.Value || len(merged[1].Parents) != 1 { t.Fatal("additional ancestry changed parent-zero derivation") }
	// Calibrate a complete one-source prefix. The longer batch adds four
	// source-admission checkpoints; its next-step checkpoint replaces the
	// one-source final checkpoint. Cancel with one private result collected.
	probe := &treePhaseCancelContext{Context: ctx}
	if _, _, _, err := ReplayCanonicalTreeChain(probe, repo, sources[:1], blobs, budget); err != nil { t.Fatal(err) }
	cancel := &treePhaseCancelContext{Context: ctx, cancelAt: probe.calls+len(sources)-1}
	out, frames, partial, err = ReplayCanonicalTreeChain(cancel, repo, sources, blobs, budget)
	if err != context.Canceled || out != nil || frames != nil || partial.Sources != 1 { t.Fatalf("between-source cancellation leaked results: %+v %v", partial, err) }
	// Returned page storage is owned, not aliased to canonical source/blob input.
	for _, frame := range pages { if len(frame) != 0 { frame[0] ^= 1; break } }
	if !bytes.Equal(blobBefore, blobs[blob]) { t.Fatal("result mutation changed blob input") }
	for i, source := range sources { if _, err := model.DecodeChangeset(ctx, bytes.NewReader(source.Frame), source.ID, step.Rewrite.InputBytes); err != nil { t.Fatalf("source %d mutated: %v", i, err) } }
}

type setTestEntry struct {
	path string
	tag  byte
	blob model.BlobID
}

func setTestBudget() TreeRewriteBudget {
	return TreeRewriteBudget{4096, 4096 * MaxTreePageBytes, 4096 * MaxTreePageBytes}
}

func setTestPut(t *testing.T, root TreePageID, frames map[TreePageID][]byte, entry setTestEntry) (TreePageID, map[TreePageID][]byte) {
	t.Helper()
	path, err := model.NewPath([]byte(entry.path))
	if err != nil {
		t.Fatal(err)
	}
	next, added, err := SetTreeLeaf(context.Background(), root, frames, path, entry.tag, entry.blob, setTestBudget())
	if err != nil {
		t.Fatalf("SET %s: %v", entry.path, err)
	}
	combined := make(map[TreePageID][]byte)
	for id, frame := range frames {
		combined[id] = frame
	}
	for id, frame := range added {
		combined[id] = frame
	}
	if _, err := CheckTreePageGraph(context.Background(), next, combined, graphTestBudget()); err != nil {
		t.Fatalf("SET %s candidate graph: %v", entry.path, err)
	}
	return next, combined
}

func setTestMap(t *testing.T, entries ...setTestEntry) (TreePageID, map[TreePageID][]byte) {
	t.Helper()
	empty, root, err := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	frames := map[TreePageID][]byte{root: empty}
	for _, entry := range entries {
		root, frames = setTestPut(t, root, frames, entry)
	}
	return root, frames
}

// Enumerate this small test graph to find a terminal. This is a read-only
// assertion helper; it does not duplicate SET's search/split/rewrite logic.
func setTestLeaf(t *testing.T, root TreePageID, frames map[TreePageID][]byte, name string) (TreePageID, UnlinkedTreePage) {
	t.Helper()
	type visit struct {
		id                   TreePageID
		directory, component []byte
	}
	stack := []visit{{id: root}}
	for count := 0; len(stack) != 0 && count < 100; count++ {
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		p, err := DecodeTreePageAt(frames[v.id], v.id, v.directory, v.component)
		if err != nil {
			t.Fatal(err)
		}
		component := append(append([]byte(nil), v.component...), p.Label...)
		full := append([]byte(nil), v.directory...)
		if len(full) != 0 {
			full = append(full, '/')
		}
		full = append(full, component...)
		if p.Tag == 4 {
			stack = append(stack, visit{id: p.Directory, directory: full})
		} else if p.Tag != 0 && string(full) == name {
			return v.id, p
		}
		for _, child := range p.Children {
			prefix := append(append([]byte(nil), component...), child.Edge)
			stack = append(stack, visit{child.ID, v.directory, prefix})
		}
	}
	t.Fatalf("terminal %q absent from bounded test graph", name)
	return TreePageID{}, UnlinkedTreePage{}
}

func TestSetTreeLeafExistingDirectoryUpdates(t *testing.T) {
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1})
	blob, _ := model.NewBlobID(tid)
	for _, directory := range []string{"dir/", "dir/sub/"} {
		t.Run(directory, func(t *testing.T) {
			a := setTestEntry{directory + "a", 1, blob}
			b := setTestEntry{directory + "b", 1, blob}
			c := setTestEntry{directory + "c", 1, blob}
			base, frames := setTestMap(t, a)
			next, frames := setTestPut(t, base, frames, b)
			opposite, _ := setTestMap(t, b, a)
			if next == base || next != opposite {
				t.Fatal("changing SET below a directory lost an entry or changed canonical shape")
			}
			aID, oldA := setTestLeaf(t, next, frames, a.path)
			if oldA.Tag != 1 || oldA.Blob != blob {
				t.Fatal("existing directory sibling changed")
			}
			// With a branch established, inserting c can retain a's exact page.
			last, combined := setTestPut(t, next, frames, c)
			retained, _ := setTestLeaf(t, last, combined, a.path)
			reverse, _ := setTestMap(t, c, b, a)
			if last == next || last != reverse || retained != aID {
				t.Fatal("directory rewrite lost canonical identity or rewrote an unrelated sibling")
			}
		})
	}
}

func TestSetTreeLeafChangesExistingValueAndRestoresRoot(t *testing.T) {
	oldTID, _ := model.NewTypedID(model.BlobKind, [32]byte{1})
	oldBlob, _ := model.NewBlobID(oldTID)
	newTID, _ := model.NewTypedID(model.BlobKind, [32]byte{2})
	newBlob, _ := model.NewBlobID(newTID)
	for _, prefix := range []string{"", "dir/sub/"} {
		for _, change := range []struct {
			name string
			tag  byte
			blob model.BlobID
		}{{"tag", 2, oldBlob}, {"blob", 1, newBlob}} {
			t.Run(prefix+change.name, func(t *testing.T) {
				original := setTestEntry{prefix + "x", 1, oldBlob}
				sibling := setTestEntry{prefix + "z", 1, oldBlob}
				base, frames := setTestMap(t, original, sibling)
				siblingID, _ := setTestLeaf(t, base, frames, sibling.path)
				next, combined := setTestPut(t, base, frames, setTestEntry{original.path, change.tag, change.blob})
				_, actual := setTestLeaf(t, next, combined, original.path)
				retained, _ := setTestLeaf(t, next, combined, sibling.path)
				if next == base || actual.Tag != change.tag || actual.Blob != change.blob || retained != siblingID {
					t.Fatal("existing-file SET dropped the new value or changed a sibling")
				}
				restored, _ := setTestPut(t, next, combined, original)
				if restored != base {
					t.Fatal("restoring the original map did not restore its canonical root")
				}
			})
		}
	}
}

func TestSetTreeLeafComponentBoundarySplit(t *testing.T) {
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1})
	blob, _ := model.NewBlobID(tid)
	base, frames := setTestMap(t, setTestEntry{"abc", 1, blob})
	next, combined := setTestPut(t, base, frames, setTestEntry{"a/x", 1, blob})
	opposite, _ := setTestMap(t, setTestEntry{"a/x", 1, blob}, setTestEntry{"abc", 1, blob})
	// The canonical map is a root labelled a with both directory terminal x
	// and continuation edge b -> c. Encode that concrete expected shape.
	_, xID, err := EncodeTreePageAt(UnlinkedTreePage{Label: []byte("x"), Tag: 1, Blob: blob}, []byte("a"), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, cID, err := EncodeTreePageAt(UnlinkedTreePage{Label: []byte("c"), Tag: 1, Blob: blob}, nil, []byte("ab"))
	if err != nil {
		t.Fatal(err)
	}
	_, expected, err := EncodeTreePageAt(UnlinkedTreePage{Label: []byte("a"), Tag: 4, Directory: xID, Children: []TreePageChild{{'b', cID}}}, nil, nil)
	if err != nil || next != expected || next != opposite {
		t.Fatalf("component-boundary split differs from exact canonical map: %v", err)
	}
	setTestLeaf(t, next, combined, "abc")
	setTestLeaf(t, next, combined, "a/x")
}

func TestSetTreeLeafCorruptionMissingAndTraversalAdmission(t *testing.T) {
	oldTID, _ := model.NewTypedID(model.BlobKind, [32]byte{1})
	oldBlob, _ := model.NewBlobID(oldTID)
	newTID, _ := model.NewTypedID(model.BlobKind, [32]byte{2})
	newBlob, _ := model.NewBlobID(newTID)
	entry := setTestEntry{"dir/file", 1, oldBlob}
	base, frames := setTestMap(t, entry)
	path, _ := model.NewPath([]byte(entry.path))
	next, candidates, err := SetTreeLeaf(context.Background(), base, frames, path, 2, newBlob, setTestBudget())
	if err != nil || next == base || len(candidates[next]) == 0 {
		t.Fatalf("candidate precondition: %v", err)
	}
	for _, sameLength := range []bool{true, false} {
		t.Run(map[bool]string{true: "same-length-occupied", false: "different-length-occupied"}[sameLength], func(t *testing.T) {
			occupied := make(map[TreePageID][]byte)
			for id, frame := range frames {
				occupied[id] = frame
			}
			corrupt := append([]byte(nil), candidates[next]...)
			if sameLength {
				corrupt[len(corrupt)-1] ^= 1
			} else {
				corrupt = append(corrupt, 0)
			}
			occupied[next] = corrupt
			snapshot := append([]byte(nil), corrupt...)
			id, output, err := SetTreeLeaf(context.Background(), base, occupied, path, 2, newBlob, setTestBudget())
			if err != ErrTreePage || id != (TreePageID{}) || output != nil || !bytes.Equal(occupied[next], snapshot) {
				t.Fatalf("corrupt occupied ID accepted or changed: %v", err)
			}
		})
	}
	leafID, _ := setTestLeaf(t, base, frames, entry.path)
	missing := make(map[TreePageID][]byte)
	for id, frame := range frames {
		if id != leafID {
			missing[id] = frame
		}
	}
	if id, output, err := SetTreeLeaf(context.Background(), base, missing, path, 2, newBlob, setTestBudget()); err != ErrTreePageMissing || id != (TreePageID{}) || output != nil {
		t.Fatalf("missing path page: %v", err)
	}
	// An identical SET performs no writes. This limit can therefore fail only
	// while traversing the two existing pages, not at the production cap.
	limit := setTestBudget()
	limit.Pages = 1
	if id, output, err := SetTreeLeaf(context.Background(), base, frames, path, 1, oldBlob, limit); err != metadata.ErrResourceExhausted || id != (TreePageID{}) || output != nil {
		t.Fatalf("traversal page cap: %v", err)
	}
}

func TestReplaceExistingTreeLeafSecondChildAndOccupiedBytes(t *testing.T) {
	oldTID, err := model.NewTypedID(model.BlobKind, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	oldBlob, err := model.NewBlobID(oldTID)
	if err != nil {
		t.Fatal(err)
	}
	newTID, err := model.NewTypedID(model.BlobKind, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	newBlob, err := model.NewBlobID(newTID)
	if err != nil {
		t.Fatal(err)
	}
	leaf, leafID, err := EncodeTreePageAt(UnlinkedTreePage{Tag: 1, Blob: oldBlob}, nil, []byte("z"))
	if err != nil {
		t.Fatal(err)
	}
	rootFrame, root, err := EncodeTreePageAt(UnlinkedTreePage{
		Children: []TreePageChild{{'a', leafID}, {'z', leafID}},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	frames := map[TreePageID][]byte{root: rootFrame, leafID: leaf}
	if _, err := CheckTreePageGraph(context.Background(), root, frames, graphTestBudget()); err != nil {
		t.Fatalf("base graph: %v", err)
	}
	path, err := model.NewPath([]byte("z"))
	if err != nil {
		t.Fatal(err)
	}
	pathBytes := uint64(len(rootFrame) + len(leaf))
	budget := TreeRewriteBudget{Pages: 2, ReadBytes: pathBytes, WriteBytes: pathBytes}
	next, added, err := ReplaceExistingTreeLeaf(context.Background(), root, frames, path, 2, newBlob, budget)
	if err != nil || next == root || len(added) != 2 {
		t.Fatalf("second-child replacement: root=%v frames=%d err=%v", next, len(added), err)
	}
	combined := make(map[TreePageID][]byte)
	for id, frame := range frames {
		combined[id] = frame
	}
	for id, frame := range added {
		combined[id] = frame
	}
	page, err := DecodeTreePageAt(combined[next], next, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Children) != 2 || page.Children[0].Edge != 'a' || page.Children[0].ID != leafID ||
		page.Children[1].Edge != 'z' || page.Children[1].ID == leafID {
		t.Fatalf("wrong child rewritten or sibling lost: %+v", page.Children)
	}
	replaced, err := DecodeTreePageAt(combined[page.Children[1].ID], page.Children[1].ID, nil, []byte("z"))
	if err != nil || replaced.Tag != 2 || replaced.Blob != newBlob {
		t.Fatalf("second-child terminal: tag=%d blob=%v err=%v", replaced.Tag, replaced.Blob, err)
	}
	if _, err := CheckTreePageGraph(context.Background(), next, combined, graphTestBudget()); err != nil {
		t.Fatalf("candidate graph: %v", err)
	}

	// Occupy only the new root ID, so the additional read is exactly its
	// candidate frame. The new leaf is still produced by the rewrite.
	comparisonBudget := budget
	comparisonBudget.ReadBytes += uint64(len(added[next]))
	for _, tc := range []struct {
		name    string
		corrupt bool
		short   bool
		want    error
	}{
		{"identical-at-exact-budget", false, false, nil},
		{"equal-length-corruption-at-exact-budget", true, false, ErrTreePage},
		{"admission-before-corrupt-byte-comparison", true, true, metadata.ErrResourceExhausted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			occupied := make(map[TreePageID][]byte)
			for id, frame := range frames {
				occupied[id] = frame
			}
			candidate := append([]byte(nil), added[next]...)
			if tc.corrupt {
				candidate[len(candidate)-1] ^= 1
			}
			occupied[next] = candidate
			expectedOccupied := append([]byte(nil), candidate...)
			limit := comparisonBudget
			if tc.short {
				limit.ReadBytes--
			}
			got, output, err := ReplaceExistingTreeLeaf(context.Background(), root, occupied, path, 2, newBlob, limit)
			if tc.want != nil {
				if err != tc.want || got != (TreePageID{}) || output != nil {
					t.Fatalf("wanted %v and no output, got root=%v frames=%d err=%v", tc.want, got, len(output), err)
				}
			} else if err != nil || got != next || len(output) != 1 {
				t.Fatalf("exact occupied comparison: root=%v frames=%d err=%v", got, len(output), err)
			}
			if !bytes.Equal(occupied[next], expectedOccupied) {
				t.Fatal("occupied bytes were overwritten")
			}
		})
	}
}
