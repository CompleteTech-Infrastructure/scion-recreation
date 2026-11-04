package query

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

func TestDiffTextLiteralHunks(t *testing.T) {
	for _, tc := range []struct {
		name, old, next, want string
		context uint64
	}{
		{"equal", "a\n", "a\n", "", 1},
		{"empty", "", "", "", 0},
		{"insert", "", "a\n", "@@ -0,0 +1,1 @@\n+a\n", 0},
		{"delete", "a\n", "", "@@ -1,1 +0,0 @@\n-a\n", 0},
		{"replace", "a\nb\nc\n", "a\nB\nc\n", "@@ -2,1 +2,1 @@\n-b\n+B\n", 0},
		{"context", "a\nb\nc\n", "a\nB\nc\n", "@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n", 1},
		{"insert-middle", "a\nc\n", "a\nb\nc\n", "@@ -1,0 +2,1 @@\n+b\n", 0},
		{"insert-context", "a\nc\n", "a\nb\nc\n", "@@ -1,2 +1,3 @@\n a\n+b\n c\n", 1},
		{"delete-context", "a\nb\nc\n", "a\nc\n", "@@ -1,3 +1,2 @@\n a\n-b\n c\n", 1},
		{"unterminated-context", "a\nz", "b\nz", "@@ -1,2 +1,2 @@\n-a\n+b\n z\n\\ No newline at end of file\n", 1},
		{"delete-middle", "a\nb\nc\n", "a\nc\n", "@@ -2,1 +1,0 @@\n-b\n", 0},
		{"final-newline", "a", "a\n", "@@ -1,1 +1,1 @@\n-a\n\\ No newline at end of file\n+a\n", 0},
		{"missing-both", "a", "b", "@@ -1,1 +1,1 @@\n-a\n\\ No newline at end of file\n+b\n\\ No newline at end of file\n", 0},
		{"raw-crlf", "\xff\r\n", "\xfe\r\n", "@@ -1,1 +1,1 @@\n-\xff\r\n+\xfe\r\n", 0},
		{"coarse", "a\nb\nc\nd\n", "A\nb\nc\nD\n", "@@ -1,4 +1,4 @@\n-a\n-b\n-c\n-d\n+A\n+b\n+c\n+D\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DiffText(context.Background(), []byte(tc.old), []byte(tc.next), TextDiffBudget{1024,1024,100,tc.context})
			if err != nil || string(got.Hunk) != tc.want {
				t.Fatalf("got=%q want=%q err=%v", got.Hunk, tc.want, err)
			}
			oldNL := len(tc.old)>0 && tc.old[len(tc.old)-1]=='\n'
			newNL := len(tc.next)>0 && tc.next[len(tc.next)-1]=='\n'
			if got.OldFinalNewline != oldNL || got.NewFinalNewline != newNL {
				t.Fatal("newline flags changed")
			}
		})
	}
}

func TestDiffTextRejectsWithoutPartialOutput(t *testing.T) {
	for _, tc := range []struct {
		old, next string
		budget TextDiffBudget
		want error
	}{
		{"a\x00", "b", TextDiffBudget{10,100,10,0}, ErrDiffBinary},
		{"a", "b\x00", TextDiffBudget{10,100,10,0}, ErrDiffBinary},
		{"a", "b", TextDiffBudget{1,100,10,0}, ErrDiffLimit},
		{"a\n", "b\n", TextDiffBudget{4,100,1,0}, ErrDiffLimit},
		{"a", "b", TextDiffBudget{2,1,2,0}, ErrDiffLimit},
		{"", "", TextDiffBudget{}, ErrDiffLimit},
		{"", "", TextDiffBudget{1,1,1,2}, ErrDiffLimit},
		{"", "", TextDiffBudget{65<<20,1,1,0}, ErrDiffLimit},
	} {
		got, err := DiffText(context.Background(), []byte(tc.old), []byte(tc.next), tc.budget)
		if !errors.Is(err,tc.want) || !reflect.DeepEqual(got,TextDiff{}) {
			t.Fatalf("rejection exposed output: %+v %v",got,err)
		}
	}
	ctx,cancel := context.WithCancel(context.Background())
	cancel()
	got,err := DiffText(ctx,[]byte("a"),[]byte("b"),TextDiffBudget{2,100,2,0})
	if !errors.Is(err,context.Canceled) || !reflect.DeepEqual(got,TextDiff{}) {
		t.Fatal("cancellation returned output")
	}
	if _,err := DiffText(nil,nil,nil,TextDiffBudget{1,1,1,0}); !errors.Is(err,ErrDiffInput) {
		t.Fatal("nil context accepted")
	}
}

func TestDiffTextExactOutputBudgetAndOwnership(t *testing.T) {
	old,next := []byte("a\n"),[]byte("b\n")
	want := "@@ -1,1 +1,1 @@\n-a\n+b\n"
	budget := TextDiffBudget{4,uint64(len(want)),2,0}
	got,err := DiffText(context.Background(),old,next,budget)
	if err != nil || string(got.Hunk)!=want { t.Fatal(err) }
	old[0],next[0]='X','Y'
	if string(got.Hunk)!=want { t.Fatal("output aliases inputs") }
	budget.OutputBytes--
	if got,err := DiffText(context.Background(),old,next,budget); !errors.Is(err,ErrDiffLimit) || got.Hunk!=nil { t.Fatal("one-byte output overflow accepted") }
}

func fileDiffOp(t *testing.T, path string, mode model.OperationTag, digestByte byte) model.Operation {
	t.Helper()
	p, err := model.NewPath([]byte(path))
	if err != nil { t.Fatal(err) }
	var digest [32]byte
	digest[0] = digestByte
	typed, _ := model.NewTypedID(model.BlobKind, digest)
	id, _ := model.NewBlobID(typed)
	op, err := model.NewOperation(p, mode, &id)
	if err != nil { t.Fatal(err) }
	return op
}

func TestFileEntryDiffAllSmallStates(t *testing.T) {
	// For each of three independent paths: absent, regular blob1,
	// executable blob1, or symlink blob2. Expected deltas come from states.
	for oldCode := 0; oldCode < 64; oldCode++ {
		for newCode := 0; newCode < 64; newCode++ {
			var old, next []model.Operation
			var want []FileDelta
			for path, a, b := 0, oldCode, newCode; path < 3; path, a, b = path+1, a/4, b/4 {
				x, y := a%4, b%4
				name := string(byte('a'+path))
				var before, after model.Operation
				blob := func(state int) byte { if state == 3 { return 2 }; return 1 }
				if x != 0 { before = fileDiffOp(t, name, model.OperationTag(x), blob(x)); old = append(old, before) }
				if y != 0 { after = fileDiffOp(t, name, model.OperationTag(y), blob(y)); next = append(next, after) }
				if x != y {
					p, _ := model.NewPath([]byte(name))
					want = append(want, FileDelta{Path: p, Before: before, After: after, BeforePresent: x != 0, AfterPresent: y != 0, ModeChanged: x != 0 && y != 0 && x != y, ContentChanged: x != 0 && y != 0 && blob(x) != blob(y)})
				}
			}
			got, err := DiffFileEntries(context.Background(), old, next, FileDiffBudget{6, 6, 3})
			if err != nil || len(got) != len(want) { t.Fatalf("%d/%d: %v %v", oldCode, newCode, got, err) }
			for i := range want { if got[i] != want[i] { t.Fatalf("%d/%d delta%d", oldCode, newCode, i) } }
		}
	}
}

func TestFileEntryDiffContentAndRawPaths(t *testing.T) {
	old := []model.Operation{fileDiffOp(t, "A", model.SetRegular, 1), fileDiffOp(t, "a", model.SetSymlink, 1), fileDiffOp(t, "\xff", model.SetRegular, 1)}
	next := []model.Operation{fileDiffOp(t, "A", model.SetRegular, 2), fileDiffOp(t, "a", model.SetSymlink, 2), fileDiffOp(t, "\xff", model.SetExecutable, 1)}
	got, err := DiffFileEntries(context.Background(), old, next, FileDiffBudget{6, 6, 3})
	if err != nil || len(got) != 3 { t.Fatal(got, err) }
	for i := 0; i < 3; i++ {
		if got[i].Path != old[i].Path() || !got[i].BeforePresent || !got[i].AfterPresent || got[i].ContentChanged != (i < 2) || got[i].ModeChanged != (i == 2) { t.Fatal(i, got[i]) }
	}
	// Returned immutable values do not alias the caller's slice slots.
	old[0], next[0] = model.Operation{}, model.Operation{}
	if got[0].Before.Path().Validate() != nil || got[0].After.Path().Validate() != nil { t.Fatal("slice alias") }
}

type fileDiffCancelContext struct { context.Context; cancel context.CancelFunc; calls, at int }
func (c *fileDiffCancelContext) Err() error {
	c.calls++
	if c.calls == c.at { c.cancel() }
	return c.Context.Err()
}

func TestFileEntryDiffRejectsAndBudgets(t *testing.T) {
	a, b := fileDiffOp(t, "a", model.SetRegular, 1), fileDiffOp(t, "b", model.SetRegular, 1)
	deleted, _ := model.NewOperation(a.Path(), model.Delete, nil)
	for _, bad := range [][]model.Operation{{{}}, {deleted}, {a, a}, {b, a}} {
		for _, side := range []bool{false, true} {
			old, next := bad, []model.Operation(nil)
			if side { old, next = next, old }
			if got, err := DiffFileEntries(context.Background(), old, next, FileDiffBudget{10, 100, 10}); got != nil || !errors.Is(err, ErrFileDiffInput) { t.Fatal(got, err) }
		}
	}
	for _, budget := range []FileDiffBudget{{}, {1000001, 1, 1}, {1, 65<<20, 1}, {1, 1, 2}, {1, 100, 1}, {2, 1, 2}, {2, 2, 1}} {
		if got, err := DiffFileEntries(context.Background(), []model.Operation{a}, []model.Operation{b}, budget); got != nil || !errors.Is(err, ErrFileDiffLimit) { t.Fatal(budget, got, err) }
	}
	if got, err := DiffFileEntries(context.Background(), []model.Operation{a}, []model.Operation{b}, FileDiffBudget{2, 2, 2}); err != nil || len(got) != 2 { t.Fatal(got, err) }
	if got, err := DiffFileEntries(nil, nil, nil, FileDiffBudget{1, 1, 1}); got != nil || !errors.Is(err, ErrFileDiffInput) { t.Fatal(got, err) }
	// Cancel before emission, after one delta, and at the final check.
	for _, at := range []int{4, 5, 6} {
		ctx, cancel := context.WithCancel(context.Background())
		mid := &fileDiffCancelContext{Context: ctx, cancel: cancel, at: at}
		got, err := DiffFileEntries(mid, []model.Operation{a}, []model.Operation{b}, FileDiffBudget{2, 2, 2})
		cancel()
		if got != nil || !errors.Is(err, context.Canceled) { t.Fatal(at, got, err) }
		if got, err := DiffFileEntries(ctx, nil, nil, FileDiffBudget{1, 1, 1}); got != nil || !errors.Is(err, context.Canceled) { t.Fatal(got, err) }
	}
}

func canonicalDiffBlob(t *testing.T, payload []byte) (model.BlobID, []byte) {
	t.Helper()
	id, err := model.HashBlob(context.Background(), uint64(len(payload)), bytes.NewReader(payload))
	if err != nil { t.Fatal(err) }
	var frame bytes.Buffer
	if err := model.EncodeBlob(context.Background(), &frame, uint64(len(payload)), bytes.NewReader(payload)); err != nil { t.Fatal(err) }
	return id, frame.Bytes()
}

func TestCanonicalTextDiffMatchesVerifiedPayloads(t *testing.T) {
	for _, pair := range [][2]string{{"", ""}, {"a\n", "A\n"}, {"a", "a\n"}, {"\xff\r\na", "\xff\r\nA"}, {"same", "same"}} {
		oldID, oldFrame := canonicalDiffBlob(t, []byte(pair[0]))
		nextID, nextFrame := canonicalDiffBlob(t, []byte(pair[1]))
		budget := TextDiffBudget{InputBytes: 1024, OutputBytes: 1024, Lines: 100, Context: 1}
		want, err := DiffText(context.Background(), []byte(pair[0]), []byte(pair[1]), budget)
		if err != nil { t.Fatal(err) }
		got, err := DiffCanonicalText(context.Background(), oldID, nextID, oldFrame, nextFrame, budget)
		if err != nil || !bytes.Equal(got.Hunk, want.Hunk) || got.OldFinalNewline != want.OldFinalNewline || got.NewFinalNewline != want.NewFinalNewline { t.Fatal(pair, got, want, err) }
	}
}

func TestCanonicalTextDiffFailsBeforeResult(t *testing.T) {
	oldID, oldFrame := canonicalDiffBlob(t, []byte("a\n"))
	nextID, nextFrame := canonicalDiffBlob(t, []byte("A\n"))
	badOld := append([]byte(nil), oldFrame...); badOld[len(badOld)-1] ^= 1
	badNext := append([]byte(nil), nextFrame...); badNext[len(badNext)-1] ^= 1
	for _, tc := range []struct { oldID, nextID model.BlobID; old, next []byte }{
		{oldID, nextID, badOld, nextFrame}, {oldID, nextID, oldFrame, badNext},
		{oldID, nextID, oldFrame[:len(oldFrame)-1], nextFrame}, {oldID, nextID, oldFrame, nextFrame[:len(nextFrame)-1]},
		{oldID, nextID, append(append([]byte(nil), oldFrame...), 0), nextFrame},
		{oldID, nextID, oldFrame, append(append([]byte(nil), nextFrame...), 0)},
		{oldID, oldID, oldFrame, badOld}, // Equal IDs must not skip verification.
		{nextID, nextID, oldFrame, nextFrame}, {oldID, model.BlobID{}, oldFrame, nextFrame},
	} {
		got, err := DiffCanonicalText(context.Background(), tc.oldID, tc.nextID, tc.old, tc.next, TextDiffBudget{100, 100, 100, 1})
		if err == nil || got.Hunk != nil || got.OldFinalNewline || got.NewFinalNewline { t.Fatal(got, err) }
	}
	for _, budget := range []TextDiffBudget{{}, {3, 100, 10, 0}, {4, 1, 10, 0}, {4, 100, 1, 0}, {4, 100, 1, 2}} {
		got, err := DiffCanonicalText(context.Background(), oldID, nextID, oldFrame, nextFrame, budget)
		if !errors.Is(err, ErrDiffLimit) || got.Hunk != nil || got.OldFinalNewline || got.NewFinalNewline { t.Fatal(budget, got, err) }
	}
	if _, err := DiffCanonicalText(context.Background(), oldID, nextID, oldFrame, nextFrame, TextDiffBudget{4, 100, 2, 0}); err != nil { t.Fatal("exact combined payload budget", err) }
	emptyID, emptyFrame := canonicalDiffBlob(t, nil)
	if got, err := DiffCanonicalText(context.Background(), oldID, emptyID, oldFrame, emptyFrame, TextDiffBudget{2, 100, 1, 0}); err != nil || got.Hunk == nil || !got.OldFinalNewline || got.NewFinalNewline { t.Fatal("zero remaining payload budget", got, err) }
	binaryID, binaryFrame := canonicalDiffBlob(t, []byte{0})
	if got, err := DiffCanonicalText(context.Background(), oldID, binaryID, oldFrame, binaryFrame, TextDiffBudget{100, 100, 100, 0}); !errors.Is(err, ErrDiffBinary) || got.Hunk != nil || got.OldFinalNewline || got.NewFinalNewline { t.Fatal(got, err) }
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if got, err := DiffCanonicalText(ctx, oldID, nextID, oldFrame, nextFrame, TextDiffBudget{100, 100, 100, 0}); !errors.Is(err, context.Canceled) || got.Hunk != nil { t.Fatal(got, err) }
	if got, err := DiffCanonicalText(nil, oldID, nextID, oldFrame, nextFrame, TextDiffBudget{100, 100, 100, 0}); !errors.Is(err, ErrDiffInput) || got.Hunk != nil { t.Fatal(got, err) }
}

func TestFileEntryDiffBudgetAdmission(t *testing.T) {
	// Empty selections cannot exhaust input or output budgets: each rejection
	// below must come from the budget's admission constraint itself.
	for _, tc := range []struct {
		name   string
		budget FileDiffBudget
	}{
		{"entries-above-maximum", FileDiffBudget{1000001, 1, 1}},
		{"path-bytes-above-maximum", FileDiffBudget{1, (64 << 20) + 1, 1}},
		{"changes-above-entries", FileDiffBudget{1, 1, 2}},
		{"zero-entries", FileDiffBudget{0, 1, 1}},
		{"zero-path-bytes", FileDiffBudget{1, 0, 1}},
		{"zero-changes", FileDiffBudget{1, 1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DiffFileEntries(context.Background(), nil, nil, tc.budget)
			if got != nil || !errors.Is(err, ErrFileDiffLimit) {
				t.Fatalf("budget %+v admitted: deltas=%v err=%v", tc.budget, got, err)
			}
		})
	}
	t.Run("exact-maxima", func(t *testing.T) {
		got, err := DiffFileEntries(context.Background(), nil, nil, FileDiffBudget{1000000, 64 << 20, 1000000})
		if err != nil || len(got) != 0 {
			t.Fatalf("maximum budget rejected: deltas=%v err=%v", got, err)
		}
	})
}

func privateDiffTree(t *testing.T, rows []model.Operation) (derived.TreePageID, map[derived.TreePageID][]byte) {
	t.Helper()
	empty, root, err := derived.EncodeTreePageAt(derived.UnlinkedTreePage{}, nil, nil)
	if err != nil { t.Fatal(err) }
	frames := map[derived.TreePageID][]byte{root: empty}
	for _, row := range rows {
		blob, _ := row.Target()
		next, added, err := derived.SetTreeLeaf(context.Background(), root, frames, row.Path(), byte(row.Tag()), blob, derived.TreeRewriteBudget{4096, 4096*derived.MaxTreePageBytes, 4096*derived.MaxTreePageBytes})
		if err != nil { t.Fatal(err) }
		for id, frame := range added { frames[id] = frame }; root = next
	}
	return root, frames
}

func privateDiffBudget() PrivateTreeDiffBudget {
	side := derived.TreeEntriesBudget{Graph: derived.TreeGraphBudget{4096, 4096*derived.MaxTreePageBytes, 64<<20}, Entries: 4096, PathBytes: 64<<20}
	return PrivateTreeDiffBudget{Side: [2]derived.TreeEntriesBudget{side, side}, Compare: FileDiffBudget{8192, 64<<20, 8192}}
}

func TestPrivateTreeDiffMatchesFileEntries(t *testing.T) {
	makeRow := func(path string, tag model.OperationTag, digest byte) model.Operation {
		p, err := model.NewPath([]byte(path)); if err != nil { t.Fatal(err) }
		tid, err := model.NewTypedID(model.BlobKind, [32]byte{digest}); if err != nil { t.Fatal(err) }
		blob, err := model.NewBlobID(tid); if err != nil { t.Fatal(err) }
		op, err := model.NewOperation(p, tag, &blob); if err != nil { t.Fatal(err) }; return op
	}
	before := []model.Operation{makeRow("a.", model.SetRegular, 1), makeRow("a/b", model.SetRegular, 1), makeRow("a0", model.SetSymlink, 2)}
	after := []model.Operation{makeRow("a/b", model.SetExecutable, 3), makeRow("a0", model.SetSymlink, 2), makeRow("\xff", model.SetRegular, 2)}
	for _, sides := range [][2][]model.Operation{{nil, nil}, {nil, after}, {before, nil}, {before, after}, {after, before}, {before, before}} {
		var roots [2]derived.TreePageID; var frames [2]map[derived.TreePageID][]byte
		for i := range roots { roots[i], frames[i] = privateDiffTree(t, sides[i]) }
		want, err := DiffFileEntries(context.Background(), sides[0], sides[1], privateDiffBudget().Compare); if err != nil { t.Fatal(err) }
		got, usage, err := DiffPrivateTrees(context.Background(), roots, frames, privateDiffBudget())
		if err != nil || len(got) != len(want) || usage[0].Visits == 0 || usage[1].Visits == 0 { t.Fatal(got, usage, err) }
		for i := range want { if got[i] != want[i] { t.Fatal("tree/entry diff mismatch", got[i], want[i]) } }
		// Each side must be verified even for equal roots; second map is missing.
		if roots[0] == roots[1] {
			frames[1] = nil
			if got, _, err := DiffPrivateTrees(context.Background(), roots, frames, privateDiffBudget()); err != derived.ErrTreePageMissing || got != nil { t.Fatal(got, err) }
		}
	}
	root, frames := privateDiffTree(t, after)
	roots, both := [2]derived.TreePageID{root, root}, [2]map[derived.TreePageID][]byte{frames, frames}
	for side := 0; side < 2; side++ {
		budget := privateDiffBudget(); budget.Side[side].Entries = 1
		if got, _, err := DiffPrivateTrees(context.Background(), roots, both, budget); err != metadata.ErrResourceExhausted || got != nil { t.Fatal(side, got, err) }
	}
	budget := privateDiffBudget(); budget.Compare.Entries = 1; budget.Compare.Changes = 1
	if got, usage, err := DiffPrivateTrees(context.Background(), roots, both, budget); err != ErrFileDiffLimit || got != nil || usage[1].Visits == 0 { t.Fatal(got, usage, err) }
	budget.Compare = FileDiffBudget{}
	if got, usage, err := DiffPrivateTrees(context.Background(), roots, both, budget); err != ErrFileDiffLimit || got != nil || usage != [2]derived.TreeGraphUsage{} { t.Fatal(got, usage, err) }
	if got, _, err := DiffPrivateTrees(nil, roots, both, privateDiffBudget()); err != ErrFileDiffInput || got != nil { t.Fatal(got, err) }
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if got, _, err := DiffPrivateTrees(ctx, roots, both, privateDiffBudget()); err != context.Canceled || got != nil { t.Fatal(got, err) }
}

func TestPrivateExactPathDiff(t *testing.T) {
	path, err := model.NewPath([]byte("dir/\xff")); if err != nil { t.Fatal(err) }
	makeRow := func(tag model.OperationTag, digest byte) model.Operation {
		tid, _ := model.NewTypedID(model.BlobKind, [32]byte{digest}); blob, _ := model.NewBlobID(tid)
		op, err := model.NewOperation(path, tag, &blob); if err != nil { t.Fatal(err) }; return op
	}
	regular, executable, symlink := makeRow(model.SetRegular, 1), makeRow(model.SetExecutable, 2), makeRow(model.SetSymlink, 3)
	states := [][]model.Operation{nil, {regular}, {executable}, {symlink}, {makeRow(model.SetExecutable, 1)}, {makeRow(model.SetRegular, 2)}}
	budget := [2]derived.TreeLookupBudget{{4096, 4096*derived.MaxTreePageBytes}, {4096, 4096*derived.MaxTreePageBytes}}
	for _, before := range states {
		for _, after := range states {
			var roots [2]derived.TreePageID; var frames [2]map[derived.TreePageID][]byte
			roots[0], frames[0] = privateDiffTree(t, before); roots[1], frames[1] = privateDiffTree(t, after)
			want, err := DiffFileEntries(context.Background(), before, after, FileDiffBudget{2, 131070, 1}); if err != nil { t.Fatal(err) }
			got, usage, err := DiffPrivateTreePath(context.Background(), roots, frames, path, budget)
			if err != nil || len(got) != len(want) || usage[0].Pages == 0 || usage[1].Pages == 0 { t.Fatal(got, usage, err) }
			if len(want) == 1 && got[0] != want[0] { t.Fatal(got, want) }
			if roots[0] == roots[1] {
				frames[1] = nil
				if got, _, err := DiffPrivateTreePath(context.Background(), roots, frames, path, budget); got != nil || err != derived.ErrTreePageMissing { t.Fatal(got, err) }
			}
		}
	}
	root, frames := privateDiffTree(t, []model.Operation{regular})
	roots, both := [2]derived.TreePageID{root, root}, [2]map[derived.TreePageID][]byte{frames, frames}
	dir, _ := model.NewPath([]byte("dir"))
	if got, _, err := DiffPrivateTreePath(context.Background(), roots, both, dir, budget); got != nil || err != nil { t.Fatal("directory is not a file leaf", got, err) }
	for side := 0; side < 2; side++ {
		limited := budget; limited[side].ReadBytes = 1
		if got, _, err := DiffPrivateTreePath(context.Background(), roots, both, path, limited); got != nil || err != metadata.ErrResourceExhausted { t.Fatal(got, err) }
		bad := [2]map[derived.TreePageID][]byte{frames, frames}
		bad[side] = make(map[derived.TreePageID][]byte)
		for id, frame := range frames { bad[side][id] = frame }
		corrupt := append([]byte(nil), frames[root]...); corrupt[0] ^= 1; bad[side][root] = corrupt
		if got, _, err := DiffPrivateTreePath(context.Background(), roots, bad, path, budget); got != nil || err != derived.ErrTreePage { t.Fatal(got, err) }
	}
	if got, _, err := DiffPrivateTreePath(nil, roots, both, path, budget); got != nil || err != ErrFileDiffInput { t.Fatal(got, err) }
	if got, _, err := DiffPrivateTreePath(context.Background(), roots, both, model.Path{}, budget); got != nil || err != ErrFileDiffInput { t.Fatal(got, err) }
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if got, _, err := DiffPrivateTreePath(ctx, roots, both, path, budget); got != nil || err != context.Canceled { t.Fatal(got, err) }
}
