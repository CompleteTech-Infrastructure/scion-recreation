package edit

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"canopy.local/canopy/internal/model"
)

func fileFixture(t *testing.T, mode model.OperationTag, content string) FileVersion {
	t.Helper()
	v, err := PresentFile(mode, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestWholeFileMergeDecisions(t *testing.T) {
	absent := AbsentFile()
	a := fileFixture(t, model.SetRegular, "a\r\n")
	b := fileFixture(t, model.SetRegular, "b\n")
	binary := fileFixture(t, model.SetRegular, "\x00\xff")
	link := fileFixture(t, model.SetSymlink, "../raw\xff")
	exec := fileFixture(t, model.SetExecutable, "a\r\n")
	for _, tc := range []struct {
		name string
		base, left, right, want FileVersion
		conflict bool
	}{
		{"unchanged", a, a, a, a, false},
		{"one-side-edit", a, a, b, b, false},
		{"identical-edit", a, b, b, b, false},
		{"one-side-delete", a, a, absent, absent, false},
		{"both-delete", a, absent, absent, absent, false},
		{"one-side-add", absent, absent, binary, binary, false},
		{"identical-add", absent, link, link, link, false},
		{"mode-only", a, a, exec, exec, false},
		{"delete-modify", a, absent, b, FileVersion{}, true},
		{"distinct-add", absent, a, b, FileVersion{}, true},
		{"type-change", a, link, exec, FileVersion{}, true},
		{"mode-versus-bytes", a, exec, b, FileVersion{}, true},
		{"binary-versus-text", a, binary, b, FileVersion{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, swap := range []bool{false, true} {
				left, right := tc.left, tc.right
				if swap {
					left, right = right, left
				}
				got, c, err := MergeFileVersions(context.Background(), tc.base, left, right, 1024)
				if err != nil || got != tc.want || (c != nil) != tc.conflict {
					t.Fatalf("swap=%v result=%v conflict=%v err=%v", swap, got, c, err)
				}
				if c != nil && *c != (FileConflict{tc.base, left, right}) {
					t.Fatal("conflict rewrote exact side states")
				}
			}
		})
	}
}

func TestFileStatePresenceOwnershipAndBudgets(t *testing.T) {
	if _, err := PresentFile(model.SetRegular, nil); !errors.Is(err, ErrFileState) {
		t.Fatal("missing content accepted")
	}
	for _, mode := range []model.OperationTag{model.Delete, 255} {
		if _, err := PresentFile(mode, []byte{}); !errors.Is(err, ErrFileState) {
			t.Fatal("invalid present mode accepted")
		}
	}
	empty := fileFixture(t, model.SetRegular, "")
	content, present := empty.Content()
	if !present || content == nil || len(content) != 0 || empty.IsAbsent() || !AbsentFile().IsAbsent() {
		t.Fatal("empty and absent conflated")
	}
	got, c, err := MergeFileVersions(context.Background(), AbsentFile(), empty, AbsentFile(), 0)
	if err != nil || c != nil || got != empty {
		t.Fatal("zero budget rejected empty content")
	}
	input := []byte{0, 255}
	owned, err := PresentFile(model.SetSymlink, input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 1
	out, _ := owned.Content()
	out[0] = 2
	again, _ := owned.Content()
	if !bytes.Equal(again, []byte{0, 255}) {
		t.Fatal("file value aliases caller bytes")
	}
	if mode, ok := owned.Mode(); !ok || mode != model.SetSymlink {
		t.Fatal("symlink mode changed")
	}
	for _, budget := range []uint64{5, 65 << 20} {
		got, c, err := MergeFileVersions(context.Background(), owned, owned, owned, budget)
		if !errors.Is(err, ErrFileBudget) || got != (FileVersion{}) || c != nil {
			t.Fatal("budget failure exposed a result")
		}
	}
	for i := 0; i < 3; i++ {
		states := []FileVersion{empty, empty, empty}
		states[i] = FileVersion{}
		got, c, err := MergeFileVersions(context.Background(), states[0], states[1], states[2], 0)
		if !errors.Is(err, ErrFileState) || got != (FileVersion{}) || c != nil {
			t.Fatal("missing side admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, c, err := MergeFileVersions(ctx, empty, empty, empty, 0); !errors.Is(err, context.Canceled) || got != (FileVersion{}) || c != nil {
		t.Fatal("cancellation exposed result")
	}
	if _, _, err := MergeFileVersions(nil, empty, empty, empty, 0); !errors.Is(err, ErrFileState) {
		t.Fatal("nil context accepted")
	}
}

func TestTextFileMergeComposition(t *testing.T) {
	regular := func(s string) FileVersion { return fileFixture(t, model.SetRegular, s) }
	executable := func(s string) FileVersion { return fileFixture(t, model.SetExecutable, s) }
	link := func(s string) FileVersion { return fileFixture(t, model.SetSymlink, s) }
	base := regular("a\nb\n")
	for _, tc := range []struct { name string; base, left, right, want FileVersion; conflict bool }{
		{"disjoint-content", base, regular("A\nb\n"), regular("a\nB\n"), regular("A\nB\n"), false},
		{"mode-and-content", base, executable("a\nb\n"), regular("A\nb\n"), executable("A\nb\n"), false},
		{"same-mode-both-content", base, executable("A\nb\n"), executable("a\nB\n"), executable("A\nB\n"), false},
		{"mode-revert-and-content", executable("a\nb\n"), regular("a\nb\n"), executable("A\nb\n"), regular("A\nb\n"), false},
		{"empty-after-delete-lines", base, regular("b\n"), regular("a\n"), regular(""), false},
		{"raw-newline", regular("\xff\r\nb"), regular("\xff\r\nB"), executable("\xff\r\nb"), executable("\xff\r\nB"), false},
		{"identical", base, regular("x"), regular("x"), regular("x"), false},
		{"delete-modify", base, AbsentFile(), regular("A\nb\n"), FileVersion{}, true},
		{"distinct-additions", AbsentFile(), regular("a"), regular("b"), FileVersion{}, true},
		{"symlink-content", link("a\nb\n"), link("A\nb\n"), link("a\nB\n"), FileVersion{}, true},
		{"type-content", base, link("a\nb\n"), regular("A\nb\n"), FileVersion{}, true},
		{"overlap", base, regular("A\nb\n"), regular("Z\nb\n"), FileVersion{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, swap := range []bool{false, true} {
				left, right := tc.left, tc.right
				if swap { left, right = right, left }
				got, conflict, err := MergeTextFileVersions(context.Background(), tc.base, left, right, ThreeWayTextBudget{1024, 100, 10000, 100})
				if err != nil || got != tc.want || (conflict != nil) != tc.conflict { t.Fatal(got, conflict, err) }
				if conflict != nil && *conflict != (FileConflict{tc.base, left, right}) { t.Fatal("conflict lost exact states") }
			}
		})
	}
}

func TestTextFileMergeErrorsAndOpaqueFastPath(t *testing.T) {
	base := fileFixture(t, model.SetRegular, "a\nb\n")
	left := fileFixture(t, model.SetRegular, "A\nb\n")
	right := fileFixture(t, model.SetRegular, "a\nB\n")
	for _, tc := range []struct { budget ThreeWayTextBudget; want error }{
		{ThreeWayTextBudget{}, ErrTextLimit}, {ThreeWayTextBudget{11, 6, 8, 2}, ErrFileBudget},
		{ThreeWayTextBudget{12, 5, 8, 2}, ErrTextLimit}, {ThreeWayTextBudget{12, 6, 7, 2}, ErrTextLimit}, {ThreeWayTextBudget{12, 6, 8, 1}, ErrTextLimit},
	} {
		got, conflict, err := MergeTextFileVersions(context.Background(), base, left, right, tc.budget)
		if got.Validate() == nil || conflict != nil || !errors.Is(err, tc.want) { t.Fatal(tc, got, conflict, err) }
	}
	// Fast paths still admit all bytes but do not consume text work budgets.
	if got, conflict, err := MergeTextFileVersions(context.Background(), base, left, left, ThreeWayTextBudget{11, 1, 1, 1}); got.Validate() == nil || conflict != nil || !errors.Is(err, ErrFileBudget) { t.Fatal(got, conflict, err) }
	if got, conflict, err := MergeTextFileVersions(context.Background(), base, left, left, ThreeWayTextBudget{12, 1, 1, 1}); err != nil || conflict != nil || got != left { t.Fatal(got, conflict, err) }
	if got, conflict, err := MergeTextFileVersions(context.Background(), base, left, right, ThreeWayTextBudget{12, 6, 8, 2}); err != nil || conflict != nil || got != fileFixture(t, model.SetRegular, "A\nB\n") { t.Fatal(got, conflict, err) }
	for _, tc := range []struct { ctx context.Context; base FileVersion; want error }{
		{nil, base, ErrFileState}, {context.Background(), FileVersion{}, ErrFileState},
	} {
		got, conflict, err := MergeTextFileVersions(tc.ctx, tc.base, left, right, ThreeWayTextBudget{100, 100, 100, 100})
		if got.Validate() == nil || conflict != nil || !errors.Is(err, tc.want) { t.Fatal(got, conflict, err) }
	}
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if got, conflict, err := MergeTextFileVersions(ctx, base, left, right, ThreeWayTextBudget{100, 100, 100, 100}); got.Validate() == nil || conflict != nil || !errors.Is(err, context.Canceled) { t.Fatal(got, conflict, err) }
	a := fileFixture(t, model.SetRegular, "\x00")
	b := fileFixture(t, model.SetRegular, "\x00a")
	c := fileFixture(t, model.SetRegular, "\x00b")
	if got, conflict, err := MergeTextFileVersions(context.Background(), a, b, c, ThreeWayTextBudget{100, 100, 100, 100}); got.Validate() == nil || conflict != nil || !errors.Is(err, ErrTextInput) { t.Fatal(got, conflict, err) }
	// Unchanged/identical whole-file fast paths never parse or normalize bytes.
	if got, conflict, err := MergeTextFileVersions(context.Background(), a, b, b, ThreeWayTextBudget{100, 100, 100, 100}); err != nil || conflict != nil || got != b { t.Fatal(got, conflict, err) }
}

func TestCanonicalFileMergeStateMatrix(t *testing.T) {
	states := []FileVersion{AbsentFile(), fileFixture(t, model.SetRegular, ""), fileFixture(t, model.SetRegular, "a\x00"), fileFixture(t, model.SetExecutable, "a\x00"), fileFixture(t, model.SetSymlink, "../x")}
	for _, base := range states { for _, left := range states { for _, right := range states {
		versions := [3]FileVersion{base, left, right}
		var sides [3]CanonicalFileSide
		for i, v := range versions {
			if v.IsAbsent() { continue }
			content, _ := v.Content(); mode, _ := v.Mode()
			ids, frames := canonicalMergeInputs(t, [3]string{string(content), "", ""})
			sides[i] = CanonicalFileSide{true, mode, ids[0], frames[0]}
		}
		want, conflict, err := MergeFileVersions(context.Background(), base, left, right, 100); if err != nil { t.Fatal(err) }
		got, gotConflict, err := MergeCanonicalFileVersions(context.Background(), sides, 100)
		if err != nil || got != want || (gotConflict == nil) != (conflict == nil) { t.Fatal(versions, got, gotConflict, err) }
		if conflict != nil && *conflict != *gotConflict { t.Fatal(gotConflict, conflict) }
	} } }
}

func TestCanonicalFileMergeRejectsUnverifiedStates(t *testing.T) {
	ids, frames := canonicalMergeInputs(t, [3]string{"a", "a", "a"})
	var sides [3]CanonicalFileSide
	for i := range sides { sides[i] = CanonicalFileSide{true, model.SetRegular, ids[i], frames[i]} }
	for i := range sides {
		for mode := 0; mode < 5; mode++ {
			bad := sides
			switch mode {
			case 0: bad[i].Frame = append([]byte(nil), frames[i]...); bad[i].Frame[len(bad[i].Frame)-1] ^= 1
			case 1: bad[i].Frame = frames[i][:len(frames[i])-1]
			case 2: bad[i].ID = model.BlobID{}
			case 3: bad[i].Mode = model.Delete
			case 4: bad[i].Present = false
			}
			got, conflict, err := MergeCanonicalFileVersions(context.Background(), bad, 100)
			if err == nil || got != (FileVersion{}) || conflict != nil { t.Fatal(i, mode, got, conflict, err) }
		}
	}
	if got, conflict, err := MergeCanonicalFileVersions(context.Background(), sides, 2); err != ErrFileBudget || got != (FileVersion{}) || conflict != nil { t.Fatal(got, conflict, err) }
	if got, conflict, err := MergeCanonicalFileVersions(context.Background(), sides, 3); err != nil || conflict != nil || got != fileFixture(t, model.SetRegular, "a") { t.Fatal(got, conflict, err) }
	emptyIDs, emptyFrames := canonicalMergeInputs(t, [3]string{"", "", ""})
	empty := [3]CanonicalFileSide{{}, {true, model.SetRegular, emptyIDs[1], emptyFrames[1]}, {}}
	if got, conflict, err := MergeCanonicalFileVersions(context.Background(), empty, 0); err != nil || conflict != nil || got.IsAbsent() || got != fileFixture(t, model.SetRegular, "") { t.Fatal("present-empty became absent", got, conflict, err) }
	empty[0].Frame = []byte{}
	if got, conflict, err := MergeCanonicalFileVersions(context.Background(), empty, 0); err != ErrFileState || got != (FileVersion{}) || conflict != nil { t.Fatal(got, conflict, err) }
	if got, conflict, err := MergeCanonicalFileVersions(nil, sides, 100); err != ErrFileState || got != (FileVersion{}) || conflict != nil { t.Fatal(got, conflict, err) }
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if got, conflict, err := MergeCanonicalFileVersions(ctx, sides, 100); err != context.Canceled || got != (FileVersion{}) || conflict != nil { t.Fatal(got, conflict, err) }
}

func TestCanonicalTextFileMergeParity(t *testing.T) {
	reg := func(s string) FileVersion { return fileFixture(t, model.SetRegular, s) }
	exec := func(s string) FileVersion { return fileFixture(t, model.SetExecutable, s) }
	link := func(s string) FileVersion { return fileFixture(t, model.SetSymlink, s) }
	for _, v := range [][3]FileVersion{
		{reg("a\nb\nc\n"), exec("A\nb\nc\n"), reg("a\nb\nC\n")},
		{reg("a"), reg("b"), reg("c")}, {reg("a"), AbsentFile(), reg("b")},
		{AbsentFile(), reg("a"), reg("b")}, {reg("a"), link("a"), reg("b")},
		{link("a"), link("b"), link("c")}, {AbsentFile(), reg(""), AbsentFile()},
		{reg("a\x00"), reg("a\x00"), exec("b\x00")},
		{reg("a\x00"), reg("b\x00"), reg("c\x00")},
		{reg("\xff\r\na"), reg("\xff\r\nA"), exec("\xff\r\na")},
	} {
		var sides [3]CanonicalFileSide
		for i, version := range v {
			if version.IsAbsent() { continue }
			content, _ := version.Content(); mode, _ := version.Mode()
			ids, frames := canonicalMergeInputs(t, [3]string{string(content), "", ""})
			sides[i] = CanonicalFileSide{true, mode, ids[0], frames[0]}
		}
		budget := ThreeWayTextBudget{1024, 100, 1000, 100}
		want, conflict, wantErr := MergeTextFileVersions(context.Background(), v[0], v[1], v[2], budget)
		got, gotConflict, err := MergeCanonicalTextFileVersions(context.Background(), sides, budget)
		if !errors.Is(err, wantErr) || got != want || (gotConflict == nil) != (conflict == nil) { t.Fatal(v, got, gotConflict, err, wantErr) }
		if conflict != nil && *conflict != *gotConflict { t.Fatal(conflict, gotConflict) }
	}
}

func TestCanonicalTextFileMergeVerificationAndAdmission(t *testing.T) {
	ids, frames := canonicalMergeInputs(t, [3]string{"a", "a", "a"})
	var sides [3]CanonicalFileSide
	for i := range sides { sides[i] = CanonicalFileSide{true, model.SetRegular, ids[i], frames[i]} }
	for i := range sides {
		bad := sides; bad[i].Frame = append([]byte(nil), frames[i]...); bad[i].Frame[len(bad[i].Frame)-1] ^= 1
		got, conflict, err := MergeCanonicalTextFileVersions(context.Background(), bad, ThreeWayTextBudget{3, 1, 1, 1})
		if err == nil || got != (FileVersion{}) || conflict != nil { t.Fatal(i, got, conflict, err) }
	}
	for _, budget := range []ThreeWayTextBudget{{}, {3, 0, 1, 1}, {3, 1, 4000001, 1}, {65<<20, 1, 1, 1}} {
		got, conflict, err := MergeCanonicalTextFileVersions(context.Background(), sides, budget)
		if err != ErrTextLimit || got != (FileVersion{}) || conflict != nil { t.Fatal(got, conflict, err) }
	}
	if got, conflict, err := MergeCanonicalTextFileVersions(context.Background(), sides, ThreeWayTextBudget{2, 1, 1, 1}); err != ErrFileBudget || got != (FileVersion{}) || conflict != nil { t.Fatal(got, conflict, err) }
	// Three input lines exceed Lines=1, but verified whole-file equality needs
	// no text analysis; work admission is intentionally not consumed here.
	if got, conflict, err := MergeCanonicalTextFileVersions(context.Background(), sides, ThreeWayTextBudget{3, 1, 1, 1}); err != nil || conflict != nil || got != fileFixture(t, model.SetRegular, "a") { t.Fatal(got, conflict, err) }
	if got, conflict, err := MergeCanonicalTextFileVersions(nil, sides, ThreeWayTextBudget{3, 1, 1, 1}); err != ErrFileState || got != (FileVersion{}) || conflict != nil { t.Fatal(got, conflict, err) }
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if got, conflict, err := MergeCanonicalTextFileVersions(ctx, sides, ThreeWayTextBudget{3, 1, 1, 1}); err != context.Canceled || got != (FileVersion{}) || conflict != nil { t.Fatal(got, conflict, err) }
}

func TestPrepareFileOperationCanonicalRoundTrip(t *testing.T) {
	path, err := model.NewPath([]byte("dir/\xff")); if err != nil { t.Fatal(err) }
	for _, mode := range []model.OperationTag{model.SetRegular, model.SetExecutable, model.SetSymlink} {
		for _, content := range []string{"", "a\x00b", "\xff\r\na", "../target"} {
			version := fileFixture(t, mode, content)
			got, err := PrepareFileOperation(context.Background(), path, version, uint64(len(content)))
			if err != nil || got.Operation.Path() != path || got.Operation.Tag() != mode || len(got.BlobFrame) != len(content)+22 { t.Fatal(got, err) }
			id, present := got.Operation.Target(); if !present { t.Fatal("SET target missing") }
			var decoded bytes.Buffer
			n, err := model.DecodeBlob(context.Background(), bytes.NewReader(got.BlobFrame), id, &decoded, uint64(len(content)))
			if err != nil || n != uint64(len(content)) || decoded.String() != content { t.Fatal(n, err) }
			again, err := PrepareFileOperation(context.Background(), path, version, uint64(len(content)))
			if err != nil || again.Operation != got.Operation || !bytes.Equal(again.BlobFrame, got.BlobFrame) { t.Fatal("not deterministic", err) }
			got.BlobFrame[0] ^= 1
			original, _ := version.Content()
			if string(original) != content || again.BlobFrame[0] == got.BlobFrame[0] { t.Fatal("frame aliases immutable input or another output") }
		}
	}
	deleted, err := PrepareFileOperation(context.Background(), path, AbsentFile(), 0)
	if err != nil || deleted.Operation.Path() != path || deleted.Operation.Tag() != model.Delete || deleted.BlobFrame != nil { t.Fatal(deleted, err) }
	if _, ok := deleted.Operation.Target(); ok { t.Fatal("DELETE carried target") }
}

func TestPrepareFileOperationRejectsBeforeOutput(t *testing.T) {
	path, err := model.NewPath([]byte("file")); if err != nil { t.Fatal(err) }
	version := fileFixture(t, model.SetRegular, "abc")
	for _, tc := range []struct { path model.Path; version FileVersion; limit uint64; want error }{
		{path, version, 2, ErrFileBudget}, {path, version, 65<<20, ErrFileBudget},
		{model.Path{}, version, 3, ErrFileState}, {path, FileVersion{}, 3, ErrFileState},
	} {
		got, err := PrepareFileOperation(context.Background(), tc.path, tc.version, tc.limit)
		if err != tc.want || got.Operation != (model.Operation{}) || got.BlobFrame != nil { t.Fatal(got, err) }
	}
	if got, err := PrepareFileOperation(nil, path, version, 3); err != ErrFileState || got.Operation != (model.Operation{}) || got.BlobFrame != nil { t.Fatal(got, err) }
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if got, err := PrepareFileOperation(ctx, path, version, 3); err != context.Canceled || got.Operation != (model.Operation{}) || got.BlobFrame != nil { t.Fatal(got, err) }
}

func TestPrepareFileOperationsSharedAdmissionAndOwnership(t *testing.T) {
	var entries []ResolvedFileEntry
	for i, state := range []FileVersion{AbsentFile(), fileFixture(t, model.SetRegular, ""), fileFixture(t, model.SetExecutable, "ab"), fileFixture(t, model.SetSymlink, "ab")} {
		path, err := model.NewPath([]byte{byte('a'+i)}); if err != nil { t.Fatal(err) }
		entries = append(entries, ResolvedFileEntry{path, state})
	}
	budget := FilePreparationBudget{4, 4, 4, 70} // 3 headers + two 2-byte payloads.
	got, err := PrepareFileOperations(context.Background(), entries, budget)
	if err != nil || len(got) != 4 { t.Fatal(got, err) }
	for i, entry := range entries {
		want, err := PrepareFileOperation(context.Background(), entry.Path, entry.Version, uint64(len(entry.Version.content)))
		if err != nil || got[i].Operation != want.Operation || !bytes.Equal(got[i].BlobFrame, want.BlobFrame) { t.Fatal(i, got[i], want, err) }
	}
	if got[0].BlobFrame != nil || len(got[1].BlobFrame) != 22 { t.Fatal("absence/empty conflated") }
	left, _ := got[2].Operation.Target(); right, _ := got[3].Operation.Target()
	if left != right || got[2].Operation.Tag() == got[3].Operation.Tag() { t.Fatal("identity/mode mismatch") }
	got[2].BlobFrame[0] ^= 1
	if got[2].BlobFrame[0] == got[3].BlobFrame[0] { t.Fatal("duplicate content shares mutable frame") }
	for _, b := range []FilePreparationBudget{{3,4,4,70}, {4,3,4,70}, {4,4,3,70}, {4,4,4,69}} {
		if out, err := PrepareFileOperations(context.Background(), entries, b); err != ErrFileBudget || out != nil { t.Fatal(b, out, err) }
	}
	if out, err := PrepareFileOperations(context.Background(), entries[:1], FilePreparationBudget{1,1,0,0}); err != nil || len(out) != 1 || out[0].BlobFrame != nil { t.Fatal(out, err) }
	if out, err := PrepareFileOperations(context.Background(), nil, FilePreparationBudget{1,1,0,0}); err != nil || out != nil { t.Fatal(out, err) }
	for _, bad := range [][]ResolvedFileEntry{{entries[0], entries[0]}, {entries[1], entries[0]}, {entries[0], {entries[1].Path, FileVersion{}}}, {{model.Path{}, AbsentFile()}}} {
		if out, err := PrepareFileOperations(context.Background(), bad, budget); err != ErrFileState || out != nil { t.Fatal(out, err) }
	}
	if out, err := PrepareFileOperations(nil, entries, budget); err != ErrFileState || out != nil { t.Fatal(out, err) }
}

// Cancel after the first complete candidate has been appended; a second entry
// context check must discard it. The threshold is discovered via a baseline
// one-entry call, avoiding dependence on codec check counts.
type preparationCancelContext struct { context.Context; calls, cancelAt int }
func (c *preparationCancelContext) Err() error {
	c.calls++
	if c.cancelAt > 0 && c.calls >= c.cancelAt { return context.Canceled }
	return nil
}

func TestPrepareFileOperationsLateCancellationDiscardsPrefix(t *testing.T) {
	a, _ := model.NewPath([]byte("a")); b, _ := model.NewPath([]byte("b"))
	state := fileFixture(t, model.SetRegular, "content")
	budget := FilePreparationBudget{2,2,14,58}
	baseline := &preparationCancelContext{Context: context.Background()}
	if out, err := PrepareFileOperations(baseline, []ResolvedFileEntry{{a,state}}, budget); err != nil || len(out) != 1 { t.Fatal(out, err) }
	// Extra preflight row adds one Err call; the single-call final check is
	// replaced by the second PrepareFileOperation entry check at this offset.
	late := &preparationCancelContext{Context: context.Background(), cancelAt: baseline.calls+1}
	if out, err := PrepareFileOperations(late, []ResolvedFileEntry{{a,state},{b,state}}, budget); err != context.Canceled || out != nil { t.Fatal(out, err) }
}

func TestMergeFileEntriesCollectsAllConflictsWithoutPartialResolution(t *testing.T) {
	path := func(s string) model.Path { p, err := model.NewPath([]byte(s)); if err != nil { t.Fatal(err) }; return p }
	a, b, c := fileFixture(t, model.SetRegular, "a"), fileFixture(t, model.SetRegular, "b"), fileFixture(t, model.SetRegular, "c")
	entries := []FileMergeEntry{
		{path("A"), a, b, c},
		{path("a"), a, a, b},
		{path("\xff"), a, AbsentFile(), c},
	}
	got, conflicts, err := MergeFileEntries(context.Background(), entries, FileMergeBudget{3,3,8})
	if err != nil || got != nil || len(conflicts) != 2 { t.Fatal(got, conflicts, err) }
	for i, entry := range []FileMergeEntry{entries[0], entries[2]} {
		if conflicts[i].Path != entry.Path || conflicts[i].Sides != (FileConflict{entry.Base, entry.Left, entry.Right}) { t.Fatal(conflicts) }
	}
	conflicts[0] = PathFileConflict{}
	if entries[0].Path != path("A") || entries[0].Left != b { t.Fatal("output aliases input slice") }
	entries[0].Right = b; entries[2].Left = c
	got, conflicts, err = MergeFileEntries(context.Background(), entries, FileMergeBudget{3,3,9})
	if err != nil || conflicts != nil || len(got) != 3 { t.Fatal(got, conflicts, err) }
	for i, entry := range entries {
		want, conflict, err := MergeFileVersions(context.Background(), entry.Base, entry.Left, entry.Right, 9)
		if err != nil || conflict != nil || got[i] != (ResolvedFileEntry{entry.Path, want}) { t.Fatal(got, err) }
	}
}

func TestMergeFileEntriesSharedAdmissionAndLateCancellation(t *testing.T) {
	a, _ := model.NewPath([]byte("a")); b, _ := model.NewPath([]byte("b"))
	state := fileFixture(t, model.SetSymlink, "x")
	entries := []FileMergeEntry{{a,state,state,state},{b,state,state,state}}
	for _, budget := range []FileMergeBudget{{1,2,6}, {2,1,6}, {2,2,5}, {}, {4097,2,6}, {2,65<<20,6}, {2,2,65<<20}} {
		if got, conflicts, err := MergeFileEntries(context.Background(), entries, budget); err != ErrFileBudget || got != nil || conflicts != nil { t.Fatal(got, conflicts, err) }
	}
	for _, bad := range [][]FileMergeEntry{{entries[0],entries[0]}, {entries[1],entries[0]}, {{a,state,state,FileVersion{}}}, {{model.Path{},state,state,state}}} {
		if got, conflicts, err := MergeFileEntries(context.Background(), bad, FileMergeBudget{2,2,6}); err != ErrFileState || got != nil || conflicts != nil { t.Fatal(got, conflicts, err) }
	}
	if got, conflicts, err := MergeFileEntries(context.Background(), nil, FileMergeBudget{1,1,0}); err != nil || got != nil || conflicts != nil { t.Fatal(got, conflicts, err) }
	if got, conflicts, err := MergeFileEntries(context.Background(), []FileMergeEntry{{a,AbsentFile(),AbsentFile(),AbsentFile()}}, FileMergeBudget{1,1,0}); err != nil || conflicts != nil || len(got) != 1 || !got[0].Version.IsAbsent() { t.Fatal(got, conflicts, err) }
	baseline := &preparationCancelContext{Context: context.Background()}
	if got, conflicts, err := MergeFileEntries(baseline, entries[:1], FileMergeBudget{2,2,6}); err != nil || conflicts != nil || len(got) != 1 { t.Fatal(got, conflicts, err) }
	// Second preflight adds one check, then cancel at second merge's entry.
	late := &preparationCancelContext{Context: context.Background(), cancelAt: baseline.calls+1}
	if got, conflicts, err := MergeFileEntries(late, entries, FileMergeBudget{2,2,6}); err != context.Canceled || got != nil || conflicts != nil { t.Fatal(got, conflicts, err) }
	if got, conflicts, err := MergeFileEntries(nil, entries, FileMergeBudget{2,2,6}); err != ErrFileState || got != nil || conflicts != nil { t.Fatal(got, conflicts, err) }
}

func TestCanonicalFileBatchParityAndSharedAdmission(t *testing.T) {
	ids, frames := canonicalMergeInputs(t, [3]string{"x", "y", "z"})
	var sides [3]CanonicalFileSide
	for i := range sides { sides[i] = CanonicalFileSide{true, model.SetRegular, ids[i], frames[i]} }
	a, _ := model.NewPath([]byte("a")); b, _ := model.NewPath([]byte("\xff"))
	entries := []CanonicalFileMergeEntry{{a,sides},{b,sides}}
	budget := FileMergeBudget{2,2,6}
	out, conflicts, err := MergeCanonicalFileEntries(context.Background(), entries, budget)
	if err != nil || out != nil || len(conflicts) != 2 { t.Fatal(out, conflicts, err) }
	_, want, err := MergeCanonicalFileVersions(context.Background(), sides, 3)
	if err != nil || want == nil { t.Fatal(want, err) }
	for i, conflict := range conflicts { if conflict.Path != entries[i].Path || conflict.Sides != *want { t.Fatal(conflict) } }
	entries[0].Sides[2] = sides[1]; entries[1].Sides[1] = sides[0]
	out, conflicts, err = MergeCanonicalFileEntries(context.Background(), entries, budget)
	if err != nil || conflicts != nil || len(out) != 2 { t.Fatal(out, conflicts, err) }
	for i, entry := range entries {
		want, conflict, err := MergeCanonicalFileVersions(context.Background(), entry.Sides, 3)
		if err != nil || conflict != nil || out[i] != (ResolvedFileEntry{entry.Path,want}) { t.Fatal(out, conflict, err) }
	}
	for _, bad := range []FileMergeBudget{{1,2,6},{2,1,6},{2,2,5},{},{4097,2,6},{2,65<<20,6},{2,2,65<<20}} {
		if out, conflicts, err := MergeCanonicalFileEntries(context.Background(), entries, bad); err != ErrFileBudget || out != nil || conflicts != nil { t.Fatal(out, conflicts, err) }
	}
	// A later corrupt frame must suppress even an earlier valid conflict.
	entries[0].Sides = sides
	for side := range sides {
		bad := append([]CanonicalFileMergeEntry(nil), entries...)
		bad[1].Sides = sides
		bad[1].Sides[side].Frame = append([]byte(nil), frames[side]...)
		bad[1].Sides[side].Frame[len(frames[side])-1] ^= 1
		if out, conflicts, err := MergeCanonicalFileEntries(context.Background(), bad, budget); err == nil || out != nil || conflicts != nil { t.Fatal(out, conflicts, err) }
	}
}

func TestCanonicalFileBatchEmptyInvalidAndCancellation(t *testing.T) {
	a, _ := model.NewPath([]byte("a")); b, _ := model.NewPath([]byte("b"))
	ids, frames := canonicalMergeInputs(t, [3]string{"", "", ""})
	empty := CanonicalFileSide{true,model.SetExecutable,ids[0],frames[0]}
	entries := []CanonicalFileMergeEntry{{a,[3]CanonicalFileSide{{},empty,empty}},{b,[3]CanonicalFileSide{}}}
	budget := FileMergeBudget{2,2,0}
	out, conflicts, err := MergeCanonicalFileEntries(context.Background(), entries, budget)
	if err != nil || conflicts != nil || len(out) != 2 || out[0].Version.IsAbsent() || !out[1].Version.IsAbsent() { t.Fatal(out, conflicts, err) }
	if out, conflicts, err := MergeCanonicalFileEntries(context.Background(), nil, budget); err != nil || out != nil || conflicts != nil { t.Fatal(out, conflicts, err) }
	badSide := CanonicalFileSide{Frame: []byte{}}
	for _, bad := range [][]CanonicalFileMergeEntry{{entries[0],entries[0]}, {entries[1],entries[0]}, {{model.Path{},[3]CanonicalFileSide{}}}, {{a,[3]CanonicalFileSide{badSide}}}, {{a,[3]CanonicalFileSide{{Present:true}}}}} {
		if out, conflicts, err := MergeCanonicalFileEntries(context.Background(), bad, budget); err != ErrFileState || out != nil || conflicts != nil { t.Fatal(out, conflicts, err) }
	}
	if out, conflicts, err := MergeCanonicalFileEntries(nil, entries, budget); err != ErrFileState || out != nil || conflicts != nil { t.Fatal(out, conflicts, err) }
	baseline := &preparationCancelContext{Context:context.Background()}
	if _, _, err := MergeCanonicalFileEntries(baseline, entries, budget); err != nil { t.Fatal(err) }
	// Every cancellation point, including after verified staging and final
	// merge resolution, must suppress both result collections.
	for at := 1; at <= baseline.calls; at++ {
		ctx := &preparationCancelContext{Context:context.Background(),cancelAt:at}
		if out, conflicts, err := MergeCanonicalFileEntries(ctx, entries, budget); err != context.Canceled || out != nil || conflicts != nil { t.Fatal(at, out, conflicts, err) }
	}
}
