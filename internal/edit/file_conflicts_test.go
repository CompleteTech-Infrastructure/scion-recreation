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
		name                    string
		base, left, right, want FileVersion
		conflict                bool
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
