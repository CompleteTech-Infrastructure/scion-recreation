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
