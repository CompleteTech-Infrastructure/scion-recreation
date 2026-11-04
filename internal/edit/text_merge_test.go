package edit

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"canopy.local/canopy/internal/model"
)

func TestTextHunkComposition(t *testing.T) {
	for _, tc := range []struct {
		name, base, want string
		left, right      []TextHunk
	}{
		{"disjoint", "a\nb\nc\n", "A\nb\nC\n", []TextHunk{{0, 1, []byte("A")}}, []TextHunk{{4, 5, []byte("C")}}},
		{"adjacent", "ab", "XY", []TextHunk{{0, 1, []byte("X")}}, []TextHunk{{1, 2, []byte("Y")}}},
		{"identical", "abc", "aXc", []TextHunk{{1, 2, []byte("X")}}, []TextHunk{{1, 2, []byte("X")}}},
		{"same-insertion", "ab", "aXb", []TextHunk{{1, 1, []byte("X")}}, []TextHunk{{1, 1, []byte("X")}}},
		{"delete", "abc", "a", []TextHunk{{1, 2, nil}}, []TextHunk{{2, 3, nil}}},
		{"raw-newlines", "\xff\r\na", "\xff\r\nA", nil, []TextHunk{{3, 4, []byte("A")}}},
		{"empty", "", "", nil, nil},
		{"empty-insertion", "", "\x00\xff", []TextHunk{{0, 0, []byte{0, 255}}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, swap := range []bool{false, true} {
				left, right := tc.left, tc.right
				if swap {
					left, right = right, left
				}
				got, conflict, err := MergeTextHunks(context.Background(), []byte(tc.base), left, right, TextMergeBudget{1024, 10})
				if err != nil || conflict != nil || !bytes.Equal(got, []byte(tc.want)) {
					t.Fatalf("swap=%v got=%q conflict=%v err=%v", swap, got, conflict, err)
				}
			}
		})
	}
}

func TestTextHunkConflicts(t *testing.T) {
	for _, tc := range []struct {
		left, right TextHunk
	}{
		{TextHunk{0, 2, []byte("X")}, TextHunk{1, 3, []byte("Y")}},
		{TextHunk{1, 1, []byte("X")}, TextHunk{1, 1, []byte("Y")}},
		{TextHunk{0, 2, nil}, TextHunk{0, 0, []byte("X")}},
		{TextHunk{0, 2, nil}, TextHunk{2, 2, []byte("X")}},
		{TextHunk{0, 3, nil}, TextHunk{1, 1, []byte("X")}},
	} {
		for _, swap := range []bool{false, true} {
			left, right := tc.left, tc.right
			if swap {
				left, right = right, left
			}
			got, conflict, err := MergeTextHunks(context.Background(), []byte("abc"), []TextHunk{left}, []TextHunk{right}, TextMergeBudget{1024, 10})
			if err != nil || got != nil || conflict == nil || *conflict != (TextConflict{0, 0}) {
				t.Fatalf("conflicting hunks escaped: output=%q conflict=%v err=%v", got, conflict, err)
			}
		}
	}
	// First conflict indices must refer to the original side, not sorted order.
	got, c, err := MergeTextHunks(context.Background(), []byte("abcd"), []TextHunk{{2, 3, nil}}, []TextHunk{{0, 1, nil}, {2, 4, nil}}, TextMergeBudget{1024, 10})
	if err != nil || got != nil || c == nil || *c != (TextConflict{0, 1}) {
		t.Fatalf("original indices lost: %v %v", c, err)
	}
}

func TestTextHunkRejectionAndOwnership(t *testing.T) {
	for _, hunks := range [][]TextHunk{
		{{2, 1, nil}}, {{0, 4, nil}}, {{1, 2, nil}, {0, 1, nil}},
		{{0, 2, nil}, {1, 3, nil}}, {{0, 0, nil}, {0, 1, nil}},
		{{0, 1, nil}, {1, 1, []byte("x")}},
	} {
		got, conflict, err := MergeTextHunks(context.Background(), []byte("abc"), hunks, nil, TextMergeBudget{1024, 10})
		if !errors.Is(err, ErrTextInput) || got != nil || conflict != nil {
			t.Fatalf("invalid side accepted: %v %v", hunks, err)
		}
	}
	for _, budget := range []TextMergeBudget{{0, 1}, {1, 0}, {65 << 20, 1}, {1, 1000001}, {2, 10}, {10, 1}} {
		got, conflict, err := MergeTextHunks(context.Background(), []byte("a"), []TextHunk{{0, 0, []byte("x")}}, []TextHunk{{1, 1, []byte("y")}}, budget)
		if !errors.Is(err, ErrTextLimit) || got != nil || conflict != nil {
			t.Fatalf("budget accepted: %v %v", budget, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, c, err := MergeTextHunks(ctx, nil, nil, nil, TextMergeBudget{1, 1}); !errors.Is(err, context.Canceled) || got != nil || c != nil {
		t.Fatalf("cancellation ignored: %v", err)
	}
	if _, _, err := MergeTextHunks(nil, nil, nil, nil, TextMergeBudget{1, 1}); !errors.Is(err, ErrTextInput) {
		t.Fatalf("nil context accepted: %v", err)
	}
	base, replacement := []byte("ab"), []byte("X")
	out, c, err := MergeTextHunks(context.Background(), base, []TextHunk{{0, 1, replacement}}, nil, TextMergeBudget{3, 1})
	if err != nil || c != nil {
		t.Fatal(err, c)
	}
	base[1], replacement[0] = 'z', 'Y'
	if string(out) != "Xb" {
		t.Fatal("output aliases input")
	}
}

// Exercise an equal edit before the first conflict in both side orientations.
func TestTextHunkConflictAfterCoalescing(t *testing.T) {
	left := []TextHunk{{0, 1, []byte("X")}, {2, 4, nil}}
	right := []TextHunk{{0, 1, []byte("X")}, {3, 5, nil}}
	for _, swap := range []bool{false, true} {
		if swap {
			left, right = right, left
		}
		out, c, err := MergeTextHunks(context.Background(), []byte("abcde"), left, right, TextMergeBudget{16, 4})
		if err != nil || out != nil || c == nil || *c != (TextConflict{1, 1}) {
			t.Fatalf("coalescing lost conflict indices: %v %v", c, err)
		}
	}
}

func TestThreeWayTextMerge(t *testing.T) {
	for _, tc := range []struct { name, base, left, right, want string; conflict bool }{
		{"separated-multiple", "a\nb\nc\nd\ne\n", "A\nb\nc\nd\nE\n", "a\nb\nC\nd\ne\n", "A\nb\nC\nd\nE\n", false},
		{"adjacent-lines", "a\nb\n", "A\nb\n", "a\nB\n", "A\nB\n", false},
		{"identical", "a\n", "A\n", "A\n", "A\n", false},
		{"empty", "", "", "", "", false},
		{"empty-add", "", "A", "A", "A", false},
		{"one-delete", "a\n", "", "a\n", "", false},
		{"raw-newline", "\xff\r\na", "\xff\r\nA", "\xff\r\na", "\xff\r\nA", false},
		{"newline-removal", "a\n", "a", "a\n", "a", false},
		{"overlap", "a\n", "A\n", "B\n", "", true},
		{"insert-boundary", "a\nb\n", "a\nX\nb\n", "a\nB\n", "", true},
		{"delete-modify", "a\n", "", "A\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, swap := range []bool{false, true} {
				left, right := tc.left, tc.right
				if swap { left, right = right, left }
				got, conflict, err := MergeText(context.Background(), []byte(tc.base), []byte(left), []byte(right), ThreeWayTextBudget{1024, 100, 10000, 100})
				if err != nil || (conflict != nil) != tc.conflict || (!tc.conflict && !bytes.Equal(got, []byte(tc.want))) || (tc.conflict && got != nil) { t.Fatalf("got %q conflict %v err %v", got, conflict, err) }
			}
		})
	}
}

// Every one-sided edit must round-trip exactly, including repeated-line LCS
// ties, insertions/deletions and unterminated final lines.
func TestThreeWayTextOneSidedRoundTrip(t *testing.T) {
	inputs := []string{"", "a", "a\n", "b\n", "a\na\n", "a\nb\n", "b\na\n", "a\nb\na\n", "b\na\nb", "\n\n", "\xff\r\n"}
	for _, base := range inputs {
		for _, side := range inputs {
			for _, swap := range []bool{false, true} {
				left, right := side, base
				if swap { left, right = right, left }
				got, conflict, err := MergeText(context.Background(), []byte(base), []byte(left), []byte(right), ThreeWayTextBudget{1024, 100, 10000, 100})
				if err != nil || conflict != nil || !bytes.Equal(got, []byte(side)) { t.Fatalf("base %q side %q got %q %v %v", base, side, got, conflict, err) }
			}
		}
	}
}

func TestThreeWayTextLimitsAndInput(t *testing.T) {
	for _, budget := range []ThreeWayTextBudget{
		{}, {65<<20, 1, 1, 1}, {100, 1000001, 1, 1}, {100, 100, 4000001, 1}, {100, 100, 100, 1000001},
		{5, 3, 4, 1}, {6, 2, 4, 1}, {6, 3, 3, 1}, {6, 3, 4, 0},
	} {
		got, conflict, err := MergeText(context.Background(), []byte("a\n"), []byte("A\n"), []byte("a\n"), budget)
		if got != nil || conflict != nil || !errors.Is(err, ErrTextLimit) { t.Fatal(budget, got, conflict, err) }
	}
	got, conflict, err := MergeText(context.Background(), []byte("a\n"), []byte("A\n"), []byte("a\n"), ThreeWayTextBudget{6, 3, 4, 1})
	if err != nil || conflict != nil || string(got) != "A\n" { t.Fatal(got, conflict, err) }
	for _, budget := range []ThreeWayTextBudget{{12, 6, 7, 2}, {12, 6, 8, 1}} {
		got, conflict, err := MergeText(context.Background(), []byte("a\nb\n"), []byte("A\nb\n"), []byte("a\nB\n"), budget)
		if got != nil || conflict != nil || !errors.Is(err, ErrTextLimit) { t.Fatal(budget, got, conflict, err) }
	}
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	for _, tc := range []struct { ctx context.Context; base, left, right []byte; want error }{
		{nil, nil, nil, nil, ErrTextInput}, {ctx, nil, nil, nil, context.Canceled},
		{context.Background(), []byte{0}, nil, nil, ErrTextInput},
		{context.Background(), nil, []byte{0}, nil, ErrTextInput},
		{context.Background(), nil, nil, []byte{0}, ErrTextInput},
	} {
		got, conflict, err := MergeText(tc.ctx, tc.base, tc.left, tc.right, ThreeWayTextBudget{100, 100, 100, 100})
		if got != nil || conflict != nil || !errors.Is(err, tc.want) { t.Fatal(got, conflict, err) }
	}
}

func canonicalMergeInputs(t *testing.T, inputs [3]string) ([3]model.BlobID, [3][]byte) {
	t.Helper()
	var ids [3]model.BlobID
	var frames [3][]byte
	for i, input := range inputs {
		var err error
		ids[i], err = model.HashBlob(context.Background(), uint64(len(input)), bytes.NewReader([]byte(input)))
		if err != nil { t.Fatal(err) }
		var frame bytes.Buffer
		if err := model.EncodeBlob(context.Background(), &frame, uint64(len(input)), bytes.NewReader([]byte(input))); err != nil { t.Fatal(err) }
		frames[i] = frame.Bytes()
	}
	return ids, frames
}

func TestCanonicalTextMergeMatchesPayloads(t *testing.T) {
	budget := ThreeWayTextBudget{1024, 100, 1000, 100}
	for _, inputs := range [][3]string{
		{"", "", ""}, {"a\nb\nc\n", "A\nb\nc\n", "a\nb\nC\n"},
		{"a", "b", "c"}, {"a", "", ""}, {"same", "same", "same"},
		{"\xff\r\na", "\xff\r\nA", "\xff\r\na"},
	} {
		ids, frames := canonicalMergeInputs(t, inputs)
		want, conflict, err := MergeText(context.Background(), []byte(inputs[0]), []byte(inputs[1]), []byte(inputs[2]), budget)
		if err != nil { t.Fatal(err) }
		got, gotConflict, err := MergeCanonicalText(context.Background(), ids, frames, budget)
		if err != nil || !bytes.Equal(got, want) || (gotConflict == nil) != (conflict == nil) { t.Fatal(inputs, got, gotConflict, err) }
		if conflict != nil && *conflict != *gotConflict { t.Fatal(conflict, gotConflict) }
	}
}

func TestCanonicalTextMergeRejectsEveryUnverifiedSide(t *testing.T) {
	ids, frames := canonicalMergeInputs(t, [3]string{"a", "a", "a"})
	budget := ThreeWayTextBudget{100, 100, 1000, 100}
	for side := 0; side < 3; side++ {
		for mode := 0; mode < 5; mode++ {
			badIDs, badFrames := ids, frames
			frame := append([]byte(nil), frames[side]...)
			switch mode {
			case 0: frame[len(frame)-1] ^= 1
			case 1: frame = frame[:len(frame)-1]
			case 2: frame = append(frame, 0)
			case 3: badIDs[side] = model.BlobID{}
			case 4: frame[21] = 255 // Declared payload cannot exceed remaining budget.
			}
			badFrames[side] = frame
			got, conflict, err := MergeCanonicalText(context.Background(), badIDs, badFrames, budget)
			if err == nil || got != nil || conflict != nil { t.Fatal(side, mode, got, conflict, err) }
		}
	}
	for _, budget := range []ThreeWayTextBudget{{}, {2, 100, 100, 100}, {100, 2, 100, 100}, {65<<20, 100, 100, 100}, {100, 100, 4000001, 100}} {
		got, conflict, err := MergeCanonicalText(context.Background(), ids, frames, budget)
		if !errors.Is(err, ErrTextLimit) || got != nil || conflict != nil { t.Fatal(budget, got, conflict, err) }
	}
	ids, frames = canonicalMergeInputs(t, [3]string{"a", "", ""})
	if got, conflict, err := MergeCanonicalText(context.Background(), ids, frames, ThreeWayTextBudget{1, 1, 4, 2}); err != nil || conflict != nil || len(got) != 0 { t.Fatal("zero remaining payload allowance", got, conflict, err) }
	ids, frames = canonicalMergeInputs(t, [3]string{"", "", "\x00"})
	if got, conflict, err := MergeCanonicalText(context.Background(), ids, frames, budget); !errors.Is(err, ErrTextInput) || got != nil || conflict != nil { t.Fatal(got, conflict, err) }
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if got, conflict, err := MergeCanonicalText(ctx, ids, frames, budget); !errors.Is(err, context.Canceled) || got != nil || conflict != nil { t.Fatal(got, conflict, err) }
	if got, conflict, err := MergeCanonicalText(nil, ids, frames, budget); !errors.Is(err, ErrTextInput) || got != nil || conflict != nil { t.Fatal(got, conflict, err) }
}
