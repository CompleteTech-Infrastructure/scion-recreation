package edit

import (
	"bytes"
	"context"
	"errors"
	"testing"
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
