package query

import (
	"context"
	"errors"
	"reflect"
	"testing"
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
