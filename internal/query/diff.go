// Package query contains bounded query primitives, not authorization or storage.
package query

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

var (
	ErrDiffInput = errors.New("invalid text diff input")
	ErrDiffLimit = errors.New("text diff budget exhausted")
	ErrDiffBinary = errors.New("NUL-bearing input is not admitted as text")
)

// TextDiffBudget admits total input bytes, combined lines, output bytes and
// context lines. Byte ceilings are 64 MiB and the combined line ceiling is one
// million. Context may be zero and may not exceed Lines. All other limits >0.
type TextDiffBudget struct {
	InputBytes, OutputBytes, Lines, Context uint64
}

// TextDiff contains at most one complete coarse unified-diff fragment, with no
// file headers. Nil Hunk means equal bytes. Newline flags describe each original
// input independently; empty input has no final newline. Hunk is caller-owned.
type TextDiff struct {
	Hunk []byte
	OldFinalNewline, NewFinalNewline bool
}

// DiffText preserves exact bytes, including CRLF and invalid UTF-8. It emits one
// deterministic replacement for everything between the longest common line
// prefix/suffix, with bounded surrounding context. It is not a minimal edit
// script. Missing newlines use explicit unified-diff markers, never silent LF
// insertion. NUL input is rejected; this is NOT comprehensive binary detection.
// Callers must classify/admit text and authorize both inputs before using this
// helper. Tree traversal, binary diffs, renames/copies, paging and RPC assembly
// are separate QRY-04 work. Inputs must not be mutated during this call.
func DiffText(ctx context.Context, old, next []byte, budget TextDiffBudget) (TextDiff, error) {
	var zero TextDiff
	if ctx == nil {
		return zero, ErrDiffInput
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if budget.InputBytes == 0 || budget.InputBytes > 64<<20 || budget.OutputBytes == 0 || budget.OutputBytes > 64<<20 || budget.Lines == 0 || budget.Lines > 1000000 || budget.Context > budget.Lines {
		return zero, ErrDiffLimit
	}
	if uint64(len(old)) > budget.InputBytes || uint64(len(next)) > budget.InputBytes-uint64(len(old)) {
		return zero, ErrDiffLimit
	}
	var usedLines uint64
	split := func(data []byte) ([]int, error) {
		var ends []int
		for i, b := range data {
			if i%(32<<10) == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			if b == 0 {
				return nil, ErrDiffBinary
			}
			if b == '\n' || i == len(data)-1 {
				if usedLines == budget.Lines {
					return nil, ErrDiffLimit
				}
				usedLines++
				ends = append(ends, i+1)
			}
		}
		return ends, nil
	}
	a, err := split(old)
	if err != nil {
		return zero, err
	}
	b, err := split(next)
	if err != nil {
		return zero, err
	}
	line := func(data []byte, ends []int, i int) []byte {
		start := 0
		if i > 0 {
			start = ends[i-1]
		}
		return data[start:ends[i]]
	}
	prefix := 0
	for prefix < len(a) && prefix < len(b) {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if !bytes.Equal(line(old, a, prefix), line(next, b, prefix)) {
			break
		}
		prefix++
	}
	result := TextDiff{OldFinalNewline: len(old)>0 && old[len(old)-1]=='\n', NewFinalNewline: len(next)>0 && next[len(next)-1]=='\n'}
	if prefix == len(a) && prefix == len(b) {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		return result, nil
	}
	suffix := 0
	for suffix < len(a)-prefix && suffix < len(b)-prefix {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if !bytes.Equal(line(old, a, len(a)-suffix-1), line(next, b, len(b)-suffix-1)) {
			break
		}
		suffix++
	}
	start := max(0, prefix-int(budget.Context))
	tail := min(suffix, int(budget.Context))
	oldEnd, newEnd := len(a)-suffix, len(b)-suffix
	oldCount, newCount := oldEnd-start+tail, newEnd-start+tail
	position := func(count int) int {
		if count == 0 {
			return start
		}
		return start+1
	}
	var out []byte
	appendPart := func(part []byte) error {
		if uint64(len(part)) > budget.OutputBytes-uint64(len(out)) {
			return ErrDiffLimit
		}
		for len(part)>0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			n := min(len(part), 32<<10)
			out = append(out, part[:n]...)
			part = part[n:]
		}
		return nil
	}
	emit := func(mark byte, data []byte) error {
		if err := appendPart([]byte{mark}); err != nil { return err }
		if err := appendPart(data); err != nil { return err }
		if data[len(data)-1] != '\n' {
			return appendPart([]byte("\n\\ No newline at end of file\n"))
		}
		return nil
	}
	header := fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", position(oldCount), oldCount, position(newCount), newCount)
	if err := appendPart([]byte(header)); err != nil { return zero, err }
	for i := start; i < prefix; i++ {
		if err := emit(' ', line(old,a,i)); err != nil { return zero, err }
	}
	for i := prefix; i < oldEnd; i++ {
		if err := emit('-', line(old,a,i)); err != nil { return zero, err }
	}
	for i := prefix; i < newEnd; i++ {
		if err := emit('+', line(next,b,i)); err != nil { return zero, err }
	}
	for i := oldEnd; i < oldEnd+tail; i++ {
		if err := emit(' ', line(old,a,i)); err != nil { return zero, err }
	}
	if err := ctx.Err(); err != nil { return zero, err }
	result.Hunk = out
	return result, nil
}
