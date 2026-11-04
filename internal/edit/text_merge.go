// Package edit contains pure edit primitives, not authorized repository operations.
package edit

import (
	"bytes"
	"context"
	"errors"
)

var (
	ErrTextInput = errors.New("invalid text hunk input")
	ErrTextLimit = errors.New("text merge budget exhausted")
)

// TextHunk replaces base[Start:End] with Data. Offsets are bytes, not characters
// or lines; Start==End is insertion. No newline or Unicode normalization occurs.
// Each side must be sorted, nonoverlapping and unambiguous at insertion boundaries.
// Callers own inputs and must not mutate them during MergeTextHunks.
type TextHunk struct {
	Start, End uint64
	Data       []byte
}

// TextMergeBudget bounds total base/replacement input bytes and output bytes,
// and the combined hunk count. Limits must be positive and cannot exceed the
// canonical changeset-size ceiling (64 MiB) and one million hunks respectively.
type TextMergeBudget struct {
	Bytes, Hunks uint64
}

// TextConflict identifies the first overlapping pair by original side indices.
// It is not an exhaustive conflict list. No merged output escapes on conflict.
type TextConflict struct {
	Left, Right int
}

func textOverlap(a, b TextHunk) bool {
	if a.Start == a.End {
		return a.Start >= b.Start && a.Start <= b.End
	}
	if b.Start == b.End {
		return b.Start >= a.Start && b.Start <= a.End
	}
	return a.Start < b.End && b.Start < a.End
}

// MergeTextHunks composes already-computed edits against the SAME explicit base.
// It does not compute diffs, select merge bases, detect binary files, establish
// provenance/authorization, publish changes or resolve multiple-base merges.
// Exact identical cross-side edits coalesce. Other overlapping edits (including
// insertion at a replacement boundary) conservatively return a structured
// conflict rather than guessing order. Adjacent nonempty replacements commute.
// This bounded primitive is partial EDT-01 work; diff/base integration is separate.
func MergeTextHunks(ctx context.Context, base []byte, left, right []TextHunk, budget TextMergeBudget) ([]byte, *TextConflict, error) {
	if ctx == nil {
		return nil, nil, ErrTextInput
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if budget.Bytes == 0 || budget.Bytes > 64<<20 || budget.Hunks == 0 || budget.Hunks > 1000000 {
		return nil, nil, ErrTextLimit
	}
	if uint64(len(base)) > budget.Bytes || uint64(len(left)) > budget.Hunks || uint64(len(right)) > budget.Hunks-uint64(len(left)) {
		return nil, nil, ErrTextLimit
	}
	used := uint64(len(base))
	for _, side := range [][]TextHunk{left, right} {
		for i, h := range side {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			if h.Start > h.End || h.End > uint64(len(base)) || (i > 0 && (side[i-1].Start >= h.Start || textOverlap(side[i-1], h))) {
				return nil, nil, ErrTextInput
			}
			if uint64(len(h.Data)) > budget.Bytes-used {
				return nil, nil, ErrTextLimit
			}
			used += uint64(len(h.Data))
		}
	}
	// Indices refer to original inputs; the merged order never retains copies of
	// replacement bytes. Preflight the complete result before allocating output.
	type chosen struct {
		h TextHunk
		side, index int
	}
	order := make([]chosen, 0, len(left)+len(right))
	size := uint64(len(base))
	for i, j := 0, 0; i < len(left) || j < len(right); {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		var next chosen
		if j == len(right) || (i < len(left) && left[i].Start <= right[j].Start) {
			next = chosen{left[i], 0, i}
			i++
		} else {
			next = chosen{right[j], 1, j}
			j++
		}
		if len(order) > 0 {
			prior := order[len(order)-1]
			if textOverlap(prior.h, next.h) {
				if prior.side != next.side && prior.h.Start == next.h.Start && prior.h.End == next.h.End && bytes.Equal(prior.h.Data, next.h.Data) {
					continue
				}
				conflict := &TextConflict{Left: prior.index, Right: next.index}
				if prior.side == 1 {
					conflict.Left, conflict.Right = next.index, prior.index
				}
				return nil, conflict, nil
			}
		}
		size -= next.h.End - next.h.Start
		size += uint64(len(next.h.Data))
		if size > budget.Bytes {
			return nil, nil, ErrTextLimit
		}
		order = append(order, next)
	}
	out := make([]byte, 0, int(size))
	appendBytes := func(b []byte) error {
		for len(b) > 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			n := min(len(b), 32<<10)
			out = append(out, b[:n]...)
			b = b[n:]
		}
		return nil
	}
	at := uint64(0)
	for _, item := range order {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if err := appendBytes(base[at:item.h.Start]); err != nil {
			return nil, nil, err
		}
		if err := appendBytes(item.h.Data); err != nil {
			return nil, nil, err
		}
		at = item.h.End
	}
	if err := appendBytes(base[at:]); err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return out, nil, nil
}

// ThreeWayTextBudget bounds combined input bytes and output bytes separately,
// combined input lines,
// combined allocated LCS cells (including sentinel row/column), and derived
// hunks. Limits are local policy: 64 MiB, one million lines/hunks, four million
// cells maximum. LCS uses uint32 cells and iterative traversal, not recursion.
type ThreeWayTextBudget struct { Bytes, Lines, Cells, Hunks uint64 }

// MergeText derives deterministic line edits against one explicit base and
// composes them with MergeTextHunks. Lines retain LF/CRLF and missing-final-LF
// bytes verbatim; non-UTF-8 bytes are not decoded. NUL input rejects, but that
// guard is NOT a comprehensive binary classifier. Callers must classify text,
// establish the correct base and authorize inputs before using this primitive.
// Inputs must not be mutated during the call. No publication is performed.
//
// Matching uses exact line tokens and longest-common-subsequence alignment;
// equal-score alternatives consume a base line first. Overlaps conservatively
// conflict under MergeTextHunks rules. Conflict indices refer to the derived
// left/right hunk sequences, not line numbers. Exhaustion yields no output.
func MergeText(ctx context.Context, base, left, right []byte, budget ThreeWayTextBudget) ([]byte, *TextConflict, error) {
	if ctx == nil { return nil, nil, ErrTextInput }
	if err := ctx.Err(); err != nil { return nil, nil, err }
	if budget.Bytes == 0 || budget.Bytes > 64<<20 || budget.Lines == 0 || budget.Lines > 1000000 || budget.Cells == 0 || budget.Cells > 4000000 || budget.Hunks == 0 || budget.Hunks > 1000000 {
		return nil, nil, ErrTextLimit
	}
	var used uint64
	for _, input := range [][]byte{base, left, right} {
		if uint64(len(input)) > budget.Bytes-used { return nil, nil, ErrTextLimit }
		used += uint64(len(input))
		if bytes.IndexByte(input, 0) >= 0 { return nil, nil, ErrTextInput }
	}
	type lines struct { offsets []int; tokens []uint32 }
	// Intern exact strings once per input line. This avoids comparing long
	// byte strings in every quadratic LCS cell; map equality remains exact.
	intern := make(map[string]uint32)
	var lineCount uint64
	split := func(input []byte) (lines, error) {
		out := lines{offsets: []int{0}}
		for start := 0; start < len(input); {
			if err := ctx.Err(); err != nil { return lines{}, err }
			if lineCount == budget.Lines { return lines{}, ErrTextLimit }
			end := len(input)
			if at := bytes.IndexByte(input[start:], '\n'); at >= 0 { end = start + at + 1 }
			key := string(input[start:end])
			token, ok := intern[key]
			if !ok { token = uint32(len(intern)+1); intern[key] = token }
			out.tokens = append(out.tokens, token)
			out.offsets = append(out.offsets, end)
			lineCount++
			start = end
		}
		return out, nil
	}
	b, err := split(base)
	if err != nil { return nil, nil, err }
	l, err := split(left)
	if err != nil { return nil, nil, err }
	r, err := split(right)
	if err != nil { return nil, nil, err }
	var cells, hunkCount uint64
	diff := func(side lines, data []byte) ([]TextHunk, error) {
		prefix := 0
		for prefix < len(b.tokens) && prefix < len(side.tokens) && b.tokens[prefix] == side.tokens[prefix] {
			if prefix%4096 == 0 { if err := ctx.Err(); err != nil { return nil, err } }
			prefix++
		}
		bend, send := len(b.tokens), len(side.tokens)
		for bend > prefix && send > prefix && b.tokens[bend-1] == side.tokens[send-1] {
			if bend%4096 == 0 { if err := ctx.Err(); err != nil { return nil, err } }
			bend--; send--
		}
		n, m := bend-prefix, send-prefix
		if n == 0 && m == 0 { return nil, nil }
		cost := uint64(n+1)*uint64(m+1)
		if cost > budget.Cells-cells { return nil, ErrTextLimit }
		cells += cost
		width := m+1
		table := make([]uint32, int(cost))
		for i := n-1; i >= 0; i-- {
			if err := ctx.Err(); err != nil { return nil, err }
			for j := m-1; j >= 0; j-- {
				if j%4096 == 0 { if err := ctx.Err(); err != nil { return nil, err } }
				if b.tokens[prefix+i] == side.tokens[prefix+j] {
					table[i*width+j] = table[(i+1)*width+j+1]+1
				} else {
					table[i*width+j] = max(table[(i+1)*width+j], table[i*width+j+1])
				}
			}
		}
		var hunks []TextHunk
		startI, startJ := -1, -1
		flush := func(i, j int) error {
			if startI < 0 { return nil }
			if hunkCount == budget.Hunks { return ErrTextLimit }
			hunks = append(hunks, TextHunk{uint64(b.offsets[prefix+startI]), uint64(b.offsets[prefix+i]), data[side.offsets[prefix+startJ]:side.offsets[prefix+j]]})
			hunkCount++
			startI, startJ = -1, -1
			return nil
		}
		i, j := 0, 0
		for i < n || j < m {
			if err := ctx.Err(); err != nil { return nil, err }
			if i < n && j < m && b.tokens[prefix+i] == side.tokens[prefix+j] {
				if err := flush(i, j); err != nil { return nil, err }
				i++; j++
				continue
			}
			if startI < 0 { startI, startJ = i, j }
			if i < n && (j == m || table[(i+1)*width+j] >= table[i*width+j+1]) { i++ } else { j++ }
		}
		if err := flush(i, j); err != nil { return nil, err }
		return hunks, nil
	}
	lh, err := diff(l, left)
	if err != nil { return nil, nil, err }
	rh, err := diff(r, right)
	if err != nil { return nil, nil, err }
	return MergeTextHunks(ctx, base, lh, rh, TextMergeBudget{Bytes: budget.Bytes, Hunks: budget.Hunks})
}
