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
		h           TextHunk
		side, index int
	}
	order := make([]chosen, 0, len(left)+len(right))
	size := uint64(len(base))
	for i, j := 0, 0; i < len(left) || j < len(right); {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		var next chosen
		// Order equal starts by end before side, so a boundary insertion is
		// compared with the preceding replacement before an adjacent one.
		if j == len(right) || (i < len(left) && (left[i].Start < right[j].Start ||
			left[i].Start == right[j].Start && left[i].End <= right[j].End)) {
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
