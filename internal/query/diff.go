// Package query contains bounded query primitives, not authorization or storage.
package query

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
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

var (
	ErrFileDiffInput = errors.New("invalid file-entry diff input")
	ErrFileDiffLimit = errors.New("file-entry diff budget exhausted")
)

// FileDiffBudget bounds combined input entries, combined path bytes and emitted
// deltas. Explicit positive limits are required: one million entries/deltas and
// 64 MiB path bytes maximum. These are local query admission limits.
type FileDiffBudget struct { Entries, PathBytes, Changes uint64 }

// FileDelta owns immutable canonical values. Presence flags distinguish an
// absent side from its invalid zero Operation: add is false/true, delete is
// true/false, modification is true/true. ModeChanged and ContentChanged apply
// only to modifications. A mode change includes executable and symlink changes;
// content compares typed blob identities, never decoded text or target paths.
type FileDelta struct {
	Path model.Path
	Before, After model.Operation
	BeforePresent, AfterPresent bool
	ModeChanged, ContentChanged bool
}

// DiffFileEntries compares two exact corresponding selections of file entries,
// represented by canonical SET operations sorted strictly by raw byte path.
// DELETE operations, duplicate/unsorted paths and invalid values reject. It
// does not sort, normalize paths, resolve symlinks or infer renames/copies.
//
// This is a bounded selection comparator, NOT a tree/page traversal or tree
// validity verifier. Callers must supply complete matching selected scopes;
// a missing row then means absence within that selection. They must validate
// tree structure and blob content and authorize both selections before calling.
// It does not fetch bytes, classify binary content or produce text patches.
// Inputs must not be mutated concurrently. Errors return no partial deltas.
func DiffFileEntries(ctx context.Context, before, after []model.Operation, budget FileDiffBudget) ([]FileDelta, error) {
	if ctx == nil { return nil, ErrFileDiffInput }
	if err := ctx.Err(); err != nil { return nil, err }
	if budget.Entries == 0 || budget.Entries > 1000000 || budget.PathBytes == 0 || budget.PathBytes > 64<<20 || budget.Changes == 0 || budget.Changes > budget.Entries {
		return nil, ErrFileDiffLimit
	}
	if uint64(len(before)) > budget.Entries || uint64(len(after)) > budget.Entries-uint64(len(before)) { return nil, ErrFileDiffLimit }
	var pathBytes uint64
	for _, side := range [][]model.Operation{before, after} {
		for i, op := range side {
			if err := ctx.Err(); err != nil { return nil, err }
			id, present := op.Target()
			if op.Path().Validate() != nil || !present || id.Validate() != nil || (i > 0 && side[i-1].Path().Compare(op.Path()) >= 0) {
				return nil, ErrFileDiffInput
			}
			// Each Path already owns at most 65,535 bytes. This temporary copy
			// is bounded independently before charging aggregate path storage.
			n := uint64(len(op.Path().Bytes()))
			if n > budget.PathBytes-pathBytes { return nil, ErrFileDiffLimit }
			pathBytes += n
		}
	}
	var deltas []FileDelta
	for i, j := 0, 0; i < len(before) || j < len(after); {
		if err := ctx.Err(); err != nil { return nil, err }
		var d FileDelta
		switch {
		case j == len(after) || (i < len(before) && before[i].Path().Compare(after[j].Path()) < 0):
			d = FileDelta{Path: before[i].Path(), Before: before[i], BeforePresent: true}
			i++
		case i == len(before) || after[j].Path().Compare(before[i].Path()) < 0:
			d = FileDelta{Path: after[j].Path(), After: after[j], AfterPresent: true}
			j++
		default:
			old, next := before[i], after[j]
			i++; j++
			if old == next { continue }
			oldID, _ := old.Target()
			nextID, _ := next.Target()
			d = FileDelta{Path: old.Path(), Before: old, After: next, BeforePresent: true, AfterPresent: true, ModeChanged: old.Tag() != next.Tag(), ContentChanged: oldID != nextID}
		}
		if uint64(len(deltas)) == budget.Changes { return nil, ErrFileDiffLimit }
		deltas = append(deltas, d)
	}
	if err := ctx.Err(); err != nil { return nil, err }
	return deltas, nil
}

// DiffCanonicalText verifies two complete canonical blob frames, then runs the
// bounded text diff over their verified payloads. It always verifies BOTH frames,
// including equal expected IDs. A known digest is not an authorization grant.
// Callers must authorize delivery and explicitly classify/admit text first;
// the NUL guard in DiffText is not comprehensive binary classification.
//
// Both inputs are present blobs: this does not model absent files, tree changes,
// mode changes, compression envelopes or remote fetches. InputBytes admits the
// combined decoded payload bytes (excluding two 22-byte canonical headers).
// Decoding uses private in-memory staging and exposes no partial content. Limits
// are not peak-memory ceilings; buffers and output have bounded owned storage.
// Input frames must not be modified during the call. Errors return zero TextDiff.
func DiffCanonicalText(ctx context.Context, oldID, nextID model.BlobID, oldFrame, nextFrame []byte, budget TextDiffBudget) (TextDiff, error) {
	var zero TextDiff
	if ctx == nil { return zero, ErrDiffInput }
	if err := ctx.Err(); err != nil { return zero, err }
	if budget.InputBytes == 0 || budget.InputBytes > 64<<20 || budget.OutputBytes == 0 || budget.OutputBytes > 64<<20 || budget.Lines == 0 || budget.Lines > 1000000 || budget.Context > budget.Lines {
		return zero, ErrDiffLimit
	}
	frameBytes := budget.InputBytes + 44
	if uint64(len(oldFrame)) > frameBytes || uint64(len(nextFrame)) > frameBytes-uint64(len(oldFrame)) { return zero, ErrDiffLimit }
	var old, next bytes.Buffer
	used, err := model.DecodeBlob(ctx, bytes.NewReader(oldFrame), oldID, &old, budget.InputBytes)
	if err != nil { return zero, err }
	if _, err := model.DecodeBlob(ctx, bytes.NewReader(nextFrame), nextID, &next, budget.InputBytes-used); err != nil { return zero, err }
	return DiffText(ctx, old.Bytes(), next.Bytes(), budget)
}

// PrivateTreeDiffBudget gives each side its OWN traversal/output allowance,
// ordered before then after. Compare separately bounds combined selected rows,
// combined path bytes and emitted deltas. No allowance is silently reset across
// sides: total admitted traversal work is bounded by the sum of both Side caps.
// These are admission limits, not peak-memory or interruptible CPU guarantees.
type PrivateTreeDiffBudget struct {
	Side [2]derived.TreeEntriesBudget
	Compare FileDiffBudget
}

// DiffPrivateTrees verifies and enumerates two entire supplied private page
// graphs, then compares their canonical file entries. Both graphs are checked
// even when root IDs match. Missing/invalid pages and exhaustion are errors,
// never absence. No partial deltas escape. Usage counters on errors describe
// attempted private traversal, not public progress or an authorization receipt.
//
// This does not validate file blob bytes, establish repository/source binding,
// publication/retention, authorize output, fetch pages or classify text. Callers
// must establish provenance and authorize BOTH graphs before any disclosure,
// including paths, counts and timing. Unreachable map frames are ignored. Maps
// and frames must not mutate during the call. No resumable cursor is provided.
func DiffPrivateTrees(ctx context.Context, roots [2]derived.TreePageID, frames [2]map[derived.TreePageID][]byte, budget PrivateTreeDiffBudget) ([]FileDelta, [2]derived.TreeGraphUsage, error) {
	var usage [2]derived.TreeGraphUsage
	// Reject invalid comparator/context admission before traversing any graph.
	if _, err := DiffFileEntries(ctx, nil, nil, budget.Compare); err != nil { return nil, usage, err }
	var rows [2][]model.Operation
	for i := range roots {
		var err error
		rows[i], usage[i], err = derived.ReadTreeEntries(ctx, roots[i], frames[i], budget.Side[i])
		if err != nil { return nil, usage, err }
	}
	deltas, err := DiffFileEntries(ctx, rows[0], rows[1], budget.Compare)
	return deltas, usage, err
}
