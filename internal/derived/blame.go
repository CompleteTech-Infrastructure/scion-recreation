package derived

import (
	"bytes"
	"context"
	"errors"

	"canopy.local/canopy/internal/model"
)

var (
	ErrLineOriginInput = errors.New("invalid private line-origin input")
	ErrLineOriginBinary = errors.New("NUL-bearing content is not admitted as text")
	ErrLineOriginBudget = errors.New("private line-origin budget exhausted")
)

// LineOriginSpan is a PRIVATE zero-based half-open line interval. Numbering is
// local to this algorithm, not a definition of the public RPC's line numbering.
// Adjacent intervals with the same origin are coalesced; no author data is held.
type LineOriginSpan struct {
	Start, End uint64
	Origin model.ChangesetID
}

// LineOriginBudget bounds combined input bytes/lines, allocated LCS cells,
// conservative byte-comparison work and output intervals. Maximums are 1 MiB,
// 4096 lines, 1M cells and 64 MiB comparisons. These are not measured RSS limits.
type LineOriginBudget struct { InputBytes, Lines, Cells, CompareBytes, Spans uint64 }
type LineOriginUsage struct { InputBytes, Lines, Cells, CompareBytes uint64 }

// DeriveFirstParentLineOrigins propagates one supplied first-parent origin ID
// per old line through an exact-byte longest-common-subsequence alignment.
// Matching lines inherit their old origin; unmatched new lines belong to current.
// Duplicate-line ties skip the old line before inserting a new line; matching
// equal current lines is preferred. It does not detect moved/copied lines beyond
// that ordered alignment or consult additional parents.
//
// LF terminates a line and remains part of its identity. An empty file has zero
// lines; a final non-LF suffix is one line; a final LF adds no phantom line.
// CR and non-UTF8 bytes stay literal. Any NUL in either side rejects as binary;
// callers must explicitly admit text, since absence of NUL is not a universal
// binary classifier. Adding/removing a final newline changes that line's origin.
//
// Origin provenance, first-parent selection, canonical blob/source verification,
// repository membership, publication and all disclosure permissions are caller
// obligations. This is not a durable index, history walker or public endpoint.
// Inputs must remain stable. No error/cancellation returns partial intervals.
func DeriveFirstParentLineOrigins(ctx context.Context, current model.ChangesetID, before, after []byte, prior []model.ChangesetID, budget LineOriginBudget) ([]LineOriginSpan, LineOriginUsage, error) {
	var used LineOriginUsage
	bad := func(err error) ([]LineOriginSpan, LineOriginUsage, error) { return nil, used, err }
	if ctx == nil || current.Validate() != nil { return bad(ErrLineOriginInput) }
	if err := ctx.Err(); err != nil { return bad(err) }
	if !validLineOriginBudget(budget) { return bad(ErrLineOriginBudget) }
	if uint64(len(before)) > budget.InputBytes || uint64(len(after)) > budget.InputBytes-uint64(len(before)) { return bad(ErrLineOriginBudget) }
	used.InputBytes = uint64(len(before)+len(after))
	split := func(data []byte) ([][]byte, error) {
		var lines [][]byte
		start := 0
		add := func(end int) error {
			if used.Lines == budget.Lines { return ErrLineOriginBudget }
			used.Lines++; lines = append(lines, data[start:end]); start = end
			return nil
		}
		for i, b := range data {
			if i%4096 == 0 { if err := ctx.Err(); err != nil { return nil, err } }
			if b == 0 { return nil, ErrLineOriginBinary }
			if b == '\n' { if err := add(i+1); err != nil { return nil, err } }
		}
		if start < len(data) { if err := add(len(data)); err != nil { return nil, err } }
		return lines, nil
	}
	old, err := split(before); if err != nil { return bad(err) }
	next, err := split(after); if err != nil { return bad(err) }
	if len(prior) != len(old) { return bad(ErrLineOriginInput) }
	for _, id := range prior { if err := ctx.Err(); err != nil { return bad(err) }; if id.Validate() != nil { return bad(ErrLineOriginInput) } }
	width := len(next)+1
	cells := uint64(len(old)+1)*uint64(width)
	if cells > budget.Cells { return bad(ErrLineOriginBudget) }
	used.Cells = cells
	matrix := make([]uint32, int(cells))
	const matched uint32 = 1<<31
	score := func(i, j int) uint32 { return matrix[i*width+j] &^ matched }
	for i := len(old)-1; i >= 0; i-- {
		if err := ctx.Err(); err != nil { return bad(err) }
		for j := len(next)-1; j >= 0; j-- {
			if err := ctx.Err(); err != nil { return bad(err) }
			equal := false
			if len(old[i]) == len(next[j]) {
				// Reserve both complete line lengths before comparison; the
				// recorded cost is conservative, not actual bytes inspected.
				cost := uint64(len(old[i])+len(next[j]))
				if cost > budget.CompareBytes-used.CompareBytes { return bad(ErrLineOriginBudget) }
				used.CompareBytes += cost
				equal = bytes.Equal(old[i], next[j])
			}
			if equal { matrix[i*width+j] = matched | (score(i+1, j+1)+1) } else {
				v := score(i+1, j); if other := score(i, j+1); other > v { v = other }; matrix[i*width+j] = v
			}
		}
	}
	var spans []LineOriginSpan
	for i, j := 0, 0; j < len(next); {
		if err := ctx.Err(); err != nil { return bad(err) }
		origin := current
		if i < len(old) {
			if matrix[i*width+j]&matched != 0 { origin = prior[i]; i++ } else if score(i+1, j) >= score(i, j+1) { i++; continue }
		}
		if len(spans) != 0 && spans[len(spans)-1].Origin == origin { spans[len(spans)-1].End++ } else {
			if uint64(len(spans)) == budget.Spans { return bad(ErrLineOriginBudget) }
			spans = append(spans, LineOriginSpan{uint64(j), uint64(j+1), origin})
		}
		j++
	}
	if err := ctx.Err(); err != nil { return bad(err) }
	return spans, used, nil
}

func validLineOriginBudget(b LineOriginBudget) bool {
	return b.InputBytes > 0 && b.InputBytes <= 1<<20 && b.Lines > 0 && b.Lines <= 4096 && b.Cells > 0 && b.Cells <= 1<<20 && b.CompareBytes > 0 && b.CompareBytes <= 64<<20 && b.Spans > 0 && b.Spans <= b.Lines
}

var ErrLineOriginAbsent = errors.New("selected path has no current file")

// CanonicalBlameBudget admits complete DAG/history work plus at most one LCS
// attempt per changed text blob in the selected current file lifetime. Each
// attempt has its own Derive ceiling; summed work is not one LCS quantum.
// BlobBytes separately caps aggregate complete frames decoded for blame (at
// most 1 MiB), beyond the history replay's earlier blob integrity passes.
type CanonicalBlameBudget struct {
	History CanonicalPathHistoryBudget
	Derive LineOriginBudget
	BlobBytes uint64
}
type CanonicalBlameUsage struct {
	History CanonicalPathHistoryUsage
	BlobBytes, Updates uint64
	Lines LineOriginUsage
}
// CanonicalLineOrigins is a PRIVATE source/path-bound text result. Mode and Blob
// describe the selected present regular/executable file; empty content is valid.
// Spans use this algorithm's zero-based intervals, not public RPC numbering.
type CanonicalLineOrigins struct {
	Source model.ChangesetID
	Path model.Path
	Mode model.OperationTag
	Blob model.BlobID
	Spans []LineOriginSpan
}

// ReadCanonicalDAGLineOrigins derives origins internally from checked canonical
// DAG/path history. It starts at the latest absent-to-present event in the
// selected first-parent lineage, so deletion/re-add never inherits old origins.
// Earlier lifetimes are not text-classified (but still integrity-checked by
// replay). Mode-only regular/executable changes preserve origins. Every state
// in the current lifetime must be explicitly admitted regular/executable text;
// symlink states reject, NUL rejects, and a currently absent path has a distinct
// PRIVATE ErrLineOriginAbsent result. No rename/copy/all-parent inference occurs.
//
// Source publication, durable retention and authorization remain external.
// This is not a durable index or public endpoint. Inputs must stay stable.
// All errors return a zero result; usage/errors must never expose hidden data.
func ReadCanonicalDAGLineOrigins(ctx context.Context, repository [16]byte, source model.ChangesetID, path model.Path, sources []TreeSourceFrame, blobs map[model.BlobID][]byte, budget CanonicalBlameBudget) (CanonicalLineOrigins, CanonicalBlameUsage, error) {
	var used CanonicalBlameUsage
	bad := func(err error) (CanonicalLineOrigins, CanonicalBlameUsage, error) { return CanonicalLineOrigins{}, used, err }
	if ctx == nil || source.Validate() != nil || path.Validate() != nil { return bad(ErrLineOriginInput) }
	if err := ctx.Err(); err != nil { return bad(err) }
	if !validLineOriginBudget(budget.Derive) || budget.BlobBytes == 0 || budget.BlobBytes > 1<<20 { return bad(ErrLineOriginBudget) }
	history, historyUsage, err := ReadCanonicalDAGPathHistory(ctx, repository, source, path, sources, blobs, budget.History)
	used.History = historyUsage
	if err != nil { return bad(err) }
	if len(history) == 0 || !history[0].AfterPresent { return bad(ErrLineOriginAbsent) }
	start := -1
	for i, event := range history { if !event.BeforePresent && event.AfterPresent { start = i; break } }
	if start == -1 { return bad(ErrLineOriginInput) }
	var previous model.Operation
	var content []byte
	var spans []LineOriginSpan
	for i := start; i >= 0; i-- {
		if err := ctx.Err(); err != nil { return bad(err) }
		event := history[i]
		if !event.AfterPresent || (i != start && (!event.BeforePresent || event.Before != previous)) { return bad(ErrLineOriginInput) }
		tag := event.After.Tag()
		if tag != model.SetRegular && tag != model.SetExecutable { return bad(ErrLineOriginInput) }
		id, present := event.After.Target(); if !present { return bad(ErrLineOriginInput) }
		priorID, hadPrior := previous.Target()
		if hadPrior && priorID == id { previous = event.After; continue }
		frame, exists := blobs[id]; if !exists { return bad(ErrTreeBlobMissing) }
		if uint64(len(frame)) > budget.BlobBytes-used.BlobBytes { return bad(ErrLineOriginBudget) }
		used.BlobBytes += uint64(len(frame))
		var decoded bytes.Buffer
		if _, err := model.DecodeBlob(ctx, bytes.NewReader(frame), id, &decoded, uint64(len(frame))); err != nil { return bad(err) }
		var prior []model.ChangesetID
		for _, span := range spans { for line := span.Start; line < span.End; line++ { if err := ctx.Err(); err != nil { return bad(err) }; prior = append(prior, span.Origin) } }
		used.Updates++
		nextSpans, work, err := DeriveFirstParentLineOrigins(ctx, event.Changeset, content, decoded.Bytes(), prior, budget.Derive)
		used.Lines.InputBytes += work.InputBytes; used.Lines.Lines += work.Lines; used.Lines.Cells += work.Cells; used.Lines.CompareBytes += work.CompareBytes
		if err != nil { return bad(err) }
		spans, content, previous = nextSpans, decoded.Bytes(), event.After
	}
	if err := ctx.Err(); err != nil { return bad(err) }
	id, _ := previous.Target()
	return CanonicalLineOrigins{Source: source, Path: path, Mode: previous.Tag(), Blob: id, Spans: spans}, used, nil
}
