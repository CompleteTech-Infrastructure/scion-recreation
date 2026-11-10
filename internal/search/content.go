package search

import (
	"bytes"
	"context"
	"strings"
	"unicode/utf8"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

// ContentClass is a private bounded-index admission policy, not a universal
// binary detector or public protocol. Classification follows successful hash
// verification. Symlink precedes size, then NUL, then invalid UTF-8.
type ContentClass uint8
const (
	ContentText ContentClass = iota + 1
	ContentSymlink
	ContentTooLarge
	ContentBinary
	ContentInvalidUTF8
)
type ContentEntry struct { Operation model.Operation; Class ContentClass; Text string }
type ContentSnapshot struct {
	repository [16]byte
	source model.ChangesetID
	entries []ContentEntry
	fileBytes uint64
}
type ContentBudget struct { Files, FrameBytes, FileBytes, TextBytes uint64 }
type ContentUsage struct { Files, FrameBytes, TextBytes uint64 }

type contentStage struct { limit uint64; data []byte }
func (s *contentStage) Write(p []byte) (int, error) {
	keep := min(uint64(len(p)), s.limit-uint64(len(s.data)))
	s.data = append(s.data, p[:int(keep)]...)
	return len(p), nil
}

// BuildContentSnapshot consumes only a canonical PathSnapshot, re-verifying
// every referenced blob against its exact typed identity. Full frames are
// admitted before decoding; repeated references count repeatedly. A private
// staging writer retains at most FileBytes for regular/executable files and no
// payload for symlinks, while the decoder still verifies the entire frame.
// Oversize is a classification, not truncated
// text; malformed/missing frames are errors, never classification shortcuts.
//
// Files <=4096, aggregate frame/text bytes <=1MiB. Staging, owned text copies
// and decoder buffer are separate bounded allocations, not a measured RSS cap.
// Inputs must remain stable during construction. Any failure returns nil.
// No durable index, freshness/outbox state, publication or authorization is
// established. Content and classifications must not bypass permission checks.
func BuildContentSnapshot(ctx context.Context, paths *PathSnapshot, blobs map[model.BlobID][]byte, budget ContentBudget) (*ContentSnapshot, ContentUsage, error) {
	snapshot, used, err := buildContentSnapshot(ctx, paths, nil, blobs, budget)
	return snapshot, used.Admission, err
}

type ContentReuseUsage struct { Admission ContentUsage; Reused uint64 }
type contentReuseKey struct { blob model.BlobID; symlink bool }

// BuildContentSnapshotReusing avoids decoding already verified immutable blob
// content from a previous private snapshot in the SAME repository and with the
// SAME FileBytes policy. Exact blob ID and symlink-vs-file mode select reuse;
// path, revision and regular/executable mode come from the new canonical paths.
// Deleted paths are absent because only the new snapshot's rows are visited.
// Previous revision need not be an ancestor: immutable content identity, not
// event order, justifies reuse. This does not update either input snapshot.
//
// On failed builds, Files counts attempted rows admitted before blob lookup,
// including a missing-frame row (fresh builds now share this accounting).
// FrameBytes charges newly decoded references only; Files and TextBytes charge
// all new rows, including reused data. Reused counts rows, not unique objects.
// New references are not added to the reuse map during this build. The previous
// <=4096 rows bound map setup; all text still fits the new aggregate text cap.
// Missing raw bytes are allowed ONLY for a verified reuse hit. Supplied bytes
// for a hit are not consulted. The new PathSnapshot must already have passed
// full canonical replay, so this saves content decoding, not tree verification
// or network fetches. Nil previous is equivalent to a fresh content build.
// This remains private computation, not an authorization or retention receipt.
func BuildContentSnapshotReusing(ctx context.Context, paths *PathSnapshot, previous *ContentSnapshot, blobs map[model.BlobID][]byte, budget ContentBudget) (*ContentSnapshot, ContentReuseUsage, error) {
	return buildContentSnapshot(ctx, paths, previous, blobs, budget)
}

func buildContentSnapshot(ctx context.Context, paths *PathSnapshot, previous *ContentSnapshot, blobs map[model.BlobID][]byte, budget ContentBudget) (*ContentSnapshot, ContentReuseUsage, error) {
	var usage ContentReuseUsage
	used := &usage.Admission
	bad := func(err error) (*ContentSnapshot, ContentReuseUsage, error) { return nil, usage, err }
	if ctx == nil || paths == nil || paths.source.Validate() != nil || budget.Files == 0 || budget.Files > 4096 || budget.FrameBytes == 0 || budget.FrameBytes > 1<<20 || budget.FileBytes > 1<<20 || budget.TextBytes > 1<<20 { return bad(metadata.ErrInvalidArgument) }
	if previous != nil && (previous.source.Validate() != nil || previous.repository != paths.repository || previous.fileBytes != budget.FileBytes) { return bad(metadata.ErrInvalidArgument) }
	if err := ctx.Err(); err != nil { return bad(err) }
	var reusable map[contentReuseKey]ContentEntry
	if previous != nil {
		reusable = make(map[contentReuseKey]ContentEntry,len(previous.entries))
		for _, entry := range previous.entries {
			if err := ctx.Err(); err != nil { return bad(err) }
			id, ok := entry.Operation.Target(); if !ok { return bad(metadata.ErrInvalidArgument) }
			reusable[contentReuseKey{id,entry.Operation.Tag()==model.SetSymlink}] = entry
		}
	}
	var entries []ContentEntry
	for _, row := range paths.rows {
		if err := ctx.Err(); err != nil { return bad(err) }
		id, ok := row.Target(); if !ok { return bad(metadata.ErrInvalidArgument) }
		if used.Files == budget.Files { return bad(metadata.ErrResourceExhausted) }
		used.Files++
		if entry, ok := reusable[contentReuseKey{id,row.Tag()==model.SetSymlink}]; ok {
			n := uint64(len(entry.Text))
			if n > budget.TextBytes-used.TextBytes { return bad(metadata.ErrResourceExhausted) }
			used.TextBytes += n; usage.Reused++
			entry.Operation = row; entries = append(entries,entry)
			continue
		}
		frame, ok := blobs[id]; if !ok { return bad(metadata.ErrFailedPrecondition) }
		if uint64(len(frame)) > budget.FrameBytes-used.FrameBytes { return bad(metadata.ErrResourceExhausted) }
		used.FrameBytes += uint64(len(frame))
		stage := &contentStage{limit: budget.FileBytes}
		// Symlinks never expose text, even when their payload exceeds FileBytes
		// or contains NUL/invalid UTF-8. Discard only staging bytes, not validation.
		if row.Tag() == model.SetSymlink { stage.limit = 0 }
		n, err := model.DecodeBlob(ctx, bytes.NewReader(frame), id, stage, budget.FrameBytes)
		if err != nil { return bad(err) }
		entry := ContentEntry{Operation: row}
		switch {
		case row.Tag() == model.SetSymlink: entry.Class = ContentSymlink
		case n > budget.FileBytes: entry.Class = ContentTooLarge
		case bytes.IndexByte(stage.data, 0) >= 0: entry.Class = ContentBinary
		case !utf8.Valid(stage.data): entry.Class = ContentInvalidUTF8
		default:
			if n > budget.TextBytes-used.TextBytes { return bad(metadata.ErrResourceExhausted) }
			used.TextBytes += n; entry.Class = ContentText; entry.Text = string(stage.data)
		}
		entries = append(entries, entry)
	}
	if err := ctx.Err(); err != nil { return bad(err) }
	return &ContentSnapshot{repository: paths.repository, source: paths.source, entries: entries, fileBytes: budget.FileBytes}, usage, nil
}

// Entries returns a private owned slice; immutable strings/operations preserve
// exact source content without aliasing caller frame bytes. It is not a public
// result or permission grant, including entries excluded from text search.
func (s *ContentSnapshot) Entries() []ContentEntry {
	if s == nil { return nil }
	return append([]ContentEntry(nil), s.entries...)
}
type ContentQueryBudget struct { Work, Matches uint64 }

// Contains returns files containing a nonempty literal UTF-8 byte string, once
// per file, in path order. There is no normalization, tokenization or regex.
// Expected source/repository must match exactly. Work reserves text-length
// times needle-length before each bounded library search; cancellation is
// checked between searches, not inside strings.Contains. No partial results.
func (s *ContentSnapshot) Contains(ctx context.Context, repository [16]byte, source model.ChangesetID, needle string, budget ContentQueryBudget) ([]model.Operation, uint64, error) {
	var used uint64
	bad := func(err error) ([]model.Operation, uint64, error) { return nil, used, err }
	if ctx == nil || s == nil || s.source.Validate() != nil || repository != s.repository || source != s.source || len(needle) == 0 || len(needle) > 65535 || !utf8.ValidString(needle) || strings.IndexByte(needle,0) >= 0 || budget.Work == 0 || budget.Work > 64<<20 || budget.Matches == 0 || budget.Matches > 4096 { return bad(metadata.ErrInvalidArgument) }
	if err := ctx.Err(); err != nil { return bad(err) }
	var out []model.Operation
	for _, entry := range s.entries {
		if err := ctx.Err(); err != nil { return bad(err) }
		if entry.Class != ContentText { continue }
		cost := uint64(len(entry.Text))*uint64(len(needle))
		if cost > budget.Work-used { return bad(metadata.ErrResourceExhausted) }; used += cost
		if !strings.Contains(entry.Text, needle) { continue }
		if uint64(len(out)) == budget.Matches { return bad(metadata.ErrResourceExhausted) }
		out = append(out, entry.Operation)
	}
	if err := ctx.Err(); err != nil { return bad(err) }
	return out, used, nil
}
