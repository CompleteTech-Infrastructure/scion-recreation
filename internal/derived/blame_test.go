package derived

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"canopy.local/canopy/internal/model"
)

func blameID(t *testing.T, b byte) model.ChangesetID {
	t.Helper()
	tid, err := model.NewTypedID(model.ChangesetKind, [32]byte{b}); if err != nil { t.Fatal(err) }
	id, err := model.NewChangesetID(tid); if err != nil { t.Fatal(err) }; return id
}
func blameBudget() LineOriginBudget { return LineOriginBudget{1<<20, 4096, 1<<20, 64<<20, 4096} }

func TestFirstParentLineOriginsExactByteSemantics(t *testing.T) {
	a, b, current := blameID(t, 1), blameID(t, 2), blameID(t, 3)
	for _, tc := range []struct { name, old, next string; prior []model.ChangesetID; want []LineOriginSpan }{
		{"empty", "", "", nil, nil},
		{"root", "", "a\nb\n", nil, []LineOriginSpan{{0, 2, current}}},
		{"delete all", "a\nb", "", []model.ChangesetID{a, b}, nil},
		{"identity", "a\nb\n", "a\nb\n", []model.ChangesetID{a, b}, []LineOriginSpan{{0, 1, a}, {1, 2, b}}},
		{"coalesce", "a\nb", "a\nb", []model.ChangesetID{a, a}, []LineOriginSpan{{0, 2, a}}},
		{"insert", "a\nb\n", "a\nx\nb\n", []model.ChangesetID{a, b}, []LineOriginSpan{{0, 1, a}, {1, 2, current}, {2, 3, b}}},
		{"delete first", "a\nb\n", "b\n", []model.ChangesetID{a, b}, []LineOriginSpan{{0, 1, b}}},
		{"replace", "a\nb\n", "a\nc\n", []model.ChangesetID{a, b}, []LineOriginSpan{{0, 1, a}, {1, 2, current}}},
		{"newline added", "a", "a\n", []model.ChangesetID{a}, []LineOriginSpan{{0, 1, current}}},
		{"newline removed", "a\n", "a", []model.ChangesetID{a}, []LineOriginSpan{{0, 1, current}}},
		{"empty lines", "\n\n", "\n\n", []model.ChangesetID{a, b}, []LineOriginSpan{{0, 1, a}, {1, 2, b}}},
		{"literal CR", "a\r\n", "a\n", []model.ChangesetID{a}, []LineOriginSpan{{0, 1, current}}},
		{"literal bytes", "\xff\n", "\xff\n", []model.ChangesetID{a}, []LineOriginSpan{{0, 1, a}}},
		{"tie skips old", "a\nb\n", "b\na\n", []model.ChangesetID{a, b}, []LineOriginSpan{{0, 1, b}, {1, 2, current}}},
		{"duplicate prefers equal", "a\na\n", "a\n", []model.ChangesetID{a, b}, []LineOriginSpan{{0, 1, a}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := DeriveFirstParentLineOrigins(context.Background(), current, []byte(tc.old), []byte(tc.next), tc.prior, blameBudget())
			if err != nil || !reflect.DeepEqual(got, tc.want) { t.Fatalf("origins: %+v want %+v: %v", got, tc.want, err) }
		})
	}
}

func TestFirstParentLineOriginsBoundsAndFailures(t *testing.T) {
	a, current := blameID(t, 1), blameID(t, 2)
	old, next := []byte("a\nb\n"), []byte("a\nc\n")
	prior := []model.ChangesetID{a, a}
	budget := LineOriginBudget{8, 4, 9, 16, 2}
	got, used, err := DeriveFirstParentLineOrigins(context.Background(), current, old, next, prior, budget)
	if err != nil || len(got) != 2 || used != (LineOriginUsage{8, 4, 9, 16}) { t.Fatalf("exact bounds: %+v %v", used, err) }
	for _, field := range []string{"input", "lines", "cells", "compare", "spans"} {
		short := budget; switch field { case "input": short.InputBytes--; case "lines": short.Lines--; case "cells": short.Cells--; case "compare": short.CompareBytes--; case "spans": short.Spans-- }
		if out, _, err := DeriveFirstParentLineOrigins(context.Background(), current, old, next, prior, short); err != ErrLineOriginBudget || out != nil { t.Fatalf("%s overflow exposed intervals: %v", field, err) }
	}
	for _, invalid := range []LineOriginBudget{{}, {1<<20+1, 4, 9, 16, 2}, {8, 4097, 9, 16, 2}, {8, 4, 1<<20+1, 16, 2}, {8, 4, 9, 64<<20+1, 2}, {8, 4, 9, 16, 5}} {
		if out, _, err := DeriveFirstParentLineOrigins(context.Background(), current, old, next, prior, invalid); err != ErrLineOriginBudget || out != nil { t.Fatal("invalid admission accepted") }
	}
	for _, invalid := range [][]model.ChangesetID{nil, {a}, {a, a, a}, {a, {}}} {
		if out, _, err := DeriveFirstParentLineOrigins(context.Background(), current, old, next, invalid, blameBudget()); err != ErrLineOriginInput || out != nil { t.Fatal("invalid first-parent origin coverage accepted") }
	}
	for _, pair := range [][2][]byte{{[]byte("a\x00"), next}, {old, []byte("\x00")}} {
		if out, _, err := DeriveFirstParentLineOrigins(context.Background(), current, pair[0], pair[1], prior, blameBudget()); err != ErrLineOriginBinary || out != nil { t.Fatal("binary side yielded origins") }
	}
	if out, _, err := DeriveFirstParentLineOrigins(nil, current, old, next, prior, budget); err != ErrLineOriginInput || out != nil { t.Fatal("nil context accepted") }
	if out, _, err := DeriveFirstParentLineOrigins(context.Background(), model.ChangesetID{}, old, next, prior, budget); err != ErrLineOriginInput || out != nil { t.Fatal("invalid current ID accepted") }
	got[0].Origin = current
	if prior[0] != a || string(old) != "a\nb\n" || string(next) != "a\nc\n" { t.Fatal("output aliased caller state") }
}

type blameCancelContext struct { context.Context; calls, at int }
func (c *blameCancelContext) Err() error { c.calls++; if c.at != 0 && c.calls >= c.at { return context.Canceled }; return nil }

func TestFirstParentLineOriginsCancellationDiscardsPartialIntervals(t *testing.T) {
	a, b, current := blameID(t, 1), blameID(t, 2), blameID(t, 3)
	before, after := []byte("a\nb\n"), []byte("a\nx\nb\n")
	probe := &blameCancelContext{Context: context.Background()}
	if out, _, err := DeriveFirstParentLineOrigins(probe, current, before, after, []model.ChangesetID{a, b}, blameBudget()); err != nil || len(out) != 3 { t.Fatal(err) }
	// The final call is the completion check; the preceding checkpoint is
	// before the third interval, after earlier intervals were collected.
	cancel := &blameCancelContext{Context: context.Background(), at: probe.calls-1}
	if out, _, err := DeriveFirstParentLineOrigins(cancel, current, before, after, []model.ChangesetID{a, b}, blameBudget()); err != context.Canceled || out != nil { t.Fatal("late cancellation exposed partial origins") }
	ctx, stop := context.WithCancel(context.Background()); stop()
	if out, _, err := DeriveFirstParentLineOrigins(ctx, current, before, after, []model.ChangesetID{a, b}, blameBudget()); err != context.Canceled || out != nil { t.Fatal("precancellation ignored") }
}

func TestCanonicalDAGLineOriginsResetLifetimeAndBindSource(t *testing.T) {
	ctx := context.Background(); repo := [16]byte{10}
	path, _ := model.NewPath([]byte("a")); missing, _ := model.NewPath([]byte("missing"))
	binary, binaryFrame := treeCanonicalBlob(t, []byte{0})
	base, baseFrame := treeCanonicalBlob(t, []byte("a\nb\n"))
	inserted, insertedFrame := treeCanonicalBlob(t, []byte("a\nx\nb\n"))
	final, finalFrame := treeCanonicalBlob(t, []byte("a\nx\nb"))
	blobs := map[model.BlobID][]byte{binary: binaryFrame, base: baseFrame, inserted: insertedFrame, final: finalFrame}
	original := make(map[model.BlobID][]byte); for id, frame := range blobs { original[id] = append([]byte(nil), frame...) }
	var sources []TreeSourceFrame
	for _, state := range []struct { tag model.OperationTag; blob model.BlobID }{{model.SetRegular, binary}, {model.Delete, model.BlobID{}}, {model.SetRegular, base}, {model.SetRegular, inserted}, {model.SetExecutable, inserted}, {model.SetExecutable, final}, {model.SetSymlink, final}} {
		var target *model.BlobID; if state.tag != model.Delete { target = &state.blob }
		op, err := model.NewOperation(path, state.tag, target); if err != nil { t.Fatal(err) }
		change := model.ChangesetInput{RepoID: repo, Operations: []model.Operation{op}}
		if len(sources) != 0 { change.Parents = []model.ChangesetID{sources[len(sources)-1].ID} }
		sources = append(sources, treeReplaySource(t, change))
	}
	graph := TreeObjectGraphBudget{graphTestBudget(), 1<<20}
	step := TreeCheckedWriteBudget{graph, graph, TreeChangesetBudget{TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}, 4096, model.MaxChangesetPayload}}
	history := CanonicalPathHistoryBudget{TreeReplayBudget{7, 1<<20, 4096, 4096*MaxTreePageBytes, step}, PathHistoryChainBudget{7, 1<<20, 7, TreeLookupBudget{4096, 4096*MaxTreePageBytes}}}
	budget := CanonicalBlameBudget{history, blameBudget(), uint64(len(baseFrame)+len(insertedFrame)+len(finalFrame))}
	got, used, err := ReadCanonicalDAGLineOrigins(ctx, repo, sources[5].ID, path, sources, blobs, budget)
	want := []LineOriginSpan{{0, 1, sources[2].ID}, {1, 2, sources[3].ID}, {2, 3, sources[5].ID}}
	if err != nil || got.Source != sources[5].ID || got.Path != path || got.Mode != model.SetExecutable || got.Blob != final || !reflect.DeepEqual(got.Spans, want) || used.Updates != 3 || used.BlobBytes != budget.BlobBytes || used.Lines != (LineOriginUsage{25, 13, 31, 48}) { t.Fatalf("canonical blame: %+v %+v %v", got, used, err) }
	// Executable-only changes preserve every origin and do not re-decode
	// the unchanged blob after its current-lifetime predecessor was verified.
	modeOnly, modeUsage, err := ReadCanonicalDAGLineOrigins(ctx, repo, sources[4].ID, path, sources, blobs, budget)
	wantMode := []LineOriginSpan{{0, 1, sources[2].ID}, {1, 2, sources[3].ID}, {2, 3, sources[2].ID}}
	if err != nil || modeOnly.Mode != model.SetExecutable || !reflect.DeepEqual(modeOnly.Spans, wantMode) || modeUsage.Updates != 2 || modeUsage.BlobBytes != uint64(len(baseFrame)+len(insertedFrame)) { t.Fatal("mode-only change took line ownership") }
	for _, tc := range []struct { source model.ChangesetID; path model.Path; want error }{{sources[0].ID, path, ErrLineOriginBinary}, {sources[1].ID, path, ErrLineOriginAbsent}, {sources[6].ID, path, ErrLineOriginInput}, {sources[5].ID, missing, ErrLineOriginAbsent}} {
		out, _, err := ReadCanonicalDAGLineOrigins(ctx, repo, tc.source, tc.path, sources, blobs, budget)
		if err != tc.want || !reflect.DeepEqual(out, CanonicalLineOrigins{}) { t.Fatalf("explicit absent/binary/type policy: %v", err) }
	}
	for _, dimension := range []string{"blob", "cells", "compare", "spans"} {
		short := budget
		switch dimension { case "blob": short.BlobBytes--; case "cells": short.Derive.Cells = 15; case "compare": short.Derive.CompareBytes = 23; case "spans": short.Derive.Spans = 2 }
		if out, _, err := ReadCanonicalDAGLineOrigins(ctx, repo, sources[5].ID, path, sources, blobs, short); err != ErrLineOriginBudget || !reflect.DeepEqual(out, CanonicalLineOrigins{}) { t.Fatalf("%s exhaustion exposed partial origins: %v", dimension, err) }
	}
	if out, _, err := ReadCanonicalDAGLineOrigins(ctx, repo, sources[5].ID, path, sources, nil, budget); err == nil || !reflect.DeepEqual(out, CanonicalLineOrigins{}) { t.Fatal("missing retained blob accepted") }
	if out, _, err := ReadCanonicalDAGLineOrigins(ctx, [16]byte{11}, sources[5].ID, path, sources, blobs, budget); err == nil || !reflect.DeepEqual(out, CanonicalLineOrigins{}) { t.Fatal("foreign repository accepted") }
	bad := append([]TreeSourceFrame(nil), sources...); bad[6].Frame = append([]byte(nil), bad[6].Frame...); bad[6].Frame[len(bad[6].Frame)-1] ^= 1
	if out, _, err := ReadCanonicalDAGLineOrigins(ctx, repo, sources[5].ID, path, bad, blobs, budget); err == nil || !reflect.DeepEqual(out, CanonicalLineOrigins{}) { t.Fatal("off-lineage source corruption ignored") }
	// The final completion checkpoint occurs after private spans exist.
	probe := &blameCancelContext{Context: ctx}
	if _, _, err := ReadCanonicalDAGLineOrigins(probe, repo, sources[5].ID, path, sources, blobs, budget); err != nil { t.Fatal(err) }
	cancel := &blameCancelContext{Context: ctx, at: probe.calls}
	if out, _, err := ReadCanonicalDAGLineOrigins(cancel, repo, sources[5].ID, path, sources, blobs, budget); err != context.Canceled || !reflect.DeepEqual(out, CanonicalLineOrigins{}) { t.Fatal("final cancellation exposed origins") }
	for id, frame := range blobs { if !bytes.Equal(frame, original[id]) { t.Fatal("canonical blame mutated blob input") } }
}
