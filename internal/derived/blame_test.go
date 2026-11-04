package derived

import (
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
