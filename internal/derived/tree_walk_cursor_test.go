//go:build darwin || linux

package derived_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
	"canopy.local/canopy/internal/storage/treepages"
)

type cursorAuthority struct{ denied bool }

func (a *cursorAuthority) Authorize(context.Context, derived.TreePageID, string) error {
	if a.denied {
		return errors.New("denied")
	}
	return nil
}

type cursorReader struct {
	get          func(context.Context, derived.TreePageID) ([]byte, error)
	reads, bytes uint64
}

func (r *cursorReader) GetCandidate(c context.Context, id derived.TreePageID) ([]byte, error) {
	r.reads++
	b, e := r.get(c, id)
	r.bytes += uint64(len(b))
	return b, e
}
func cursorLimits() derived.TreeWalkLimits {
	return derived.TreeWalkLimits{Fetches: 20000, Terminals: 10000, PageBytes: 20000 * derived.MaxTreePageBytes, MaxDepth: 65536}
}
func cursorQuantum() derived.TreeWalkQuantum {
	return derived.TreeWalkQuantum{Fetches: 4096, Terminals: 4096, PageBytes: 4096 * derived.MaxTreePageBytes}
}
func cursorStore(t *testing.T, a *cursorAuthority, frames map[derived.TreePageID][]byte) (*treepages.Staging, string) {
	t.Helper()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := treepages.OpenStaging(root, treepages.Options{MaxStoredBytes: 8 << 20, MaxCandidates: 4096, MaxConcurrentOps: 2, RecoveryBatch: 64}, a)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	for i := 0; ; i++ {
		done, e := s.RecoverTemps(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		if done {
			break
		}
		if i == 10 {
			t.Fatal("fixture recovery did not complete")
		}
	}
	for id, b := range frames {
		if _, e := s.Stage(context.Background(), id, bytes.NewReader(b)); e != nil {
			t.Fatal(e)
		}
	}
	return s, root
}
func cursorEncode(t *testing.T, p derived.UnlinkedTreePage, component []byte) (derived.TreePageID, []byte) {
	t.Helper()
	b, id, e := derived.EncodeTreePageAt(p, nil, component)
	if e != nil {
		t.Fatal(e)
	}
	return id, b
}

// Seed TREE-CURSOR-299-v1. One shared branch appears under each root edge;
// its shared file page is expanded under every distinct component prefix.
func cursorWide(t *testing.T, roots, leaves int) (derived.TreePageID, map[derived.TreePageID][]byte, uint64, uint64) {
	t.Helper()
	tid, _ := model.NewTypedID(model.BlobKind, sha256.Sum256([]byte("cursor-file")))
	blob, _ := model.NewBlobID(tid)
	leaf, b := cursorEncode(t, derived.UnlinkedTreePage{Label: []byte("z"), Tag: 1, Blob: blob}, []byte{1, 1})
	frames := map[derived.TreePageID][]byte{leaf: b}
	branch := derived.UnlinkedTreePage{}
	for i := 1; len(branch.Children) < leaves; i++ {
		if i == '/' {
			continue
		}
		branch.Children = append(branch.Children, derived.TreePageChild{Edge: byte(i), ID: leaf})
	}
	bid, b := cursorEncode(t, branch, []byte{1})
	frames[bid] = b
	top := derived.UnlinkedTreePage{}
	for i := 1; i <= roots; i++ {
		top.Children = append(top.Children, derived.TreePageChild{Edge: byte(i), ID: bid})
	}
	root, b := cursorEncode(t, top, nil)
	frames[root] = b
	return root, frames, uint64(roots * leaves), uint64(roots + 1 + roots*(leaves+1) + roots*leaves)
}
func TestStoredTreeCursorCrossesQuantumWithoutSkippingSharedContexts(t *testing.T) {
	root, frames, terms, fetches := cursorWide(t, 22, 254)
	s, _ := cursorStore(t, &cursorAuthority{}, frames)
	r := &cursorReader{get: s.GetCandidate}
	c, e := derived.NewTreeWalkCursor(root, r, cursorLimits())
	if e != nil {
		t.Fatal(e)
	}
	var p derived.TreeWalkProgress
	calls := 0
	for ; calls < 20; calls++ {
		p, e = c.Advance(context.Background(), cursorQuantum())
		if e != nil {
			t.Fatal(e)
		}
		if p.Quantum.Fetches > 4096 || p.Quantum.Terminals > 4096 || p.Quantum.PageBytes > 4096*derived.MaxTreePageBytes {
			t.Fatal("quantum overrun", p)
		}
		if p.TopologyDone {
			break
		}
	}
	if !p.TopologyDone || calls < 2 || p.Total.Terminals != terms || p.Total.Fetches != fetches || p.Total.Fetches != r.reads || p.Total.PageBytes != r.bytes {
		t.Fatalf("calls=%d progress=%+v reads=%d bytes=%d expected=%d/%d", calls+1, p, r.reads, r.bytes, terms, fetches)
	}
	before := r.reads
	p, e = c.Advance(context.Background(), cursorQuantum())
	if e != nil || !p.TopologyDone || r.reads != before || p.Quantum != (derived.TreeWalkUsage{}) {
		t.Fatal("completion repeated work", p, e)
	}
	if _, e := derived.CheckTreePageGraph(context.Background(), root, frames, derived.TreeGraphBudget{Visits: 4096, PageBytes: 4096 * derived.MaxTreePageBytes, ContextBytes: 64 << 20}); !errors.Is(e, metadata.ErrResourceExhausted) {
		t.Fatal("single quantum unexpectedly sufficient", e)
	}
	t.Logf("seed TREE-CURSOR-299-v1: actual private frames=%d; occurrences=%d; fetches=%d; bytes=%d; quanta=%d", len(frames), terms, fetches, r.bytes, calls+1)
}
func TestStoredTreeCursorMatchesSmallTopologyOracle(t *testing.T) {
	root, frames, terms, fetches := cursorWide(t, 2, 2)
	s, _ := cursorStore(t, &cursorAuthority{}, frames)
	want, e := derived.CheckTreePageGraph(context.Background(), root, frames, derived.TreeGraphBudget{Visits: 4096, PageBytes: 4096 * derived.MaxTreePageBytes, ContextBytes: 64 << 20})
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range []uint64{1, 2, 4, 4096} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			c, e := derived.NewTreeWalkCursor(root, s, cursorLimits())
			if e != nil {
				t.Fatal(e)
			}
			q := cursorQuantum()
			q.Fetches = n
			q.Terminals = 1
			for i := 0; i < 100; i++ {
				p, e := c.Advance(context.Background(), q)
				if e != nil {
					t.Fatal(e)
				}
				if p.TopologyDone {
					if p.Total.Terminals != terms || p.Total.Terminals != want.Terminals || p.Total.Fetches != fetches {
						t.Fatal(p, want)
					}
					return
				}
			}
			t.Fatal("no completion")
		})
	}
}
func TestStoredTreeCursorEmptyDirectoryAndLongPaths(t *testing.T) {
	tid, _ := model.NewTypedID(model.BlobKind, sha256.Sum256([]byte("target")))
	blob, _ := model.NewBlobID(tid)
	for _, raw := range [][]byte{nil, []byte("dir/sub/file"), bytes.Repeat([]byte{'x'}, 65535)} {
		t.Run(fmt.Sprint(len(raw)), func(t *testing.T) {
			var root derived.TreePageID
			var frames map[derived.TreePageID][]byte
			var e error
			if raw == nil {
				id, b := cursorEncode(t, derived.UnlinkedTreePage{}, nil)
				root, frames = id, map[derived.TreePageID][]byte{id: b}
			} else {
				path, e := model.NewPath(raw)
				if e != nil {
					t.Fatal(e)
				}
				root, frames, e = derived.BuildSingleLeafTree(context.Background(), path, 1, blob, derived.TreeBuildBudget{Pages: 4096, Bytes: 4096 * derived.MaxTreePageBytes})
				if e != nil {
					t.Fatal(e)
				}
			}
			s, _ := cursorStore(t, &cursorAuthority{}, frames)
			c, e := derived.NewTreeWalkCursor(root, s, cursorLimits())
			if e != nil {
				t.Fatal(e)
			}
			q := cursorQuantum()
			q.Fetches = 1
			for i := 0; i < 2000; i++ {
				p, e := c.Advance(context.Background(), q)
				if e != nil {
					t.Fatal(e)
				}
				if p.TopologyDone {
					want := uint64(0)
					if raw != nil {
						want = 1 + uint64(bytes.Count(raw, []byte{'/'}))
					}
					if p.Total.Terminals != want {
						t.Fatal(p, want)
					}
					return
				}
			}
			t.Fatal("not done")
		})
	}
}
func TestStoredTreeCursorFailuresAreStickyAndNeverComplete(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "denied", "cancel", "bytes", "fetches", "terminals", "depth", "oversized", "readerError", "badContext"} {
		t.Run(kind, func(t *testing.T) {
			root, frames, _, _ := cursorWide(t, 2, 2)
			a := &cursorAuthority{}
			s, dir := cursorStore(t, a, frames)
			r := &cursorReader{get: s.GetCandidate}
			limits := cursorLimits()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "missing":
				for id := range frames {
					if id != root {
						b, _ := id.MarshalBinary()
						if e := os.Remove(filepath.Join(dir, "candidate-tree-v1-"+hex.EncodeToString(b))); e != nil {
							t.Fatal(e)
						}
						break
					}
				}
			case "corrupt":
				b, _ := root.MarshalBinary()
				name := filepath.Join(dir, "candidate-tree-v1-"+hex.EncodeToString(b))
				if e := os.Chmod(name, 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(name, []byte("torn"), 0400); e != nil {
					t.Fatal(e)
				}
				if e := os.Chmod(name, 0400); e != nil {
					t.Fatal(e)
				}
			case "denied":
				a.denied = true
			case "cancel":
				cancel()
			case "bytes":
				limits.PageBytes = derived.MaxTreePageBytes
			case "fetches":
				limits.Fetches = 1
			case "terminals":
				limits.Terminals = 1
			case "depth":
				limits.MaxDepth = 1
			case "oversized":
				r.get = func(context.Context, derived.TreePageID) ([]byte, error) {
					return make([]byte, derived.MaxTreePageBytes+1), nil
				}
			case "readerError":
				r.get = func(context.Context, derived.TreePageID) ([]byte, error) {
					return []byte("some data"), errors.New("backend failed")
				}
			case "badContext":
				// A 254-byte label is valid at offset zero but cannot fit
				// the 253-byte anchor remainder at component offset two.
				tid, _ := model.NewTypedID(model.BlobKind, sha256.Sum256([]byte("long")))
				blob, _ := model.NewBlobID(tid)
				id, b := cursorEncode(t, derived.UnlinkedTreePage{Label: bytes.Repeat([]byte{'z'}, 254), Tag: 1, Blob: blob}, nil)
				parent := derived.UnlinkedTreePage{Label: []byte("x"), Children: []derived.TreePageChild{{Edge: 'y', ID: id}, {Edge: 'z', ID: id}}}
				var bp []byte
				root, bp = cursorEncode(t, parent, nil)
				frames = map[derived.TreePageID][]byte{root: bp, id: b}
				r.get = func(_ context.Context, id derived.TreePageID) ([]byte, error) { return frames[id], nil }

			}
			c, e := derived.NewTreeWalkCursor(root, r, limits)
			if e != nil {
				t.Fatal(e)
			}
			p, e := c.Advance(ctx, cursorQuantum())
			if e == nil || p.TopologyDone {
				t.Fatal("failure became completion", p, e)
			}
			reads := r.reads
			p, e2 := c.Advance(context.Background(), cursorQuantum())
			if e2 != e || p.TopologyDone || r.reads != reads {
				t.Fatal("failed attempt resumed", p, e, e2)
			}
		})
	}
}
func TestStoredTreeCursorConcurrentAdmissionAndCancellation(t *testing.T) {
	root, b := cursorEncode(t, derived.UnlinkedTreePage{}, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	r := &cursorReader{get: func(ctx context.Context, _ derived.TreePageID) ([]byte, error) {
		close(entered)
		select {
		case <-release:
			return b, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	c, e := derived.NewTreeWalkCursor(root, r, cursorLimits())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		p, e := c.Advance(ctx, cursorQuantum())
		if p.TopologyDone {
			result <- errors.New("canceled operation completed")
			return
		}
		result <- e
	}()
	<-entered
	p, e := c.Advance(context.Background(), cursorQuantum())
	if !errors.Is(e, derived.ErrTreeWalkBusy) || p.TopologyDone {
		t.Fatal(p, e)
	}
	cancel()
	if e := <-result; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestStoredTreeCursorRejectsZeroAndInvalidConfiguration(t *testing.T) {
	root, b := cursorEncode(t, derived.UnlinkedTreePage{}, nil)
	r := &cursorReader{get: func(context.Context, derived.TreePageID) ([]byte, error) { return b, nil }}
	var zero derived.TreeWalkCursor
	if p, e := zero.Advance(context.Background(), cursorQuantum()); !errors.Is(e, metadata.ErrInvalidArgument) || p.TopologyDone {
		t.Fatal(p, e)
	}
	var nilReader *cursorReader
	for _, reader := range []derived.TreeCandidateReader{nil, nilReader} {
		if _, e := derived.NewTreeWalkCursor(root, reader, cursorLimits()); !errors.Is(e, metadata.ErrInvalidArgument) {
			t.Fatal(e)
		}
	}
	for _, change := range []func(*derived.TreeWalkLimits){func(l *derived.TreeWalkLimits) { l.Fetches = 0 }, func(l *derived.TreeWalkLimits) { l.Terminals = 0 }, func(l *derived.TreeWalkLimits) { l.PageBytes = 1 }, func(l *derived.TreeWalkLimits) { l.MaxDepth = 65537 }} {
		l := cursorLimits()
		change(&l)
		if _, e := derived.NewTreeWalkCursor(root, r, l); !errors.Is(e, metadata.ErrInvalidArgument) {
			t.Fatal(e)
		}
	}
	c, e := derived.NewTreeWalkCursor(root, r, cursorLimits())
	if e != nil {
		t.Fatal(e)
	}
	q := cursorQuantum()
	q.Fetches = 4097
	if _, e = c.Advance(context.Background(), q); !errors.Is(e, metadata.ErrInvalidArgument) {
		t.Fatal(e)
	}
	if p, e := c.Advance(context.Background(), cursorQuantum()); e != nil || !p.TopologyDone {
		t.Fatal("invalid call poisoned valid cursor", p, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, e := c.Advance(ctx, cursorQuantum()); !errors.Is(e, context.Canceled) || p.TopologyDone {
		t.Fatal("completed cursor ignores cancellation", p, e)
	}
}
