package workspace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"canopy.local/canopy/internal/model"
)

// This fixture supplies an injected barrier and trusted-caller assertions;
// it does not emulate native OS notifications or independently prove a base tree.
type injectedBarrier struct{ action func(context.Context) error }

func (b *injectedBarrier) Barrier(c context.Context) error {
	if b.action != nil {
		return b.action(c)
	}
	return nil
}
func (b *injectedBarrier) Close() error { return nil }

func watchFixture(t *testing.T, change func(*WatchLimits)) (*Watch, string, string) {
	t.Helper()
	root, meta := t.TempDir(), privateMetadataDir(t)
	m := Manifest{Base: testChangeset(t, "watch baseline"), SparseVersion: 1, SparseAll: true, State: Clean}
	watchOK(t, Save(meta, m))
	limits := WatchLimits{Candidates: 2, CandidateBytes: 32, Queue: 4, Entries: 20, Bytes: 4096, Depth: 4, Descriptors: 2, Attempts: 12, Duration: time.Second}
	if change != nil {
		change(&limits)
	}
	w, err := OpenWatch(root, meta, limits, &injectedBarrier{})
	watchCheck(t, err == nil, "%v", err)
	t.Cleanup(func() { _ = w.Close() })
	return w, root, meta
}
func watchCheck(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}
func watchIs(t *testing.T, err, target error) {
	t.Helper()
	watchCheck(t, errors.Is(err, target), "got %v, want %v", err, target)
}
func watchOK(t *testing.T, err error) {
	t.Helper()
	watchCheck(t, err == nil, "%v", err)
}
func watchFile(t *testing.T, path, contents string) {
	t.Helper()
	f, e := os.Create(path)
	watchCheck(t, e == nil, "%v", e)
	if _, e = f.WriteString(contents); e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	watchCheck(t, e == nil, "%v", e)
}
func watchUnknown(t *testing.T, w *Watch, meta string) {
	t.Helper()
	m, _, _ := w.Snapshot()
	watchCheck(t, !(m.State != Uncertain), "state=%v", m.State)
	disk, e := Load(meta)
	watchCheck(t, !(e == nil && disk.State == Clean), "unexpected durable clean")
}
func watchProof(w *Watch, s WatchScan) CleanAssertion {
	m, _, _ := w.Snapshot()
	p := s.AssertionBinding(m)
	p.ContentVerifiedDurable = true
	return p
}
func watchScan(t *testing.T, w *Watch) WatchScan {
	t.Helper()
	s, e := w.Scan(context.Background())
	watchCheck(t, e == nil, "%v", e)
	return s
}

func TestWatchRealInventoryAndContentAssertion(t *testing.T) {
	w, root, meta := watchFixture(t, nil)
	raw := "raw\n\\\t\x7f"
	watchFile(t, filepath.Join(root, raw), "base")
	watchOK(t, os.Mkdir(filepath.Join(root, "sub"), 0700))
	watchFile(t, filepath.Join(root, "sub", "file"), "child")
	outside := t.TempDir()
	watchFile(t, filepath.Join(outside, "secret"), "outside")
	for name, target := range map[string]string{"out": outside, "in": "sub"} {
		watchOK(t, os.Symlink(target, filepath.Join(root, name)))
	}
	path := []byte(raw)
	watchOK(t, w.Observe([]WatchEvent{{WatchPath, path}}))
	path[0] = 'x'
	m, _, _ := w.Snapshot()
	requirePathBytes(t, m.DirtyPaths, []byte(raw))
	s := watchScan(t, w)
	var paths []string
	for _, e := range s.Entries {
		paths = append(paths, string(e.Path.Bytes()))
	}
	if !slices.Equal(paths, []string{"in", "out", raw, "sub", "sub/file"}) {
		t.Fatalf("raw inventory=%q", paths)
	}
	watchCheck(t, !(!s.Progress.Complete || !s.Progress.RestartAtRoot || s.Progress.OwnedDescriptors != 2), "progress=%+v", s.Progress)
	// Enumeration alone is not a content proof, even for identical stat metadata.
	proof := s.AssertionBinding(m)
	watchIs(t, w.Finish(context.Background(), s, proof), ErrWatchStale)
	watchUnknown(t, w, meta)
	s = watchScan(t, w)
	proof = watchProof(w, s)
	got, e := os.ReadFile(filepath.Join(root, raw))
	watchCheck(t, e == nil, "%v", e)
	proof.ContentVerifiedDurable = string(got) == "base"
	watchOK(t, w.Finish(context.Background(), s, proof))
	disk, e := Load(meta)
	watchCheck(t, !(e != nil || disk.State != Clean), "durable clean=%+v %v", disk, e)
	watchOK(t, w.Observe([]WatchEvent{{WatchPath, []byte(raw)}}))
	watchFile(t, filepath.Join(root, raw), "edit")
	s = watchScan(t, w)
	proof = watchProof(w, s)
	got, e = os.ReadFile(filepath.Join(root, raw))
	watchCheck(t, e == nil, "%v", e)
	proof.ContentVerifiedDurable = string(got) == "base"
	watchIs(t, w.Finish(context.Background(), s, proof), ErrWatchStale)
	watchUnknown(t, w, meta)
}

func TestWatchEventsAndBounds(t *testing.T) {
	cases := []struct {
		name   string
		events []WatchEvent
		limit  bool
	}{
		{"loss", []WatchEvent{{Kind: WatchLoss}}, false},
		{"invalid-utf8-event", []WatchEvent{{WatchPath, []byte{0xff}}}, false},
		{"loss-full", []WatchEvent{{Kind: WatchLoss}}, false},
		{"unknown-kind", []WatchEvent{{Kind: 99}}, true},
		{"escape", []WatchEvent{{WatchPath, []byte("../out")}}, true},
		{"nul", []WatchEvent{{WatchPath, []byte{'x', 0}}}, true},
		{"queue", make([]WatchEvent, 5), true},
		{"candidate", []WatchEvent{{WatchPath, []byte("a")}, {WatchPath, []byte("b")}, {WatchPath, []byte("c")}}, true},
		{"bytes", []WatchEvent{{WatchPath, []byte("123456789012345678901234567890123")}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, _, meta := watchFixture(t, nil)
			if tc.name == "loss-full" {
				watchOK(t, w.Observe([]WatchEvent{{WatchPath, []byte("a")}, {WatchPath, []byte("b")}}))
			}
			_, before, _ := w.Snapshot()
			e := w.Observe(tc.events)
			watchCheck(t, !((e != nil) != tc.limit), "error=%v", e)
			m, after, _ := w.Snapshot()
			watchCheck(t, !(after <= before || len(m.DirtyPaths) > 2), "generation/hints=%d %+v", after, m)
			if tc.name == "invalid-utf8-event" {
				requirePathBytes(t, m.DirtyPaths, []byte{0xff})
			}
			watchUnknown(t, w, meta)
		})
	}
}
func TestWatchScanBudgetsAndErrors(t *testing.T) {
	for _, kind := range []string{"entries", "bytes", "depth", "queue", "descriptors", "time", "cancel", "cancel-mid", "missing", "nested-missing", "retry"} {
		t.Run(kind, func(t *testing.T) {
			limits := map[string]func(*WatchLimits){
				"entries": func(l *WatchLimits) { l.Entries = 1 }, "bytes": func(l *WatchLimits) { l.Bytes = 16 },
				"depth": func(l *WatchLimits) { l.Depth = 1 }, "queue": func(l *WatchLimits) { l.Queue = 1 },
				"descriptors": func(l *WatchLimits) { l.Descriptors = 1 }, "time": func(l *WatchLimits) { l.Duration = time.Nanosecond },
				"retry": func(l *WatchLimits) { l.Attempts = 1 },
			}
			w, root, meta := watchFixture(t, limits[kind])
			if kind == "nested-missing" {
				watchOK(t, os.Mkdir(filepath.Join(root, "sub"), 0700))
				watchFile(t, filepath.Join(root, "sub", "a"), "x")
				w.step = func(p model.Path) {
					if string(p.Bytes()) == "sub/a" {
						watchOK(t, os.RemoveAll(filepath.Join(root, "sub")))
						w.step = nil
					}
				}
			} else if kind == "depth" {
				watchOK(t, os.MkdirAll(filepath.Join(root, "a", "b"), 0700))
			} else if kind == "queue" {
				for _, p := range []string{"a", "b"} {
					watchOK(t, os.Mkdir(filepath.Join(root, p), 0700))
				}
			} else if kind == "missing" {
				watchOK(t, os.Remove(root))
			} else {
				watchFile(t, filepath.Join(root, "a"), "x")
				watchFile(t, filepath.Join(root, "b"), "x")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel" {
				cancel()
			}
			if kind == "cancel-mid" {
				w.step = func(model.Path) { cancel() }
			}
			s, e := w.Scan(ctx)
			if kind == "retry" {
				watchCheck(t, e == nil, "%v", e)
				s, e = w.Scan(ctx)
			}
			watchCheck(t, !(e == nil || s.Progress.Complete), "expected incomplete: %+v %v", s.Progress, e)
			watchCheck(t, !(s.Progress.Bytes > w.limits.Bytes || s.Progress.Entries > w.limits.Entries || s.Progress.OwnedDescriptors > w.limits.Descriptors), "budget overrun %+v", s.Progress)
			watchCheck(t, w.Finish(context.Background(), s, watchProof(w, s)) != nil, "incomplete clean")
			watchUnknown(t, w, meta)
		})
	}
}

func TestWatchNewerGenerationAndScanQueue(t *testing.T) {
	for _, queue := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-path", true: "scan-queue"}[queue], func(t *testing.T) {
			w, root, meta := watchFixture(t, nil)
			watchFile(t, filepath.Join(root, "a"), "base")
			watchOK(t, w.Observe([]WatchEvent{{WatchPath, []byte("a")}}))
			entered, release := make(chan struct{}), make(chan struct{})
			w.step = func(model.Path) { close(entered); <-release }
			type result struct {
				s WatchScan
				e error
			}
			done := make(chan result, 1)
			go func() { s, e := w.Scan(context.Background()); done <- result{s, e} }()
			<-entered
			if _, e := Load(meta); e != nil {
				t.Fatalf("scan held metadata lock: %v", e)
			}
			if queue {
				if _, e := w.Scan(context.Background()); !errors.Is(e, ErrWatchLimit) {
					t.Fatal(e)
				}
			} else {
				watchOK(t, w.Observe([]WatchEvent{{WatchPath, []byte("a")}}))
				watchFile(t, filepath.Join(root, "a"), "edit")
			}
			close(release)
			old := <-done
			w.step = nil
			watchCheck(t, !(!errors.Is(old.e, ErrWatchStale)), "old scan=%v", old.e)
			newer := watchScan(t, w)
			watchCheck(t, w.Finish(context.Background(), old.s, watchProof(w, old.s)) != nil, "old scan cleared newer state")
			watchCheck(t, w.Finish(context.Background(), newer, watchProof(w, newer)) != nil, "stale generation cleared")
			watchUnknown(t, w, meta)
			newest := watchScan(t, w)
			watchOK(t, w.Finish(context.Background(), newest, watchProof(w, newest)))
		})
	}
}
func TestWatchRootAndDirectoryReplacement(t *testing.T) {
	for _, when := range []string{"before", "during", "after", "directory-link", "same-inode-link"} {
		t.Run(when, func(t *testing.T) {
			w, root, meta := watchFixture(t, nil)
			watchOK(t, os.Mkdir(filepath.Join(root, "sub"), 0700))
			replace := func() {
				watchOK(t, os.Rename(root, root+"-old"))
				t.Cleanup(func() { _ = os.RemoveAll(root + "-old") })
				watchOK(t, os.Mkdir(root, 0700))
			}
			if when == "before" {
				replace()
			}
			if when == "during" {
				w.step = func(model.Path) { replace(); w.step = nil }
			}
			if when == "directory-link" || when == "same-inode-link" {
				outside := t.TempDir()
				w.step = func(p model.Path) {
					if string(p.Bytes()) == "sub" {
						watchOK(t, os.Rename(filepath.Join(root, "sub"), filepath.Join(root, "moved")))
						if when == "same-inode-link" {
							outside = "moved"
						}
						watchOK(t, os.Symlink(outside, filepath.Join(root, "sub")))
						w.step = nil
					}
				}
			}
			s, e := w.Scan(context.Background())
			if when == "after" {
				watchCheck(t, e == nil, "%v", e)
				replace()
			} else {
				watchCheck(t, e != nil, "replacement accepted")
			}
			watchCheck(t, w.Finish(context.Background(), s, watchProof(w, s)) != nil, "replacement cleared")
			watchUnknown(t, w, meta)
		})
	}
}

func TestWatchPersistenceFailureAndBinding(t *testing.T) {
	stages := []string{"journal-created", "journal-written", "journal-synced", "journal-renamed", "journal-dir-synced", "next-created", "next-written", "next-synced", "next-renamed", "manifest-dir-synced", "journal-removed", "final-dir-synced", "busy", "binding", "other-writer", "metadata-replacement"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			w, _, meta := watchFixture(t, nil)
			s := watchScan(t, w)
			proof := watchProof(w, s)
			if stage == "binding" || stage == "other-writer" || stage == "metadata-replacement" {
				m, _, _ := w.Snapshot()
				if stage == "binding" {
					m.Base = testChangeset(t, "new base")
				}
				if stage == "metadata-replacement" {
					watchOK(t, os.Rename(meta, meta+"-old"))
					t.Cleanup(func() { _ = os.RemoveAll(meta + "-old") })
					watchOK(t, os.Mkdir(meta, 0700))
				}
				watchOK(t, Save(meta, m))
				watchIs(t, w.Finish(context.Background(), s, proof), ErrWatchStale)
				disk, e := Load(meta)
				watchCheck(t, !(e != nil || disk.Base != m.Base), "overwrote binding: %+v %v", disk, e)
				return
			}
			var held *metadata
			if stage == "busy" {
				var e error
				held, e = openMetadata(meta)
				watchCheck(t, e == nil, "%v", e)
			} else {
				w.hook = func(at string) error {
					if at == stage {
						return errors.New("injected durability failure")
					}
					return nil
				}
			}
			watchCheck(t, w.Observe([]WatchEvent{{WatchPath, []byte("a")}}) != nil, "missing persistence failure")
			if held != nil {
				held.close()
			}
			w.hook = nil
			if _, _, e := w.Snapshot(); e == nil {
				t.Fatal("failure not latched")
			}
			watchCheck(t, w.Finish(context.Background(), s, proof) != nil, "failed persistence authorized clean")
			recovered, e := Recover(meta)
			watchCheck(t, !(e != nil || recovered.State != Uncertain), "recovery=%+v %v", recovered, e)
			watchUnknown(t, w, meta)
		})
	}
}
func TestWatchProofBarrierAndCommitFence(t *testing.T) {
	for _, kind := range []string{"base", "sparse", "generation", "scan", "missing", "barrier-error", "barrier-event", "cancelled", "replay", "commit-race"} {
		t.Run(kind, func(t *testing.T) {
			w, _, meta := watchFixture(t, nil)
			s := watchScan(t, w)
			proof := watchProof(w, s)
			backend := w.backend.(*injectedBarrier)
			alter := map[string]func(){
				"base": func() { proof.Binding.Base = testChangeset(t, "wrong") }, "sparse": func() { proof.Binding.SparseAll = false },
				"generation": func() { proof.Generation++ }, "scan": func() { proof.ScanID++ }, "missing": func() { proof.ContentVerifiedDurable = false },
				"barrier-error": func() {
					backend.action = func(context.Context) error { return errors.New("registration/closure uncertainty") }
				},
				"barrier-event": func() {
					backend.action = func(context.Context) error { return w.Observe([]WatchEvent{{Kind: WatchLoss}}) }
				},
			}
			if action := alter[kind]; action != nil {
				action()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancelled" {
				cancel()
			}
			if kind == "commit-race" {
				entered, release := make(chan struct{}), make(chan struct{})
				once := true
				w.hook = func(at string) error {
					if at == "journal-dir-synced" && once {
						once = false
						close(entered)
						<-release
					}
					return nil
				}
				finished, observed := make(chan error, 1), make(chan error, 1)
				go func() { finished <- w.Finish(ctx, s, proof) }()
				<-entered
				go func() { observed <- w.Observe([]WatchEvent{{WatchPath, []byte("new")}}) }()
				close(release)
				watchOK(t, <-finished)
				watchOK(t, <-observed)
				watchUnknown(t, w, meta)
				return
			}
			e := w.Finish(ctx, s, proof)
			if kind == "replay" {
				watchCheck(t, e == nil, "%v", e)
				e = w.Finish(ctx, s, proof)
			}
			watchCheck(t, e != nil, "unproven clean")
			watchUnknown(t, w, meta)
		})
	}
}

func TestWatchSparseInventoryAndStartupHints(t *testing.T) {
	w, root, meta := watchFixture(t, nil)
	watchOK(t, w.Observe([]WatchEvent{{WatchPath, []byte("saved")}}))
	limits := w.limits
	watchOK(t, w.Close())
	m, e := Load(meta)
	watchOK(t, e)
	prefix := "raw\n\\"
	m.SparseAll = false
	m.Sparse = []model.Path{testPath(t, []byte(prefix))}
	watchOK(t, Save(meta, m))
	watchOK(t, os.Mkdir(filepath.Join(root, prefix), 0700))
	watchFile(t, filepath.Join(root, prefix, "leaf"), "base")
	watchOK(t, os.Mkdir(filepath.Join(root, "excluded"), 0700))
	watchFile(t, filepath.Join(root, "excluded", "leaf"), "private fixture")
	w, e = OpenWatch(root, meta, limits, &injectedBarrier{})
	watchOK(t, e)
	t.Cleanup(func() { _ = w.Close() })
	current, _, e := w.Snapshot()
	watchOK(t, e)
	requirePathBytes(t, current.DirtyPaths, []byte("saved"))
	s := watchScan(t, w)
	watchCheck(t, len(s.Entries) == 2 && string(s.Entries[1].Path.Bytes()) == prefix+"/leaf", "sparse inventory=%+v", s.Entries)
}
func TestWatchPostCleanFailureAndClose(t *testing.T) {
	for _, kind := range []string{"busy-event", "clean-final-sync", "close", "close-busy"} {
		t.Run(kind, func(t *testing.T) {
			w, root, meta := watchFixture(t, nil)
			s := watchScan(t, w)
			if kind == "clean-final-sync" {
				w.hook = func(at string) error {
					if at == "final-dir-synced" {
						return errors.New("post-commit failure")
					}
					return nil
				}
			}
			e := w.Finish(context.Background(), s, watchProof(w, s))
			if kind == "clean-final-sync" {
				watchCheck(t, e != nil, "missing commit failure")
				state, _, failed := w.Snapshot()
				watchCheck(t, state.State == Uncertain && failed != nil, "failed owner reported clean")
				disk, e := Recover(meta)
				watchCheck(t, e == nil && disk.State == Clean, "actual post-commit recovery=%+v %v", disk, e)
				return
			}
			watchOK(t, e)
			if kind == "busy-event" {
				held, e := openMetadata(meta)
				watchOK(t, e)
				watchIs(t, w.Observe([]WatchEvent{{WatchPath, []byte("a")}}), ErrBusy)
				held.close()
				state, _, failed := w.Snapshot()
				watchCheck(t, state.State == Uncertain && failed != nil, "busy owner reported clean")
				disk, e := Load(meta)
				watchCheck(t, e == nil && disk.State == Clean, "last durable record changed unexpectedly: %+v %v", disk, e)
				watchCheck(t, w.Finish(context.Background(), s, watchProof(w, s)) != nil, "poisoned owner cleared")
				return
			}
			if kind == "close-busy" {
				watchFile(t, filepath.Join(root, "a"), "base")
				w.step = func(model.Path) { watchIs(t, w.Close(), ErrWatchLimit) }
				_, e = w.Scan(context.Background())
				watchIs(t, e, ErrWatchStale)
				w.step = nil
			}
			watchOK(t, w.Close())
			_, _, e = w.Snapshot()
			watchIs(t, e, ErrWatchClosed)
			_, e = w.root.Stat(".")
			watchCheck(t, e != nil, "root FD leaked")
			_, e = w.metadataAnchor.Stat(".")
			watchCheck(t, e != nil, "metadata FD leaked")
			_, e = w.manifestAnchor.Stat()
			watchCheck(t, e != nil, "manifest FD leaked")
		})
	}
}
