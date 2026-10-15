//go:build darwin

package workspace

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func darwinFixture(t *testing.T, configure func(*darwinWatch)) (*Watch, string, string) {
	t.Helper()
	root, meta := t.TempDir(), privateMetadataDir(t)
	watchOK(t, os.Mkdir(filepath.Join(root, "sub"), 0700))
	watchFile(t, filepath.Join(root, "sub", "original"), "baseline")
	watchOK(t, Save(meta, Manifest{Base: testChangeset(t, "native baseline"), SparseVersion: 1, SparseAll: true, State: Clean}))
	limits := WatchLimits{Candidates: 16, CandidateBytes: 1024, Queue: 16, Entries: 32, Bytes: 4096, Depth: 4, Descriptors: 2, Attempts: 16, Duration: 2 * time.Second}
	w, err := openDarwinWatch(root, meta, limits, configure)
	watchOK(t, err)
	t.Cleanup(func() { _ = w.Close() })
	b := w.backend.(*darwinWatch)
	r := b.barrier(context.Background())
	watchOK(t, r.err)
	watchCheck(t, r.registrations == 3 && r.descriptors == 5, "native initial resources=%+v", r)
	t.Logf("Darwin kqueue fixture: 3 vnode registrations, 5 held native FDs; enumeration peak 6 plus rooted-resolution reserve 2; scan cap 2; pending cap %d", b.pending)
	return w, root, meta
}
func darwinTrustedBaseline(t *testing.T, w *Watch, root string) (s WatchScan) {
	t.Helper()
	bytes, e := os.ReadFile(filepath.Join(root, "sub", "original"))
	watchOK(t, e)
	watchCheck(t, string(bytes) == "baseline", "baseline content changed")
	// Fsynced fixture bytes authorize only this explicit trusted caller assertion.
	for attempt := 0; attempt < 4; attempt++ {
		s, e = w.Scan(context.Background())
		if e == nil {
			e = w.Finish(context.Background(), s, watchProof(w, s))
		}
		if e == nil {
			return s
		}
		watchIs(t, e, ErrWatchStale)
	}
	watchOK(t, e)
	return
}
func darwinAwait(t *testing.T, w *Watch, before uint64, path string) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		m, g, e := w.Snapshot()
		watchOK(t, e)
		found := path == ""
		for _, p := range m.DirtyPaths {
			if string(p.Bytes()) == path {
				found = true
			}
		}
		if g > before && found {
			watchCheck(t, m.State == Uncertain, "native notification made clean")
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("real Darwin notification deadline exceeded")
}

// Real native evidence: these tests never inject Kevent results or call Observe.
func TestDarwinNativeEvents(t *testing.T) {
	for _, kind := range []string{"descendant-content", "create-new-descendant", "rename", "delete", "root-replacement", "raw-byte-content"} {
		t.Run(kind, func(t *testing.T) {
			w, root, meta := darwinFixture(t, nil)
			old := darwinTrustedBaseline(t, w, root)
			_, before, _ := w.Snapshot()
			expected := ""
			switch kind {
			case "descendant-content":
				expected = "sub/original"
				watchFile(t, filepath.Join(root, expected), "changed!")
			case "create-new-descendant":
				watchOK(t, os.Mkdir(filepath.Join(root, "sub", "new"), 0700))
				watchFile(t, filepath.Join(root, "sub", "new", "leaf"), "first")
			case "rename":
				watchOK(t, os.Rename(filepath.Join(root, "sub", "original"), filepath.Join(root, "sub", "renamed")))
			case "delete":
				watchOK(t, os.Remove(filepath.Join(root, "sub", "original")))
			case "root-replacement":
				watchOK(t, os.Rename(root, root+"-old"))
				t.Cleanup(func() { _ = os.RemoveAll(root + "-old") })
				watchOK(t, os.Mkdir(root, 0700))
			case "raw-byte-content":
				expected = "sub/raw\n\\\t\x7f"
				watchFile(t, filepath.Join(root, expected), "first")
			}
			darwinAwait(t, w, before, func() string {
				if kind == "descendant-content" {
					return expected
				}
				return ""
			}())
			b := w.backend.(*darwinWatch)
			r := b.barrier(context.Background())
			if kind == "root-replacement" {
				watchCheck(t, r.err != nil && r.watermark >= 2, "replacement native loss missing: %+v", r)
			} else {
				watchOK(t, r.err)
			}
			if kind == "create-new-descendant" || kind == "raw-byte-content" || kind == "rename" {
				path := "sub/new/leaf"
				regs := 5
				if kind == "rename" {
					path = "sub/renamed"
					regs = 3
				}
				if kind == "raw-byte-content" {
					path = expected
					regs = 4
				}
				watchCheck(t, r.registrations == regs && r.descriptors == regs+2, "maintained resources=%+v", r)
				_, g, _ := w.Snapshot()
				watchFile(t, filepath.Join(root, path), "second")
				darwinAwait(t, w, g, path) // proves the newly registered FILE vnode sees writes
			}
			watchUnknown(t, w, meta)
			watchCheck(t, w.Finish(context.Background(), old, watchProof(w, old)) != nil, "old assertion survived event")
			watchUnknown(t, w, meta)
			t.Logf("actual native mutation %s observed; barrier watermark=%d registrations=%d held-native-FDs=%d", kind, r.watermark, r.registrations, r.descriptors)
		})
	}
}

// Synthetic fault injection is deliberately separate from real native evidence.
func TestDarwinSyntheticFaults(t *testing.T) {
	for _, kind := range []string{"queue", "kevent-error", "restart-refused", "event-error", "revoked", "unknown-registration", "registration-error"} {
		t.Run(kind, func(t *testing.T) {
			var trigger atomic.Bool
			var firstFD atomic.Uint64
			w, root, meta := darwinFixture(t, func(b *darwinWatch) {
				real := b.kevent
				b.kevent = func(k int, c, e []syscall.Kevent_t, ts *syscall.Timespec) (int, error) {
					if len(c) > 0 {
						firstFD.CompareAndSwap(0, c[0].Ident)
						if trigger.Load() && kind == "registration-error" {
							return 0, syscall.ENOSPC
						}
					} else if trigger.Load() && kind != "registration-error" {
						trigger.Store(false)
						switch kind {
						case "queue":
							return len(e), nil
						case "kevent-error":
							return 0, syscall.EIO
						case "restart-refused":
							return 0, syscall.EBADF
						case "event-error", "revoked", "unknown-registration":
							e[0] = syscall.Kevent_t{Ident: firstFD.Load(), Filter: syscall.EVFILT_VNODE, Fflags: syscall.NOTE_WRITE}
							if kind == "event-error" {
								e[0].Flags = syscall.EV_ERROR
							}
							if kind == "revoked" {
								e[0].Fflags = syscall.NOTE_REVOKE
							}
							if kind == "unknown-registration" {
								e[0].Ident = ^uint64(0)
							}
							return 1, nil
						}
					}
					return real(k, c, e, ts)
				}
			})
			b := w.backend.(*darwinWatch)
			darwinTrustedBaseline(t, w, root)
			if kind == "registration-error" {
				trigger.Store(true)
				watchFile(t, filepath.Join(root, "new"), "x")
			} else {
				trigger.Store(true)
			}
			r := b.barrier(context.Background())
			watchCheck(t, r.err != nil, "synthetic fault succeeded: %+v", r)
			watchUnknown(t, w, meta)
			again := b.barrier(context.Background())
			watchCheck(t, again.err != nil, "fault silently restarted")
			watchCheck(t, again.registrations == 0 && again.descriptors == 0, "terminal resources=%+v", again)
			_ = b.Close()
			watchCheck(t, b.root == nil && b.kq == -1 && len(b.fds) == 0 && len(b.nodes) == 0, "leaked native resources")
		})
	}
}
func TestDarwinPartialInitialization(t *testing.T) {
	for _, kind := range []string{"common-open", "second-registration", "registration-cap", "descriptor-cap", "symlink", "depth"} {
		t.Run(kind, func(t *testing.T) {
			root, meta := t.TempDir(), privateMetadataDir(t)
			watchOK(t, Save(meta, Manifest{Base: testChangeset(t, "partial"), SparseVersion: 1, SparseAll: true, State: Clean}))
			watchFile(t, filepath.Join(root, "file"), "x")
			if kind == "symlink" {
				watchOK(t, os.Symlink(t.TempDir(), filepath.Join(root, "escape")))
			}
			if kind == "depth" {
				watchOK(t, os.MkdirAll(filepath.Join(root, "a", "b"), 0700))
			}
			if kind == "common-open" {
				meta = filepath.Join(meta, "absent")
			}
			var b *darwinWatch
			var nativeFDs []int
			l := WatchLimits{Candidates: 8, CandidateBytes: 128, Queue: 8, Entries: 16, Bytes: 4096, Depth: 1, Descriptors: 2, Attempts: 2, Duration: time.Second}
			w, e := openDarwinWatch(root, meta, l, func(x *darwinWatch) {
				b = x
				if kind == "registration-cap" {
					b.registrations = 1
				}
				if kind == "descriptor-cap" {
					b.descriptors = 6
				}
				real := b.kevent
				count := 0
				b.kevent = func(k int, c, events []syscall.Kevent_t, ts *syscall.Timespec) (int, error) {
					if len(c) > 0 {
						nativeFDs = append(nativeFDs, k, int(c[0].Ident))
						count++
						if kind == "second-registration" && count == 2 {
							return 0, syscall.ENOSPC
						}
					}
					return real(k, c, events, ts)
				}
			})
			watchCheck(t, e != nil && w == nil, "partial initialization succeeded")
			for _, fd := range nativeFDs {
				watchIs(t, syscall.Fstat(fd, new(syscall.Stat_t)), syscall.EBADF)
			}
			watchCheck(t, b.root == nil && b.kq == -1 && len(b.nodes) == 0 && len(b.fds) == 0, "partial resource leak")
			if kind == "common-open" {
				watchCheck(t, b.observe == nil, "callback installed before common success")
			}
			if kind != "common-open" {
				disk, err := Load(meta)
				watchCheck(t, err != nil || disk.State == Uncertain, "partial init left clean")
			}
		})
	}
}
func TestDarwinCancelCloseAndWatermark(t *testing.T) {
	for _, kind := range []string{"cancel", "close", "watermark"} {
		t.Run(kind, func(t *testing.T) {
			w, root, meta := darwinFixture(t, nil)
			b := w.backend.(*darwinWatch)
			darwinTrustedBaseline(t, w, root)
			if kind == "cancel" {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				watchCheck(t, b.Barrier(ctx) != nil, "canceled barrier succeeded")
				_ = b.Close()
				watchUnknown(t, w, meta)
			} else if kind == "close" {
				watchOK(t, w.Close())
				watchIs(t, b.Barrier(context.Background()), ErrWatchClosed)
			} else {
				// Observe and Barrier must both unblock after releasing the common mutex.
				w.mu.Lock()
				watchFile(t, filepath.Join(root, "sub", "original"), "changed")
				done := make(chan darwinReply, 1)
				go func() { done <- b.barrier(context.Background()) }()
				time.Sleep(20 * time.Millisecond)
				w.mu.Unlock()
				select {
				case r := <-done:
					watchOK(t, r.err)
					watchCheck(t, r.watermark > 0, "empty watermark")
					m, _, _ := w.Snapshot()
					requirePathBytes(t, m.DirtyPaths, []byte("sub/original"))
				case <-time.After(3 * time.Second):
					t.Fatal("Observe/Barrier lock deadlock")
				}
				watchUnknown(t, w, meta)
				watchOK(t, w.Close())
			}
			watchCheck(t, b.root == nil && b.kq == -1 && len(b.nodes) == 0, "close/cancel resource leak")
			if kind == "close" {
				watchIs(t, w.Close(), ErrWatchClosed)
			}
		})
	}
}
