package workspace

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func linuxFixture(t *testing.T) (*Watch, *linuxWatch, string, string) {
	t.Helper()
	root, meta := t.TempDir(), privateMetadataDir(t)
	watchOK(t, os.Mkdir(filepath.Join(root, "sub"), 0700))
	watchFile(t, filepath.Join(root, "sub/file"), "baseline")
	m := Manifest{Base: testChangeset(t, "Linux fixture"), SparseVersion: 1, SparseAll: true, State: Clean}
	watchOK(t, Save(meta, m))
	l := WatchLimits{Candidates: 128, CandidateBytes: 4096, Queue: 128, Entries: 256, Bytes: 64 << 10, Depth: 8, Descriptors: 2, Attempts: 32, Duration: 2 * time.Second}
	w, err := OpenNativeWatch(root, meta, l)
	watchOK(t, err)
	t.Cleanup(func() { _ = w.Close() })
	n := w.backend.(*linuxWatch)
	// Only this fixture's known, synced baseline supplies the trusted assertion.
	s := watchScan(t, w)
	watchOK(t, w.Finish(context.Background(), s, watchProof(w, s)))
	return w, n, root, meta
}

// Actual Linux temporary filesystem operations; no notification injection.
func TestLinuxNativeKernelEvents(t *testing.T) {
	for _, kind := range []string{"content", "create", "new-descendant", "rename", "delete", "root-replacement", "byte-name"} {
		t.Run(kind, func(t *testing.T) {
			w, n, root, meta := linuxFixture(t)
			_, before, _ := w.Snapshot()
			want, mask := []string{"sub/file"}, uint32(syscall.IN_MODIFY)
			switch kind {
			case "content":
				watchFile(t, filepath.Join(root, "sub/file"), "edited")
			case "create", "byte-name":
				name := "sub/new"
				if kind == "byte-name" {
					name = "sub/\xff\n"
				}
				watchFile(t, filepath.Join(root, name), "created")
				want, mask = []string{name}, syscall.IN_CREATE
			case "new-descendant":
				watchOK(t, os.MkdirAll(filepath.Join(root, "sub/new/deep"), 0700))
				watchOK(t, n.Barrier(context.Background())) // synchronous new coverage
				scan := watchScan(t, w)
				watchCheck(t, scan.Progress.Complete, "directory inventory incomplete")
				watchOK(t, w.Finish(context.Background(), scan, watchProof(w, scan)))
				_, before, _ = w.Snapshot()
				watchOK(t, n.call(context.Background(), func() error { n.masks = 0; return nil }))
				watchFile(t, filepath.Join(root, "sub/new/deep/child"), "child")
				want, mask = []string{"sub/new/deep/child"}, syscall.IN_CREATE
			case "rename":
				watchOK(t, os.Rename(filepath.Join(root, "sub/file"), filepath.Join(root, "sub/renamed")))
				want, mask = []string{"sub/file", "sub/renamed"}, syscall.IN_MOVED_FROM|syscall.IN_MOVED_TO
			case "delete":
				watchOK(t, os.Remove(filepath.Join(root, "sub/file")))
				mask = syscall.IN_DELETE
			case "root-replacement":
				old := root + "-old"
				watchOK(t, os.Rename(root, old))
				t.Cleanup(func() { _ = os.RemoveAll(old) })
				watchOK(t, os.Mkdir(root, 0700))
				want, mask = nil, syscall.IN_MOVE_SELF
			}
			err := n.Barrier(context.Background())
			if kind == "root-replacement" {
				watchCheck(t, err != nil, "replacement accepted")
			} else {
				watchOK(t, err)
			}
			m, after, _ := w.Snapshot()
			watchCheck(t, after > before, "native event did not advance generation")
			if kind == "rename" {
				watchCheck(t, len(m.DirtyPaths) == 2, "rename path count = %d, want 2", len(m.DirtyPaths))
				first, second := string(m.DirtyPaths[0].Bytes()), string(m.DirtyPaths[1].Bytes())
				watchCheck(t, first == want[0] && second == want[1] || first == want[1] && second == want[0], "rename paths = %q, %q", first, second)
			} else {
				for _, p := range want {
					requirePathBytes(t, m.DirtyPaths, []byte(p))
				}
			}
			var observed uint32
			watchOK(t, n.call(context.Background(), func() error { observed = n.masks; return nil }))
			watchCheck(t, observed&mask == mask, "kernel masks=%x want=%x", observed, mask)
			watchUnknown(t, w, meta)
		})
	}
}

func TestLinuxNativeAssertionAndConfinement(t *testing.T) {
	w, n, root, meta := linuxFixture(t)
	outside := t.TempDir()
	watchOK(t, os.Symlink(outside, filepath.Join(root, "link")))
	watchOK(t, n.Barrier(context.Background()))
	_, generation, _ := w.Snapshot()
	watchFile(t, filepath.Join(outside, "secret"), "outside")
	watchOK(t, n.Barrier(context.Background()))
	_, after, _ := w.Snapshot()
	watchCheck(t, after == generation, "followed external symlink")
	var err error
	watchOK(t, n.call(context.Background(), func() error {
		f, e := n.openDir("link")
		err = e
		if f != nil {
			_ = f.Close()
			n.descriptors--
		}
		return nil
	}))
	watchCheck(t, err != nil, "symlink traversal accepted")
	s := watchScan(t, w)
	m, _, _ := w.Snapshot()
	watchIs(t, w.Finish(context.Background(), s, s.AssertionBinding(m)), ErrWatchStale)
	watchUnknown(t, w, meta)
	// Native events delivered by Finish's barrier invalidate a previously valid
	// scan, even when a trusted caller supplies an assertion for that old scan.
	s = watchScan(t, w)
	proof := watchProof(w, s)
	watchFile(t, filepath.Join(root, "sub/file"), "new generation")
	watchIs(t, w.Finish(context.Background(), s, proof), ErrWatchStale)
	watchUnknown(t, w, meta)
}

func linuxRecord(wd int, mask uint32, name string) []byte {
	size := 0
	if name != "" {
		size = (len(name) + 4) &^ 3
	}
	b := make([]byte, syscall.SizeofInotifyEvent+size)
	binary.NativeEndian.PutUint32(b, uint32(wd))
	binary.NativeEndian.PutUint32(b[4:], mask)
	binary.NativeEndian.PutUint32(b[12:], uint32(size))
	copy(b[16:], name)
	return b
}

// Parser/control injection proves loss/lifecycle behavior, not kernel events.
func TestLinuxNativeInjectedFailures(t *testing.T) {
	for _, kind := range []string{"overflow", "queue", "malformed", "registration", "backend-error", "restart", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			w, n, root, meta := linuxFixture(t)
			var oldFD int
			watchOK(t, n.call(context.Background(), func() error { oldFD = n.fd; return nil }))
			ctx := context.Background()
			if kind == "cancel" {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			} else {
				err := n.call(ctx, func() error {
					switch kind {
					case "registration":
						n.registrationCap = len(n.watches)
						return os.Mkdir(filepath.Join(root, "new-directory"), 0700)
					case "backend-error":
						_ = syscall.Close(n.fd)
						n.fd = -1
						n.descriptors--
						return n.step(ctx, true)
					case "restart":
						return n.fail(ErrWatchStale) // restart requires a new owner
					}
					wd := n.paths["sub"]
					data := linuxRecord(-1, syscall.IN_Q_OVERFLOW, "")
					if kind == "queue" {
						n.pendingCap = 1
						data = append(linuxRecord(wd, syscall.IN_CREATE, "a"), linuxRecord(wd, syscall.IN_CREATE, "b")...)
					}
					if kind == "malformed" {
						data = []byte{0}
					}
					var events []WatchEvent
					used := 0
					return n.fail(n.decode(data, &events, &used))
				})
				if kind == "registration" {
					watchOK(t, err)
				} else {
					watchCheck(t, err != nil, "injected failure accepted")
				}
			}
			watchCheck(t, n.Barrier(ctx) != nil, "failed backend barrier succeeded")
			var released bool
			watchOK(t, n.call(context.Background(), func() error {
				released = n.descriptors == 0 && n.fd == -1 && n.root == nil && len(n.watches) == 0
				return nil
			}))
			watchCheck(t, released, "native resources retained")
			var st syscall.Stat_t
			watchCheck(t, kind == "backend-error" || syscall.Fstat(oldFD, &st) == syscall.EBADF, "native FD retained")
			watchUnknown(t, w, meta)
			watchCheck(t, w.Finish(context.Background(), WatchScan{}, CleanAssertion{ContentVerifiedDurable: true}) != nil, "failure became clean")
			if kind == "restart" {
				watchOK(t, w.Close())
				other, e := OpenNativeWatch(root, meta, n.limits)
				watchOK(t, e)
				watchUnknown(t, other, meta)
				watchOK(t, other.Close())
			}
		})
	}
}

func TestLinuxNativePartialInitAndClose(t *testing.T) {
	count := func() int { entries, e := os.ReadDir("/proc/self/fd"); watchOK(t, e); return len(entries) }
	w, n, root, _ := linuxFixture(t)
	before := count()
	_, err := newLinuxWatch(filepath.Join(root, "missing"), n.limits)
	watchCheck(t, err != nil, "missing root accepted")
	_, err = OpenNativeWatch(root, filepath.Join(root, "missing-metadata"), n.limits)
	watchCheck(t, err != nil, "invalid metadata accepted")
	watchCheck(t, count() == before, "partial initialization leaked FDs")
	var peak int
	watchOK(t, n.call(context.Background(), func() error { peak = n.peak; return nil }))
	watchCheck(t, peak <= linuxWatchDescriptors && peak > n.limits.Descriptors, "native/scan FD accounting=%d", peak)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var unblockOnce, callbackOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(release) }) }
	defer unblock()
	watchOK(t, n.call(context.Background(), func() error {
		prior := n.observe
		n.observe = func(events []WatchEvent) error {
			callbackOnce.Do(func() { close(entered); <-release })
			return prior(events)
		}
		return nil
	}))
	watchFile(t, filepath.Join(root, "sub/file"), "barrier delivery")
	go func() { finished <- n.Barrier(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("callback did not enter")
	}
	select {
	case err := <-finished:
		t.Fatalf("barrier passed blocked delivery: %v", err)
	default:
	}
	unblock()
	watchOK(t, <-finished)
	var watermark bool
	watchOK(t, n.call(context.Background(), func() error { watermark = n.watermark > 0 && n.delivered >= n.watermark; return nil }))
	watchCheck(t, watermark, "barrier omitted synchronous watermark")
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() { _ = n.Barrier(context.Background()) })
	}
	watchOK(t, w.Close())
	group.Wait()
	select {
	case <-n.done:
	case <-time.After(time.Second):
		t.Fatal("worker retained")
	}
	watchIs(t, n.Barrier(context.Background()), ErrWatchClosed)
	watchCheck(t, n.descriptors == 0, "close leaked native descriptors")
	watchIs(t, w.Close(), ErrWatchClosed)
}

// Pending directories use the caller's queue budget, independently of the
// larger registration limit. Existing entries avoid event-batch exhaustion.
func TestLinuxNativeDirectoryQueueLimit(t *testing.T) {
	w, n, root, meta := linuxFixture(t)
	watchOK(t, n.call(context.Background(), func() error {
		n.limits.Queue = 1
		return os.Mkdir(filepath.Join(root, "other"), 0700)
	}))
	watchIs(t, n.Barrier(context.Background()), ErrWatchLimit)
	watchUnknown(t, w, meta)
}

func TestLinuxNativeHardLinkCoverage(t *testing.T) {
	for _, kind := range []string{"existing-link", "new-outside-link", "outside-write"} {
		t.Run(kind, func(t *testing.T) {
			w, n, root, meta := linuxFixture(t)
			alias := filepath.Join(t.TempDir(), "alias")
			if kind == "existing-link" {
				watchOK(t, w.Close())
				watchOK(t, os.Link(filepath.Join(root, "sub/file"), alias))
				beforeFDs, err := os.ReadDir("/proc/self/fd")
				watchOK(t, err)
				other, err := OpenNativeWatch(root, meta, n.limits)
				watchIs(t, err, ErrWatchStale)
				watchCheck(t, other == nil, "unarmed owner returned after initialization failure")
				afterFDs, err := os.ReadDir("/proc/self/fd")
				watchOK(t, err)
				watchCheck(t, len(afterFDs) == len(beforeFDs), "initial arming failure leaked FDs")
				return
			}
			_, before, _ := w.Snapshot()
			watchOK(t, os.Link(filepath.Join(root, "sub/file"), alias))
			if kind == "outside-write" {
				watchFile(t, alias, "outside mutation")
			}
			watchIs(t, n.Barrier(context.Background()), ErrWatchStale)
			_, after, _ := w.Snapshot()
			watchCheck(t, after > before, "outside hard link did not invalidate generation")
			watchUnknown(t, w, meta)
		})
	}
}

// Deterministically place an outside link between the FileInfo snapshot and
// watch installation. A pre-registration link-count check alone misses it.
func TestLinuxNativeHardLinkAdmissionRace(t *testing.T) {
	w, n, root, meta := linuxFixture(t)
	alias := filepath.Join(t.TempDir(), "alias")
	err := n.call(context.Background(), func() error {
		path := filepath.Join(root, "sub/admission")
		file, err := os.Create(path)
		if err != nil {
			return err
		}
		defer file.Close()
		before, err := file.Stat()
		if err != nil {
			return err
		}
		if err = os.Link(path, alias); err != nil {
			return err
		}
		_, err = n.register("sub/admission", before, int(file.Fd()))
		if err != nil {
			return n.fail(err)
		}
		return nil
	})
	watchIs(t, err, ErrWatchStale)
	watchUnknown(t, w, meta)
	watchIs(t, n.Barrier(context.Background()), ErrWatchStale)
}

// Public OpenNativeWatch must establish coverage without a private Barrier or
// reconciliation call. Snapshot alone must observe subsequent native events.
func TestLinuxNativeOpenArmsObservation(t *testing.T) {
	root, meta := t.TempDir(), privateMetadataDir(t)
	watchFile(t, filepath.Join(root, "file"), "baseline")
	m := Manifest{Base: testChangeset(t, "Linux open"), SparseVersion: 1, SparseAll: true, State: Clean}
	watchOK(t, Save(meta, m))
	limits := WatchLimits{Candidates: 128, CandidateBytes: 4096, Queue: 128, Entries: 256, Bytes: 64 << 10, Depth: 8, Descriptors: 2, Attempts: 32, Duration: 2 * time.Second}
	w, err := OpenNativeWatch(root, meta, limits)
	watchOK(t, err)
	defer w.Close()
	_, before, err := w.Snapshot()
	watchOK(t, err)
	watchFile(t, filepath.Join(root, "file"), "changed")
	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		m, after, err := w.Snapshot()
		watchOK(t, err)
		if after > before {
			requirePathBytes(t, m.DirtyPaths, []byte("file"))
			return
		}
		select {
		case <-deadline:
			t.Fatal("native observation was not armed at successful open")
		case <-tick.C:
		}
	}
}

// The display names on traversal FDs are workspace-relative. Metadata lookup
// must use the held FD even when those names do not exist in the process CWD.
func TestLinuxNativeEnumerationOutsideCWD(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, hardlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "nested", true: "hardlink"}[hardlink], func(t *testing.T) {
			root, meta := t.TempDir(), privateMetadataDir(t)
			watchOK(t, os.Mkdir(filepath.Join(root, "sub"), 0700))
			watchFile(t, filepath.Join(root, "sub/file"), "baseline")
			if hardlink {
				watchOK(t, os.Link(filepath.Join(root, "sub/file"), filepath.Join(t.TempDir(), "alias")))
			}
			watchOK(t, Save(meta, Manifest{Base: testChangeset(t, "cwd coverage"), SparseVersion: 1, SparseAll: true, State: Clean}))
			limits := WatchLimits{Candidates: 128, CandidateBytes: 4096, Queue: 128, Entries: 256, Bytes: 64 << 10, Depth: 8, Descriptors: 2, Attempts: 32, Duration: 2 * time.Second}
			w, err := OpenNativeWatch(root, meta, limits)
			if hardlink {
				if w != nil {
					_ = w.Close()
					t.Fatal("multiply linked descendant accepted")
				}
				watchIs(t, err, ErrWatchStale)
				return
			}
			watchOK(t, err)
			defer w.Close()
			n := w.backend.(*linuxWatch)
			watchOK(t, n.call(context.Background(), func() error {
				for _, path := range []string{".", "sub", "sub/file"} {
					if _, ok := n.paths[path]; !ok {
						return ErrWatchStale
					}
				}
				if n.peak > linuxWatchDescriptors {
					return ErrWatchLimit
				}
				return nil
			}))
		})
	}
}

// No Barrier or reconciliation is allowed after arrival: the periodic observer
// must register new file inodes before later outside-link changes can be seen.
func TestLinuxNativeRegularArrivalCoverage(t *testing.T) {
	for _, moved := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "move-in"}[moved], func(t *testing.T) {
			w, n, root, _ := linuxFixture(t)
			path := filepath.Join(root, "sub/arrived")
			outside := t.TempDir()
			if moved {
				incoming := filepath.Join(outside, "incoming")
				watchFile(t, incoming, "arrived")
				watchOK(t, os.Rename(incoming, path))
			} else {
				watchFile(t, path, "arrived")
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				var covered bool
				watchOK(t, n.call(context.Background(), func() error {
					_, covered = n.paths["sub/arrived"]
					return n.failed
				}))
				if covered {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("regular arrival never acquired inode coverage without Barrier")
				}
				time.Sleep(5 * time.Millisecond)
			}
			_, before, err := w.Snapshot()
			watchOK(t, err)
			alias := filepath.Join(outside, "alias")
			watchOK(t, os.Link(path, alias))
			watchFile(t, alias, "outside write")
			deadline = time.Now().Add(2 * time.Second)
			for {
				var failure error
				watchOK(t, n.call(context.Background(), func() error { failure = n.failed; return nil }))
				if failure != nil {
					watchIs(t, failure, ErrWatchStale)
					_, after, _ := w.Snapshot()
					watchCheck(t, after > before, "outside link did not invalidate generation")
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("outside hard link did not fail closed")
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
	}
}
