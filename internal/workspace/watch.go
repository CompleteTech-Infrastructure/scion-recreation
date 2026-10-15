package workspace

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"canopy.local/canopy/internal/model"
)

var (
	ErrWatchLimit  = errors.New("workspace observation budget exhausted")
	ErrWatchStale  = errors.New("workspace reconciliation is stale or unproven")
	ErrWatchClosed = errors.New("workspace observer closed")
)

type WatchEventKind uint8

const (
	WatchPath WatchEventKind = iota + 1
	WatchLoss                // overflow, dropped events, exhausted registrations, restart or closure
)

type WatchEvent struct {
	Kind WatchEventKind
	Path []byte
}

// WatchBackend is a seam for separately verified platform adapters. Before
// Barrier succeeds, every queued hint/loss through its watermark must have been
// synchronously delivered to Observe. Registration/coverage/drain uncertainty
// MUST return an error. Adapters arm before reconciliation, bound their own
// registrations/queues, and report later events through Observe. No native
// notification implementation or freshness guarantee is supplied here. The armed
// instance is bound at OpenWatch for this owner lifetime; restarts MUST report
// WatchLoss, even if the same instance remains. Watch owns Close after success.
type WatchBackend interface {
	Barrier(context.Context) error
	Close() error
}

type WatchLimits struct {
	// Queue caps an event batch and pending directories; Descriptors caps the
	// content scan's FDs, with a separate constant metadata reserve of six.
	Candidates, CandidateBytes, Queue, Entries, Bytes, Depth, Descriptors, Attempts int
	Duration                                                                        time.Duration
}

func (l WatchLimits) valid() bool {
	return l.Candidates > 0 && l.Candidates <= MaxPaths/2 && l.CandidateBytes > 0 && l.CandidateBytes <= MaxManifestBytes/4 &&
		l.Queue > 0 && l.Queue <= MaxPaths && l.Entries > 0 && l.Entries <= 65536 && l.Bytes > 0 && l.Bytes <= 64<<20 &&
		l.Depth > 0 && l.Depth <= 128 && l.Descriptors > 0 && l.Descriptors <= 16 && l.Attempts > 0 && l.Attempts <= 64 && l.Duration > 0 && l.Duration <= time.Minute
}

type WatchEntry struct {
	Path model.Path
	Mode os.FileMode
	Size int64
}
type WatchProgress struct {
	Entries, Bytes, OwnedDescriptors, Attempts int
	Complete                                   bool // inventory only; never content equality or clean eligibility
	RestartAtRoot                              bool // no retained cursor; every subsequent attempt restarts
}
type scanToken struct {
	owner          *Watch
	id, generation uint64
	ctx            context.Context
	complete       bool
}
type WatchScan struct {
	Entries  []WatchEntry
	Progress WatchProgress
	token    *scanToken
}

// CleanAssertion is a TRUSTED caller assertion, not a proof inferred by this
// package. It certifies that ALL selected content bytes/modes/symlink targets,
// including deletions absent from the inventory, match Binding.Base and its
// exact ordered sparse selection, and all reconciliation writes are durable.
// Produce it for this exact completed scan and generation while the backend is
// armed. Inventory/stat equality alone MUST NOT produce this assertion.
type CleanAssertion struct {
	Binding                Manifest
	Generation, ScanID     uint64
	ContentVerifiedDurable bool
}

// Watch has one cooperative generation owner per workspace. All cooperative
// content mutations must successfully Observe BEFORE mutation. Failed metadata
// persistence permanently poisons this owner: stop mutation and Load/Recover,
// then construct a new owner. Metadata must be outside watched content. Direct
// concurrent Save callers may not assert Clean behind this owner's back.
type Watch struct {
	mu                      sync.Mutex
	root                    *os.Root
	rootName, metadataName  string
	rootInfo                os.FileInfo
	metadataInfo            os.FileInfo
	metadataAnchor          *os.Root
	manifestAnchor          *os.File
	backend                 WatchBackend
	candidates              map[string]bool
	sparse                  []string
	binding, state          Manifest
	limits                  WatchLimits
	generation, scanID      uint64
	attempts                int
	busy, finishing, closed bool
	failed                  error
	hook                    func(string) error // same durability fault boundaries as CLI-01
	step                    func(model.Path)   // deterministic scan scheduling seam; nil in production
}

func cloneManifest(m Manifest) Manifest {
	m.Sparse = slices.Clone(m.Sparse)
	m.DirtyPaths = slices.Clone(m.DirtyPaths)
	return m
}
func sameBinding(a, b Manifest) bool {
	return a.Base == b.Base && a.SparseVersion == b.SparseVersion && a.SparseAll == b.SparseAll && slices.Equal(a.Sparse, b.Sparse)
}
func OpenWatch(root, metadataDir string, limits WatchLimits, backend WatchBackend) (*Watch, error) {
	if !limits.valid() || backend == nil {
		return nil, ErrWatchLimit
	}
	before, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() {
		return nil, ErrWatchStale
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	w := &Watch{root: r, rootName: root, metadataName: metadataDir, rootInfo: before, limits: limits, backend: backend, candidates: make(map[string]bool)}
	m, err := openMetadata(metadataDir)
	if err == nil {
		w.metadataInfo, err = m.dir.Stat()
		if err == nil {
			w.metadataAnchor, err = m.root.OpenRoot(".")
		}
		if err == nil {
			err = m.pending()
		}
		if err == nil {
			w.binding, err = m.read("manifest")
		}
		m.close()
	}
	if err == nil {
		w.state = cloneManifest(w.binding)
		err = w.rootSame()
	}
	if err == nil {
		w.state.DirtyPaths = nil
		events := make([]WatchEvent, 0, limits.Candidates)
		for i, p := range w.binding.DirtyPaths {
			if i >= limits.Candidates {
				break
			}
			events = append(events, WatchEvent{WatchPath, p.Bytes()})
		}
		err = w.observeLocked(events, nil)
		w.binding.DirtyPaths = nil
		for _, p := range w.binding.Sparse {
			w.sparse = append(w.sparse, string(p.Bytes()))
		}
	}
	if err != nil {
		r.Close()
		if w.metadataAnchor != nil {
			w.metadataAnchor.Close()
		}
		if w.manifestAnchor != nil {
			w.manifestAnchor.Close()
		}
		return nil, err
	}
	return w, nil
}
func (w *Watch) rootSame() error {
	current, err := os.Lstat(w.rootName)
	if err != nil {
		return err
	}
	held, err := w.root.Stat(".")
	if err != nil {
		return err
	}
	if !current.IsDir() || !os.SameFile(current, w.rootInfo) || !os.SameFile(held, w.rootInfo) {
		return ErrWatchStale
	}
	return nil
}

// persist runs only a short metadata transaction. Recheck binding under the
// accepted directory-FD lock, then retain CLI-01's uncertain union journal and
// synced install ordering. Neither scan nor backend calls hold this lock.
func (w *Watch) persist() (err error) {
	m, err := openMetadata(w.metadataName)
	if err != nil {
		return err
	}
	defer m.close()
	directory, err := m.dir.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(directory, w.metadataInfo) {
		return ErrWatchStale
	}
	if err = m.pending(); err != nil {
		return err
	}
	prior, err := m.read("manifest")
	if err != nil {
		return err
	}
	if !sameBinding(prior, w.binding) {
		return ErrWatchStale
	}
	if w.manifestAnchor != nil {
		held, e := w.manifestAnchor.Stat()
		if e != nil {
			return e
		}
		entry, e := m.root.Lstat("manifest")
		if e != nil {
			return e
		}
		if !os.SameFile(held, entry) {
			return ErrWatchStale
		}
	}
	next, err := encode(w.state)
	if err != nil {
		return err
	}
	prior.State = Uncertain
	for _, p := range w.state.DirtyPaths {
		if !slices.Contains(prior.DirtyPaths, p) {
			prior.DirtyPaths = append(prior.DirtyPaths, p)
		}
	}
	recovery, err := encode(prior)
	if err != nil {
		return err
	}
	if err = m.write("intent", recovery, func(stage string) error { return checkpoint(w.hook, "journal"+stage[len("intent"):]) }); err != nil {
		return err
	}
	if err = m.root.Rename("intent", "journal"); err != nil {
		return err
	}
	if err = checkpoint(w.hook, "journal-renamed"); err != nil {
		return err
	}
	if err = m.sync(); err != nil {
		return err
	}
	if err = checkpoint(w.hook, "journal-dir-synced"); err != nil {
		return err
	}
	if err = m.install(next, w.hook); err != nil {
		return err
	}
	anchor, err := m.open("manifest", os.O_RDONLY, 0)
	if err == nil {
		if w.manifestAnchor != nil {
			w.manifestAnchor.Close()
		}
		w.manifestAnchor = anchor
	}
	return err
}
func (w *Watch) observeLocked(events []WatchEvent, cause error) error {
	w.state.State = Uncertain
	if w.generation == ^uint64(0) {
		w.failed = ErrWatchLimit
	} else {
		w.generation++
	}
	if len(events) > w.limits.Queue {
		events = nil
		cause = errors.Join(cause, ErrWatchLimit)
	}
	incoming := 0
	for _, e := range events {
		if len(e.Path) > w.limits.CandidateBytes-incoming {
			events = nil
			cause = errors.Join(cause, ErrWatchLimit)
			break
		}
		incoming += len(e.Path)
	}
	used := 0
	for _, p := range w.state.DirtyPaths {
		used += len(p.Bytes())
	}
	for _, e := range events {
		if e.Kind != WatchPath {
			if e.Kind != WatchLoss {
				cause = errors.Join(cause, ErrWatchStale)
			}
			continue
		}
		// Validate BEFORE copying caller-controlled raw bytes.
		if model.ValidatePath(e.Path) != nil {
			cause = errors.Join(cause, ErrWatchStale)
			continue
		}
		if w.candidates[string(e.Path)] {
			continue
		}
		if len(w.state.DirtyPaths) >= w.limits.Candidates || len(e.Path) > w.limits.CandidateBytes-used {
			cause = errors.Join(cause, ErrWatchLimit)
			continue
		}
		p, _ := model.NewPath(e.Path)
		w.candidates[string(e.Path)] = true
		w.state.DirtyPaths = append(w.state.DirtyPaths, p)
		used += len(e.Path)
	}
	if w.failed != nil {
		return errors.Join(cause, w.failed)
	}
	if err := w.persist(); err != nil {
		w.failed = err
	}
	return errors.Join(cause, w.failed)
}

// Observe is synchronous; Queue bounds an admitted batch, with no hidden event
// buffer or retry. Even an oversized batch/loss advances and persists unknown.
func (w *Watch) Observe(events []WatchEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrWatchClosed
	}
	return w.observeLocked(events, w.rootSame())
}

// Snapshot reports this owner's generation. After a persistence error it stays
// Uncertain/error even when Load/Recover returns a historical Clean record;
// never treat that record as current filesystem status or resume mutation.
func (w *Watch) Snapshot() (Manifest, uint64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return cloneManifest(w.state), w.generation, ErrWatchClosed
	}
	return cloneManifest(w.state), w.generation, w.failed
}
func (w *Watch) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return ErrWatchClosed
	}
	// A live scan owns its directory FD/backend call. Invalidate it and let the
	// caller retry Close after it returns; never close a backend under Barrier.
	if w.busy || w.finishing {
		err := w.observeLocked(nil, ErrWatchLimit)
		w.mu.Unlock()
		return err
	}
	err := w.observeLocked(nil, nil)
	w.closed = true
	err = errors.Join(err, w.root.Close(), w.metadataAnchor.Close(), w.manifestAnchor.Close())
	w.mu.Unlock()
	// Never wait for adapter callbacks while holding the Observe mutex.
	return errors.Join(err, w.backend.Close())
}
func (w *Watch) selected(path string, directory bool, check func() error) (bool, error) {
	if w.binding.SparseAll {
		return true, nil
	}
	for _, s := range w.sparse {
		if err := check(); err != nil {
			return false, err
		}
		if path == s || (len(path) > len(s) && strings.HasPrefix(path, s) && path[len(s)] == '/') || directory && len(s) > len(path) && strings.HasPrefix(s, path) && s[len(path)] == '/' {
			return true, nil
		}
	}
	return false, nil
}

// Scan inventories root-confined metadata without opening content files;
// observed symlinks are not queued. Root can resolve transient in-root links;
// this is not atomic no-follow traversal or independent content verification.
// Bytes charges raw path bytes plus 16 bytes per
// examined record (including unselected names); content bytes read is ZERO.
// Queue and Entries bound private
// work/output; owned scan FDs peak at two (root + current directory). CLI-01
// transactions use four FDs plus two retained metadata/manifest inode anchors
// (at most eight explicit FDs including a concurrent scan). Go/OS path-resolution
// transient FDs and kernel buffers are not measured here. Duration/cancellation
// are checked between calls; blocking filesystem syscalls cannot be preempted.
// Attempts bounds admitted scans for this owner; there are no automatic retries.
// Entries/Bytes count admitted metadata records; one directory-entry lookahead
// can discover exhaustion. Kernel I/O bytes/buffering are not these counters.
func (w *Watch) Scan(ctx context.Context) (out WatchScan, err error) {
	deadline := time.Now().Add(w.limits.Duration)
	work, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	w.mu.Lock()
	out.Progress = WatchProgress{Attempts: w.attempts, RestartAtRoot: true}
	if w.closed || w.failed != nil {
		err = w.failed
		if w.closed {
			err = ErrWatchClosed
		}
		w.mu.Unlock()
		return
	}
	if w.busy || w.finishing || w.attempts >= w.limits.Attempts {
		err = w.observeLocked(nil, ErrWatchLimit)
		w.mu.Unlock()
		return
	}
	if err = w.observeLocked(nil, nil); err != nil {
		w.mu.Unlock()
		return
	}
	w.attempts++
	w.scanID++
	w.busy = true
	token := &scanToken{owner: w, id: w.scanID, generation: w.generation, ctx: ctx}
	out.token = token
	out.Progress = WatchProgress{Attempts: w.attempts, OwnedDescriptors: 1, RestartAtRoot: true}
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.busy = false
		if w.closed {
			err = errors.Join(err, ErrWatchClosed)
			return
		}
		if err == nil {
			err = errors.Join(ctx.Err(), work.Err())
		}
		if err == nil && token.generation != w.generation {
			err = ErrWatchStale
		}
		if err != nil {
			err = errors.Join(err, w.observeLocked(nil, nil))
			return
		}
		token.complete = true
		out.Progress.Complete = true
	}()
	if err = w.backend.Barrier(work); err != nil {
		return
	}
	check := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if time.Now().After(deadline) {
			return ErrWatchLimit
		}
		return nil
	}
	if err = check(); err != nil {
		return
	}
	if err = w.rootSame(); err != nil {
		return
	}
	if w.limits.Descriptors < 2 {
		err = ErrWatchLimit
		return
	}
	type pending struct {
		path  string
		depth int
		info  os.FileInfo
	}
	queue := []pending{{".", 0, w.rootInfo}}
	examined := 0
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if err = check(); err != nil {
			return
		}
		// A trailing /. forces directory resolution for every untrusted component;
		// even replacement with a FIFO cannot make the final open a content open.
		var f *os.File
		f, err = w.root.Open(item.path + "/.")
		if err != nil {
			return
		}
		out.Progress.OwnedDescriptors = 2
		err = func() (dirErr error) {
			defer func() { dirErr = errors.Join(dirErr, f.Close()) }()
			held, e := f.Stat()
			if e != nil {
				return e
			}
			if !held.IsDir() || !os.SameFile(held, item.info) {
				return ErrWatchStale
			}
			for {
				if e = check(); e != nil {
					return e
				}
				entries, readErr := f.ReadDir(1)
				if readErr != nil && readErr != io.EOF {
					return readErr
				}
				for _, de := range entries {
					if examined >= w.limits.Entries {
						return ErrWatchLimit
					}
					examined++
					path := de.Name()
					if item.path != "." {
						path = item.path + "/" + path
					}
					if model.ValidatePath([]byte(path)) != nil {
						return ErrWatchStale
					}
					if len(path)+16 > w.limits.Bytes-out.Progress.Bytes {
						return ErrWatchLimit
					}
					out.Progress.Bytes += len(path) + 16
					out.Progress.Entries = examined
					info, e := w.root.Lstat(path)
					if e != nil {
						return e
					}
					if w.step != nil {
						p, _ := model.NewPath([]byte(path))
						w.step(p)
					}
					selected, e := w.selected(path, info.IsDir(), check)
					if e != nil {
						return e
					}
					if !selected {
						continue
					}
					if !info.Mode().IsRegular() && !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
						return ErrWatchStale
					}
					p, _ := model.NewPath([]byte(path))
					out.Entries = append(out.Entries, WatchEntry{p, info.Mode(), info.Size()})
					if info.IsDir() {
						if item.depth+1 > w.limits.Depth || len(queue) >= w.limits.Queue {
							return ErrWatchLimit
						}
						queue = append(queue, pending{path, item.depth + 1, info})
					}
				}
				if readErr == io.EOF {
					break
				}
			}
			after, e := w.root.Lstat(item.path)
			if e != nil {
				return e
			}
			if !after.IsDir() || !os.SameFile(after, held) || after.ModTime() != held.ModTime() {
				return ErrWatchStale
			}
			return nil
		}()
		if err != nil {
			return
		}
	}
	if err = w.rootSame(); err != nil {
		return
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Path.Compare(out.Entries[j].Path) < 0 })
	err = check()
	return
}

// AssertionBinding returns copied provenance for a trusted content reconciler.
func (s WatchScan) AssertionBinding(binding Manifest) CleanAssertion {
	if s.token == nil {
		return CleanAssertion{}
	}
	return CleanAssertion{Binding: cloneManifest(binding), Generation: s.token.generation, ScanID: s.token.id}
}
func (w *Watch) Finish(ctx context.Context, scan WatchScan, proof CleanAssertion) error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return ErrWatchClosed
	}
	if w.busy || w.finishing {
		err := w.observeLocked(nil, ErrWatchLimit)
		w.mu.Unlock()
		return err
	}
	w.finishing = true
	w.mu.Unlock()
	defer func() { w.mu.Lock(); w.finishing = false; w.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(ctx, w.limits.Duration)
	defer cancel()
	if err := w.backend.Barrier(ctx); err != nil {
		return errors.Join(err, w.Observe([]WatchEvent{{Kind: WatchLoss}}))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	t := scan.token
	if w.closed {
		return ErrWatchClosed
	}
	if err := ctx.Err(); err != nil {
		return w.observeLocked(nil, err)
	}
	if w.failed != nil {
		return w.failed
	}
	if t == nil || t.owner != w || !t.complete || w.busy || t.ctx.Err() != nil || t.id != w.scanID || t.generation != w.generation ||
		!proof.ContentVerifiedDurable || proof.Generation != t.generation || proof.ScanID != t.id || !sameBinding(proof.Binding, w.binding) {
		return w.observeLocked(nil, ErrWatchStale)
	}
	if err := w.rootSame(); err != nil {
		return w.observeLocked(nil, err)
	}
	w.state.State = Clean
	w.state.DirtyPaths = nil
	if err := w.persist(); err != nil {
		w.state.State = Uncertain
		w.failed = err
		return err
	}
	clear(w.candidates)
	t.complete = false // one-use; replay never reauthorizes Clean
	return nil
}
