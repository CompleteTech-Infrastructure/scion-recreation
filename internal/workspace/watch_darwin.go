//go:build darwin

package workspace

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"time"

	"canopy.local/canopy/internal/model"
)

// Native budgets are separate from WatchLimits.Descriptors (scan FDs); kernel
// hints coalesce to one knote per registration. Userspace lookahead detects exhaustion.
const (
	darwinRegistrations = 256
	darwinDescriptors   = darwinRegistrations + 5 // root, kqueue, enumeration, two rooted-resolution FDs
	darwinPending       = 64
	darwinPasses        = 4
)

type darwinNode struct {
	file *os.File
	info os.FileInfo
	path string
}
type darwinReply struct {
	err                        error
	watermark                  uint64
	registrations, descriptors int
}
type darwinRequest struct {
	ctx   context.Context
	reply chan darwinReply
}
type darwinWatch struct {
	root                                *os.Root
	name                                string
	info                                os.FileInfo
	kq                                  int
	limits                              WatchLimits
	registrations, descriptors, pending int
	nodes                               map[string]*darwinNode
	fds                                 map[uint64]*darwinNode
	observe                             func([]WatchEvent) error
	kevent                              func(int, []syscall.Kevent_t, []syscall.Kevent_t, *syscall.Timespec) (int, error)
	requests                            chan darwinRequest
	stop, done                          chan struct{}
	once                                sync.Once
	terminal, closeErr                  error
	sequence, delivered, watermark      uint64 // single worker owns all native state
	maintain                            bool
}

// OpenNativeWatch arms Darwin vnode notifications, including regular-file writes.
// Hints require trusted durable CleanAssertion; symlinks/special files are refused.
func OpenNativeWatch(root, metadata string, limits WatchLimits) (*Watch, error) {
	return openDarwinWatch(root, metadata, limits, nil)
}
func openDarwinWatch(root, metadata string, limits WatchLimits, configure func(*darwinWatch)) (*Watch, error) {
	b := &darwinWatch{name: root, kq: -1, limits: limits, registrations: darwinRegistrations,
		descriptors: darwinDescriptors, pending: darwinPending, nodes: make(map[string]*darwinNode),
		fds: make(map[uint64]*darwinNode), kevent: syscall.Kevent, requests: make(chan darwinRequest), stop: make(chan struct{}), done: make(chan struct{}), maintain: true}
	if configure != nil {
		configure(b)
	}
	var err error
	b.root, err = os.OpenRoot(root)
	if err == nil {
		b.info, err = os.Lstat(root)
	}
	if err == nil && !b.info.IsDir() {
		err = ErrWatchStale
	}
	if err == nil {
		syscall.ForkLock.RLock()
		b.kq, err = syscall.Kqueue()
		if err == nil {
			syscall.CloseOnExec(b.kq)
		}
		syscall.ForkLock.RUnlock()
	}
	if err != nil {
		return nil, errors.Join(err, b.release())
	}
	w, err := OpenWatch(root, metadata, limits, b)
	if err != nil {
		return nil, errors.Join(err, b.release())
	}
	b.observe = w.Observe // OpenWatch must succeed before callback installation.
	go b.run()
	ctx, cancel := context.WithTimeout(context.Background(), limits.Duration)
	defer cancel()
	if err = b.Barrier(ctx); err != nil {
		return nil, errors.Join(err, w.Close())
	}
	return w, nil
}
func (b *darwinWatch) release() (err error) {
	for path, n := range b.nodes {
		err = errors.Join(err, n.file.Close())
		delete(b.nodes, path)
	}
	clear(b.fds)
	if b.kq >= 0 {
		err = errors.Join(err, syscall.Close(b.kq))
		b.kq = -1
	}
	if b.root != nil {
		err = errors.Join(err, b.root.Close())
		b.root = nil
	}
	return
}
func (b *darwinWatch) emit(event WatchEvent) error {
	// No backend mutex exists: Observe can take the common owner's mutex freely.
	if b.sequence == ^uint64(0) {
		return errors.Join(ErrWatchLimit, b.observe([]WatchEvent{{Kind: WatchLoss}}))
	}
	b.sequence++
	err := b.observe([]WatchEvent{event})
	b.delivered = b.sequence
	return err
}
func (b *darwinWatch) loss(err error) error {
	e := b.emit(WatchEvent{Kind: WatchLoss})
	b.watermark = b.delivered
	b.terminal = errors.Join(err, e, b.release())
	return b.terminal
}
func (b *darwinWatch) sameRoot() error {
	current, err := os.Lstat(b.name)
	if err != nil {
		return err
	}
	held, err := b.root.Stat(".")
	if err != nil {
		return err
	}
	if !current.IsDir() || !os.SameFile(current, b.info) || !os.SameFile(held, b.info) {
		return ErrWatchStale
	}
	return nil
}
func (b *darwinWatch) register(path string, info os.FileInfo) error {
	if n := b.nodes[path]; n != nil {
		if os.SameFile(n.info, info) {
			return nil
		}
		// Replacement creates a coverage gap even if no native hint survived.
		if err := b.emit(WatchEvent{Kind: WatchLoss}); err != nil {
			return err
		}
		fd := uint64(n.file.Fd())
		if err := n.file.Close(); err != nil {
			return err
		}
		delete(b.fds, fd)
		delete(b.nodes, path)
	}
	if len(b.nodes) >= b.registrations || len(b.nodes)+6 > b.descriptors {
		return ErrWatchLimit
	}
	f, err := b.root.OpenFile(path, syscall.O_EVTONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	held, err := f.Stat()
	after, e := b.root.Lstat(path)
	err = errors.Join(err, e)
	if err == nil && (after.Mode()&os.ModeSymlink != 0 || !os.SameFile(held, info) || !os.SameFile(after, info)) {
		err = ErrWatchStale
	}
	if err == nil {
		var change syscall.Kevent_t
		syscall.SetKevent(&change, int(f.Fd()), syscall.EVFILT_VNODE, syscall.EV_ADD|syscall.EV_CLEAR)
		change.Fflags = syscall.NOTE_WRITE | syscall.NOTE_EXTEND | syscall.NOTE_ATTRIB | syscall.NOTE_LINK | syscall.NOTE_RENAME | syscall.NOTE_DELETE | syscall.NOTE_REVOKE
		_, err = b.kevent(b.kq, []syscall.Kevent_t{change}, nil, &syscall.Timespec{})
	}
	if err != nil {
		return errors.Join(err, f.Close())
	}
	n := &darwinNode{f, held, path}
	b.nodes[path] = n
	b.fds[uint64(f.Fd())] = n
	return nil
}
func (b *darwinWatch) maintenance(ctx context.Context) error {
	if err := b.sameRoot(); err != nil {
		return err
	}
	type item struct {
		path  string
		depth int
	}
	queue := []item{{".", 0}}
	seen := make(map[string]bool)
	used := 0
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		it := queue[0]
		queue = queue[1:]
		info, err := b.root.Lstat(it.path)
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return ErrWatchStale
		}
		if len(seen) >= b.registrations || len(it.path)+16 > b.limits.Bytes-used {
			return ErrWatchLimit
		}
		used += len(it.path) + 16
		seen[it.path] = true
		if err = b.register(it.path, info); err != nil {
			return err
		}
		if !info.IsDir() {
			continue
		}
		// Root confinement plus Lstat/SameFile checks reject redirected inode coverage.
		f, err := b.root.Open(it.path + "/.")
		if err != nil {
			return err
		}
		err = func() (err error) {
			defer func() { err = errors.Join(err, f.Close()) }()
			held, err := f.Stat()
			if err != nil {
				return err
			}
			if !os.SameFile(held, info) {
				return ErrWatchStale
			}
			for {
				if err = ctx.Err(); err != nil {
					return err
				}
				entries, e := f.ReadDir(1)
				if e != nil && e != io.EOF {
					return e
				}
				for _, de := range entries {
					path := de.Name()
					if it.path != "." {
						path = it.path + "/" + path
					}
					if model.ValidatePath([]byte(path)) != nil {
						return ErrWatchStale
					}
					if it.depth+1 > b.limits.Depth || len(seen)+len(queue) >= b.registrations || len(seen)+len(queue) > b.limits.Entries {
						return ErrWatchLimit
					}
					queue = append(queue, item{path, it.depth + 1})
				}
				if e == io.EOF {
					break
				}
			}
			after, err := b.root.Lstat(it.path)
			if err != nil {
				return err
			}
			if !os.SameFile(after, held) || after.ModTime() != held.ModTime() {
				return ErrWatchStale
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	for path, n := range b.nodes {
		if !seen[path] {
			if err := errors.Join(ctx.Err(), b.emit(WatchEvent{Kind: WatchLoss})); err != nil {
				return err
			}
			fd := uint64(n.file.Fd())
			if err := n.file.Close(); err != nil {
				return err
			}
			delete(b.nodes, path)
			delete(b.fds, fd)
		}
	}
	b.maintain = false
	return b.sameRoot()
}
func (b *darwinWatch) cycle(ctx context.Context) error {
	if b.terminal != nil {
		return b.terminal
	}
	total := 0
	// An empty read after maintenance watermarks all synchronously observed hints.
	for pass := 0; pass < darwinPasses; pass++ {
		if err := ctx.Err(); err != nil {
			return b.loss(err)
		}
		if b.maintain {
			if err := b.maintenance(ctx); err != nil {
				return b.loss(err)
			}
		}
		events := make([]syscall.Kevent_t, b.pending+1)
		n, err := b.kevent(b.kq, nil, events, &syscall.Timespec{})
		if err != nil {
			return b.loss(err)
		} // no restart can silently restore coverage
		if n < 0 || n > len(events) || n > b.pending-total {
			return b.loss(ErrWatchLimit)
		}
		if n == 0 {
			if err = errors.Join(ctx.Err(), b.sameRoot()); err != nil {
				return b.loss(err)
			}
			b.watermark = b.delivered
			return nil
		}
		total += n
		for _, e := range events[:n] {
			node := b.fds[e.Ident]
			if node == nil || e.Filter != syscall.EVFILT_VNODE || e.Flags&(syscall.EV_ERROR|syscall.EV_EOF) != 0 || e.Fflags&syscall.NOTE_REVOKE != 0 {
				return b.loss(ErrWatchStale)
			}
			hint := WatchEvent{WatchPath, []byte(node.path)}
			if node.path == "." {
				hint = WatchEvent{Kind: WatchLoss}
			}
			if err = b.emit(hint); err != nil {
				return b.loss(err)
			}
			if node.path == "." && e.Fflags&(syscall.NOTE_RENAME|syscall.NOTE_DELETE) != 0 {
				return b.loss(ErrWatchStale)
			}
			if node.info.IsDir() || e.Fflags&(syscall.NOTE_RENAME|syscall.NOTE_DELETE) != 0 {
				b.maintain = true
			}
		}
	}
	return b.loss(ErrWatchLimit) // sustained churn cannot produce a false barrier
}
func (b *darwinWatch) run() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	defer close(b.done)
	for {
		select {
		case <-b.stop:
			if b.terminal == nil {
				e := b.emit(WatchEvent{Kind: WatchLoss})
				if errors.Is(e, ErrWatchClosed) {
					e = nil
				}
				b.closeErr = errors.Join(e, b.release())
			} else {
				b.closeErr = b.terminal
			}
			return
		case r := <-b.requests:
			err := b.cycle(r.ctx)
			owned := 0
			if b.root != nil {
				owned = len(b.nodes) + 2
			}
			r.reply <- darwinReply{err, b.watermark, len(b.nodes), owned}
		case <-ticker.C:
			if b.terminal == nil {
				ctx, cancel := context.WithTimeout(context.Background(), b.limits.Duration)
				_ = b.cycle(ctx)
				cancel()
			}
		}
	}
}
func (b *darwinWatch) barrier(ctx context.Context) darwinReply {
	r := darwinRequest{ctx, make(chan darwinReply, 1)}
	select {
	case <-b.done:
		return darwinReply{err: ErrWatchClosed}
	case <-ctx.Done():
		_ = b.Close()
		return darwinReply{err: ctx.Err()}
	case b.requests <- r:
	}
	select {
	case reply := <-r.reply:
		if err := ctx.Err(); err != nil {
			_ = b.Close()
			reply.err = errors.Join(reply.err, err)
		}
		return reply
	case <-b.done:
		return darwinReply{err: ErrWatchClosed}
	case <-ctx.Done():
		_ = b.Close()
		return darwinReply{err: ctx.Err()}
	}
}
func (b *darwinWatch) Barrier(ctx context.Context) error { return b.barrier(ctx).err }
func (b *darwinWatch) Close() error {
	b.once.Do(func() { close(b.stop) })
	<-b.done
	return b.closeErr
}
