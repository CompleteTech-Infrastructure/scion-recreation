package workspace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"canopy.local/canopy/internal/model"
)

// Native budgets are independent of WatchLimits.Descriptors (the content scan
// cap): one inotify FD, one root FD and at most two traversal FDs. Registrations
// and pending hints additionally obey the caller's Entries/Queue/Bytes budgets.
// Kernel queue memory and transient OS path-resolution FDs are not these counts.
const (
	linuxWatchDescriptors   = 4
	linuxWatchRegistrations = 4096
	linuxWatchPending       = 1024
	linuxWatchBytes         = 256 << 10
	linuxWatchMask          = syscall.IN_MODIFY | syscall.IN_CLOSE_WRITE | syscall.IN_ATTRIB |
		syscall.IN_CREATE | syscall.IN_DELETE | syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO |
		syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF | syscall.IN_UNMOUNT
)

type linuxRegistration struct {
	path string
	info os.FileInfo
}
type linuxRequest struct {
	ctx    context.Context
	action func() error
	reply  chan error
}
type linuxWatch struct {
	requests chan linuxRequest
	done     chan struct{}
	// Everything below is owned by run, after callback installation. No callback
	// holds a backend mutex and Close never waits while holding Watch.mu.
	fd                                             int
	root                                           *os.File
	name                                           string
	info                                           os.FileInfo
	limits                                         WatchLimits
	watches                                        map[int]linuxRegistration
	paths                                          map[string]int
	observe                                        func([]WatchEvent) error
	failed                                         error
	armed, coverage, stopping                      bool
	descriptors, peak, registrationCap, pendingCap int
	readSequence, delivered, watermark             uint64
	masks                                          uint32
}

// OpenNativeWatch uses actual Linux inotify directory notifications. Hints never
// assert content equality. A failed backend is terminal: reopen a new owner and
// reconcile; there is deliberately no silent backend restart.
func OpenNativeWatch(root, metadata string, limits WatchLimits) (*Watch, error) {
	if !limits.valid() {
		return nil, ErrWatchLimit
	}
	n, err := newLinuxWatch(root, limits)
	if err != nil {
		return nil, err
	}
	w, err := OpenWatch(root, metadata, limits, n)
	if err != nil {
		return nil, errors.Join(err, n.release())
	}
	n.observe = w.Observe // only after the common owner has successfully opened
	go n.run()
	return w, nil
}

func newLinuxWatch(root string, limits WatchLimits) (*linuxWatch, error) {
	n := &linuxWatch{fd: -1, limits: limits, requests: make(chan linuxRequest), done: make(chan struct{}),
		watches: make(map[int]linuxRegistration), paths: make(map[string]int),
		registrationCap: min(limits.Entries, linuxWatchRegistrations), pendingCap: min(limits.Queue, linuxWatchPending)}
	var err error
	n.name, err = filepath.Abs(root)
	if err == nil {
		n.fd, err = syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	}
	if err == nil {
		n.descriptors++
		var fd int
		fd, err = syscall.Open(n.name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err == nil {
			n.root = os.NewFile(uintptr(fd), n.name)
			n.descriptors++
			n.info, err = n.root.Stat()
		}
	}
	n.peak = n.descriptors
	if err != nil {
		return nil, errors.Join(err, n.release())
	}
	return n, nil
}

func (n *linuxWatch) release() error {
	var err error
	if n.fd >= 0 {
		err = syscall.Close(n.fd)
		n.fd = -1
		n.descriptors--
	}
	if n.root != nil {
		err = errors.Join(err, n.root.Close())
		n.root = nil
		n.descriptors--
	}
	clear(n.watches)
	clear(n.paths)
	return err
}

func (n *linuxWatch) fail(err error) error {
	if n.failed == nil {
		n.failed = err
		if n.observe != nil {
			n.failed = errors.Join(n.failed, n.observe([]WatchEvent{{Kind: WatchLoss}}))
		}
		n.failed = errors.Join(n.failed, n.release())
	}
	return n.failed
}

func (n *linuxWatch) call(ctx context.Context, action func() error) error {
	r := linuxRequest{ctx, action, make(chan error, 1)}
	select {
	case <-n.done:
		return ErrWatchClosed
	case n.requests <- r:
	}
	// An admitted cancellation must finish its loss delivery/resource cleanup.
	return <-r.reply
}
func (n *linuxWatch) Barrier(ctx context.Context) error { return n.call(ctx, nil) }
func (n *linuxWatch) Close() error {
	err := n.call(context.Background(), func() error { n.stopping = true; return n.release() })
	<-n.done
	return err
}
func (n *linuxWatch) run() {
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	defer close(n.done)
	for {
		select {
		case r := <-n.requests:
			var err error
			if r.action != nil {
				err = r.action()
			} else {
				err = n.step(r.ctx, true)
			}
			r.reply <- err
			if n.stopping {
				return
			}
		case <-tick.C:
			if n.armed && n.failed == nil {
				_ = n.step(context.Background(), false)
			}
		}
	}
}

func (n *linuxWatch) step(ctx context.Context, barrier bool) error {
	if n.failed != nil {
		return n.failed
	}
	ctx, cancel := context.WithTimeout(ctx, n.limits.Duration)
	defer cancel()
	if barrier {
		n.coverage = true
	}
	for pass := 0; pass < 4; pass++ {
		if err := ctx.Err(); err != nil {
			return n.fail(err)
		}
		if err := n.drain(ctx); err != nil {
			return n.fail(err)
		}
		current, err := os.Lstat(n.name)
		if err != nil {
			return n.fail(err)
		}
		if !current.IsDir() || !os.SameFile(current, n.info) {
			return n.fail(ErrWatchStale)
		}
		if !n.armed || n.coverage {
			n.coverage = false
			if err = n.maintain(ctx); err != nil {
				return n.fail(err)
			}
			n.armed = true
			continue // drain events produced during registration before success
		}
		// EAGAIN defines this concrete sequence watermark. Every record through
		// it has already been synchronously observed, including loss indications.
		n.watermark = n.readSequence
		if n.delivered != n.watermark {
			return n.fail(ErrWatchStale)
		}
		return nil
	}
	return n.fail(ErrWatchLimit)
}

func (n *linuxWatch) openDir(path string) (*os.File, error) {
	fd, err := syscall.Openat(int(n.root.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	n.descriptors++
	if path != "." {
		for _, part := range strings.Split(path, "/") {
			next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
			if e == nil {
				n.descriptors++
				n.peak = max(n.peak, n.descriptors)
			}
			closeErr := syscall.Close(fd)
			n.descriptors--
			if e != nil {
				return nil, e
			}
			if closeErr != nil {
				syscall.Close(next)
				n.descriptors--
				return nil, closeErr
			}
			fd = next
		}
	}
	n.peak = max(n.peak, n.descriptors)
	return os.NewFile(uintptr(fd), path), nil
}

func (n *linuxWatch) maintain(ctx context.Context) error {
	queue := []string{"."}
	seen, paths := make(map[int]linuxRegistration), make(map[string]int)
	entries, used := 0, 0
	for len(queue) != 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := queue[0]
		queue = queue[1:]
		f, err := n.openDir(path)
		if err != nil {
			return err
		}
		err = func() (err error) {
			defer func() { err = errors.Join(err, f.Close()); n.descriptors-- }()
			info, err := f.Stat()
			if err != nil {
				return err
			}
			wd, exists := n.paths[path]
			if exists && !os.SameFile(info, n.watches[wd].info) {
				return ErrWatchStale
			}
			if !exists {
				if len(n.watches) >= n.registrationCap {
					return ErrWatchLimit
				}
				// The proc link is intentional: it names this already root-confined,
				// no-follow directory FD, never an untrusted workspace symlink.
				wd, err = syscall.InotifyAddWatch(n.fd, "/proc/self/fd/"+strconv.Itoa(int(f.Fd())), linuxWatchMask|syscall.IN_ONLYDIR)
				if err != nil {
					return err
				}
				n.watches[wd] = linuxRegistration{path, info}
			}
			if prior, ok := seen[wd]; ok && prior.path != path {
				return ErrWatchStale // one inode at multiple paths has ambiguous coverage
			}
			seen[wd], paths[path] = linuxRegistration{path, info}, wd
			for {
				if err = ctx.Err(); err != nil {
					return err
				}
				des, e := f.Readdir(1) // descriptor-relative lstat, including DT_UNKNOWN
				if e != nil && e != io.EOF {
					return e
				}
				for _, de := range des {
					entries++
					used += len(path) + len(de.Name()) + 17
					if entries > n.limits.Entries || used > min(n.limits.Bytes, linuxWatchBytes) {
						return ErrWatchLimit
					}
					child := de.Name()
					if path != "." {
						child = path + "/" + child
					}
					if model.ValidatePath([]byte(child)) != nil {
						return ErrWatchStale
					}
					// Symlinks are parent-directory hints only; never follow targets.
					if de.IsDir() {
						if strings.Count(child, "/")+1 > n.limits.Depth || len(queue) >= n.registrationCap {
							return ErrWatchLimit
						}
						queue = append(queue, child)
					}
				}
				if e == io.EOF {
					break
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	for wd := range n.watches {
		if _, ok := seen[wd]; !ok {
			if _, err := syscall.InotifyRmWatch(n.fd, uint32(wd)); err != nil {
				return err
			}
		}
	}
	n.watches, n.paths = seen, paths
	return nil
}

// decode also serves deterministic malformed/overflow controls. It is not a
// substitute for actual Linux notification tests. Names remain uninterpreted bytes.
func (n *linuxWatch) decode(data []byte, events *[]WatchEvent, used *int) error {
	for len(data) != 0 {
		if len(data) < syscall.SizeofInotifyEvent {
			return ErrWatchStale
		}
		wd := int(int32(binary.NativeEndian.Uint32(data)))
		mask, size := binary.NativeEndian.Uint32(data[4:]), int(binary.NativeEndian.Uint32(data[12:]))
		if size > len(data)-syscall.SizeofInotifyEvent {
			return ErrWatchStale
		}
		name := data[syscall.SizeofInotifyEvent : syscall.SizeofInotifyEvent+size]
		data = data[syscall.SizeofInotifyEvent+size:]
		if n.readSequence == ^uint64(0) {
			return ErrWatchLimit
		}
		n.readSequence++
		n.masks |= mask
		if len(*events) >= n.pendingCap {
			return ErrWatchLimit
		}
		if mask&(syscall.IN_Q_OVERFLOW|syscall.IN_UNMOUNT) != 0 {
			return ErrWatchStale
		}
		reg, ok := n.watches[wd]
		if mask&syscall.IN_IGNORED != 0 {
			if ok {
				delete(n.watches, wd)
				delete(n.paths, reg.path)
			}
			n.coverage = true
			*events = append(*events, WatchEvent{Kind: WatchLoss})
		} else {
			if !ok {
				return ErrWatchStale
			}
			path := reg.path
			if size != 0 {
				end := bytes.IndexByte(name, 0)
				if end < 1 || bytes.IndexByte(name[:end], '/') >= 0 {
					return ErrWatchStale
				}
				name = name[:end]
				path = string(name)
				if reg.path != "." {
					path = reg.path + "/" + path
				}
			}
			if path == "." {
				*events = append(*events, WatchEvent{Kind: WatchLoss})
			} else {
				if model.ValidatePath([]byte(path)) != nil {
					return ErrWatchStale
				}
				if len(path) > min(n.limits.Bytes, linuxWatchBytes)-*used {
					return ErrWatchLimit
				}
				*used += len(path)
				*events = append(*events, WatchEvent{WatchPath, []byte(path)})
			}
			if mask&syscall.IN_ISDIR != 0 || mask&(syscall.IN_MOVE_SELF|syscall.IN_DELETE_SELF) != 0 {
				n.coverage = true
			}
			if mask&(syscall.IN_MOVE_SELF|syscall.IN_DELETE_SELF) != 0 || mask&syscall.IN_ISDIR != 0 && mask&(syscall.IN_MOVED_FROM|syscall.IN_DELETE) != 0 {
				return ErrWatchStale // detachment invalidates inode-to-root path mappings
			}
		}
	}
	return nil
}

func (n *linuxWatch) drain(ctx context.Context) error {
	var buf [16 << 10]byte
	var events []WatchEvent
	used := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		count, err := syscall.Read(n.fd, buf[:])
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN {
			break
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return ErrWatchStale
		}
		if err = n.decode(buf[:count], &events, &used); err != nil {
			return err
		}
	}
	if len(events) != 0 {
		if err := n.observe(events); err != nil {
			return err
		}
	}
	n.delivered = n.readSequence
	return nil
}
