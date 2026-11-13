//go:build darwin || linux

package objects

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// Changesets requires trusted ancestors/launcher and one owning store per root.
// It does not defend against hostile same-UID processes or mount administrators.
// Its mutex covers admission/lifetime only; object ingestion is concurrent.
type Changesets struct {
	mu                     sync.Mutex
	root, staging          *os.Root
	dir, stage             *os.File
	path                   string
	opts                   Options
	auth                   Authority
	ops                    diskOps
	active                 int
	ready, closing, closed bool
}

// Fault seams are copied at construction, never exposed through the public API.
// Tests must perform actual filesystem writes even when interrupting a prefix.
type diskOps struct {
	before func(string) error
	write  func(*os.File, []byte) (int, error)
}

func (s *Changesets) step(point string, fn func() error) error {
	if s.ops.before != nil {
		if err := s.ops.before(point); err != nil {
			return storageError(err)
		}
	}
	return storageError(fn())
}

func storageError(err error) error {
	if err == nil {
		return nil
	}
	var p *os.PathError
	if errors.As(err, &p) {
		err = p.Err
	}
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return errors.Join(ErrResourceExhausted, err)
	}
	return errors.Join(ErrUnavailable, err)
}

func secure(info os.FileInfo, mode os.FileMode) bool {
	if info == nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && info.Mode() == mode
}

func openAt(root *os.Root, name string, flags int, mode os.FileMode) (*os.File, error) {
	return root.OpenFile(name, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, mode)
}

func (s *Changesets) checkDirs() error {
	a, e1 := s.dir.Stat()
	b, e2 := os.Lstat(s.path)
	c, e3 := s.root.Lstat(".")
	d, e4 := s.stage.Stat()
	e, e5 := s.root.Lstat(".staging")
	f, e6 := s.staging.Lstat(".")
	if err := errors.Join(e1, e2, e3, e4, e5, e6); err != nil {
		return storageError(err)
	}
	if !secure(a, os.ModeDir|0700) || !secure(b, os.ModeDir|0700) || !secure(c, os.ModeDir|0700) ||
		!secure(d, os.ModeDir|0700) || !secure(e, os.ModeDir|0700) || !secure(f, os.ModeDir|0700) ||
		!os.SameFile(a, b) || !os.SameFile(a, c) || !os.SameFile(d, e) || !os.SameFile(d, f) ||
		a.Sys().(*syscall.Stat_t).Dev != d.Sys().(*syscall.Stat_t).Dev {
		return ErrUnavailable
	}
	return nil
}

func (s *Changesets) acquire(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return ErrInvalidArgument
	}
	if s.closing {
		return ErrClosed
	}
	if !s.ready || s.active >= s.opts.MaxConcurrentOps {
		return ErrBusy
	}
	s.active++
	return nil
}

func (s *Changesets) release() {
	s.mu.Lock()
	s.active--
	s.mu.Unlock()
}

// Close stops admission immediately. If operations remain, it returns ErrBusy;
// the owner must call Close again after they finish. It never closes live I/O.
func (s *Changesets) Close() error {
	if s == nil {
		return ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return ErrInvalidArgument
	}
	if s.closed {
		return nil
	}
	s.closing = true
	if s.active != 0 {
		return ErrBusy
	}
	s.closed = true
	return storageError(errors.Join(s.stage.Close(), s.staging.Close(), s.dir.Close(), s.root.Close()))
}

func tempName(name string) bool {
	if len(name) != 36 || !strings.HasSuffix(name, ".tmp") {
		return false
	}
	b, err := hex.DecodeString(name[:32])
	return err == nil && hex.EncodeToString(b) == name[:32]
}

// RecoverTemps removes at most RecoveryBatch private orphan files per call.
// No public operation is admitted until an EOF scan and staging fsync succeed.
// Each call restarts the scan, so cancellation cannot skip an enumerated orphan.
func (s *Changesets) RecoverTemps(ctx context.Context) (bool, error) {
	if s == nil || ctx == nil {
		return false, ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return false, ErrInvalidArgument
	}
	if s.closing {
		return false, ErrClosed
	}
	if s.ready || s.active != 0 {
		return false, ErrBusy
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := s.checkDirs(); err != nil {
		return false, err
	}
	if _, err := s.stage.Seek(0, io.SeekStart); err != nil {
		return false, storageError(err)
	}
	entries, err := s.stage.ReadDir(s.opts.RecoveryBatch)
	if err != nil && err != io.EOF {
		return false, storageError(err)
	}
	for _, entry := range entries {
		if e := ctx.Err(); e != nil {
			return false, e
		}
		info, e := s.staging.Lstat(entry.Name())
		if e != nil {
			return false, storageError(e)
		}
		if !tempName(entry.Name()) || (!secure(info, 0600) && !secure(info, 0400)) {
			return false, ErrCorruptData
		}
		if e = s.staging.Remove(entry.Name()); e != nil {
			return false, storageError(e)
		}
	}
	if e := s.stage.Sync(); e != nil {
		return false, storageError(e)
	}
	if e := ctx.Err(); e != nil {
		return false, e
	}
	s.ready = err == io.EOF
	return s.ready, nil
}

func openRoots(path string, opts Options, auth Authority, ops diskOps) (_ *Changesets, err error) {
	path, err = filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, ErrInvalidArgument
	}
	s := &Changesets{path: path, opts: opts, auth: auth, ops: ops}
	defer func() {
		if err != nil {
			for _, closer := range []io.Closer{s.stage, s.staging, s.dir, s.root} {
				if !nilDependency(closer) {
					_ = closer.Close()
				}
			}
		}
	}()
	s.dir, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, storageError(err)
	}
	s.root, err = os.OpenRoot(path)
	if err != nil {
		return nil, storageError(err)
	}
	a, e1 := s.dir.Stat()
	b, e2 := s.root.Lstat(".")
	c, e3 := os.Lstat(path)
	if e := errors.Join(e1, e2, e3); e != nil {
		return nil, storageError(e)
	}
	if !secure(a, os.ModeDir|0700) || !secure(b, os.ModeDir|0700) || !secure(c, os.ModeDir|0700) ||
		!os.SameFile(a, b) || !os.SameFile(a, c) {
		return nil, ErrUnavailable
	}
	if err = s.root.Mkdir(".staging", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, storageError(err)
	}
	s.stage, err = openAt(s.root, ".staging", os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, storageError(err)
	}
	s.staging, err = s.root.OpenRoot(".staging")
	if err != nil {
		return nil, storageError(err)
	}
	if err = s.checkDirs(); err != nil {
		return nil, err
	}
	if err = s.dir.Sync(); err != nil {
		return nil, storageError(err)
	}
	return s, nil
}
