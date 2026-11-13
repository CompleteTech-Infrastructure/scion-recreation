//go:build darwin || linux

package treepages

import (
	"canopy.local/canopy/internal/derived"
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

// Staging requires trusted ancestors/launcher and one owning store per root.
// It does not defend against hostile same-UID processes or mount administrators.
// Its mutex covers admission/lifetime only; object ingestion is concurrent.
type Staging struct {
	mu                     sync.Mutex
	root, staging          *os.Root
	dir, stage             *os.File
	path                   string
	opts                   Options
	auth                   Authority
	ops                    diskOps
	active                 int
	recovering             bool
	recoveryErr            error
	phase                  int
	usedBytes, usedCount   uint64
	ready, closing, closed bool
}

// Fault seams are copied at construction, never exposed through the public API.
// Tests must perform actual filesystem writes even when interrupting a prefix.
type diskOps struct {
	before func(string) error
	write  func(*os.File, []byte) (int, error)
}

func (s *Staging) step(point string, fn func() error) error {
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

func (s *Staging) checkDirs() error {
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

func (s *Staging) acquire(ctx context.Context) error {
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

func (s *Staging) release() {
	s.mu.Lock()
	s.active--
	s.mu.Unlock()
}

// Close stops admission immediately. If operations remain, it returns ErrBusy;
// the owner must call Close again after they finish. It never closes live I/O.
func (s *Staging) Close() error {
	if s == nil {
		return ErrInvalidArgument
	}
	s.mu.Lock()
	if s.root == nil {
		s.mu.Unlock()
		return ErrInvalidArgument
	}
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	if s.active != 0 || s.recovering {
		s.mu.Unlock()
		return ErrBusy
	}
	s.closed = true
	s.mu.Unlock()
	return storageError(errors.Join(s.stage.Close(), s.staging.Close(), s.dir.Close(), s.root.Close()))
}

func tempName(name string) bool {
	if len(name) != 36 || !strings.HasSuffix(name, ".tmp") {
		return false
	}
	b, err := hex.DecodeString(name[:32])
	return err == nil && hex.EncodeToString(b) == name[:32]
}

// RecoverTemps is trusted owner startup maintenance, never a request endpoint.
// It counts final aliases and removes orphans in finite batches before admission.
// It returns no object identities or counts. A failed scan remains unavailable;
// restart reconstructs accounting, never resetting admission on partial progress.
func (s *Staging) RecoverTemps(ctx context.Context) (done bool, err error) {
	if s == nil || ctx == nil {
		return false, ErrInvalidArgument
	}
	s.mu.Lock()
	if s.root == nil {
		s.mu.Unlock()
		return false, ErrInvalidArgument
	}
	if s.closing {
		s.mu.Unlock()
		return false, ErrClosed
	}
	if s.ready || s.active != 0 || s.recovering {
		s.mu.Unlock()
		return false, ErrBusy
	}
	if s.recoveryErr != nil {
		e := s.recoveryErr
		s.mu.Unlock()
		return false, e
	}
	s.recovering = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.recovering = false
		if err != nil {
			s.recoveryErr = err
		}
		s.mu.Unlock()
	}()
	if err = ctx.Err(); err != nil {
		return false, err
	}
	if err = s.checkDirs(); err != nil {
		return false, err
	}
	cursor, root := s.dir, s.root
	if s.phase == 1 {
		cursor, root = s.stage, s.staging
	}
	names, readErr := cursor.Readdirnames(s.opts.RecoveryBatch)
	if readErr != nil && readErr != io.EOF {
		return false, storageError(readErr)
	}
	// Cancellation is checked before enumeration; after enumeration the bounded
	// batch is accounted completely so a canceled cursor cannot skip a quota row.
	for _, name := range names {
		if s.phase == 0 && name == ".staging" {
			continue
		}
		info, e := root.Lstat(name)
		if e != nil {
			return false, storageError(e)
		}
		if s.phase == 0 {
			if !candidateNameValid(name) || !secure(info, 0400) || info.Size() < 24 || info.Size() > derived.MaxTreePageBytes {
				return false, ErrCorruptData
			}
			if !s.addUsage(uint64(info.Size()), 1) {
				return false, ErrResourceExhausted
			}
		} else {
			if !tempName(name) || (!secure(info, 0600) && !secure(info, 0400)) || info.Size() < 0 || info.Size() > derived.MaxTreePageBytes {
				return false, ErrCorruptData
			}
			// Orphans consume quota while present, including a second hardlink alias.
			if !s.addUsage(uint64(info.Size()), 1) {
				return false, ErrResourceExhausted
			}
			if e = root.Remove(name); e != nil {
				return false, storageError(e)
			}
			if e = s.stage.Sync(); e != nil {
				return false, storageError(e)
			}
			s.subtractUsage(uint64(info.Size()), 1)
		}
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}
	if readErr == io.EOF {
		if s.phase == 0 {
			s.phase = 1
			return false, nil
		}
		if err = storageError(s.stage.Sync()); err != nil {
			return false, err
		}
		s.mu.Lock()
		s.ready = true
		s.mu.Unlock()
		return true, nil
	}
	return false, nil
}

func (s *Staging) addUsage(bytes, count uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bytes > s.opts.MaxStoredBytes-s.usedBytes || count > s.opts.MaxCandidates-s.usedCount {
		return false
	}
	s.usedBytes += bytes
	s.usedCount += count
	return true
}
func (s *Staging) subtractUsage(bytes, count uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usedBytes -= bytes
	s.usedCount -= count
}

func openRoots(path string, opts Options, auth Authority, ops diskOps) (_ *Staging, err error) {
	path, err = filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, ErrInvalidArgument
	}
	s := &Staging{path: path, opts: opts, auth: auth, ops: ops}
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
