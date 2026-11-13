//go:build darwin || linux

// Package treepages stores private untrusted TREE candidate frames. A successful
// stage is NOT a graph/context validation, retention receipt, publication or grant.
package treepages

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"

	"canopy.local/canopy/internal/derived"
)

var (
	ErrInvalidArgument   = errors.New("invalid tree staging argument")
	ErrNotFound          = errors.New("tree candidate not found")
	ErrCorruptData       = errors.New("corrupt tree candidate")
	ErrResourceExhausted = errors.New("tree staging resource exhausted")
	ErrUnavailable       = errors.New("tree staging unavailable")
	ErrOutcomeUnknown    = errors.New("tree staging activation outcome unknown")
	ErrClosed            = errors.New("tree staging closed")
	ErrBusy              = errors.New("tree staging busy")
	ErrPermissionDenied  = errors.New("tree staging access denied")
)

const (
	ActionStage        = "stage"
	ActionGetCandidate = "getCandidate"
)

// Authority is trusted constructor composition, not caller input. It must bind
// current principal/session/repository/purpose and complete object visibility.
// A page digest alone is not permission; blocking providers must honor deadlines.
type Authority interface {
	Authorize(context.Context, derived.TreePageID, string) error
}

// Options caps all final entries and temporary aliases. Bytes <=1TiB, candidate
// entries <=2^32; concurrency/recovery batches 1..1024. Full stores may reject
// reuse because validating/staging another copy needs temporary quota too.
type Options struct {
	MaxStoredBytes, MaxCandidates   uint64
	MaxConcurrentOps, RecoveryBatch int
}

// CandidateID only names private staged bytes. It proves no transitive closure.
type CandidateID struct{ page derived.TreePageID }

func (c CandidateID) PageID() derived.TreePageID { return c.page }
func nilDependency(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}

// OpenStaging opens an existing private directory owned by one trusted service.
// RecoverTemps must finish before Stage/Get. Trusted startup metadata scanning
// is not a request endpoint and does not return names, object data or counts.
func OpenStaging(path string, opts Options, auth Authority) (*Staging, error) {
	return openStaging(path, opts, auth, diskOps{})
}
func openStaging(path string, opts Options, auth Authority, ops diskOps) (*Staging, error) {
	if path == "" || nilDependency(auth) || opts.MaxStoredBytes == 0 || opts.MaxStoredBytes > 1<<40 || opts.MaxCandidates == 0 || opts.MaxCandidates > 1<<32 || opts.MaxConcurrentOps < 1 || opts.MaxConcurrentOps > 1024 || opts.RecoveryBatch < 1 || opts.RecoveryBatch > 1024 {
		return nil, ErrInvalidArgument
	}
	return openRoots(path, opts, auth, ops)
}
func (s *Staging) authorize(ctx context.Context, id derived.TreePageID, action string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := s.auth.Authorize(ctx, id, action)
	if cancel := ctx.Err(); cancel != nil {
		return cancel
	}
	if err != nil {
		return ErrPermissionDenied
	}
	return nil
}
func candidateName(id derived.TreePageID) string {
	b, _ := id.MarshalBinary()
	return "candidate-tree-v1-" + hex.EncodeToString(b)
}
func candidateNameValid(name string) bool {
	const prefix = "candidate-tree-v1-"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	b, err := hex.DecodeString(name[len(prefix):])
	if err != nil {
		return false
	}
	id, err := derived.ParseTreePageID(b)
	return err == nil && candidateName(id) == name
}
func (s *Staging) openObject(ctx context.Context, id derived.TreePageID, action string) (*os.File, error) {
	if err := s.authorize(ctx, id, action); err != nil {
		return nil, err
	}
	if err := s.checkDirs(); err != nil {
		return nil, err
	}
	name := candidateName(id)
	before, err := s.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, storageError(err)
	}
	if !secure(before, 0400) {
		return nil, ErrCorruptData
	}
	f, err := openAt(s.root, name, os.O_RDONLY, 0)
	if err != nil {
		return nil, storageError(err)
	}
	after, err := f.Stat()
	if err != nil || !secure(after, 0400) || !os.SameFile(before, after) {
		_ = f.Close()
		return nil, errors.Join(ErrCorruptData, storageError(err))
	}
	return f, nil
}
func readFrame(ctx context.Context, r io.Reader) ([]byte, error) {
	b := make([]byte, derived.MaxTreePageBytes+1)
	n := 0
	empty := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		k, err := r.Read(b[n:])
		if k < 0 || k > len(b)-n {
			return nil, ErrCorruptData
		}
		n += k
		if n > derived.MaxTreePageBytes {
			return nil, ErrResourceExhausted
		}
		if err != nil && err != io.EOF {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err == io.EOF {
			return b[:n], nil
		}
		if k == 0 {
			empty++
			if empty == 100 {
				return nil, io.ErrNoProgress
			}
		} else {
			empty = 0
		}
	}
}
func (s *Staging) readObject(ctx context.Context, f *os.File, id derived.TreePageID) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, storageError(err)
	}
	if !secure(info, 0400) || info.Size() < 24 || info.Size() > derived.MaxTreePageBytes {
		return nil, ErrCorruptData
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, storageError(err)
	}
	b, err := readFrame(ctx, f)
	if err != nil {
		return nil, errors.Join(ErrCorruptData, err)
	}
	if _, err = derived.DecodeUnlinkedTreePage(b, id); err != nil {
		return nil, errors.Join(ErrCorruptData, err)
	}
	return b, nil
}

// GetCandidate returns owned bounded bytes only to trusted authorized consumers.
// Syntax/digest is checked; linked objects and path context remain UNVERIFIED.
func (s *Staging) GetCandidate(ctx context.Context, id derived.TreePageID) (value []byte, err error) {
	if id.Validate() != nil {
		return nil, ErrInvalidArgument
	}
	if err = s.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.release()
	f, err := s.openObject(ctx, id, ActionGetCandidate)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, storageError(f.Close()))
		if err != nil {
			value = nil
		}
	}()
	if value, err = s.readObject(ctx, f, id); err != nil {
		return nil, err
	}
	if err = s.checkDirs(); err != nil {
		return nil, err
	}
	err = s.authorize(ctx, id, ActionGetCandidate)
	return value, err
}

// Stage stores one syntax/digest-verified candidate. Readers must honor context
// deadlines. Quota reserves two maximum-size aliases BEFORE file creation. Short
// capacity mutexes never cover I/O. Unknown activation/cleanup retains conservative
// charges until reopen. Final entries are never rolled back or overwritten.
func (s *Staging) Stage(ctx context.Context, id derived.TreePageID, src io.Reader) (result CandidateID, err error) {
	if id.Validate() != nil || nilDependency(src) {
		return result, ErrInvalidArgument
	}
	if err = s.acquire(ctx); err != nil {
		return result, err
	}
	defer s.release()
	if err = s.authorize(ctx, id, ActionStage); err != nil {
		return result, err
	}
	if !s.addUsage(2*derived.MaxTreePageBytes, 2) {
		return result, ErrResourceExhausted
	}
	var keepBytes, keepCount uint64
	defer func() { s.subtractUsage(2*derived.MaxTreePageBytes-keepBytes, 2-keepCount) }()
	frame, err := readFrame(ctx, src)
	if err != nil {
		return result, errors.Join(ErrInvalidArgument, err)
	}
	if _, err = derived.DecodeUnlinkedTreePage(frame, id); err != nil {
		return result, errors.Join(ErrInvalidArgument, err)
	}
	if err = s.checkDirs(); err != nil {
		return result, err
	}
	var f *os.File
	var name string
	for i := 0; i < 16; i++ {
		var random [16]byte
		if _, err = rand.Read(random[:]); err != nil {
			return result, storageError(err)
		}
		name = hex.EncodeToString(random[:]) + ".tmp"
		f, err = openAt(s.staging, name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if !errors.Is(err, os.ErrExist) {
			break
		}
	}
	if err != nil {
		return result, storageError(err)
	}
	present, uncertain, committed := true, false, false
	defer func() {
		if f != nil {
			err = errors.Join(err, storageError(f.Close()))
		}
		cleanupOK := true
		if present {
			e := s.step("cleanup", func() error { return s.staging.Remove(name) })
			if e == nil {
				e = s.step("cleanupSync", s.stage.Sync)
			}
			cleanupOK = e == nil
			err = errors.Join(err, e)
		}
		if !cleanupOK || uncertain && !committed {
			keepBytes, keepCount = 2*derived.MaxTreePageBytes, 2
		}
		if err != nil {
			result = CandidateID{}
			if uncertain && !committed {
				err = errors.Join(ErrOutcomeUnknown, err)
			}
		}
	}()
	info, err := f.Stat()
	if err != nil || !secure(info, 0600) {
		return result, errors.Join(ErrUnavailable, storageError(err))
	}
	var n int
	err = s.step("write", func() error {
		var e error
		if s.ops.write != nil {
			n, e = s.ops.write(f, frame)
		} else {
			n, e = f.Write(frame)
		}
		return e
	})
	if err != nil {
		return result, err
	}
	if n != len(frame) {
		return result, io.ErrShortWrite
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = f.Chmod(0400); err != nil {
		return result, storageError(err)
	}
	if _, err = s.readObject(ctx, f, id); err != nil {
		return result, err
	}
	if err = s.step("fileSync", f.Sync); err != nil {
		return result, err
	}
	info, err = f.Stat()
	if err != nil {
		return result, storageError(err)
	}
	e := f.Close()
	f = nil
	if err = errors.Join(storageError(e), s.step("close", func() error { return nil })); err != nil {
		return result, err
	}
	if err = s.step("beforeLink", func() error { return nil }); err != nil {
		return result, err
	}
	if err = s.authorize(ctx, id, ActionStage); err != nil {
		return result, err
	}
	if err = s.checkDirs(); err != nil {
		return result, err
	}
	current, e := s.staging.Lstat(name)
	if e != nil || !secure(current, 0400) || !os.SameFile(info, current) {
		return result, errors.Join(ErrUnavailable, storageError(e))
	}
	if err = s.step("link", func() error { return nil }); err != nil {
		return result, err
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	err = s.root.Link(".staging/"+name, candidateName(id))
	reused := errors.Is(err, os.ErrExist)
	uncertain = !reused
	if err != nil && !reused {
		return result, storageError(err)
	}
	if !reused {
		keepBytes, keepCount = uint64(len(frame)), 1
	}
	if err = s.step("afterLink", func() error { return ctx.Err() }); err != nil {
		return result, err
	}
	existing, err := s.openObject(ctx, id, ActionStage)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, storageError(existing.Close())) }()
	actual, err := s.readObject(ctx, existing, id)
	if err != nil {
		return result, err
	}
	if !bytes.Equal(actual, frame) {
		return result, ErrCorruptData
	}
	uncertain = true
	if err = s.step("finalSync", existing.Sync); err != nil {
		return result, err
	}
	if err = s.step("directorySync", s.dir.Sync); err != nil {
		return result, err
	}
	if err = s.step("remove", func() error { return s.staging.Remove(name) }); err != nil {
		return result, err
	}
	present = false
	if err = s.step("stagingSync", s.stage.Sync); err != nil {
		return result, err
	}
	committed = true
	if err = s.checkDirs(); err != nil {
		return result, err
	}
	if err = s.authorize(ctx, id, ActionStage); err != nil {
		return result, err
	}
	return CandidateID{page: id}, nil
}
