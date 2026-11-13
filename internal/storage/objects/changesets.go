//go:build darwin || linux

// Package objects provides private kind-02 storage for trusted service composition.
// This primitive does not establish publication, parent validity or an IAM service.
package objects

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"

	"canopy.local/canopy/internal/model"
)

var (
	ErrInvalidArgument   = errors.New("invalid changeset store argument")
	ErrNotFound          = errors.New("changeset not found")
	ErrCorruptData       = errors.New("corrupt changeset data")
	ErrResourceExhausted = errors.New("changeset resource exhausted")
	ErrUnavailable       = errors.New("changeset storage unavailable")
	ErrOutcomeUnknown    = errors.New("changeset activation outcome unknown")
	ErrClosed            = errors.New("changeset store closed")
	ErrBusy              = errors.New("changeset store busy")
	ErrPermissionDenied  = errors.New("changeset access denied")
)

const (
	ActionPut = "put"
	ActionGet = "get"
)

// Authority is constructor-only trusted composition, never request input. It
// must bind authenticated identity/session, repository, ID, action and current
// policy. An ID alone is not permission. It must honor caller deadlines.
type Authority interface {
	Authorize(context.Context, model.ChangesetID, string) error
}

// Options bounds bytes/work per operation and admitted concurrent operations.
// Decode owns a bounded model value with additional bounded collection overhead;
// validation/re-encoding may temporarily retain several copies. No cache exists.
// MaxPayload is 1..64MiB; concurrency and recovery batches are each 1..1024.
type Options struct {
	MaxPayload       uint64
	MaxConcurrentOps int
	RecoveryBatch    int
}

type PutResult struct {
	ID     model.ChangesetID
	Reused bool
}

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

// OpenChangesets opens an existing private directory. RecoverTemps must complete
// before Put/Get. Construction inspects directories, never canonical objects.
func OpenChangesets(path string, opts Options, auth Authority) (*Changesets, error) {
	return openChangesets(path, opts, auth, diskOps{})
}

func openChangesets(path string, opts Options, auth Authority, ops diskOps) (*Changesets, error) {
	if path == "" || nilDependency(auth) || opts.MaxPayload == 0 || opts.MaxPayload > model.MaxChangesetPayload ||
		opts.MaxConcurrentOps < 1 || opts.MaxConcurrentOps > 1024 || opts.RecoveryBatch < 1 || opts.RecoveryBatch > 1024 {
		return nil, ErrInvalidArgument
	}
	return openRoots(path, opts, auth, ops)
}

func (s *Changesets) authorize(ctx context.Context, id model.ChangesetID, action string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := s.auth.Authorize(ctx, id, action)
	if cancel := ctx.Err(); cancel != nil {
		return cancel
	}
	if err != nil {
		return ErrPermissionDenied // Never disclose provider diagnostics or secrets.
	}
	return nil
}

func changesetName(id model.ChangesetID) string {
	b, _ := id.TypedID().MarshalBinary()
	return "changeset-v1-" + hex.EncodeToString(b)
}

func (s *Changesets) openObject(ctx context.Context, id model.ChangesetID, action string) (*os.File, error) {
	if err := s.authorize(ctx, id, action); err != nil {
		return nil, err
	}
	if err := s.checkDirs(); err != nil {
		return nil, err
	}
	name := changesetName(id)
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
	info, err := f.Stat()
	if err != nil || !secure(info, 0400) || !os.SameFile(before, info) {
		_ = f.Close()
		return nil, errors.Join(ErrCorruptData, storageError(err))
	}
	return f, nil
}

func (s *Changesets) decodeFile(ctx context.Context, f *os.File, id model.ChangesetID) (model.Changeset, error) {
	info, err := f.Stat()
	if err != nil {
		return model.Changeset{}, storageError(err)
	}
	if !secure(info, 0400) || info.Size() < 22 {
		return model.Changeset{}, ErrCorruptData
	}
	if uint64(info.Size()) > s.opts.MaxPayload+22 {
		return model.Changeset{}, ErrResourceExhausted
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return model.Changeset{}, storageError(err)
	}
	v, err := model.DecodeChangeset(ctx, f, id, s.opts.MaxPayload)
	if err != nil {
		if ctx.Err() != nil {
			return model.Changeset{}, ctx.Err()
		}
		return model.Changeset{}, errors.Join(ErrCorruptData, err)
	}
	return v, nil
}

// Get delivers only a fully verified immutable value, after a fresh authority
// check. No partial bytes/value escape on cancellation, denial or I/O failure.
func (s *Changesets) Get(ctx context.Context, id model.ChangesetID) (value model.Changeset, err error) {
	if id.Validate() != nil {
		return value, ErrInvalidArgument
	}
	if err = s.acquire(ctx); err != nil {
		return value, err
	}
	defer s.release()
	f, err := s.openObject(ctx, id, ActionGet)
	if err != nil {
		return value, err
	}
	defer func() {
		err = errors.Join(err, storageError(f.Close()))
		if err != nil {
			value = model.Changeset{}
		}
	}()
	if value, err = s.decodeFile(ctx, f, id); err != nil {
		return model.Changeset{}, err
	}
	if err = s.checkDirs(); err != nil {
		return model.Changeset{}, err
	}
	err = s.authorize(ctx, id, ActionGet)
	return value, err
}

type stagedWriter struct {
	s   *Changesets
	f   *os.File
	ctx context.Context
	n   uint64
}

func (w *stagedWriter) Write(p []byte) (n int, err error) {
	if uint64(len(p)) > w.s.opts.MaxPayload+22-w.n {
		return 0, ErrResourceExhausted
	}
	err = w.s.step("write", func() error {
		if w.s.ops.write != nil {
			n, err = w.s.ops.write(w.f, p)
		} else {
			n, err = w.f.Write(p)
		}
		return err
	})
	if n < 0 || n > len(p) {
		return 0, io.ErrShortWrite
	}
	w.n += uint64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if w.ctx.Err() != nil {
		err = w.ctx.Err()
	}
	return n, err
}

// exactWriter compares encoder output with existing canonical bytes, using at
// most 32KiB scratch per call. Digest equality alone never substitutes for this.
type exactWriter struct{ r io.Reader }

func (w exactWriter) Write(p []byte) (int, error) {
	var b [32 << 10]byte
	if len(p) > len(b) {
		return 0, ErrCorruptData
	}
	n, err := io.ReadFull(w.r, b[:len(p)])
	if err != nil || !bytes.Equal(p, b[:n]) {
		return 0, errors.Join(ErrCorruptData, err)
	}
	return len(p), nil
}

// Put validates/rehashes canonical kind-02 input; blocking readers must honor
// deadlines. Success requires file, final-directory and staging-directory sync.
// Failures return zero. After new activation (or verified reuse awaiting sync),
// an unconfirmed commit additionally returns ErrOutcomeUnknown. Final links are
// never rolled back; retries validate and compare rather than overwrite.
func (s *Changesets) Put(ctx context.Context, id model.ChangesetID, canonical io.Reader) (result PutResult, err error) {
	if id.Validate() != nil || nilDependency(canonical) {
		return result, ErrInvalidArgument
	}
	if err = s.acquire(ctx); err != nil {
		return result, err
	}
	defer s.release()
	if err = s.authorize(ctx, id, ActionPut); err != nil {
		return result, err
	}
	value, err := model.DecodeChangeset(ctx, canonical, id, s.opts.MaxPayload)
	if err != nil {
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
		if present {
			e := s.step("cleanup", func() error { return s.staging.Remove(name) })
			if e == nil {
				e = s.step("cleanupSync", s.stage.Sync)
			}
			err = errors.Join(err, e)
		}
		if err != nil {
			result = PutResult{}
			if uncertain && !committed {
				err = errors.Join(ErrOutcomeUnknown, err)
			}
		}
	}()
	info, err := f.Stat()
	if err != nil || !secure(info, 0600) {
		return result, errors.Join(ErrUnavailable, storageError(err))
	}
	if err = model.EncodeChangeset(ctx, &stagedWriter{s: s, f: f, ctx: ctx}, value); err != nil {
		return result, err
	}
	if err = f.Chmod(0400); err != nil {
		return result, storageError(err)
	}
	if _, err = s.decodeFile(ctx, f, id); err != nil {
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
	if err = s.authorize(ctx, id, ActionPut); err != nil {
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
	err = s.root.Link(".staging/"+name, changesetName(id))
	reused := errors.Is(err, os.ErrExist)
	uncertain = !reused // An actual link syscall error may leave an uncertain outcome.
	if err != nil && !reused {
		return result, storageError(err)
	}
	if err = s.step("afterLink", func() error { return ctx.Err() }); err != nil {
		return result, err
	}
	existing, err := s.openObject(ctx, id, ActionPut)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, storageError(existing.Close())) }()
	if _, err = s.decodeFile(ctx, existing, id); err != nil {
		return result, err
	}
	if _, err = existing.Seek(0, io.SeekStart); err != nil {
		return result, storageError(err)
	}
	if err = model.EncodeChangeset(ctx, exactWriter{existing}, value); err != nil {
		return result, err
	}
	var extra [1]byte
	if n, e := existing.Read(extra[:]); n != 0 || e != io.EOF {
		return result, errors.Join(ErrCorruptData, e)
	}
	uncertain = true // Reuse is not durability-confirmed until the same sync protocol.
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
	if err = s.authorize(ctx, id, ActionPut); err != nil {
		return result, err
	}
	return PutResult{ID: id, Reused: reused}, nil
}
