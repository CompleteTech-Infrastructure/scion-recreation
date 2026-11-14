//go:build darwin || linux

package blob

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"syscall"

	"canopy.local/canopy/internal/model"
)

// Generation must be pinned by trusted configuration outside this root.
type Generation [32]byte

// IngestRecord is private at-ingest validation evidence, not a retention pin or grant.
// Its zero value is never successful. No payload delivery API accepts it.
type IngestRecord struct{ proof [32]byte }

// ReceiptAuthority is fixed by trusted constructor composition. It must check
// current principal/session/repository/purpose, including metadata visibility.
// Open uses a zero BlobID; Put and Lookup use the exact object ID.
type ReceiptAuthority interface {
	Authorize(context.Context, model.BlobID, string) error
}

const (
	ReceiptOpen   = "blobRecordOpen"
	ReceiptPut    = "blobRecordPut"
	ReceiptLookup = "blobRecordLookup"
)

type ReceiptOptions struct {
	Blob                                   Options
	MaxStoredBytes, MaxObjects, MaxRecords uint64
}

const recordSize = 8 + 32 + model.TypedIDSize + 8 + 6*8 + 32
const generationName = ".generation-v1"

// IngestStore exclusively owns the root lifecycle. The mutex covers accounting
// and lifecycle only; concurrent Put disk I/O is never serialized by it.
type IngestStore struct {
	mu                    sync.Mutex
	fs                    *Filesystem
	records               *os.Root
	recordDir             *os.File
	authority             ReceiptAuthority
	generation            Generation
	opts                  ReceiptOptions
	bytes, objects, count uint64
	active                int
	closed                bool
	before                func(string) error
}

func receiptNil(a ReceiptAuthority) bool {
	if a == nil {
		return true
	}
	v := reflect.ValueOf(a)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Interface, reflect.Chan, reflect.Slice:
		return v.IsNil()
	}
	return false
}
func (s *IngestStore) step(p string) error {
	if s.before != nil {
		return s.before(p)
	}
	return nil
}
func receiptRoot(path string) (*os.File, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if e != nil {
		return nil, diskError(e)
	}
	st, e := f.Stat()
	if e != nil || !secure(st, os.ModeDir|0700, true) {
		f.Close()
		return nil, errors.Join(ErrUnavailable, e)
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.Join(ErrBusy, e)
	}
	return f, nil
}

// InitializeIngestRoot is an offline operation on an already-created empty0700
// directory. Failure may leave a partial root; never bless it by rerunning init.
func InitializeIngestRoot(ctx context.Context, path string) (Generation, error) {
	return initializeIngestRoot(ctx, path, nil)
}
func initializeIngestRoot(ctx context.Context, path string, before func(string) error) (g Generation, err error) {
	if ctx == nil {
		return g, ErrInvalidArgument
	}
	if err = ctx.Err(); err != nil {
		return g, err
	}
	d, err := receiptRoot(path)
	if err != nil {
		return g, err
	}
	created := false
	defer func() {
		err = errors.Join(err, diskError(d.Close()))
		if err != nil {
			if created {
				err = errors.Join(ErrOutcomeUnknown, err)
			}
			g = Generation{}
		}
	}()
	entries, e := d.ReadDir(1)
	if e != io.EOF || len(entries) != 0 {
		return g, errors.Join(ErrInvalidArgument, e)
	}
	r, e := os.OpenRoot(path)
	if e != nil {
		return g, diskError(e)
	}
	defer func() { err = errors.Join(err, diskError(r.Close())) }()
	info, e := r.Lstat(".")
	actual, e2 := d.Stat()
	if e != nil || e2 != nil || !same(info, actual) {
		return g, errors.Join(ErrUnavailable, e, e2)
	}
	if _, err = rand.Read(g[:]); err != nil {
		return g, diskError(err)
	}
	f, err := openAt(r, generationName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return g, diskError(err)
	}
	created = true
	// Any error after creation leaves initialization outcome unknown, even a close failure.
	defer func() {
		err = errors.Join(err, diskError(f.Close()))
		if err != nil {
			err = errors.Join(ErrOutcomeUnknown, err)
		}
	}()
	step := func(p string) error {
		if before != nil {
			return before(p)
		}
		return nil
	}
	if _, err = f.Write(g[:]); err == nil {
		err = f.Chmod(0400)
	}
	if err == nil {
		err = step("generationSync")
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = step("generationDirectorySync")
	}
	if err == nil {
		err = d.Sync()
	}
	return g, diskError(err)
}
func OpenIngestStore(ctx context.Context, path string, pin Generation, o ReceiptOptions, a ReceiptAuthority) (*IngestStore, error) {
	return openIngestStore(ctx, path, pin, o, a, nil, diskOps{})
}
func openIngestStore(ctx context.Context, path string, pin Generation, o ReceiptOptions, a ReceiptAuthority, before func(string) error, ops diskOps) (_ *IngestStore, err error) {
	if ctx == nil || receiptNil(a) || pin == (Generation{}) || o.MaxStoredBytes > 1<<40 || o.MaxStoredBytes < 32 || o.MaxObjects == 0 || o.MaxObjects > 1<<32 || o.MaxRecords == 0 || o.MaxRecords > 1<<32 || o.Blob.MaxEncodedBytes > 1<<39 || o.Blob.MaxConcurrentOps > 1024 || o.Blob.RecoveryBatch > 1024 {
		return nil, ErrInvalidArgument
	}
	if err = a.Authorize(ctx, model.BlobID{}, ReceiptOpen); err != nil {
		return nil, err
	}
	owner, err := receiptRoot(path)
	if err != nil {
		return nil, err
	}
	s := &IngestStore{authority: a, generation: pin, opts: o, before: before, recordDir: owner}
	defer func() {
		if err != nil {
			s.closeFiles()
		}
	}()
	// Do not create or adopt a manifest during serving open.
	r, e := os.OpenRoot(path)
	if e != nil {
		return nil, diskError(e)
	}
	manifest, e := openAt(r, generationName, os.O_RDONLY, 0)
	if e != nil {
		r.Close()
		return nil, diskError(e)
	}
	st, e := manifest.Stat()
	var raw [33]byte
	n, re := io.ReadFull(manifest, raw[:])
	ce := manifest.Close()
	r.Close()
	if e != nil || ce != nil || !secure(st, 0400, false) || n != 32 || re != io.ErrUnexpectedEOF || !bytes.Equal(raw[:32], pin[:]) {
		return nil, errors.Join(ErrUnavailable, e, ce, re)
	}
	s.fs, err = openFilesystem(path, o.Blob, ops)
	if err != nil {
		return nil, err
	}
	// The locked descriptor and Filesystem must refer to exactly the same root.
	locked, e := owner.Stat()
	opened, e2 := s.fs.dir.Stat()
	if e != nil || e2 != nil || !same(locked, opened) {
		return nil, errors.Join(ErrUnavailable, e, e2)
	}
	if err = s.fs.root.Mkdir(".records-v1", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, diskError(err)
	}
	s.records, err = s.fs.root.OpenRoot(".records-v1")
	if err != nil {
		return nil, diskError(err)
	}
	info, e := s.records.Lstat(".")
	entry, ee := s.fs.root.Lstat(".records-v1")
	if e != nil || ee != nil || !same(info, entry) || !secure(info, os.ModeDir|0700, true) {
		return nil, errors.Join(ErrUnavailable, e)
	}
	// Scan before recovery: even orphan bytes count. Batches bound enumeration memory.
	for _, dir := range []string{".", ".staging", ".records-v1"} {
		if err = s.scan(ctx, dir); err != nil {
			return nil, err
		}
	}
	for {
		done, e := s.fs.RecoverTemps(ctx)
		if e != nil {
			return nil, e
		}
		if done {
			break
		}
	}
	if err = s.fs.dir.Sync(); err != nil {
		return nil, diskError(err)
	}
	if err = a.Authorize(ctx, model.BlobID{}, ReceiptOpen); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return s, nil
}

// finalBlobName accepts only the exact lowercase kind01 writer namespace.
func finalBlobName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, prefix)
	if len(suffix) != 2*model.TypedIDSize {
		return false
	}
	raw, e := hex.DecodeString(suffix)
	if e != nil || hex.EncodeToString(raw) != suffix {
		return false
	}
	id, e := model.ParseTypedID(raw)
	return e == nil && id.Kind() == model.BlobKind
}
func (s *IngestStore) scan(ctx context.Context, dir string) error {
	f, e := openAt(s.fs.root, dir, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if e != nil {
		return diskError(e)
	}
	defer f.Close()
	for {
		xs, e := f.ReadDir(s.opts.Blob.RecoveryBatch)
		if e != nil && e != io.EOF {
			return diskError(e)
		}
		for _, x := range xs {
			if e := ctx.Err(); e != nil {
				return e
			}
			name := x.Name()
			if dir == "." && (name == ".staging" || name == ".records-v1") {
				continue
			}
			info, e := s.fs.root.Lstat(dir + "/" + name)
			if e != nil {
				return diskError(e)
			}
			temporary := false
			switch dir {
			case ".":
				if name != generationName {
					if !finalBlobName(name, "blob-v1-") {
						return ErrCorruptData
					}
					s.objects++
				}
			case ".staging":
				if !tempName(name) {
					return ErrCorruptData
				}
				temporary = true
				s.objects++
			case ".records-v1":
				temporary = tempName(name)
				if !temporary && !finalBlobName(name, "record-") {
					return ErrCorruptData
				}
				s.count++
			}
			if !secure(info, 0400, false) && !(temporary && secure(info, 0600, false)) {
				return ErrCorruptData
			}
			if info.Size() < 0 || uint64(info.Size()) > s.opts.MaxStoredBytes-s.bytes {
				return ErrResourceExhausted
			}
			s.bytes += uint64(info.Size())
			if s.bytes > s.opts.MaxStoredBytes || s.objects > s.opts.MaxObjects || s.count > s.opts.MaxRecords {
				return ErrResourceExhausted
			}
		}
		if e == io.EOF {
			return nil
		}
	}
}
func (s *IngestStore) closeFiles() error {
	var e error
	if s.records != nil {
		e = errors.Join(e, s.records.Close())
	}
	if s.fs != nil {
		e = errors.Join(e, s.fs.Close())
	}
	if s.recordDir != nil {
		e = errors.Join(e, s.recordDir.Close())
	}
	return diskError(e)
}
func (s *IngestStore) Close() error {
	if s == nil {
		return ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.active != 0 {
		return ErrBusy
	}
	s.closed = true
	return s.closeFiles()
}
func (s *IngestStore) begin(ctx context.Context, id model.BlobID, action string) error {
	if s == nil || ctx == nil || id.Validate() != nil {
		return ErrInvalidArgument
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := s.authority.Authorize(ctx, id, action); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.active >= s.opts.Blob.MaxConcurrentOps {
		return ErrBusy
	}
	s.active++
	return nil
}
func (s *IngestStore) end() { s.mu.Lock(); s.active--; s.mu.Unlock() }
func (s *IngestStore) check(ctx context.Context, id model.BlobID, action string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := s.fs.checkDirs(); e != nil {
		return e
	}
	f, e := openAt(s.fs.root, generationName, os.O_RDONLY, 0)
	if e != nil {
		return diskError(e)
	}
	st, e := f.Stat()
	var b [33]byte
	n, re := io.ReadFull(f, b[:])
	ce := f.Close()
	if e != nil || ce != nil || !secure(st, 0400, false) || n != 32 || re != io.ErrUnexpectedEOF || !bytes.Equal(b[:32], s.generation[:]) {
		return errors.Join(ErrUnavailable, e, ce, re)
	}
	a, e := s.records.Lstat(".")
	binfo, e2 := s.fs.root.Lstat(".records-v1")
	if e != nil || e2 != nil || !secure(a, os.ModeDir|0700, true) || !same(a, binfo) {
		return errors.Join(ErrUnavailable, e, e2)
	}
	return s.authority.Authorize(ctx, id, action)
}
func recordName(id model.BlobID) string {
	return "record-" + strings.TrimPrefix(blobName(id), "blob-v1-")
}

// fileIdentity includes ctime, so replacement or rewriting/restoring mtime fails.
// Stat is only a cheap identity check; it is not fresh bitrot verification.
func fileIdentity(info os.FileInfo) ([]byte, error) {
	if !secure(info, 0400, false) {
		return nil, ErrCorruptData
	}
	st := info.Sys().(*syscall.Stat_t)
	v := reflect.ValueOf(st).Elem()
	ct := v.FieldByName("Ctim")
	if !ct.IsValid() {
		ct = v.FieldByName("Ctimespec")
	}
	if !ct.IsValid() {
		return nil, ErrUnavailable
	}
	b := make([]byte, 48)
	for i, x := range []uint64{uint64(st.Dev), uint64(st.Ino), uint64(info.Size()), uint64(info.ModTime().UnixNano()), uint64(ct.FieldByName("Sec").Int()), uint64(ct.FieldByName("Nsec").Int())} {
		binary.BigEndian.PutUint64(b[i*8:], x)
	}
	return b, nil
}
func (s *IngestStore) encode(id model.BlobID, n uint64) ([]byte, error) {
	f, e := s.fs.openFinal(blobName(id))
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	ce := f.Close()
	if e != nil || ce != nil {
		return nil, diskError(errors.Join(e, ce))
	}
	ident, e := fileIdentity(info)
	if e != nil {
		return nil, e
	}
	typed, _ := id.TypedID().MarshalBinary()
	b := make([]byte, 0, recordSize)
	b = append(b, []byte("BREC0001")...)
	b = append(b, s.generation[:]...)
	b = append(b, typed...)
	b = binary.BigEndian.AppendUint64(b, n)
	b = append(b, ident...)
	sum := sha256.Sum256(b)
	return append(b, sum[:]...), nil
}
func (s *IngestStore) read(id model.BlobID) (IngestRecord, []byte, error) {
	var zero IngestRecord
	f, e := openAt(s.records, recordName(id), os.O_RDONLY, 0)
	if errors.Is(e, os.ErrNotExist) {
		return zero, nil, ErrNotFound
	}
	if e != nil {
		return zero, nil, diskError(e)
	}
	info, e := f.Stat()
	b := make([]byte, recordSize+1)
	n, re := io.ReadFull(f, b)
	ce := f.Close()
	if e != nil || ce != nil || !secure(info, 0400, false) || n != recordSize || re != io.ErrUnexpectedEOF {
		return zero, nil, errors.Join(ErrCorruptData, e, ce, re)
	}
	b = b[:n]
	sum := sha256.Sum256(b[:n-32])
	if !bytes.Equal(sum[:], b[n-32:]) {
		return zero, nil, ErrCorruptData
	}
	length := binary.BigEndian.Uint64(b[40+model.TypedIDSize:])
	if length < 22 || length-22 > s.opts.Blob.MaxPayload {
		return zero, nil, ErrCorruptData
	}
	expected, e := s.encode(id, length)
	if e != nil {
		return zero, nil, e
	}
	if !bytes.Equal(b, expected) {
		return zero, nil, ErrCorruptData
	}
	return IngestRecord{proof: sum}, b, nil
}

// Lookup performs bounded metadata I/O and never falls back to whole-blob hashing.
func (s *IngestStore) Lookup(ctx context.Context, id model.BlobID) (r IngestRecord, err error) {
	if err = s.begin(ctx, id, ReceiptLookup); err != nil {
		return r, err
	}
	defer s.end()
	if err = s.check(ctx, id, ReceiptLookup); err != nil {
		return r, err
	}
	r, _, err = s.read(id)
	if err == nil {
		// Complete barriers even when an earlier record activation was uncertain.
		f, e := openAt(s.records, recordName(id), os.O_RDONLY, 0)
		if e == nil {
			e = f.Sync()
			e = errors.Join(e, f.Close())
		}
		d, de := openAt(s.records, ".", os.O_RDONLY|syscall.O_DIRECTORY, 0)
		if de == nil {
			de = d.Sync()
			de = errors.Join(de, d.Close())
		}
		if e != nil || de != nil {
			err = errors.Join(ErrOutcomeUnknown, diskError(errors.Join(e, de)))
		}
	}
	if err == nil {
		err = s.check(ctx, id, ReceiptLookup)
	}
	if err != nil {
		r = IngestRecord{}
	}
	return
}

// Put validates through Filesystem.Put, then durably activates private metadata.
// Admission conservatively charges two encoded aliases and two record aliases;
// charges remain until reopen, including failed/uncertain operations and reuse.
func (s *IngestStore) Put(ctx context.Context, id model.BlobID, payload uint64, frame io.Reader) (r IngestRecord, err error) {
	if frame == nil {
		return r, ErrInvalidArgument
	}
	if err = s.begin(ctx, id, ReceiptPut); err != nil {
		return r, err
	}
	defer s.end()
	if err = s.check(ctx, id, ReceiptPut); err != nil {
		return r, err
	}
	s.mu.Lock()
	cost := 2*s.opts.Blob.MaxEncodedBytes + 2*recordSize
	if cost > s.opts.MaxStoredBytes-s.bytes || s.opts.MaxObjects-s.objects < 2 || s.opts.MaxRecords-s.count < 2 {
		s.mu.Unlock()
		return r, ErrResourceExhausted
	}
	s.bytes += cost
	s.objects += 2
	s.count += 2
	s.mu.Unlock()
	if _, err = s.fs.Put(ctx, id, payload, frame); err != nil {
		return r, err
	}
	// A successful blob alone never authorizes a nonzero record.
	data, err := s.encode(id, payload+22)
	if err != nil {
		return r, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return r, diskError(err)
	}
	name := hex.EncodeToString(nonce[:]) + ".tmp"
	f, err := openAt(s.records, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return r, diskError(err)
	}
	present := true
	defer func() {
		e := f.Close()
		if present {
			if x := s.step("recordCleanup"); x != nil {
				e = errors.Join(e, x)
			} else {
				e = errors.Join(e, s.records.Remove(name))
			}
		}
		d, de := openAt(s.records, ".", os.O_RDONLY|syscall.O_DIRECTORY, 0)
		if de == nil {
			e = errors.Join(e, d.Sync(), d.Close())
		} else {
			e = errors.Join(e, de)
		}
		err = errors.Join(err, diskError(e))
		if err != nil {
			r = IngestRecord{}
			err = errors.Join(ErrOutcomeUnknown, err)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return r, diskError(err)
	}
	if err = f.Chmod(0400); err != nil {
		return r, diskError(err)
	}
	if err = s.step("recordSync"); err == nil {
		err = f.Sync()
	}
	if err != nil {
		return r, diskError(err)
	}
	if err = s.check(ctx, id, ReceiptPut); err != nil {
		return r, err
	}
	if err = s.step("recordLink"); err == nil {
		err = s.records.Link(name, recordName(id))
	}
	if err != nil && !errors.Is(err, os.ErrExist) {
		return r, diskError(err)
	}
	if err = s.step("recordAfterLink"); err != nil {
		return r, diskError(err)
	}
	// EEXIST must pass the same proof and durability barriers, never mask unknown.
	_, existing, err := s.read(id)
	if err != nil {
		return r, err
	}
	if !bytes.Equal(existing, data) {
		return r, ErrCorruptData
	}
	final, err := openAt(s.records, recordName(id), os.O_RDONLY, 0)
	if err != nil {
		return r, diskError(err)
	}
	err = s.step("recordFinalSync")
	if err == nil {
		err = final.Sync()
	}
	err = errors.Join(err, final.Close())
	if err != nil {
		return r, diskError(err)
	}
	if err = s.step("recordCleanup"); err == nil {
		err = s.records.Remove(name)
	}
	if err != nil {
		return r, diskError(err)
	}
	present = false
	d, err := openAt(s.records, ".", os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return r, diskError(err)
	}
	err = s.step("recordDirectorySync")
	if err == nil {
		err = d.Sync()
	}
	err = errors.Join(err, d.Close())
	if err != nil {
		return r, diskError(err)
	}
	if err = s.check(ctx, id, ReceiptPut); err != nil {
		return r, err
	}
	r, _, err = s.read(id)
	return r, err
}
