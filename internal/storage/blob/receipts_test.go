//go:build darwin || linux

package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"canopy.local/canopy/internal/model"
)

type receiptAuth struct {
	denied bool
	calls  int
	denyAt int
}

func (a *receiptAuth) Authorize(_ context.Context, _ model.BlobID, _ string) error {
	a.calls++
	if a.denied || a.calls == a.denyAt {
		return os.ErrPermission
	}
	return nil
}
func receiptOpts() ReceiptOptions {
	blob := options()
	blob.MaxPayload = 2 << 20
	blob.MaxEncodedBytes = 4 << 20
	return ReceiptOptions{Blob: blob, MaxStoredBytes: 128 << 20, MaxObjects: 64, MaxRecords: 64}
}
func receiptFixture(t *testing.T) (string, Generation, *receiptAuth) {
	t.Helper()
	root := privateDir(t)
	g, e := InitializeIngestRoot(context.Background(), root)
	if e != nil {
		t.Fatal(e)
	}
	return root, g, &receiptAuth{}
}
func receiptOpen(t *testing.T, root string, g Generation, o ReceiptOptions, a ReceiptAuthority, before func(string) error) *IngestStore {
	t.Helper()
	s, e := openIngestStore(context.Background(), root, g, o, a, before, diskOps{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := s.Close(); e != nil {
			t.Error(e)
		}
	})
	return s
}
func receiptPut(t *testing.T, s *IngestStore, p []byte) (model.BlobID, IngestRecord) {
	t.Helper()
	id, frame := fixture(t, p)
	r, e := s.Put(context.Background(), id, uint64(len(p)), bytes.NewReader(frame))
	if e != nil || r == (IngestRecord{}) {
		t.Fatalf("Put: %v %v", r, e)
	}
	return id, r
}

func TestIngestRecordLifecycle(t *testing.T) {
	root, g, a := receiptFixture(t)
	s := receiptOpen(t, root, g, receiptOpts(), a, nil)
	p := bytes.Repeat([]byte("receipt-fixture-304"), 100000)
	id, r := receiptPut(t, s, p)
	_, again := receiptPut(t, s, p)
	if again != r {
		t.Fatal("reuse identity")
	}
	requireError(t, s.Close(), nil)
	s = receiptOpen(t, root, g, receiptOpts(), a, nil)
	got, e := s.Lookup(context.Background(), id)
	if e != nil || got != r {
		t.Fatal("reopen", e)
	}
	if _, e = OpenIngestStore(context.Background(), root, g, receiptOpts(), a); !errors.Is(e, ErrBusy) {
		t.Fatal("ownership", e)
	}
	a.denied = true
	for _, x := range []model.BlobID{id, func() model.BlobID { x, _ := fixture(t, []byte("cold")); return x }()} {
		got, e = s.Lookup(context.Background(), x)
		if got != (IngestRecord{}) || !errors.Is(e, os.ErrPermission) {
			t.Fatal("denied existence", e)
		}
	}
	a.denied = false
}
func TestIngestRecordInitAndPin(t *testing.T) {
	root, g, a := receiptFixture(t)
	wrong := g
	wrong[0] ^= 1
	_, e := OpenIngestStore(context.Background(), root, wrong, receiptOpts(), a)
	requireError(t, e, ErrUnavailable)
	_, e = InitializeIngestRoot(context.Background(), root)
	requireError(t, e, ErrInvalidArgument)
	var typedNil *receiptAuth
	_, e = OpenIngestStore(context.Background(), root, g, receiptOpts(), typedNil)
	requireError(t, e, ErrInvalidArgument)
	a.denied = true
	_, e = OpenIngestStore(context.Background(), filepath.Join(root, "missing"), g, receiptOpts(), a)
	requireError(t, e, os.ErrPermission)
	for _, point := range []string{"generationSync", "generationDirectorySync"} {
		p := privateDir(t)
		sentinel := errors.New(point)
		got, e := initializeIngestRoot(context.Background(), p, func(x string) error {
			if x == point {
				return sentinel
			}
			return nil
		})
		if got != (Generation{}) {
			t.Fatal("failed init generation")
		}
		requireError(t, e, ErrOutcomeUnknown)
		requireError(t, e, sentinel)
	}
}
func TestIngestRecordRejectDamage(t *testing.T) {
	for _, damage := range []string{"record", "recordType", "recordGeneration", "missingRecord", "blob", "missingBlob", "substitution", "generation"} {
		t.Run(damage, func(t *testing.T) {
			root, g, a := receiptFixture(t)
			s := receiptOpen(t, root, g, receiptOpts(), a, nil)
			id, _ := receiptPut(t, s, []byte("damage"))
			path := filepath.Join(root, blobName(id))
			switch damage {
			case "recordType", "recordGeneration":
				path = filepath.Join(root, ".records-v1", recordName(id))
				b, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				if damage == "recordType" {
					b[42] ^= 1
				} else {
					b[8] ^= 1
				}
				sum := sha256.Sum256(b[:recordSize-32])
				copy(b[recordSize-32:], sum[:])
				os.Chmod(path, 0600)
				os.WriteFile(path, b, 0400)
				os.Chmod(path, 0400)
			case "record":
				path = filepath.Join(root, ".records-v1", recordName(id))
				os.Chmod(path, 0600)
				os.WriteFile(path, make([]byte, recordSize), 0400)
				os.Chmod(path, 0400)
			case "missingRecord":
				os.Remove(filepath.Join(root, ".records-v1", recordName(id)))
			case "missingBlob":
				os.Remove(path)
			case "blob":
				os.Chmod(path, 0600)
				os.WriteFile(path, []byte("corrupt"), 0400)
				os.Chmod(path, 0400)
			case "substitution":
				b, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				os.Rename(path, path+"-old")
				if e = os.WriteFile(path, b, 0400); e != nil {
					t.Fatal(e)
				}
			case "generation":
				path = filepath.Join(root, generationName)
				os.Chmod(path, 0600)
				os.WriteFile(path, make([]byte, 32), 0400)
				os.Chmod(path, 0400)
			}
			r, e := s.Lookup(context.Background(), id)
			if r != (IngestRecord{}) || e == nil {
				t.Fatal("accepted damaged proof", e)
			}
		})
	}
}
func TestIngestRecordFaultsAndCancellation(t *testing.T) {
	for _, point := range []string{"recordSync", "recordLink", "recordAfterLink", "recordFinalSync", "recordCleanup", "recordDirectorySync", "cancel"} {
		t.Run(point, func(t *testing.T) {
			root, g, a := receiptFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sentinel := errors.New(point)
			hook := func(x string) error {
				if x == point {
					return sentinel
				}
				if point == "cancel" && x == "recordAfterLink" {
					cancel()
				}
				return nil
			}
			s := receiptOpen(t, root, g, receiptOpts(), a, hook)
			id, frame := fixture(t, []byte("fault"))
			r, e := s.Put(ctx, id, 5, bytes.NewReader(frame))
			if r != (IngestRecord{}) {
				t.Fatal("failure record")
			}
			requireError(t, e, ErrOutcomeUnknown)
			if point == "cancel" {
				requireError(t, e, context.Canceled)
			} else {
				requireError(t, e, sentinel)
			}
			// Existing record reuse must encounter the same failed barrier.
			if point != "cancel" {
				r, e = s.Put(context.Background(), id, 5, bytes.NewReader(frame))
				if r != (IngestRecord{}) {
					t.Fatal("reuse masked uncertainty")
				}
				requireError(t, e, sentinel)
			}
			requireError(t, s.Close(), nil)
			s = receiptOpen(t, root, g, receiptOpts(), a, nil)
			// Recovery may expose only an independently barrier-completed proof or missing.
			r, e = s.Lookup(context.Background(), id)
			if e != nil && !errors.Is(e, ErrNotFound) {
				t.Fatal(e)
			}
			if e == nil && r == (IngestRecord{}) {
				t.Fatal("zero success")
			}
		})
	}
}
func TestIngestRecordQuotaRecovery(t *testing.T) {
	root, g, a := receiptFixture(t)
	o := receiptOpts()
	o.MaxObjects = 2
	o.MaxRecords = 2
	s := receiptOpen(t, root, g, o, a, nil)
	id, r := receiptPut(t, s, []byte("quota"))
	_, frame := fixture(t, []byte("quota"))
	got, e := s.Put(context.Background(), id, 5, bytes.NewReader(frame))
	if got != (IngestRecord{}) {
		t.Fatal("quota success")
	}
	requireError(t, e, ErrResourceExhausted)
	requireError(t, s.Close(), nil)
	s = receiptOpen(t, root, g, o, a, nil)
	got, e = s.Lookup(context.Background(), id)
	if e != nil || got != r {
		t.Fatal("recovered proof", e)
	}
	requireError(t, s.Close(), nil)
	// Both namespaces account orphan bytes/entries across process lifetimes.
	orphan := filepath.Join(root, ".records-v1", "00000000000000000000000000000000.tmp")
	if e = os.WriteFile(orphan, make([]byte, 100), 0600); e != nil {
		t.Fatal(e)
	}
	o.MaxRecords = 1
	_, e = OpenIngestStore(context.Background(), root, g, o, a)
	requireError(t, e, ErrResourceExhausted)
	o = receiptOpts()
	o.MaxStoredBytes = 33
	_, e = OpenIngestStore(context.Background(), root, g, o, a)
	requireError(t, e, ErrResourceExhausted)
}

// Authority in production must be concurrency safe; this fixture avoids mutable state.
type allowReceipts struct{}

func (allowReceipts) Authorize(context.Context, model.BlobID, string) error { return nil }
func TestIngestRecordConcurrentDiskIO(t *testing.T) {
	root, g, _ := receiptFixture(t)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	s := receiptOpen(t, root, g, receiptOpts(), allowReceipts{}, func(p string) error {
		if p == "recordSync" {
			entered <- struct{}{}
			<-release
		}
		return nil
	})
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		id, frame := fixture(t, []byte{byte(i)})
		wg.Add(1)
		go func() { defer wg.Done(); _, e := s.Put(context.Background(), id, 1, bytes.NewReader(frame)); errs <- e }()
	}
	<-entered
	<-entered
	requireError(t, s.Close(), ErrBusy)
	close(release)
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
}

func TestIngestRecordFinalAuthorization(t *testing.T) {
	root, g, a := receiptFixture(t)
	s := receiptOpen(t, root, g, receiptOpts(), a, nil)
	id, _ := receiptPut(t, s, []byte("policy"))
	a.denyAt = a.calls + 3
	r, e := s.Lookup(context.Background(), id)
	if r != (IngestRecord{}) {
		t.Fatal("revoked lookup")
	}
	requireError(t, e, os.ErrPermission)
	a.denyAt = a.calls + 4
	_, frame := fixture(t, []byte("policy"))
	r, e = s.Put(context.Background(), id, 6, bytes.NewReader(frame))
	if r != (IngestRecord{}) {
		t.Fatal("revoked put")
	}
	requireError(t, e, os.ErrPermission)
}
func TestIngestRecordBlobFailureCannotMint(t *testing.T) {
	root, g, a := receiptFixture(t)
	sentinel := errors.New("blob final sync")
	s, e := openIngestStore(context.Background(), root, g, receiptOpts(), a, nil, diskOps{before: func(p string) error {
		if p == "finalSync" {
			return sentinel
		}
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	id, frame := fixture(t, []byte("failure"))
	r, e := s.Put(context.Background(), id, 7, bytes.NewReader(frame))
	if r != (IngestRecord{}) {
		t.Fatal("blob failure minted record")
	}
	requireError(t, e, ErrOutcomeUnknown)
	requireError(t, e, sentinel)
	_, e = s.Lookup(context.Background(), id)
	requireError(t, e, ErrNotFound)
}
