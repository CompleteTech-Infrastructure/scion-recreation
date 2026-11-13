//go:build darwin || linux

package objects

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"

	"canopy.local/canopy/internal/model"
)

// Fixture seed CHANGESET-STORE-264-v1. Real files; injected errno is not capacity proof.
type testAuthority func(context.Context, model.ChangesetID, string) error

func (a testAuthority) Authorize(ctx context.Context, id model.ChangesetID, action string) error {
	return a(ctx, id, action)
}

var allow = testAuthority(func(context.Context, model.ChangesetID, string) error { return nil })

func storeOptions() Options {
	return Options{MaxPayload: 1 << 20, MaxConcurrentOps: 2, RecoveryBatch: 2}
}

func storeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func changesetFixture(t *testing.T, message string) (model.ChangesetID, []byte) {
	t.Helper()
	v, err := model.NewChangeset(model.ChangesetInput{Message: []byte(message)})
	if err != nil {
		t.Fatal(err)
	}
	id, err := model.HashChangeset(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := model.EncodeChangeset(context.Background(), &b, v); err != nil {
		t.Fatal(err)
	}
	return id, b.Bytes()
}

func objectPath(root string, id model.ChangesetID) string {
	b, _ := id.TypedID().MarshalBinary()
	return filepath.Join(root, "changeset-v1-"+hex.EncodeToString(b))
}

func readyStore(t *testing.T, root string, auth Authority, ops diskOps) *Changesets {
	t.Helper()
	s, err := openChangesets(root, storeOptions(), auth, ops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for i := 0; i < 100; i++ {
		done, err := s.RecoverTemps(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if done {
			return s
		}
	}
	t.Fatal("recovery did not terminate")
	return nil
}

func putFrame(t *testing.T, s *Changesets, id model.ChangesetID, frame []byte) PutResult {
	t.Helper()
	r, err := s.Put(context.Background(), id, bytes.NewReader(frame))
	if err != nil || r.ID != id {
		t.Fatalf("put: %+v %v", r, err)
	}
	return r
}

func requireStoreError(t *testing.T, r PutResult, err, want error) {
	t.Helper()
	if r != (PutResult{}) || !errors.Is(err, want) {
		t.Fatalf("result=%+v error=%v want=%v", r, err, want)
	}
}

func TestChangesetRoundTripReuseConcurrent(t *testing.T) {
	root := storeRoot(t)
	s := readyStore(t, root, allow, diskOps{})
	id, frame := changesetFixture(t, "CHANGESET-STORE-264-v1\x00\xff")
	var wg sync.WaitGroup
	results := make(chan PutResult, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			r, err := s.Put(context.Background(), id, bytes.NewReader(frame))
			results <- r
			errs <- err
		})
	}
	wg.Wait()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if a, b := <-results, <-results; a.Reused == b.Reused {
		t.Fatal("expected exactly one initial creation")
	}
	before, err := os.Stat(objectPath(root, id))
	if err != nil || before.Mode().Perm() != 0400 {
		t.Fatal("final permissions", err)
	}
	if !putFrame(t, s, id, frame).Reused {
		t.Fatal("expected reuse")
	}
	after, _ := os.Stat(objectPath(root, id))
	if !os.SameFile(before, after) {
		t.Fatal("replaced existing inode")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = readyStore(t, root, allow, diskOps{})
	v, err := s.Get(context.Background(), id)
	var b bytes.Buffer
	if err != nil || model.EncodeChangeset(context.Background(), &b, v) != nil || !bytes.Equal(frame, b.Bytes()) {
		t.Fatal("reopen exact canonical value", err)
	}
	raw, err := os.ReadFile(objectPath(root, id))
	if err != nil || !bytes.Equal(raw, frame) {
		t.Fatal("stored canonical bytes", err)
	}
}

type noProgressSource struct{}

func (noProgressSource) Read([]byte) (int, error) { return 0, nil }

func TestChangesetRejectCanonical(t *testing.T) {
	root := storeRoot(t)
	s := readyStore(t, root, allow, diskOps{})
	id, frame := changesetFixture(t, "malformed")
	other, _ := changesetFixture(t, "other")
	for _, name := range []string{"truncated", "trailing", "version", "kind", "digest", "size", "noProgress"} {
		t.Run(name, func(t *testing.T) {
			data := bytes.Clone(frame)
			expected := id
			switch name {
			case "truncated":
				data = data[:len(data)-1]
			case "trailing":
				data = append(data, 0)
			case "version":
				data[12] = 2
			case "kind":
				data[13] = byte(model.BlobKind)
			case "digest":
				expected = other
			case "size":
				binary.BigEndian.PutUint64(data[14:22], 1<<20+1)
			}
			var src io.Reader = bytes.NewReader(data)
			if name == "noProgress" {
				src = noProgressSource{}
			}
			r, err := s.Put(context.Background(), expected, src)
			if r != (PutResult{}) || err == nil {
				t.Fatalf("accepted malformed input: %+v %v", r, err)
			}
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatal("input classification", err)
			}
			if _, err := os.Stat(objectPath(root, expected)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("activated rejected input", err)
			}
		})
	}
}

func TestChangesetExistingCorruption(t *testing.T) {
	id, frame := changesetFixture(t, "corruption")
	for _, name := range []string{"digest", "truncated", "trailing", "mode", "symlink", "directory"} {
		t.Run(name, func(t *testing.T) {
			root := storeRoot(t)
			s := readyStore(t, root, allow, diskOps{})
			path := objectPath(root, id)
			data := bytes.Clone(frame)
			switch name {
			case "digest":
				data[len(data)-1] ^= 1
			case "truncated":
				data = data[:len(data)-1]
			case "trailing":
				data = append(data, 0)
			}
			var err error
			switch name {
			case "symlink":
				err = os.Symlink(filepath.Join(storeRoot(t), "absent"), path)
			case "directory":
				err = os.Mkdir(path, 0700)
			default:
				mode := os.FileMode(0400)
				if name == "mode" {
					mode = 0600
				}
				err = os.WriteFile(path, data, mode)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, _ := os.Lstat(path)
			r, err := s.Put(context.Background(), id, bytes.NewReader(frame))
			requireStoreError(t, r, err, ErrCorruptData)
			v, err := s.Get(context.Background(), id)
			if !errors.Is(err, ErrCorruptData) || !reflect.DeepEqual(v, model.Changeset{}) {
				t.Fatal("corrupt delivery", err)
			}
			after, _ := os.Lstat(path)
			if !os.SameFile(before, after) {
				t.Fatal("corrupt destination replaced")
			}
		})
	}
}

// Every boundary runs on a real filesystem. ENOSPC/EDQUOT are injected results,
// not evidence of physical fullness, power loss, or remote durability.
func TestChangesetFaultBoundaries(t *testing.T) {
	points := []string{"write", "partial", "fileSync", "close", "beforeLink", "link", "afterLink", "finalSync", "directorySync", "remove", "stagingSync", "cleanup", "cleanupSync"}
	for _, cause := range []syscall.Errno{syscall.EIO, syscall.ENOSPC, syscall.EDQUOT} {
		for _, point := range points {
			t.Run(cause.Error()+"/"+point, func(t *testing.T) {
				root := storeRoot(t)
				reached := false
				ops := diskOps{before: func(p string) error {
					if p == point {
						reached = true
						return cause
					}
					return nil
				}}
				if point == "partial" || point == "cleanup" || point == "cleanupSync" {
					ops.write = func(f *os.File, p []byte) (int, error) {
						n, err := f.Write(p[:len(p)/2])
						if err != nil {
							return n, err
						}
						if point == "partial" {
							reached = true
						}
						return n, cause
					}
				}
				s := readyStore(t, root, allow, ops)
				id, frame := changesetFixture(t, "fault boundaries")
				r, err := s.Put(context.Background(), id, bytes.NewReader(frame))
				if !reached || !errors.Is(err, cause) || r != (PutResult{}) {
					t.Fatalf("boundary reached=%v result=%+v error=%v", reached, r, err)
				}
				if cause != syscall.EIO && !errors.Is(err, ErrResourceExhausted) {
					t.Fatal("capacity classification", err)
				}
				activated := point == "afterLink" || point == "finalSync" || point == "directorySync" || point == "remove" || point == "stagingSync"
				if activated && !errors.Is(err, ErrOutcomeUnknown) {
					t.Fatal("uncertain activation reported without ErrOutcomeUnknown", err)
				}
				_, statErr := os.Stat(objectPath(root, id))
				if activated && statErr != nil || !activated && !errors.Is(statErr, os.ErrNotExist) {
					t.Fatal("activation state", statErr)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				s = readyStore(t, root, allow, diskOps{})
				if activated && !putFrame(t, s, id, frame).Reused {
					t.Fatal("retry failed to reuse uncertain activation")
				}
			})
		}
	}
}

func TestChangesetAuthority(t *testing.T) {
	id, frame := changesetFixture(t, "authority")
	var typedNil testAuthority
	for _, a := range []Authority{nil, typedNil} {
		s, err := OpenChangesets(storeRoot(t), storeOptions(), a)
		if s != nil || !errors.Is(err, ErrInvalidArgument) {
			t.Fatal("accepted missing authority", err)
		}
	}
	for _, action := range []string{ActionPut, ActionGet} {
		for _, denyAt := range []int{1, 4} {
			root := storeRoot(t)
			seed := readyStore(t, root, allow, diskOps{})
			putFrame(t, seed, id, frame)
			if err := seed.Close(); err != nil {
				t.Fatal(err)
			}
			calls := 0
			auth := testAuthority(func(_ context.Context, got model.ChangesetID, gotAction string) error {
				calls++
				if got != id || gotAction != action {
					t.Error("authority binding")
				}
				if calls == denyAt || action == ActionGet && denyAt == 4 && calls == 2 {
					return errors.New("secret-provider-detail")
				}
				return nil
			})
			s := readyStore(t, root, auth, diskOps{})
			if denyAt == 1 {
				if err := os.Remove(objectPath(root, id)); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(objectPath(root, id), 0700); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			if action == ActionPut {
				var r PutResult
				r, err = s.Put(context.Background(), id, bytes.NewReader(frame))
				requireStoreError(t, r, err, ErrPermissionDenied)
			} else {
				var v model.Changeset
				v, err = s.Get(context.Background(), id)
				if !reflect.DeepEqual(v, model.Changeset{}) {
					t.Fatal("value escaped denial")
				}
			}
			wantCalls := denyAt
			if action == ActionGet && denyAt == 4 {
				wantCalls = 2
			}
			if err == nil || err.Error() != ErrPermissionDenied.Error() || calls != wantCalls {
				t.Fatal("unredacted or missing authority", err, calls)
			}
		}
	}
}

// A reached process exit probes ordering/reopen; it does not simulate power loss.
func TestChangesetProcessCrash(t *testing.T) {
	if point := os.Getenv("SCION_CHANGESET_CRASH"); point != "" {
		root := os.Getenv("SCION_CHANGESET_ROOT")
		s := readyStore(t, root, allow, diskOps{before: func(p string) error {
			if p == point {
				os.Exit(82)
			}
			return nil
		}})
		id, frame := changesetFixture(t, "process-crash")
		putFrame(t, s, id, frame)
		t.Fatal("crash point not reached")
	}
	for _, point := range []string{"write", "fileSync", "beforeLink", "afterLink", "directorySync", "stagingSync"} {
		t.Run(point, func(t *testing.T) {
			root := storeRoot(t)
			cmd := exec.Command(os.Args[0], "-test.run=^TestChangesetProcessCrash$", "-test.v")
			cmd.Env = append(os.Environ(), "SCION_CHANGESET_CRASH="+point, "SCION_CHANGESET_ROOT="+root)
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 82 {
				t.Fatalf("crash child: %v %s", err, output)
			}
			s := readyStore(t, root, allow, diskOps{})
			id, frame := changesetFixture(t, "process-crash")
			activated := point == "afterLink" || point == "directorySync" || point == "stagingSync"
			if _, err := s.Get(context.Background(), id); activated && err != nil || !activated && !errors.Is(err, ErrNotFound) {
				t.Fatal("crash reopen", err)
			}
			if putFrame(t, s, id, frame).Reused != activated {
				t.Fatal("crash retry state")
			}
		})
	}
}
