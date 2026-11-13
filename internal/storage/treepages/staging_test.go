//go:build darwin || linux

package treepages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"canopy.local/canopy/internal/derived"
)

// Seed TREE-STAGING-279-v1; private candidates prove no graph/retention receipt.
func treeFixture(t *testing.T, linked bool) (derived.TreePageID, []byte) {
	t.Helper()
	page := derived.UnlinkedTreePage{}
	if linked {
		raw := append([]byte("CTP\x00\x00\x01\x01"), bytes.Repeat([]byte{42}, 32)...)
		id, err := derived.ParseTreePageID(raw)
		if err != nil {
			t.Fatal(err)
		}
		page.Label, page.Tag, page.Directory = []byte("x"), 4, id
	}
	frame, id, err := derived.EncodeTreePageAt(page, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return id, frame
}

func privateRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func frameID(t *testing.T, frame []byte) derived.TreePageID {
	t.Helper()
	d := sha256.Sum256(frame)
	id, err := derived.ParseTreePageID(append([]byte("CTP\x00\x00\x01\x01"), d[:]...))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type authFunc func(context.Context, derived.TreePageID, string) error

func (f authFunc) Authorize(ctx context.Context, id derived.TreePageID, a string) error {
	return f(ctx, id, a)
}

var allow = authFunc(func(context.Context, derived.TreePageID, string) error { return nil })

func opts() Options {
	return Options{MaxStoredBytes: 8 * derived.MaxTreePageBytes, MaxCandidates: 8, MaxConcurrentOps: 2, RecoveryBatch: 2}
}
func pathFor(root string, id derived.TreePageID) string {
	b, _ := id.MarshalBinary()
	return filepath.Join(root, "candidate-tree-v1-"+hex.EncodeToString(b))
}
func ready(t *testing.T, root string, o Options, a Authority, ops diskOps) *Staging {
	t.Helper()
	s, err := openStaging(root, o, a, ops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for range 100 {
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
func stage(t *testing.T, s *Staging, id derived.TreePageID, b []byte) CandidateID {
	t.Helper()
	r, err := s.Stage(context.Background(), id, bytes.NewReader(b))
	if err != nil || r.PageID() != id {
		t.Fatalf("stage: %+v %v", r, err)
	}
	return r
}
func failed(t *testing.T, r CandidateID, err, want error) {
	t.Helper()
	if r != (CandidateID{}) || !errors.Is(err, want) {
		t.Fatalf("result=%+v error=%v want=%v", r, err, want)
	}
}

func TestStagingRoundTripConcurrent(t *testing.T) {
	for _, linked := range []bool{false, true} {
		root := privateRoot(t)
		s := ready(t, root, opts(), allow, diskOps{})
		id, b := treeFixture(t, linked)
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for range 2 {
			wg.Go(func() { _, err := s.Stage(context.Background(), id, bytes.NewReader(b)); errs <- err })
		}
		wg.Wait()
		for range 2 {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
		before, err := os.Stat(pathFor(root, id))
		if err != nil || before.Mode().Perm() != 0400 || before.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			t.Fatal("private final", err)
		}
		stage(t, s, id, b)
		after, _ := os.Stat(pathFor(root, id))
		if !os.SameFile(before, after) {
			t.Fatal("reuse replaced inode")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s = ready(t, root, opts(), allow, diskOps{})
		got, err := s.GetCandidate(context.Background(), id)
		if err != nil || !bytes.Equal(got, b) {
			t.Fatal("reopen exact frame", err)
		}
		got[0] ^= 1
		again, err := s.GetCandidate(context.Background(), id)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatal("returned shared bytes", err)
		}
		xs, err := os.ReadDir(root)
		if err != nil || len(xs) != 2 {
			t.Fatal("candidate-only namespace", err)
		}
	}
}

type sourceFunc func([]byte) (int, error)

func (f sourceFunc) Read(p []byte) (int, error) { return f(p) }
func TestStagingInput(t *testing.T) {
	s := ready(t, privateRoot(t), opts(), allow, diskOps{})
	id, frame := treeFixture(t, false)
	for _, name := range []string{"truncated", "trailing", "kind", "version", "size", "syntax", "digest", "nil", "typedNil", "noProgress", "readError"} {
		t.Run(name, func(t *testing.T) {
			b, expected := bytes.Clone(frame), id
			switch name {
			case "truncated":
				b = b[:len(b)-1]
			case "trailing":
				b = append(b, 0)
			case "kind":
				b[14] = 2
			case "version":
				b[13] = 2
			case "size":
				b = make([]byte, derived.MaxTreePageBytes+1)
			case "syntax":
				binary.BigEndian.PutUint16(b[19:21], 256)
				expected = frameID(t, b)
			case "digest":
				expected, _ = treeFixture(t, true)
			}
			var src io.Reader = bytes.NewReader(b)
			switch name {
			case "nil":
				src = nil
			case "typedNil":
				var typed *bytes.Reader
				src = typed
			case "noProgress":
				src = sourceFunc(func([]byte) (int, error) { return 0, nil })
			case "readError":
				src = sourceFunc(func(p []byte) (int, error) { return copy(p, b), syscall.EIO })
			}
			r, err := s.Stage(context.Background(), expected, src)
			if err == nil || r != (CandidateID{}) {
				t.Fatal("accepted malformed input", err)
			}
		})
	}
	stage(t, s, id, frame)
}

func TestStagingCorruptOccupied(t *testing.T) {
	id, frame := treeFixture(t, false)
	for _, name := range []string{"digest", "trailing", "mode", "symlink", "directory"} {
		root := privateRoot(t)
		s := ready(t, root, opts(), allow, diskOps{})
		path, b := pathFor(root, id), bytes.Clone(frame)
		switch name {
		case "digest":
			b[len(b)-1] ^= 1
		case "trailing":
			b = append(b, 0)
		}
		var err error
		switch name {
		case "symlink":
			err = os.Symlink(filepath.Join(privateRoot(t), "absent"), path)
		case "directory":
			err = os.Mkdir(path, 0700)
		default:
			err = os.WriteFile(path, b, 0400)
		}
		if name == "mode" {
			err = os.Chmod(path, 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
		before, _ := os.Lstat(path)
		original, _ := os.ReadFile(path)
		r, err := s.Stage(context.Background(), id, bytes.NewReader(frame))
		failed(t, r, err, ErrCorruptData)
		got, err := s.GetCandidate(context.Background(), id)
		if got != nil || !errors.Is(err, ErrCorruptData) {
			t.Fatal("corrupt delivery", name, err)
		}
		after, _ := os.Lstat(path)
		now, _ := os.ReadFile(path)
		if !os.SameFile(before, after) || !bytes.Equal(now, original) {
			t.Fatal("occupied destination changed")
		}
	}
}

// Actual files plus injected errno prove classification, not physical fullness.
func TestStagingFaults(t *testing.T) {
	points := []string{"write", "partial", "fileSync", "close", "beforeLink", "link", "afterLink", "finalSync", "directorySync", "remove", "stagingSync", "cleanup", "cleanupSync"}
	for _, cause := range []syscall.Errno{syscall.EIO, syscall.ENOSPC, syscall.EDQUOT} {
		for _, point := range points {
			t.Run(cause.Error()+"/"+point, func(t *testing.T) {
				root, hit := privateRoot(t), false
				ops := diskOps{before: func(p string) error {
					if p == point {
						hit = true
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
							hit = true
						}
						return n, cause
					}
				}
				s := ready(t, root, opts(), allow, ops)
				id, b := treeFixture(t, true)
				r, err := s.Stage(context.Background(), id, bytes.NewReader(b))
				failed(t, r, err, cause)
				if !hit || cause != syscall.EIO && !errors.Is(err, ErrResourceExhausted) {
					t.Fatal("unreached or unclassified fault", err)
				}
				activated := point == "afterLink" || point == "finalSync" || point == "directorySync" || point == "remove" || point == "stagingSync"
				if errors.Is(err, ErrOutcomeUnknown) != activated {
					t.Fatal("activation uncertainty", err)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				s = ready(t, root, opts(), allow, diskOps{})
				got, err := s.GetCandidate(context.Background(), id)
				if activated && (err != nil || !bytes.Equal(got, b)) || !activated && !errors.Is(err, ErrNotFound) {
					t.Fatal("fault reopen", err)
				}
				stage(t, s, id, b)
			})
		}
	}
}

func TestStagingAuthority(t *testing.T) {
	var typedNil authFunc
	for _, auth := range []Authority{nil, typedNil} {
		if s, err := OpenStaging(privateRoot(t), opts(), auth); s != nil || !errors.Is(err, ErrInvalidArgument) {
			t.Fatal("missing authority", err)
		}
	}
	id, b := treeFixture(t, false)
	for _, action := range []string{ActionStage, ActionGetCandidate} {
		for _, warm := range []bool{false, true} {
			root := privateRoot(t)
			s := ready(t, root, opts(), allow, diskOps{})
			if warm {
				stage(t, s, id, b)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			calls := 0
			auth := authFunc(func(_ context.Context, got derived.TreePageID, a string) error {
				calls++
				if got != id || a != action {
					t.Error("authority binding")
				}
				return errors.New("private policy detail")
			})
			s = ready(t, root, opts(), auth, diskOps{})
			var err error
			if action == ActionStage {
				var r CandidateID
				r, err = s.Stage(context.Background(), id, sourceFunc(func([]byte) (int, error) { t.Fatal("denied input consumed"); return 0, io.EOF }))
				failed(t, r, err, ErrPermissionDenied)
			} else {
				var got []byte
				got, err = s.GetCandidate(context.Background(), id)
				if got != nil {
					t.Fatal("unauthorized bytes")
				}
			}
			if calls != 1 || err == nil || err.Error() != ErrPermissionDenied.Error() {
				t.Fatal("existence leak or unredacted denial", err)
			}
		}
	}
	for _, action := range []string{ActionStage, ActionGetCandidate} {
		root, calls := privateRoot(t), 0
		s := ready(t, root, opts(), allow, diskOps{})
		stage(t, s, id, b)
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s = ready(t, root, opts(), authFunc(func(_ context.Context, _ derived.TreePageID, a string) error {
			calls++
			if action == a && (a == ActionStage && calls == 4 || a == ActionGetCandidate && calls == 2) {
				return context.DeadlineExceeded
			}
			return nil
		}), diskOps{})
		if action == ActionStage {
			r, err := s.Stage(context.Background(), id, bytes.NewReader(b))
			failed(t, r, err, ErrPermissionDenied)
		} else {
			got, err := s.GetCandidate(context.Background(), id)
			if got != nil || !errors.Is(err, ErrPermissionDenied) {
				t.Fatal("delivery denial", err)
			}
		}
	}
}

func TestStagingQuotaRecovery(t *testing.T) {
	root, o := privateRoot(t), opts()
	o.MaxCandidates, o.MaxStoredBytes = 2, 2*derived.MaxTreePageBytes
	s := ready(t, root, o, allow, diskOps{})
	id, b := treeFixture(t, false)
	stage(t, s, id, b)
	other, linked := treeFixture(t, true)
	r, err := s.Stage(context.Background(), other, bytes.NewReader(linked))
	failed(t, r, err, ErrResourceExhausted)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = ready(t, root, o, allow, diskOps{})
	r, err = s.Stage(context.Background(), other, bytes.NewReader(linked))
	failed(t, r, err, ErrResourceExhausted)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if err := os.WriteFile(filepath.Join(root, ".staging", fmt.Sprintf("%032x.tmp", i)), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	s, err = OpenStaging(root, opts(), allow)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err = s.Stage(context.Background(), id, bytes.NewReader(b))
	failed(t, r, err, ErrBusy)
	for range 20 {
		before, _ := os.ReadDir(filepath.Join(root, ".staging"))
		done, err := s.RecoverTemps(context.Background())
		after, _ := os.ReadDir(filepath.Join(root, ".staging"))
		if err != nil || len(before)-len(after) > opts().RecoveryBatch {
			t.Fatal("bounded orphan recovery", err)
		}
		if done {
			stage(t, s, other, linked)
			return
		}
	}
	t.Fatal("quota recovery did not finish")
}

func TestStagingCancellation(t *testing.T) {
	for _, point := range []string{"admission", "source", "beforeLink", "afterLink", "shortWrite"} {
		root := privateRoot(t)
		ctx, cancel := context.WithCancel(context.Background())
		op := diskOps{before: func(p string) error {
			if p == point {
				cancel()
			}
			return nil
		}}
		if point == "shortWrite" {
			op.write = func(f *os.File, p []byte) (int, error) { return f.Write(p[:len(p)/2]) }
		}
		s := ready(t, root, opts(), allow, op)
		id, b := treeFixture(t, false)
		var src io.Reader = bytes.NewReader(b)
		if point == "source" {
			src = sourceFunc(func(p []byte) (int, error) { cancel(); return copy(p, b), nil })
		}
		if point == "admission" {
			cancel()
		}
		r, err := s.Stage(ctx, id, src)
		cancel()
		want := error(context.Canceled)
		if point == "shortWrite" {
			want = io.ErrShortWrite
		}
		failed(t, r, err, want)
		if errors.Is(err, ErrOutcomeUnknown) != (point == "afterLink") {
			t.Fatal("cancellation uncertainty", err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s = ready(t, root, opts(), allow, diskOps{})
		stage(t, s, id, b)
	}
}

func TestStagingProcessCrash(t *testing.T) {
	if point := os.Getenv("SCION_TREE_CRASH"); point != "" {
		s := ready(t, os.Getenv("SCION_TREE_ROOT"), opts(), allow, diskOps{before: func(p string) error {
			if p == point {
				os.Exit(82)
			}
			return nil
		}})
		id, b := treeFixture(t, true)
		stage(t, s, id, b)
		t.Fatal("crash point not reached")
	}
	for _, point := range []string{"write", "fileSync", "beforeLink", "afterLink", "directorySync", "stagingSync"} {
		t.Run(point, func(t *testing.T) {
			root := privateRoot(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStagingProcessCrash$", "-test.v")
			cmd.Env = append(os.Environ(), "SCION_TREE_CRASH="+point, "SCION_TREE_ROOT="+root)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 82 {
				t.Fatalf("crash child: %v %s", err, out)
			}
			s := ready(t, root, opts(), allow, diskOps{})
			id, b := treeFixture(t, true)
			activated := point == "afterLink" || point == "directorySync" || point == "stagingSync"
			got, err := s.GetCandidate(context.Background(), id)
			if activated && (err != nil || !bytes.Equal(got, b)) || !activated && !errors.Is(err, ErrNotFound) {
				t.Fatal("crash reopen", err)
			}
			stage(t, s, id, b)
		})
	}
}

func TestStagingAdmissionClose(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	o := opts()
	o.MaxConcurrentOps = 1
	s := ready(t, privateRoot(t), o, allow, diskOps{})
	id, b := treeFixture(t, false)
	done := make(chan error, 1)
	go func() {
		_, err := s.Stage(context.Background(), id, sourceFunc(func([]byte) (int, error) { close(entered); <-release; return 0, io.ErrUnexpectedEOF }))
		done <- err
	}()
	<-entered
	r, err := s.Stage(context.Background(), id, bytes.NewReader(b))
	failed(t, r, err, ErrBusy)
	if _, err := s.RecoverTemps(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("recovery during active operation", err)
	}
	if err := s.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("closed active descriptor", err)
	}
	close(release)
	if err := <-done; !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	r, err = s.Stage(context.Background(), id, bytes.NewReader(b))
	failed(t, r, err, ErrClosed)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStagingRootConfinement(t *testing.T) {
	for _, point := range []string{"rootMode", "rootLink", "stageMode", "stageLink", "rootSwap", "stageSwap"} {
		t.Run(point, func(t *testing.T) {
			root, outside := privateRoot(t), privateRoot(t)
			sentinel := filepath.Join(outside, "sentinel")
			if err := os.WriteFile(sentinel, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			switch point {
			case "rootMode":
				os.Chmod(root, 0750)
			case "rootLink":
				os.Remove(root)
				os.Symlink(outside, root)
			case "stageMode":
				os.Mkdir(filepath.Join(root, ".staging"), 0755)
			case "stageLink":
				os.Symlink(outside, filepath.Join(root, ".staging"))
			}
			ops := diskOps{before: func(p string) error {
				if p == "beforeLink" && (point == "rootSwap" || point == "stageSwap") {
					path := root
					if point == "stageSwap" {
						path = filepath.Join(root, ".staging")
					}
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, path); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}}
			s, err := openStaging(root, opts(), allow, ops)
			if point != "rootSwap" && point != "stageSwap" {
				if s != nil || err == nil {
					t.Fatal("unsafe constructor", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				for range 100 {
					done, e := s.RecoverTemps(context.Background())
					if e != nil {
						t.Fatal(e)
					}
					if done {
						break
					}
				}
				id, b := treeFixture(t, false)
				r, e := s.Stage(context.Background(), id, bytes.NewReader(b))
				if r != (CandidateID{}) || e == nil {
					t.Fatal("accepted replaced directory", e)
				}
			}
			b, e := os.ReadFile(sentinel)
			if e != nil || string(b) != "untouched" {
				t.Fatal("outside changed", e)
			}
			xs, e := os.ReadDir(outside)
			if e != nil || len(xs) != 1 {
				t.Fatal("outside entries", e)
			}
		})
	}
}

func TestStagingFailedRecoveryStaysUnavailable(t *testing.T) {
	root, o := privateRoot(t), opts()
	s := ready(t, root, o, allow, diskOps{})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(privateRoot(t), filepath.Join(root, ".staging", fmt.Sprintf("%032x.tmp", 1))); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStaging(root, o, allow)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var failedRecovery bool
	for range 10 {
		done, err := s.RecoverTemps(context.Background())
		if done {
			t.Fatal("unsafe orphan accepted")
		}
		if err != nil {
			failedRecovery = true
			break
		}
	}
	if !failedRecovery {
		t.Fatal("unsafe orphan not inspected")
	}
	for range 3 {
		if done, err := s.RecoverTemps(context.Background()); done || err == nil {
			t.Fatal("failed scan forgot cursor/accounting", err)
		}
	}
	id, b := treeFixture(t, false)
	r, err := s.Stage(context.Background(), id, bytes.NewReader(b))
	failed(t, r, err, ErrBusy)
}
