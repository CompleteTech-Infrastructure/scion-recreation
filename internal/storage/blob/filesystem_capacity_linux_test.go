//go:build linux && scion_real_filesystem

package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestFilesystemRealCapacity is opt-in local kernel capacity qualification.
// It does not qualify physical quotas, durable media, or power-loss behavior.
func TestFilesystemRealCapacity(t *testing.T) {
	const marker = "SCION_BLOB_CAPACITY_CHILD"
	if os.Getenv(marker) == "1" {
		realCapacityChild(t)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "--user", "--map-root-user", "--mount", "--propagation", "private", executable,
		"-test.run=^TestFilesystemRealCapacity$", "-test.v", "-test.timeout=25s")
	// The mountpoint belongs to this test; only the isolated child mounts it.
	cmd.Env = append(os.Environ(), marker+"=1", "SCION_BLOB_CAPACITY_ROOT="+t.TempDir(), "SCION_BLOB_PARENT_MOUNT_NS="+namespace)
	output, err := cmd.CombinedOutput()
	t.Logf("isolated real-filesystem child output:\n%s", output)
	if err != nil {
		t.Fatalf("required local tmpfs qualification failed (no skip): %v; context=%v", err, ctx.Err())
	}
}

// This helper is reachable only via the explicit marker above. A second mount
// namespace check prevents an accidental direct helper invocation from mounting
// in the caller's namespace.
func realCapacityChild(t *testing.T) {
	namespace, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	parent := os.Getenv("SCION_BLOB_PARENT_MOUNT_NS")
	mountpoint := os.Getenv("SCION_BLOB_CAPACITY_ROOT")
	if parent == "" || parent == namespace || !filepath.IsAbs(mountpoint) {
		t.Fatal("helper requires a private mount namespace and absolute disposable mountpoint")
	}
	const capacity = 2 << 20
	if err = syscall.Mount("tmpfs", mountpoint, "tmpfs", syscall.MS_NODEV|syscall.MS_NOSUID|syscall.MS_NOEXEC,
		"size=2097152,mode=0700,nr_inodes=1024"); err != nil {
		t.Fatalf("required real tmpfs mount unavailable (no skip): %v", err)
	}
	defer func() {
		if err := syscall.Unmount(mountpoint, 0); err != nil {
			t.Error(err)
		}
	}()
	var fs syscall.Statfs_t
	if err := syscall.Statfs(mountpoint, &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Type != 0x01021994 || fs.Blocks*uint64(fs.Bsize) != capacity {
		t.Fatalf("unexpected backend: type=%x blocks=%d bsize=%d", fs.Type, fs.Blocks, fs.Bsize)
	}
	t.Logf("backend=Linux kernel tmpfs capacity=%d mount_namespace=%s parent_namespace=%s uid=%d seed=OBJ02-REAL-CAPACITY-v1; no injected diskOps; not physical quota or power-loss evidence", capacity, namespace, parent, os.Geteuid())
	root := filepath.Join(mountpoint, "store")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	filler := filepath.Join(mountpoint, "capacity-reservation")
	if err := os.WriteFile(filler, make([]byte, 1536<<10), 0600); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1<<20)
	for offset := 0; offset < len(payload); offset += sha256.Size {
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], uint64(offset/sha256.Size))
		digest := sha256.Sum256(append([]byte("OBJ02-REAL-CAPACITY-v1"), counter[:]...))
		copy(payload[offset:], digest[:])
	}
	id, frame := fixture(t, payload)
	opts := options()
	opts.MaxEncodedBytes = 4 << 20 // Above both frame size and filesystem capacity.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var opened []*Filesystem
	defer func() {
		for _, store := range opened {
			if err := store.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	open := func(t *testing.T) *Filesystem {
		t.Helper()
		s, err := OpenFilesystem(root, opts)
		if err != nil {
			t.Fatal(err)
		}
		opened = append(opened, s)
		for {
			done, err := s.RecoverTemps(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if done {
				return s
			}
		}
	}
	s := open(t)
	if !t.Run("kernel-enospc-no-false-object", func(t *testing.T) {
		if err := syscall.Statfs(root, &fs); err != nil {
			t.Fatal(err)
		}
		available := fs.Bavail * uint64(fs.Bsize)
		if available < 128<<10 || available >= uint64(len(frame)) {
			t.Fatalf("bad capacity fixture: available=%d frame=%d", available, len(frame))
		}
		source := &capacityObservedReader{Reader: bytes.NewReader(frame), staging: filepath.Join(root, ".staging")}
		result, err := s.Put(ctx, id, uint64(len(payload)), source)
		if !errors.Is(err, ErrResourceExhausted) || !errors.Is(err, syscall.ENOSPC) {
			t.Fatalf("expected real kernel ENOSPC and ErrResourceExhausted: %v", err)
		}
		if result != (PutResult{}) || errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("mid-write failure result=%+v err=%v", result, err)
		}
		consumed := len(frame) - source.Len()
		if source.peak <= 28 || consumed >= len(frame) || consumed <= 0 {
			t.Fatalf("not a mid-write failure: staged_peak=%d consumed=%d frame=%d", source.peak, consumed, len(frame))
		}
		noTemps(t, root)
		if _, err := os.Lstat(filepath.Join(root, blobName(id))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("false final object: %v", err)
		}
		reader, err := s.OpenCanonical(ctx, id)
		if reader != nil {
			reader.Close()
			t.Fatal("failed put exposed a reader")
		}
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("failed put lookup: %v", err)
		}
		if err := syscall.Statfs(root, &fs); err != nil {
			t.Fatal(err)
		}
		if fs.Bavail*uint64(fs.Bsize) != available {
			t.Fatal("failed put leaked capacity")
		}
		t.Logf("actual_errno=ENOSPC available_before=%d staged_peak=%d input_consumed=%d/%d result=zero final=absent staging=empty capacity_reclaimed=true", available, source.peak, consumed, len(frame))
	}) {
		return
	}
	t.Run("reopen-cleanup-free-capacity-and-retry", func(t *testing.T) {
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s = open(t)
		noTemps(t, root)
		reader, err := s.OpenCanonical(ctx, id)
		if reader != nil {
			reader.Close()
			t.Fatal("reopen exposed failed object")
		}
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("reopen lookup: %v", err)
		}
		if err := os.Remove(filler); err != nil {
			t.Fatal(err)
		}
		result, err := s.Put(ctx, id, uint64(len(payload)), bytes.NewReader(frame))
		if err != nil || result.ID != id || result.Reused || result.PayloadBytes != uint64(len(payload)) {
			t.Fatalf("retry result=%+v err=%v", result, err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s = open(t)
		reader, err = s.OpenCanonical(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		got, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || !bytes.Equal(got, frame) {
			t.Fatalf("reopened retry bytes: read=%v close=%v equal=%v", readErr, closeErr, bytes.Equal(got, frame))
		}
		noTemps(t, root)
		t.Log("reopen=absent-before-retry recovery=clean retry=fresh-success reopened_retry=exact-canonical-frame")
	})
	// Close descriptor roots before unmount, including on subtest failure.
	if err := s.Close(); err != nil {
		t.Error(err)
	}
}

// Observe actual staged bytes without intercepting or replacing filesystem I/O.
type capacityObservedReader struct {
	*bytes.Reader
	staging string
	peak    int64
}

func (r *capacityObservedReader) Read(p []byte) (int, error) {
	entries, err := os.ReadDir(r.staging)
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return 0, err
		}
		r.peak = max(r.peak, info.Size())
	}
	return r.Reader.Read(p)
}
