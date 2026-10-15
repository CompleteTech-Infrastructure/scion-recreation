package workspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"canopy.local/canopy/internal/model"
)

func testChangeset(t *testing.T, label string) model.ChangesetID {
	t.Helper()
	digest := sha256.Sum256([]byte(label))
	id, err := model.NewTypedID(model.ChangesetKind, digest)
	if err != nil {
		t.Fatal(err)
	}
	base, err := model.NewChangesetID(id)
	if err != nil {
		t.Fatal(err)
	}
	return base
}

func testPath(t *testing.T, raw []byte) model.Path {
	t.Helper()
	p, err := model.NewPath(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func privateMetadataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testManifest(t *testing.T) Manifest {
	t.Helper()
	return Manifest{
		Base:          testChangeset(t, "base A"),
		SparseVersion: 1,
		Sparse: []model.Path{
			testPath(t, []byte{'s', 'r', 'c', '/', 0xff}),
			testPath(t, []byte("docs/README.md")),
		},
		State:      Dirty,
		DirtyPaths: []model.Path{testPath(t, []byte{'w', 'o', 'r', 'k', '/', 0xfe})},
	}
}

func requirePathBytes(t *testing.T, got []model.Path, want ...[]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("path count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i].Bytes(), want[i]) {
			t.Fatalf("path[%d] = %x, want %x", i, got[i].Bytes(), want[i])
		}
	}
}

func TestManifestRoundTripPreservesSparseBytesAndDirtyState(t *testing.T) {
	dir := privateMetadataDir(t)
	in := testManifest(t)
	if err := Save(dir, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if out.Base != in.Base || out.SparseVersion != 1 || out.SparseAll || out.State != Dirty {
		t.Fatalf("round trip lost base or state: %#v", out)
	}
	requirePathBytes(t, out.Sparse, []byte{'s', 'r', 'c', '/', 0xff}, []byte("docs/README.md"))
	requirePathBytes(t, out.DirtyPaths, []byte{'w', 'o', 'r', 'k', '/', 0xfe})

	for _, sparseAll := range []bool{false, true} {
		m := Manifest{Base: in.Base, SparseVersion: 1, SparseAll: sparseAll, State: Clean}
		if err := Save(dir, m); err != nil {
			t.Fatal(err)
		}
		got, err := Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got.SparseAll != sparseAll || got.State != Clean || len(got.Sparse) != 0 || len(got.DirtyPaths) != 0 {
			t.Fatalf("sparse-all=%v round trip = %#v", sparseAll, got)
		}
	}
	info, err := os.Lstat(filepath.Join(dir, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("manifest mode/type = %v, want regular 0600", info.Mode())
	}
}

func appendU32(b *bytes.Buffer, value uint32) { _ = binary.Write(b, binary.BigEndian, value) }

func checksummedFrame(payload []byte) []byte {
	frame := new(bytes.Buffer)
	frame.WriteString("CNWSJ001")
	appendU32(frame, uint32(len(payload)))
	sum := sha256.Sum256(payload)
	frame.Write(sum[:])
	frame.Write(payload)
	return frame.Bytes()
}

// This oracle spells out the accepted framing instead of asking the product encoder
// to generate its own expected bytes.
func manifestFrameOracle(t *testing.T, m Manifest) []byte {
	t.Helper()
	base, err := m.Base.TypedID().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	payload := new(bytes.Buffer)
	payload.Write(base)
	_ = binary.Write(payload, binary.BigEndian, uint16(1)) // sparse syntax v1
	payload.WriteByte(0)                                   // literal selection, not all
	payload.WriteByte(2)                                   // dirty state
	appendU32(payload, uint32(len(m.Sparse)))
	for _, p := range m.Sparse {
		appendU32(payload, uint32(len(p.Bytes())))
		payload.Write(p.Bytes())
	}
	appendU32(payload, uint32(len(m.DirtyPaths)))
	for _, p := range m.DirtyPaths {
		appendU32(payload, uint32(len(p.Bytes())))
		payload.Write(p.Bytes())
	}
	return checksummedFrame(payload.Bytes())
}

func TestManifestEncodingMatchesIndependentOracle(t *testing.T) {
	dir := privateMetadataDir(t)
	m := testManifest(t)
	rootA, err := model.ParseChangesetIDText("canopy:1:02:f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee")
	if err != nil {
		t.Fatal(err)
	}
	m.Base = rootA
	if err := Save(dir, m); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	want := manifestFrameOracle(t, m)
	if !bytes.Equal(got, want) {
		t.Fatalf("manifest frame differs from independent oracle\ngot:  %x\nwant: %x", got, want)
	}
}

func TestManifestRejectsChecksummedInvalidFramesAndOversizedRecords(t *testing.T) {
	seed := testManifest(t)
	frame := manifestFrameOracle(t, seed)
	basePayload := frame[44:]
	invalid := []struct {
		name string
		edit func([]byte)
	}{
		{"typed-id-version", func(p []byte) { binary.BigEndian.PutUint16(p[:2], 0) }},
		{"blob-used-as-base", func(p []byte) { p[2] = byte(model.BlobKind) }},
		{"sparse-marker", func(p []byte) { p[37] = 2 }},
		{"state", func(p []byte) { p[38] = 4 }},
		{"invalid-path-byte", func(p []byte) { p[47] = 0 }},
		{"path-count", func(p []byte) { binary.BigEndian.PutUint32(p[39:43], MaxPaths+1) }},
		{"path-length", func(p []byte) { binary.BigEndian.PutUint32(p[43:47], uint32(model.MaxPathBytes+1)) }},
	}
	dir := privateMetadataDir(t)
	for _, tc := range invalid {
		payload := append([]byte(nil), basePayload...)
		tc.edit(payload)
		if err := os.WriteFile(filepath.Join(dir, "manifest"), checksummedFrame(payload), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s frame error = %v, want ErrCorrupt", tc.name, err)
		}
	}

	rootA, err := model.ParseChangesetIDText("canopy:1:02:f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee")
	if err != nil {
		t.Fatal(err)
	}
	base, err := rootA.TypedID().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	large := new(bytes.Buffer)
	large.Write(base)
	_ = binary.Write(large, binary.BigEndian, uint16(1))
	large.Write([]byte{0, 1}) // literal sparse selection, explicitly clean
	appendU32(large, MaxPaths)
	path := bytes.Repeat([]byte{'x'}, 1024)
	for i := 0; i < MaxPaths; i++ {
		appendU32(large, uint32(len(path)))
		large.Write(path)
	}
	appendU32(large, 0)
	oversized := checksummedFrame(large.Bytes())
	if len(oversized) <= MaxManifestBytes {
		t.Fatal("oversized fixture did not exceed the record cap")
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest"), oversized, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("oversized valid frame error = %v, want ErrCorrupt", err)
	}
}

func TestManifestValidationAndMissingStateFailClosed(t *testing.T) {
	dir := privateMetadataDir(t)
	if _, err := Load(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing manifest error = %v, want os.ErrNotExist", err)
	}
	valid := testManifest(t)
	bad := []struct {
		name string
		edit func(*Manifest)
	}{
		{"base", func(m *Manifest) { m.Base = model.ChangesetID{} }},
		{"sparse-version", func(m *Manifest) { m.SparseVersion = 2 }},
		{"all-with-selection", func(m *Manifest) { m.SparseAll = true }},
		{"clean-with-dirty-path", func(m *Manifest) { m.State = Clean }},
		{"dirty-without-path", func(m *Manifest) { m.DirtyPaths = nil }},
		{"unknown-state", func(m *Manifest) { m.State = DirtyState(99) }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			d := privateMetadataDir(t)
			m := valid
			m.Sparse = append([]model.Path(nil), valid.Sparse...)
			m.DirtyPaths = append([]model.Path(nil), valid.DirtyPaths...)
			tc.edit(&m)
			if err := Save(d, m); err == nil {
				t.Fatal("Save accepted invalid or pending metadata")
			}
			if _, err := os.Lstat(filepath.Join(d, "manifest")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid save left a manifest: %v", err)
			}
		})
	}
	uncertainDir := privateMetadataDir(t)
	uncertain := Manifest{Base: valid.Base, SparseVersion: 1, State: Uncertain}
	if err := Save(uncertainDir, uncertain); err != nil {
		t.Fatalf("Save rejected explicit uncertain state with empty hints: %v", err)
	}
	got, err := Load(uncertainDir)
	if err != nil || got.State != Uncertain || len(got.DirtyPaths) != 0 {
		t.Fatalf("uncertain state did not round trip: %#v, %v", got, err)
	}
}

func TestManifestRejectsCorruptionAndTruncation(t *testing.T) {
	seedDir := privateMetadataDir(t)
	if err := Save(seedDir, testManifest(t)); err != nil {
		t.Fatal(err)
	}
	valid, err := os.ReadFile(filepath.Join(seedDir, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	truncated := append([]byte(nil), valid[:len(valid)-1]...)
	badChecksum := append([]byte(nil), valid...)
	badChecksum[44] ^= 0x80
	badMagic := append([]byte(nil), valid...)
	badMagic[0] ^= 1
	trailing := append(append([]byte(nil), valid...), 0)
	for _, tc := range []struct {
		name string
		data []byte
	}{{"truncated", truncated}, {"checksum", badChecksum}, {"magic", badMagic}, {"trailing", trailing}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateMetadataDir(t)
			if err := os.WriteFile(filepath.Join(dir, "manifest"), tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(dir); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Load error = %v, want ErrCorrupt", err)
			}
		})
	}
}

func TestManifestRecoveryRejectsCorruptJournal(t *testing.T) {
	dir := privateMetadataDir(t)
	if err := Save(dir, testManifest(t)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "journal")
	if err := os.WriteFile(journal, []byte("CNWSJ001\x00\x00"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(dir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Recover error = %v, want ErrCorrupt", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted metadata with a corrupt journal")
	}
	after, err := os.ReadFile(filepath.Join(dir, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed recovery changed the current manifest")
	}
	if _, err := os.Lstat(journal); err != nil {
		t.Fatalf("failed recovery removed the corrupt journal: %v", err)
	}
}

func TestManifestRecoveryRetainsDirtyUnionAndUncertainEmptyHints(t *testing.T) {
	t.Run("dirty-union", func(t *testing.T) {
		dir := privateMetadataDir(t)
		old := testManifest(t)
		if err := Save(dir, old); err != nil {
			t.Fatal(err)
		}
		newPath := testPath(t, []byte("new/dirty"))
		proposed := Manifest{
			Base: testChangeset(t, "base B"), SparseVersion: 1, SparseAll: true,
			State: Dirty, DirtyPaths: []model.Path{newPath},
		}
		stop := errors.New("interrupt after manifest sync")
		err := save(dir, proposed, func(stage string) error {
			if stage == "manifest-dir-synced" {
				return stop
			}
			return nil
		})
		if !errors.Is(err, stop) {
			t.Fatalf("save error = %v, want injected interruption", err)
		}
		got, err := Recover(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got.State != Uncertain || !containsPath(got.DirtyPaths, old.DirtyPaths[0].Bytes()) || !containsPath(got.DirtyPaths, newPath.Bytes()) {
			t.Fatalf("recovery lost uncertainty or dirty path union: %#v", got)
		}
		if got.Base != old.Base || got.SparseAll || len(got.Sparse) != len(old.Sparse) {
			t.Fatal("recovery failed to preserve the prior base and sparse selection")
		}
	})

	t.Run("initialization-with-no-hints", func(t *testing.T) {
		dir := privateMetadataDir(t)
		initial := Manifest{Base: testChangeset(t, "initial base"), SparseVersion: 1, State: Clean}
		stop := errors.New("interrupt after journal sync")
		err := save(dir, initial, func(stage string) error {
			if stage == "journal-dir-synced" {
				return stop
			}
			return nil
		})
		if !errors.Is(err, stop) {
			t.Fatalf("save error = %v, want injected interruption", err)
		}
		got, err := Recover(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got.State != Uncertain || len(got.DirtyPaths) != 0 || got.Base != initial.Base {
			t.Fatalf("interrupted initialization = %#v, want uncertain with no hints", got)
		}
		if err := Save(dir, got); err != nil {
			t.Fatalf("Save rejected explicit uncertain state: %v", err)
		}
		loaded, err := Load(dir)
		if err != nil || loaded.State != Uncertain {
			t.Fatalf("recovered uncertain state was not durable: %#v, %v", loaded, err)
		}
	})
}

func TestManifestBusyLockIsScopedToItsMetadataDirectory(t *testing.T) {
	first, second := privateMetadataDir(t), privateMetadataDir(t)
	m := testManifest(t)
	if err := Save(first, m); err != nil {
		t.Fatal(err)
	}
	locked, err := openMetadata(first)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.close()
	if err := Save(first, m); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent Save error = %v, want ErrBusy", err)
	}
	if _, err := Recover(first); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent Recover error = %v, want ErrBusy", err)
	}
	if err := Save(second, m); err != nil {
		t.Fatalf("unrelated metadata directory was serialized: %v", err)
	}
}

func TestManifestRejectsNonPrivateMetadataDirectory(t *testing.T) {
	dir := privateMetadataDir(t)
	prior := testManifest(t)
	if err := Save(dir, prior); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "manifest")
	before, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("nonprivate fixture mode = %v, %v; want 0755", info, err)
	}
	if err := Save(dir, prior); err == nil {
		t.Fatal("Save accepted a nonprivate metadata directory")
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted a nonprivate metadata directory")
	}
	if _, err := Recover(dir); err == nil {
		t.Fatal("Recover accepted a nonprivate metadata directory")
	}
	after, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("rejected metadata operations changed the recorded dirty manifest")
	}

	control := privateMetadataDir(t)
	if err := Save(control, prior); err != nil {
		t.Fatalf("private control Save failed: %v", err)
	}
	loaded, err := Load(control)
	if err != nil || loaded.State != Dirty {
		t.Fatalf("private control Load = %#v, %v; want dirty state", loaded, err)
	}
	if recovered, err := Recover(control); err != nil || recovered.State != Dirty {
		t.Fatalf("private control Recover = %#v, %v; want dirty state", recovered, err)
	}
}

const crashDirEnv = "CANOPY_TEST_MANIFEST_CRASH_DIR"
const crashPointEnv = "CANOPY_TEST_MANIFEST_CRASH_POINT"
const crashActionEnv = "CANOPY_TEST_MANIFEST_CRASH_ACTION"

func TestManifestCrashBoundariesPreserveDirtyState(t *testing.T) {
	if runManifestCrashChild(t, "TestManifestCrashBoundariesPreserveDirtyState") {
		return
	}

	points := []string{
		"journal-created", "journal-written", "journal-synced", "journal-renamed", "journal-dir-synced",
		"next-created", "next-written", "next-synced", "next-renamed",
		"manifest-dir-synced", "journal-removed", "final-dir-synced",
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			dir := privateMetadataDir(t)
			old := testManifest(t)
			if err := Save(dir, old); err != nil {
				t.Fatal(err)
			}
			output := crashAtManifestCheckpoint(t, "TestManifestCrashBoundariesPreserveDirtyState", dir, point, "save")

			got, recoverErr := Recover(dir)
			committed := point == "journal-removed" || point == "final-dir-synced"
			if recoverErr != nil {
				t.Fatalf("Recover after %s: %v (child output %q)", point, recoverErr, output)
			}
			if committed {
				if got.State != Clean {
					t.Fatalf("committed checkpoint state = %v, want Clean", got.State)
				}
				return
			}
			prepublication := point == "journal-created" || point == "journal-written" || point == "journal-synced"
			wantState := Uncertain
			if prepublication {
				wantState = Dirty
			}
			if got.State != wantState {
				t.Fatalf("recovery at %s returned state %v, want %v", point, got.State, wantState)
			}
			if got.Base != old.Base || !containsPath(got.DirtyPaths, old.DirtyPaths[0].Bytes()) {
				t.Fatalf("recovery at %s lost prior dirty path bytes", point)
			}
			if prepublication && got.SparseAll {
				t.Fatalf("prepublication recovery changed prior sparse selection at %s", point)
			}
		})
	}
	t.Run("interrupted-initialization", func(t *testing.T) {
		dir := privateMetadataDir(t)
		crashAtManifestCheckpoint(t, "TestManifestCrashBoundariesPreserveDirtyState", dir, "journal-synced", "save")
		if _, err := Recover(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Recover interrupted initial creation = %v, want os.ErrNotExist", err)
		}
		if _, err := Load(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Load interrupted initial creation = %v, want os.ErrNotExist", err)
		}
	})
}

func TestManifestRecoveryCrashBoundariesRemainUncertain(t *testing.T) {
	if runManifestCrashChild(t, "TestManifestRecoveryCrashBoundariesRemainUncertain") {
		return
	}
	points := []string{"next-created", "next-written", "next-synced", "next-renamed", "manifest-dir-synced", "journal-removed", "final-dir-synced"}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			dir := privateMetadataDir(t)
			old := testManifest(t)
			if err := Save(dir, old); err != nil {
				t.Fatal(err)
			}
			stop := errors.New("leave durable journal")
			err := save(dir, Manifest{Base: testChangeset(t, "base B"), SparseVersion: 1, State: Clean}, func(stage string) error {
				if stage == "journal-dir-synced" {
					return stop
				}
				return nil
			})
			if !errors.Is(err, stop) {
				t.Fatalf("save error = %v, want interrupted pending transaction", err)
			}
			crashAtManifestCheckpoint(t, "TestManifestRecoveryCrashBoundariesRemainUncertain", dir, point, "recover")
			got, err := Recover(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != Uncertain || !containsPath(got.DirtyPaths, old.DirtyPaths[0].Bytes()) {
				t.Fatalf("repeat recovery after %s returned %#v; expected uncertain old dirt", point, got)
			}
		})
	}
}

func runManifestCrashChild(t *testing.T, testName string) bool {
	t.Helper()
	dir := os.Getenv(crashDirEnv)
	if dir == "" {
		return false
	}
	point, action := os.Getenv(crashPointEnv), os.Getenv(crashActionEnv)
	hook := func(stage string) error {
		if stage == point {
			os.Exit(79)
		}
		return nil
	}
	var err error
	switch action {
	case "save":
		err = save(dir, Manifest{Base: testChangeset(t, "base B"), SparseVersion: 1, SparseAll: true, State: Clean}, hook)
	case "recover":
		_, err = recoverMetadata(dir, hook)
	default:
		t.Fatalf("unknown crash action %q", action)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Fatalf("%s did not reach checkpoint %q", testName, point)
	return true
}

func crashAtManifestCheckpoint(t *testing.T, testName, dir, point, action string) []byte {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = withoutEnv(os.Environ(), crashDirEnv, crashPointEnv, crashActionEnv)
	cmd.Env = append(cmd.Env, crashDirEnv+"="+dir, crashPointEnv+"="+point, crashActionEnv+"="+action)
	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 79 {
		t.Fatalf("crash child result = %v, output %q; want exit 79", err, output)
	}
	return output
}

func withoutEnv(env []string, keys ...string) []string {
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		keep := true
		for _, key := range keys {
			if strings.HasPrefix(entry, key+"=") {
				keep = false
				break
			}
		}
		if keep {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func containsPath(paths []model.Path, want []byte) bool {
	for _, path := range paths {
		if bytes.Equal(path.Bytes(), want) {
			return true
		}
	}
	return false
}

func TestManifestDoesNotFollowSymlinkOrTouchSiblingFiles(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "metadata")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(parent, "user-data")
	if err := os.WriteFile(sibling, []byte("keep exact bytes\x00"), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "outside-target")
	if err := os.WriteFile(target, []byte("outside metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "manifest")); err != nil {
		t.Fatal(err)
	}
	err := Save(dir, testManifest(t))
	gotTarget, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(gotTarget, []byte("outside metadata")) {
		t.Fatalf("metadata operation followed manifest symlink: target became %q", gotTarget)
	}
	if err == nil {
		if _, err := Load(dir); err != nil {
			t.Fatalf("safe replacement was not readable: %v", err)
		}
	} else if _, err := Load(dir); err == nil {
		t.Fatal("Load followed or accepted the rejected manifest symlink")
	}
	gotSibling, err := os.ReadFile(sibling)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSibling, []byte("keep exact bytes\x00")) {
		t.Fatalf("sibling user file changed: %q", gotSibling)
	}
}

const manifestUmaskDirEnv = "CANOPY_TEST_MANIFEST_UMASK_DIR"
const manifestUmaskValueEnv = "CANOPY_TEST_MANIFEST_UMASK"

// The child changes only its own umask. Keeping this in a subprocess avoids a
// process-global test setting that could race with unrelated package tests.
func TestManifestRestrictiveUmaskChild(t *testing.T) {
	dir := os.Getenv(manifestUmaskDirEnv)
	if dir == "" {
		return
	}
	maskText := os.Getenv(manifestUmaskValueEnv)
	mask, err := strconv.ParseUint(maskText, 8, 32)
	if err != nil {
		t.Fatalf("parse child umask %q: %v", maskText, err)
	}

	want := testManifest(t)
	oldMask := syscall.Umask(int(mask))
	saveErr := Save(dir, want)
	syscall.Umask(oldMask)
	if saveErr != nil {
		t.Fatalf("Save under child umask %04o: %v", mask, saveErr)
	}
	requireOwnerReadWritePrivate(t, dir, "lock")
	requireOwnerReadWritePrivate(t, dir, "manifest")
	got, err := Load(dir)
	if err != nil || got.State != Dirty || got.Base != want.Base {
		t.Fatalf("Load after acknowledged Save = %#v, %v; want saved dirty state", got, err)
	}
	recovered, err := Recover(dir)
	if err != nil || recovered.State != Dirty || recovered.Base != want.Base {
		t.Fatalf("Recover after acknowledged Save = %#v, %v; want saved dirty state", recovered, err)
	}

	// Observe the transient intent/next entries while the same restrictive mask
	// is active. They must be usable before the operation can acknowledge success.
	seenIntent, seenNext := false, false
	oldMask = syscall.Umask(int(mask))
	updateErr := save(dir, got, func(stage string) error {
		var name *string
		switch stage {
		case "journal-created":
			seenIntent = true
			value := "intent"
			name = &value
		case "next-created":
			seenNext = true
			value := "next"
			name = &value
		default:
			return nil
		}
		info, err := os.Lstat(filepath.Join(dir, *name))
		if err != nil {
			return fmt.Errorf("stat new %s at %s: %w", *name, stage, err)
		}
		if info.Mode().Perm()&0600 != 0600 || info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("new %s mode %04o at %s lacks private owner read/write", *name, info.Mode().Perm(), stage)
		}
		return nil
	})
	syscall.Umask(oldMask)
	if updateErr != nil {
		t.Fatalf("metadata update under child umask %04o: %v", mask, updateErr)
	}
	if !seenIntent || !seenNext {
		t.Fatalf("creation checkpoints observed intent=%v next=%v", seenIntent, seenNext)
	}
	if got, err := Load(dir); err != nil || got.State != Dirty || got.Base != want.Base {
		t.Fatalf("Load after restrictive-umask update = %#v, %v", got, err)
	}
}

func TestManifestRestrictiveUmaskSaveRecovers(t *testing.T) {
	cases := []struct {
		name         string
		mask         string
		existingLock bool
	}{
		{name: "new-lock-0400", mask: "0400"},
		{name: "existing-lock-0400", mask: "0400", existingLock: true},
		{name: "new-lock-0200", mask: "0200"},
		{name: "existing-lock-0200", mask: "0200", existingLock: true},
		{name: "control-0000", mask: "0000"},
		{name: "control-0022", mask: "0022"},
		{name: "control-0077", mask: "0077"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateMetadataDir(t)
			if tc.existingLock {
				lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if err := lock.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Join(dir, "lock"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			sentinel := []byte("umask probe user bytes\x00\xff")
			if err := os.WriteFile(filepath.Join(dir, "user-content"), sentinel, 0600); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(os.Args[0], "-test.run=^TestManifestRestrictiveUmaskChild$", "-test.timeout=15s")
			cmd.Env = withoutEnv(os.Environ(), manifestUmaskDirEnv, manifestUmaskValueEnv)
			cmd.Env = append(cmd.Env, manifestUmaskDirEnv+"="+dir, manifestUmaskValueEnv+"="+tc.mask)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child Save/reopen under umask %s: %v; output=%s", tc.mask, err, output)
			}
			requireOwnerReadWritePrivate(t, dir, "lock")
			requireOwnerReadWritePrivate(t, dir, "manifest")
			loaded, err := Load(dir)
			if err != nil || loaded.State != Dirty {
				t.Fatalf("parent Load after child acknowledgement = %#v, %v", loaded, err)
			}
			got, err := os.ReadFile(filepath.Join(dir, "user-content"))
			if err != nil || !bytes.Equal(got, sentinel) {
				t.Fatalf("user content changed: %x, %v", got, err)
			}
		})
	}
}

func requireOwnerReadWritePrivate(t *testing.T, dir, name string) {
	t.Helper()
	info, err := os.Lstat(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		t.Fatalf("%s owner/link identity = %#v, want current UID and one link", name, info.Sys())
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0600 != 0600 || info.Mode().Perm()&0077 != 0 {
		t.Fatalf("%s type/mode = %v, want private regular file with owner read/write", name, info.Mode())
	}
}

func TestManifestReservedSymlinkSubstitutionsFailClosed(t *testing.T) {
	t.Run("lock-save", func(t *testing.T) {
		dir := privateMetadataDir(t)
		prior := testManifest(t)
		if err := Save(dir, prior); err != nil {
			t.Fatal(err)
		}
		manifestPath := filepath.Join(dir, "manifest")
		before, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, "lock")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("manifest", filepath.Join(dir, "lock")); err != nil {
			t.Fatal(err)
		}
		if err := Save(dir, Manifest{Base: prior.Base, SparseVersion: 1, State: Clean}); err == nil {
			t.Fatal("Save accepted an in-root lock symlink to the replaceable manifest")
		}
		after, err := os.ReadFile(manifestPath)
		if err != nil || !bytes.Equal(after, before) {
			t.Fatalf("rejected lock substitution changed manifest bytes: %x, %v", after, err)
		}
		requireSymlinkEntry(t, filepath.Join(dir, "lock"))
	})

	t.Run("manifest-load", func(t *testing.T) {
		dir := privateMetadataDir(t)
		prior := testManifest(t)
		if err := Save(dir, prior); err != nil {
			t.Fatal(err)
		}
		manifestPath := filepath.Join(dir, "manifest")
		targetPath := filepath.Join(dir, "manifest-target")
		before, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(manifestPath, targetPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("manifest-target", manifestPath); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); err == nil {
			t.Fatal("Load followed an in-root manifest symlink")
		}
		after, err := os.ReadFile(targetPath)
		if err != nil || !bytes.Equal(after, before) {
			t.Fatalf("manifest symlink target changed: %x, %v", after, err)
		}
		requireSymlinkEntry(t, manifestPath)
	})

	t.Run("journal-recover", func(t *testing.T) {
		dir := privateMetadataDir(t)
		prior := testManifest(t)
		if err := Save(dir, prior); err != nil {
			t.Fatal(err)
		}
		manifestBefore, err := os.ReadFile(filepath.Join(dir, "manifest"))
		if err != nil {
			t.Fatal(err)
		}
		stop := errors.New("leave a published journal for substitution probe")
		err = save(dir, Manifest{Base: testChangeset(t, "next clean base"), SparseVersion: 1, State: Clean}, func(stage string) error {
			if stage == "journal-renamed" {
				return stop
			}
			return nil
		})
		if !errors.Is(err, stop) {
			t.Fatalf("Save interruption = %v, want injected journal checkpoint", err)
		}
		journalPath := filepath.Join(dir, "journal")
		targetPath := filepath.Join(dir, "journal-target")
		before, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(journalPath, targetPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("journal-target", journalPath); err != nil {
			t.Fatal(err)
		}
		if _, err := Recover(dir); err == nil {
			t.Fatal("Recover followed an in-root journal symlink")
		}
		after, err := os.ReadFile(targetPath)
		if err != nil || !bytes.Equal(after, before) {
			t.Fatalf("journal symlink target changed: %x, %v", after, err)
		}
		manifestAfter, err := os.ReadFile(filepath.Join(dir, "manifest"))
		if err != nil || !bytes.Equal(manifestAfter, manifestBefore) {
			t.Fatalf("rejected journal substitution changed manifest bytes: %x, %v", manifestAfter, err)
		}
		requireSymlinkEntry(t, journalPath)
	})
}

func requireSymlinkEntry(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat %s: %v", path, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("entry %s has mode %v, want symlink preserved", path, info.Mode())
	}
}

func TestManifestReservedHardlinksFailClosed(t *testing.T) {
	t.Run("lock-save", func(t *testing.T) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "metadata")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		prior := testManifest(t)
		if err := Save(dir, prior); err != nil {
			t.Fatal(err)
		}
		manifestBefore, err := os.ReadFile(filepath.Join(dir, "manifest"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, "lock")); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(parent, "lock-target")
		want := []byte("preserve linked lock target\x00\xff")
		if err := os.WriteFile(target, want, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(target, filepath.Join(dir, "lock")); err != nil {
			t.Fatal(err)
		}
		if err := Save(dir, Manifest{Base: prior.Base, SparseVersion: 1, State: Clean}); err == nil {
			t.Fatal("Save accepted a hardlinked lock")
		}
		requireHardlinkTargetPreserved(t, filepath.Join(dir, "lock"), target, want)
		manifestAfter, err := os.ReadFile(filepath.Join(dir, "manifest"))
		if err != nil || !bytes.Equal(manifestAfter, manifestBefore) {
			t.Fatalf("rejected hardlinked lock changed manifest: %x, %v", manifestAfter, err)
		}
	})

	t.Run("manifest-load", func(t *testing.T) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "metadata")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := Save(dir, testManifest(t)); err != nil {
			t.Fatal(err)
		}
		manifest := filepath.Join(dir, "manifest")
		target := filepath.Join(parent, "manifest-target")
		want, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(manifest, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(target, manifest); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); err == nil {
			t.Fatal("Load accepted a hardlinked manifest")
		}
		requireHardlinkTargetPreserved(t, manifest, target, want)
	})

	t.Run("journal-recover", func(t *testing.T) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "metadata")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		prior := testManifest(t)
		if err := Save(dir, prior); err != nil {
			t.Fatal(err)
		}
		manifestBefore, err := os.ReadFile(filepath.Join(dir, "manifest"))
		if err != nil {
			t.Fatal(err)
		}
		stop := errors.New("leave a published journal for hardlink probe")
		err = save(dir, Manifest{Base: prior.Base, SparseVersion: 1, State: Clean}, func(stage string) error {
			if stage == "journal-renamed" {
				return stop
			}
			return nil
		})
		if !errors.Is(err, stop) {
			t.Fatalf("Save interruption = %v, want injected journal checkpoint", err)
		}
		journal := filepath.Join(dir, "journal")
		target := filepath.Join(parent, "journal-target")
		want, err := os.ReadFile(journal)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(journal, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(target, journal); err != nil {
			t.Fatal(err)
		}
		if _, err := Recover(dir); err == nil {
			t.Fatal("Recover accepted a hardlinked journal")
		}
		requireHardlinkTargetPreserved(t, journal, target, want)
		manifestAfter, err := os.ReadFile(filepath.Join(dir, "manifest"))
		if err != nil || !bytes.Equal(manifestAfter, manifestBefore) {
			t.Fatalf("rejected hardlinked journal changed manifest: %x, %v", manifestAfter, err)
		}
	})
}

func requireHardlinkTargetPreserved(t *testing.T, reserved, target string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("hardlink target changed: %x, %v", got, err)
	}
	reservedInfo, err := os.Lstat(reserved)
	if err != nil {
		t.Fatalf("Lstat reserved hardlink %s: %v", reserved, err)
	}
	targetInfo, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	reservedStat, reservedOK := reservedInfo.Sys().(*syscall.Stat_t)
	targetStat, targetOK := targetInfo.Sys().(*syscall.Stat_t)
	if !reservedOK || !targetOK || reservedStat.Nlink != 2 || targetStat.Nlink != 2 || !os.SameFile(reservedInfo, targetInfo) {
		t.Fatalf("hardlink entries were changed or unlinked: reserved=%#v target=%#v", reservedInfo.Sys(), targetInfo.Sys())
	}
}

func TestManifestReservedModesFailClosed(t *testing.T) {
	t.Run("manifest-0644", func(t *testing.T) {
		dir := privateMetadataDir(t)
		prior := testManifest(t)
		if err := Save(dir, prior); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "manifest")
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); err == nil {
			t.Fatal("Load accepted a group/other-readable manifest")
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(after, before) {
			t.Fatalf("rejected public manifest changed bytes: %x, %v", after, err)
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != 0644 {
			t.Fatalf("rejected manifest mode = %v, %v; want preserved 0644", info, err)
		}
	})

	for _, mode := range []os.FileMode{0200, 0400} {
		t.Run(fmt.Sprintf("lock-%04o", mode), func(t *testing.T) {
			dir := privateMetadataDir(t)
			prior := testManifest(t)
			if err := Save(dir, prior); err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(dir, "manifest")
			before, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			lock := filepath.Join(dir, "lock")
			if err := os.Remove(lock); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lock, []byte("bad lock mode"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(lock, mode); err != nil {
				t.Fatal(err)
			}
			if err := Save(dir, Manifest{Base: prior.Base, SparseVersion: 1, State: Clean}); err == nil {
				t.Fatalf("Save accepted pre-existing lock mode %04o without owner read/write", mode)
			}
			after, err := os.ReadFile(manifestPath)
			if err != nil || !bytes.Equal(after, before) {
				t.Fatalf("rejected lock mode changed manifest bytes: %x, %v", after, err)
			}
			lockInfo, err := os.Lstat(lock)
			if err != nil || lockInfo.Mode().Perm() != mode {
				t.Fatalf("rejected lock mode changed: %v, %v", lockInfo, err)
			}
		})
	}
}

const manifestFIFODirEnv = "CANOPY_TEST_MANIFEST_FIFO_DIR"

func TestManifestLockFIFOChild(t *testing.T) {
	dir := os.Getenv(manifestFIFODirEnv)
	if dir == "" {
		return
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted a FIFO lock")
	}
}

func TestManifestLockFIFORejectedWithoutBlocking(t *testing.T) {
	dir := privateMetadataDir(t)
	if err := Save(dir, testManifest(t)); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "manifest")
	before, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, "lock")
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(lock, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestManifestLockFIFOChild$", "-test.timeout=5s")
	cmd.Env = withoutEnv(os.Environ(), manifestFIFODirEnv)
	cmd.Env = append(cmd.Env, manifestFIFODirEnv+"="+dir)
	output, err := cmd.CombinedOutput()
	if err != nil || ctx.Err() != nil {
		t.Fatalf("FIFO lock probe failed or blocked: %v, context=%v; output=%s", err, ctx.Err(), output)
	}
	info, err := os.Lstat(lock)
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("FIFO lock was changed: %v, %v", info, err)
	}
	after, err := os.ReadFile(manifestPath)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("rejected FIFO lock changed manifest: %x, %v", after, err)
	}
}

func TestManifestRecoverBusyDuringActiveSaveAtNextRename(t *testing.T) {
	if runManifestLockReplacementSaveChild(t) {
		return
	}
	dir := privateMetadataDir(t)
	prior := testManifest(t)
	if err := Save(dir, prior); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, "lock")
	lockBefore, err := os.Lstat(lockPath)
	if err != nil || !lockBefore.Mode().IsRegular() {
		t.Fatalf("initial stable lock = %v, %v", lockBefore, err)
	}
	next := Manifest{Base: prior.Base, SparseVersion: 1, State: Clean}
	observed := false
	err = save(dir, next, func(stage string) error {
		if stage != "next-renamed" {
			return nil
		}
		observed = true
		lockAtReplace, lockErr := os.Lstat(lockPath)
		if lockErr != nil || !os.SameFile(lockBefore, lockAtReplace) {
			t.Errorf("lock identity at next-renamed changed: %v, %v", lockAtReplace, lockErr)
		}
		manifestBefore, err := os.ReadFile(filepath.Join(dir, "manifest"))
		if err != nil {
			t.Errorf("read manifest at replacement checkpoint: %v", err)
			return nil
		}
		journalBefore, err := os.ReadFile(filepath.Join(dir, "journal"))
		if err != nil {
			t.Errorf("read journal at replacement checkpoint: %v", err)
			return nil
		}
		if _, err := Recover(dir); !errors.Is(err, ErrBusy) {
			t.Errorf("Recover during active Save returned %v, want ErrBusy", err)
		}
		manifestAfter, manifestErr := os.ReadFile(filepath.Join(dir, "manifest"))
		journalAfter, journalErr := os.ReadFile(filepath.Join(dir, "journal"))
		if manifestErr != nil || !bytes.Equal(manifestAfter, manifestBefore) {
			t.Errorf("active Recover changed manifest bytes: %x, %v", manifestAfter, manifestErr)
		}
		if journalErr != nil || !bytes.Equal(journalAfter, journalBefore) {
			t.Errorf("active Recover changed journal bytes: %x, %v", journalAfter, journalErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Save after busy Recover checkpoint: %v", err)
	}
	if !observed {
		t.Fatal("active Save did not reach the next-renamed replacement checkpoint")
	}
	lockAfter, err := os.Lstat(lockPath)
	if err != nil || !os.SameFile(lockBefore, lockAfter) {
		t.Fatalf("lock identity after Save changed: %v, %v", lockAfter, err)
	}
	got, err := Load(dir)
	if err != nil || got.State != Clean || got.Base != prior.Base {
		t.Fatalf("completed Save state = %#v, %v; want explicit Clean state", got, err)
	}
}

const (
	manifestLockReplacementSaveDirEnv = "CANOPY_TEST_MANIFEST_LOCK_REPLACEMENT_SAVE_DIR"
	manifestLockReplacementCtrlEnv    = "CANOPY_TEST_MANIFEST_LOCK_REPLACEMENT_CTRL_DIR"
	manifestLockReplacementReady      = "save-paused"
	manifestLockReplacementRelease    = "save-release"
)

// TestManifestLockReplacementBlocksActiveSaveRecovery pauses a Save in a
// separate process after next has become the manifest but before the journal
// is removed. It then replaces only the reserved lock entry and exercises all
// public APIs while the Save still owns its transaction lock.
func TestManifestLockReplacementBlocksActiveSaveRecovery(t *testing.T) {
	dir := privateMetadataDir(t)
	controlDir := privateMetadataDir(t)
	prior := testManifest(t)
	if err := Save(dir, prior); err != nil {
		t.Fatal(err)
	}

	lockPath := filepath.Join(dir, "lock")
	lockBefore, err := os.Lstat(lockPath)
	if err != nil || !lockBefore.Mode().IsRegular() {
		t.Fatalf("initial lock entry = %v, %v; want regular file", lockBefore, err)
	}
	manifestPath := filepath.Join(dir, "manifest")
	journalPath := filepath.Join(dir, "journal")
	readyPath := filepath.Join(controlDir, manifestLockReplacementReady)
	releasePath := filepath.Join(controlDir, manifestLockReplacementRelease)

	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestManifestRecoverBusyDuringActiveSaveAtNextRename$",
		"-test.timeout=12s")
	cmd.Env = withoutEnv(os.Environ(), manifestLockReplacementSaveDirEnv, manifestLockReplacementCtrlEnv)
	cmd.Env = append(cmd.Env,
		manifestLockReplacementSaveDirEnv+"="+dir,
		manifestLockReplacementCtrlEnv+"="+controlDir)
	var childStdout, childStderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &childStdout, &childStderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start active Save subprocess: %v", err)
	}
	childDone := make(chan error, 1)
	go func() { childDone <- cmd.Wait() }()
	childWaited := false
	released := false
	releaseChild := func() {
		if released {
			return
		}
		released = true
		_ = os.WriteFile(releasePath, []byte("continue\n"), 0600)
	}
	defer func() {
		releaseChild()
		if !childWaited {
			select {
			case <-childDone:
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				<-childDone
			}
		}
	}()

	checkpointDeadline := time.Now().Add(8 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect active Save checkpoint: %v", err)
		}
		select {
		case childErr := <-childDone:
			childWaited = true
			t.Fatalf("Save subprocess exited before next-renamed checkpoint: %v; stdout=%q stderr=%q", childErr, childStdout.String(), childStderr.String())
		default:
		}
		if !time.Now().Before(checkpointDeadline) {
			t.Fatal("Save subprocess did not reach next-renamed checkpoint before the bounded deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}

	entryNamesBefore := manifestMetadataEntryNames(t, dir)
	manifestBefore, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest at active Save checkpoint: %v", err)
	}
	journalBefore, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("read journal at active Save checkpoint: %v", err)
	}

	// Unlinking the old name leaves the Save process's open descriptor intact.
	// The new regular file is the only directory entry the simulated actor replaces.
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("remove reserved lock entry: %v", err)
	}
	replacement, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("create replacement lock entry: %v", err)
	}
	if _, err := replacement.Write([]byte("replacement lock\n")); err != nil {
		_ = replacement.Close()
		t.Fatalf("write replacement lock entry: %v", err)
	}
	if err := replacement.Chmod(0600); err != nil {
		_ = replacement.Close()
		t.Fatalf("set replacement lock mode: %v", err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatalf("close replacement lock entry: %v", err)
	}
	lockAfterReplacement, err := os.Lstat(lockPath)
	if err != nil || !lockAfterReplacement.Mode().IsRegular() || lockAfterReplacement.Mode().Perm() != 0600 || os.SameFile(lockBefore, lockAfterReplacement) {
		t.Fatalf("lock entry was not replaced by a private new inode: before=%v after=%v err=%v", lockBefore, lockAfterReplacement, err)
	}
	requireSameManifestMetadataEntries(t, entryNamesBefore, manifestMetadataEntryNames(t, dir))

	if _, err := Recover(dir); !errors.Is(err, ErrBusy) {
		t.Errorf("Recover during active Save after lock replacement = %v, want ErrBusy", err)
	}
	requireActiveSaveBytesUnchanged(t, dir, entryNamesBefore, manifestPath, journalPath, manifestBefore, journalBefore, "Recover")
	if _, err := Load(dir); !errors.Is(err, ErrBusy) {
		t.Errorf("Load during active Save after lock replacement = %v, want ErrBusy", err)
	}
	requireActiveSaveBytesUnchanged(t, dir, entryNamesBefore, manifestPath, journalPath, manifestBefore, journalBefore, "Load")
	if err := Save(dir, replacementLockNextManifest(t)); !errors.Is(err, ErrBusy) {
		t.Errorf("Save during active Save after lock replacement = %v, want ErrBusy", err)
	}
	requireActiveSaveBytesUnchanged(t, dir, entryNamesBefore, manifestPath, journalPath, manifestBefore, journalBefore, "Save")

	releaseChild()
	select {
	case childErr := <-childDone:
		childWaited = true
		if childErr != nil {
			t.Fatalf("active Save subprocess failed after release: %v; stdout=%q stderr=%q", childErr, childStdout.String(), childStderr.String())
		}
	case <-ctx.Done():
		t.Fatalf("active Save subprocess did not finish after release before the bounded deadline: %v", ctx.Err())
	}

	want := replacementLockNextManifest(t)
	got, err := Load(dir)
	if err != nil || !manifestMatchesLockReplacementNext(got, want) {
		t.Fatalf("final Load = %#v, %v; want exact next manifest %#v", got, err, want)
	}
	if _, err := os.Lstat(journalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed Save left journal entry: %v", err)
	}
	recovered, err := Recover(dir)
	if err != nil || !manifestMatchesLockReplacementNext(recovered, want) {
		t.Fatalf("Recover after completed Save = %#v, %v; want exact next manifest %#v", recovered, err, want)
	}
}

func runManifestLockReplacementSaveChild(t *testing.T) bool {
	t.Helper()
	dir := os.Getenv(manifestLockReplacementSaveDirEnv)
	if dir == "" {
		return false
	}
	controlDir := os.Getenv(manifestLockReplacementCtrlEnv)
	if controlDir == "" {
		t.Fatal("missing lock-replacement control directory")
	}
	readyPath := filepath.Join(controlDir, manifestLockReplacementReady)
	releasePath := filepath.Join(controlDir, manifestLockReplacementRelease)
	reachedCheckpoint := false
	err := save(dir, replacementLockNextManifest(t), func(stage string) error {
		if stage != "next-renamed" {
			return nil
		}
		if reachedCheckpoint {
			return errors.New("Save reached next-renamed more than once")
		}
		reachedCheckpoint = true
		if err := os.WriteFile(readyPath, []byte("paused\n"), 0600); err != nil {
			return err
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(releasePath); err == nil {
				return nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			time.Sleep(10 * time.Millisecond)
		}
		return errors.New("timed out waiting for lock-replacement test release")
	})
	if err != nil {
		t.Fatalf("Save subprocess transaction failed: %v", err)
	}
	if !reachedCheckpoint {
		t.Fatal("Save subprocess did not reach next-renamed checkpoint")
	}
	return true
}

func replacementLockNextManifest(t *testing.T) Manifest {
	t.Helper()
	return Manifest{
		Base:          testChangeset(t, "lock-replacement next base"),
		SparseVersion: 1,
		Sparse: []model.Path{
			testPath(t, []byte{'s', 'r', 'c', '/', 0xfd}),
			testPath(t, []byte("docs/lock-replacement")),
		},
		State: Clean,
	}
}

func manifestMatchesLockReplacementNext(got, want Manifest) bool {
	if got.Base != want.Base || got.SparseVersion != 1 || got.SparseAll || got.State != Clean || len(got.DirtyPaths) != 0 {
		return false
	}
	return len(got.Sparse) == 2 &&
		bytes.Equal(got.Sparse[0].Bytes(), []byte{'s', 'r', 'c', '/', 0xfd}) &&
		bytes.Equal(got.Sparse[1].Bytes(), []byte("docs/lock-replacement"))
}

func manifestMetadataEntryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read metadata directory entries: %v", err)
	}
	names := make([]string, len(entries))
	for i := range entries {
		names[i] = entries[i].Name()
	}
	return names
}

func requireSameManifestMetadataEntries(t *testing.T, want, got []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("metadata directory entry count = %v, want %v", got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("metadata directory entries = %v, want %v", got, want)
			return
		}
	}
}

func requireActiveSaveBytesUnchanged(t *testing.T, dir string, entryNamesBefore []string, manifestPath, journalPath string, manifestBefore, journalBefore []byte, api string) {
	t.Helper()
	requireSameManifestMetadataEntries(t, entryNamesBefore, manifestMetadataEntryNames(t, dir))
	manifestAfter, err := os.ReadFile(manifestPath)
	if err != nil || !bytes.Equal(manifestAfter, manifestBefore) {
		t.Errorf("%s during active Save changed manifest bytes: %x, %v", api, manifestAfter, err)
	}
	journalAfter, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(journalAfter, journalBefore) {
		t.Errorf("%s during active Save changed or removed journal bytes: %x, %v", api, journalAfter, err)
	}
}

func TestManifestRootAnchorSurvivesDirectoryRename(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "metadata")
	moved := filepath.Join(parent, "metadata-moved")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	prior := testManifest(t)
	if err := Save(dir, prior); err != nil {
		t.Fatal(err)
	}
	next := Manifest{Base: prior.Base, SparseVersion: 1, State: Clean}
	sentinel := []byte("decoy directory must remain untouched\x00")
	decoyCreated := false
	err := save(dir, next, func(stage string) error {
		if stage != "journal-created" || decoyCreated {
			return nil
		}
		if err := os.Rename(dir, moved); err != nil {
			return err
		}
		if err := os.Mkdir(dir, 0700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "user-content"), sentinel, 0600); err != nil {
			return err
		}
		decoyCreated = true
		return nil
	})
	if err != nil {
		t.Fatalf("Save after metadata directory rename: %v", err)
	}
	if !decoyCreated {
		t.Fatal("Save did not reach the rename checkpoint")
	}
	got, err := Load(moved)
	if err != nil || got.State != Clean || got.Base != prior.Base {
		t.Fatalf("anchored metadata at renamed directory = %#v, %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "manifest")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Save wrote a manifest into the replacement pathname: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "user-content" {
		t.Fatalf("replacement directory entries = %v, %v; want only untouched user-content", entries, err)
	}
	gotSentinel, err := os.ReadFile(filepath.Join(dir, "user-content"))
	if err != nil || !bytes.Equal(gotSentinel, sentinel) {
		t.Fatalf("replacement directory user content changed: %x, %v", gotSentinel, err)
	}
}
