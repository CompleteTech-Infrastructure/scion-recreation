package workspace

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
