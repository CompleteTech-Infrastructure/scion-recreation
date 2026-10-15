// Package workspace persists local workspace metadata. It never reads or writes
// workspace content. Callers must durably record dirty/uncertain state BEFORE
// touching content, and may explicitly save Clean only after reconciliation and
// durable content writes. A manifest is neither object verification nor access.
package workspace

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"syscall"

	"canopy.local/canopy/internal/model"
)

const (
	MaxManifestBytes = 4 << 20
	MaxPaths         = 4096
)

type DirtyState uint8

const (
	Clean DirtyState = iota + 1
	Dirty
	Uncertain
)

var (
	ErrCorrupt          = errors.New("corrupt workspace metadata")
	ErrRecoveryRequired = errors.New("workspace metadata recovery required")
	ErrBusy             = errors.New("workspace metadata busy")
)

// Manifest uses accepted canonical changeset IDs and byte paths. Sparse syntax
// version 1 is an ordered list of literal subtree prefixes, without globbing or
// normalization. SparseAll selects the root; an empty list otherwise selects
// nothing. DirtyPaths are hints, never an exhaustive claim when Uncertain.
type Manifest struct {
	Base          model.ChangesetID
	SparseVersion uint16
	SparseAll     bool
	Sparse        []model.Path
	State         DirtyState
	DirtyPaths    []model.Path
}

func encode(m Manifest) ([]byte, error) {
	if m.Base.Validate() != nil || m.SparseVersion != 1 || m.SparseAll && len(m.Sparse) != 0 ||
		m.State < Clean || m.State > Uncertain || m.State == Clean && len(m.DirtyPaths) != 0 ||
		m.State == Dirty && len(m.DirtyPaths) == 0 {
		return nil, ErrCorrupt
	}
	n := 44 + model.TypedIDSize + 4 + 8
	for _, paths := range [][]model.Path{m.Sparse, m.DirtyPaths} {
		if len(paths) > MaxPaths {
			return nil, ErrCorrupt
		}
		for _, p := range paths {
			if p.Validate() != nil {
				return nil, ErrCorrupt
			}
			n += 4 + len(p.Bytes())
			if n > MaxManifestBytes {
				return nil, ErrCorrupt
			}
		}
	}
	b := make([]byte, 44, n)
	copy(b, "CNWSJ001")
	id, _ := m.Base.TypedID().MarshalBinary()
	b = append(b, id...)
	b = binary.BigEndian.AppendUint16(b, m.SparseVersion)
	all := byte(0)
	if m.SparseAll {
		all = 1
	}
	b = append(b, all, byte(m.State))
	for _, paths := range [][]model.Path{m.Sparse, m.DirtyPaths} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(paths)))
		for _, p := range paths {
			raw := p.Bytes()
			b = binary.BigEndian.AppendUint32(b, uint32(len(raw)))
			b = append(b, raw...)
		}
	}
	binary.BigEndian.PutUint32(b[8:12], uint32(len(b)-44))
	sum := sha256.Sum256(b[44:])
	copy(b[12:44], sum[:])
	return b, nil
}

func decode(b []byte) (Manifest, error) {
	var m Manifest
	if len(b) < 91 || len(b) > MaxManifestBytes || string(b[:8]) != "CNWSJ001" ||
		uint64(binary.BigEndian.Uint32(b[8:12])) != uint64(len(b)-44) {
		return m, ErrCorrupt
	}
	sum := sha256.Sum256(b[44:])
	if !bytes.Equal(b[12:44], sum[:]) {
		return m, ErrCorrupt
	}
	var err error
	m.Base, err = model.ParseChangesetID(b[44:79])
	if err != nil || b[81] > 1 {
		return Manifest{}, ErrCorrupt
	}
	m.SparseVersion, m.SparseAll, m.State = binary.BigEndian.Uint16(b[79:81]), b[81] == 1, DirtyState(b[82])
	b = b[83:]
	for _, out := range []*[]model.Path{&m.Sparse, &m.DirtyPaths} {
		if len(b) < 4 {
			return Manifest{}, ErrCorrupt
		}
		count := uint64(binary.BigEndian.Uint32(b[:4]))
		b = b[4:]
		if count > MaxPaths || count > uint64(len(b))/5 {
			return Manifest{}, ErrCorrupt
		}
		for i := uint64(0); i < count; i++ {
			if len(b) < 4 {
				return Manifest{}, ErrCorrupt
			}
			n := uint64(binary.BigEndian.Uint32(b[:4]))
			b = b[4:]
			if n > model.MaxPathBytes || n > uint64(len(b)) {
				return Manifest{}, ErrCorrupt
			}
			p, err := model.NewPath(b[:int(n)])
			if err != nil {
				return Manifest{}, ErrCorrupt
			}
			*out = append(*out, p)
			b = b[int(n):]
		}
	}
	if len(b) != 0 {
		return Manifest{}, ErrCorrupt
	}
	if _, err := encode(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

type metadata struct {
	root *os.Root
	lock *os.File
}

// The directory is dedicated metadata, must already exist and be private to the
// current UID. A per-directory advisory lock serializes only these small metadata
// transactions, including recovery. No repository/content lock is acquired.
func openMetadata(dir string) (*metadata, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	m := &metadata{root: r}
	info, err := r.Stat(".")
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
			err = errors.New("workspace metadata directory must be private and owned")
		}
	}
	if err == nil {
		m.lock, err = r.OpenFile("lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	}
	if err == nil {
		err = privateRegular(m.lock)
	}
	if err == nil {
		err = syscall.Flock(int(m.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if errors.Is(err, syscall.EWOULDBLOCK) {
			err = ErrBusy
		}
	}
	if err != nil {
		m.close()
		return nil, err
	}
	return m, nil
}

func privateRegular(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return ErrCorrupt
	}
	return nil
}
func (m *metadata) close() {
	if m.lock != nil {
		m.lock.Close() // Closing releases flock even after an interrupted operation.
	}
	m.root.Close()
}
func (m *metadata) sync() error {
	f, err := m.root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (m *metadata) read(name string) (Manifest, error) {
	f, err := m.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	if err := privateRegular(f); err != nil {
		return Manifest{}, err
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	if err != nil {
		return Manifest{}, err
	}
	return decode(b)
}
func (m *metadata) pending() error {
	for _, name := range []string{"intent", "journal", "next"} {
		if _, err := m.root.Lstat(name); err == nil {
			return ErrRecoveryRequired
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
func checkpoint(hook func(string) error, stage string) error {
	if hook != nil {
		return hook(stage)
	}
	return nil
}
func (m *metadata) write(name string, b []byte, hook func(string) error) (err error) {
	f, err := m.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	if err = checkpoint(hook, name+"-created"); err == nil {
		var n int
		n, err = f.Write(b)
		if err == nil && n != len(b) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = checkpoint(hook, name+"-written")
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = checkpoint(hook, name+"-synced")
	}
	return err
}

// Load never supplies an implicit clean/default state on missing, pending,
// inaccessible or corrupt metadata. An error invalidates the returned value.
func Load(dir string) (Manifest, error) {
	m, err := openMetadata(dir)
	if err != nil {
		return Manifest{}, err
	}
	defer m.close()
	if err = m.pending(); err != nil {
		return Manifest{}, err
	}
	return m.read("manifest")
}

// Save commits only metadata. On any error, callers must stop content operations
// and Load/Recover before proceeding. Successful Clean is an explicit caller
// assertion; this package cannot infer cleanliness from the filesystem.
func Save(dir string, next Manifest) error { return save(dir, next, nil) }
func save(dir string, next Manifest, hook func(string) error) error {
	b, err := encode(next)
	if err != nil {
		return err
	}
	m, err := openMetadata(dir)
	if err != nil {
		return err
	}
	defer m.close()
	if err = m.pending(); err != nil {
		return err
	}
	prior, err := m.read("manifest")
	if errors.Is(err, os.ErrNotExist) {
		prior = next
	} else if err != nil {
		return err
	}
	prior.State = Uncertain
	seen := make(map[model.Path]bool)
	paths := make([]model.Path, 0)
	for _, list := range [][]model.Path{prior.DirtyPaths, next.DirtyPaths} {
		for _, p := range list {
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}
	prior.DirtyPaths = paths
	recovery, err := encode(prior)
	if err != nil {
		return err
	}
	// Publish only a complete, synced journal. An incomplete intent cannot have
	// changed the active manifest and can be discarded by explicit recovery.
	if err = m.write("intent", recovery, func(stage string) error {
		return checkpoint(hook, "journal"+stage[len("intent"):])
	}); err != nil {
		return err
	}
	if err = m.root.Rename("intent", "journal"); err != nil {
		return err
	}
	if err = checkpoint(hook, "journal-renamed"); err != nil {
		return err
	}
	if err = m.sync(); err != nil {
		return err
	}
	if err = checkpoint(hook, "journal-dir-synced"); err != nil {
		return err
	}
	return m.install(b, hook)
}

func (m *metadata) install(b []byte, hook func(string) error) error {
	if err := m.write("next", b, hook); err != nil {
		return err
	}
	if err := m.root.Rename("next", "manifest"); err != nil {
		return err
	}
	if err := checkpoint(hook, "next-renamed"); err != nil {
		return err
	}
	if err := m.sync(); err != nil {
		return err
	}
	if err := checkpoint(hook, "manifest-dir-synced"); err != nil {
		return err
	}
	if err := m.root.Remove("journal"); err != nil {
		return err
	}
	if err := checkpoint(hook, "journal-removed"); err != nil {
		return err
	}
	if err := m.sync(); err != nil {
		return err
	}
	return checkpoint(hook, "final-dir-synced")
}

// Recover persists the journal's conservative state, retaining the prior base
// and selection and the union of dirty hints. It never labels content clean.
// Corrupt/torn published journals remain untouched for explicit repair; no
// fallback is safe. An unpublished intent precedes all manifest changes and
// is discarded explicitly, returning the intact prior manifest (or missing).
// Recovery is repeatable after process loss at any installation boundary.
func Recover(dir string) (Manifest, error) {
	return recoverMetadata(dir, nil)
}
func recoverMetadata(dir string, hook func(string) error) (Manifest, error) {
	m, err := openMetadata(dir)
	if err != nil {
		return Manifest{}, err
	}
	defer m.close()
	recovery, err := m.read("journal")
	if errors.Is(err, os.ErrNotExist) {
		if _, err := m.root.Lstat("next"); err == nil {
			return Manifest{}, ErrRecoveryRequired
		} else if !errors.Is(err, os.ErrNotExist) {
			return Manifest{}, err
		}
		prior, err := m.read("manifest")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return Manifest{}, err
		}
		if removeErr := m.root.Remove("intent"); removeErr == nil {
			if syncErr := m.sync(); syncErr != nil {
				return Manifest{}, syncErr
			}
		} else if !errors.Is(removeErr, os.ErrNotExist) {
			return Manifest{}, removeErr
		}
		return prior, err
	}
	if err != nil {
		return Manifest{}, err
	}
	if recovery.State != Uncertain {
		return Manifest{}, ErrCorrupt
	}
	b, err := encode(recovery)
	if err != nil {
		return Manifest{}, err
	}
	if err = m.root.Remove("next"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	if err = m.install(b, hook); err != nil {
		return Manifest{}, err
	}
	return recovery, nil
}
