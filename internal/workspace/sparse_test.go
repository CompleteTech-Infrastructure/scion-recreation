package workspace

import (
	"bytes"
	"testing"

	"canopy.local/canopy/internal/model"
)

func TestSparseLiteralMembershipAndPruning(t *testing.T) {
	paths := []model.Path{testPath(t, []byte("a/b")), testPath(t, []byte("a-")), testPath(t, []byte{'x', '/', 0xff}), testPath(t, []byte("*.go"))}
	s, err := CompileSparseSelection(1, false, paths)
	if err != nil { t.Fatal(err) }
	for _, tc := range []struct { path string; selected, descend bool }{
		{"a", false, true}, {"a/b", true, true}, {"a/b/c", true, true},
		{"ab", false, false}, {"a/bc", false, false}, {"a-", true, true},
		{"x", false, true}, {"x/\xff", true, true}, {"x/\xfe", false, false},
		{"*.go", true, true}, {"main.go", false, false}, {"A/b", false, false},
	} {
		p := testPath(t, []byte(tc.path))
		if s.Selects(p) != tc.selected || s.MayContain(p) != tc.descend {
			t.Fatalf("path %q: selected=%v descend=%v", tc.path, s.Selects(p), s.MayContain(p))
		}
	}
	paths[0] = testPath(t, []byte("changed"))
	if !s.Selects(testPath(t, []byte("a/b"))) || s.Selects(paths[0]) { t.Fatal("selection aliases caller slice") }
}

func TestSparseValidationAndEmptyAll(t *testing.T) {
	p := testPath(t, []byte("a"))
	for _, tc := range []struct { version uint16; all bool; paths []model.Path }{
		{0, false, nil}, {2, false, nil}, {1, true, []model.Path{p}},
		{1, false, []model.Path{{}}}, {1, false, make([]model.Path, MaxPaths+1)},
	} {
		if s, err := CompileSparseSelection(tc.version, tc.all, tc.paths); s != nil || err != ErrSparseSelection { t.Fatal("invalid selection accepted") }
	}
	for _, all := range []bool{false, true} {
		s, err := CompileSparseSelection(1, all, nil)
		if err != nil || s.Empty() == all || s.Selects(p) != all || s.MayContain(p) != all { t.Fatalf("all=%v: %v", all, err) }
		if s.Selects(model.Path{}) || s.MayContain(model.Path{}) { t.Fatal("zero path accepted") }
	}
	var s *SparseSelection
	if !s.Empty() || s.Selects(p) || s.MayContain(p) { t.Fatal("nil selection did not deny") }
}

func TestSparseAggregateBoundaryAndDuplicates(t *testing.T) {
	// Fill the manifest-size boundary with repeated maximum-sized records
	// and one final path. Duplicates count toward admission before deduplication.
	large := testPath(t, bytes.Repeat([]byte{'x'}, 65531))
	paths := make([]model.Path, 63)
	for i := range paths { paths[i] = large }
	remaining := MaxManifestBytes - (91 + 63*(4+65531))
	paths = append(paths, testPath(t, bytes.Repeat([]byte{'y'}, remaining-4)))
	s, err := CompileSparseSelection(1, false, paths)
	if err != nil || len(s.ordered) != 2 || !s.Selects(large) { t.Fatalf("exact boundary/duplicates: %v", err) }
	paths[len(paths)-1] = testPath(t, bytes.Repeat([]byte{'y'}, remaining-3))
	if s, err := CompileSparseSelection(1, false, paths); s != nil || err != ErrSparseSelection { t.Fatal("aggregate overflow accepted") }
}
