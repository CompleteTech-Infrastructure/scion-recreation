package workspace

import (
	"errors"
	"sort"
	"strings"

	"canopy.local/canopy/internal/model"
)

var ErrSparseSelection = errors.New("invalid sparse selection")

// SparseSelection is the immutable literal-prefix selection already defined by
// Manifest sparse version 1. It is not a glob parser, exclusion language, access
// grant, checkout plan or permission projection. Callers must intersect results
// with current authorized visibility before fetching or materializing anything.
// No filesystem or repository traversal is performed here.
type SparseSelection struct {
	all bool
	prefixes map[string]struct{}
	ordered []string
}

// CompileSparseSelection accepts exactly manifest v1 semantics: all selects the
// root, an empty prefix list selects nothing, and every other entry selects its
// exact byte path and descendants. Special-looking bytes remain literal. Unknown
// versions and ambiguous all-plus-prefix input fail closed. Count and aggregate
// encoding bounds match the sparse portion of a minimal manifest record.
func CompileSparseSelection(version uint16, all bool, prefixes []model.Path) (*SparseSelection, error) {
	if version != 1 || len(prefixes) > MaxPaths || all && len(prefixes) != 0 {
		return nil, ErrSparseSelection
	}
	// Fixed manifest framing and fields, with no dirty path hints.
	n := 44 + model.TypedIDSize + 4 + 8
	for _, p := range prefixes {
		if p.Validate() != nil {
			return nil, ErrSparseSelection
		}
		n += 4 + len(p.Bytes())
		if n > MaxManifestBytes {
			return nil, ErrSparseSelection
		}
	}
	s := &SparseSelection{all: all, prefixes: make(map[string]struct{}, len(prefixes))}
	for _, p := range prefixes {
		key := string(p.Bytes())
		if _, exists := s.prefixes[key]; !exists {
			s.prefixes[key] = struct{}{}
			s.ordered = append(s.ordered, key)
		}
	}
	sort.Strings(s.ordered)
	return s, nil
}

// Empty permits pruning the root without listing it. A nil selection fails
// closed. A valid all selection is nonempty even if the actual tree is empty.
func (s *SparseSelection) Empty() bool {
	return s == nil || !s.all && len(s.ordered) == 0
}

func (s *SparseSelection) selects(path string) bool {
	if s.all {
		return true
	}
	if _, ok := s.prefixes[path]; ok {
		return true
	}
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			if _, ok := s.prefixes[path[:i]]; ok {
				return true
			}
		}
	}
	return false
}

// Selects reports only literal sparse membership of a canonical non-root path.
// Ancestors of a selected prefix are not themselves selected leaf content.
func (s *SparseSelection) Selects(path model.Path) bool {
	return s != nil && path.Validate() == nil && s.selects(string(path.Bytes()))
}

// MayContain reports whether a canonical directory path is selected or could
// contain a selected descendant. False permits subtree pruning without listing
// it. True proves neither existence nor authorization and must not cause hidden
// names or unrelated leaf contents to be materialized. Use Empty for the root.
func (s *SparseSelection) MayContain(directory model.Path) bool {
	if s == nil || directory.Validate() != nil {
		return false
	}
	path := string(directory.Bytes())
	if s.selects(path) {
		return true
	}
	prefix := path + "/"
	i := sort.SearchStrings(s.ordered, prefix)
	return i < len(s.ordered) && strings.HasPrefix(s.ordered[i], prefix)
}
