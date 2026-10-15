// Package fixtures produces small, deterministic source records and explicit
// oracles for correctness tests. It imports no native implementation or Git.
// Synthetic source IDs below are neither native typed IDs nor Git object IDs.
package fixtures

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	SchemaVersion               = 1
	FixtureVersion              = "adversarial-source-v1"
	MaxWidth                    = 64
	MaxDepth                    = 16
	MaxCommits                  = 32
	MaxEntries                  = 128
	MaxPathBytes                = 1024
	MaxContentBytes             = 256
	MaxRecordBytes              = 4096 // Negative fixture decoder input cap only.
	MaxSourceRecordBytes        = 32768
	Regular              uint32 = 0100644
	Executable           uint32 = 0100755
	Symlink              uint32 = 0120000
)

type Config struct {
	Seed         uint64
	Width, Depth int
}

// All byte-bearing fields use []byte so JSON preserves even invalid UTF-8 via
// base64. Ordering is unsigned raw-byte order, never host or display order.
type Entry struct {
	Path          []byte
	Mode          uint32
	Content       []byte
	ContentSHA256 string
}
type Operation struct {
	Path    []byte
	Delete  bool
	Mode    uint32
	Content []byte
}
type Commit struct {
	ID, Label          string
	Parents            []string
	Message, RawRecord []byte
	Operations         []Operation
}
type TreeOracle struct {
	Commit  string
	Entries []Entry
}
type QueryOracle struct {
	Left, Right         string
	LeftIsAncestor      bool
	BestCommonAncestors []string
}
type Repository struct {
	Name    string
	Commits []Commit
	Trees   []TreeOracle
	Queries []QueryOracle
}
type ApplicationInput struct {
	Name       string
	Base       []Entry
	Operations []Operation
	Expected   []Entry
	Outcome    string
}

type MergeInput struct {
	Name              string
	Base, Left, Right []Entry
	Policy            string
	Expected          []Entry
	Conflicts         [][]byte
}

// Disposition names a specific host profile, not a probe of the running host.
// No fixture is materialized to a filesystem by this package.
type Disposition struct {
	Repository, Commit, Profile, Reason string
	Paths                               [][]byte
}
type Negative struct {
	Name, InputKind string
	Raw             []byte
	Expected        string
}
type Manifest struct {
	SchemaVersion                                      int
	FixtureVersion, SourceIdentityScheme, OraclePolicy string
	Config                                             Config
	Repositories                                       []Repository
	Applications                                       []ApplicationInput
	Merges                                             []MergeInput
	Negatives                                          []Negative
	HostDispositions                                   []Disposition
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func entry(path string, mode uint32, content []byte) Entry {
	return Entry{[]byte(path), mode, append([]byte{}, content...), digest(content)}
}
func set(path string, mode uint32, content []byte) Operation {
	return Operation{Path: []byte(path), Mode: mode, Content: append([]byte{}, content...)}
}
func sortedEntries(e []Entry) []Entry {
	sort.Slice(e, func(i, j int) bool { return bytes.Compare(e[i].Path, e[j].Path) < 0 })
	return e
}
func sortedOps(o []Operation) []Operation {
	sort.Slice(o, func(i, j int) bool { return bytes.Compare(o[i].Path, o[j].Path) < 0 })
	return o
}

// Generate is bounded by the constants above; input values have no implicit
// defaults. Seed affects source payloads, not which required adversarial cases
// exist. Width and Depth select the bounded wide-tree and linear-history sizes.
func Generate(c Config) (Manifest, error) {
	if c.Width < 1 || c.Width > MaxWidth || c.Depth < 1 || c.Depth > MaxDepth {
		return Manifest{}, fmt.Errorf("width must be 1..%d and depth 1..%d", MaxWidth, MaxDepth)
	}
	m := Manifest{SchemaVersion: SchemaVersion, FixtureVersion: FixtureVersion, Config: c,
		SourceIdentityScheme: "fixture-sha256: SHA-256 of exact RawRecord; not Git/native IDs",
		OraclePolicy:         "bounded transitive closure; simultaneous first-parent leaf delta; named whole-entry three-way cases"}
	m.Repositories = append(m.Repositories, Repository{Name: "empty", Commits: []Commit{}, Trees: []TreeOracle{}, Queries: []QueryOracle{}})
	payload := []byte(fmt.Sprintf("seed=%d\n", c.Seed))
	files := []Operation{
		set("A", Regular, []byte("upper")), set("CON", Regular, []byte("reserved host name")), set("a", Regular, []byte("lower")),
		set("binary", Regular, []byte{0, 1, 0xff, 10, 0}), set("empty", Regular, []byte{}),
		set("exec", Executable, payload), set("link", Symlink, []byte("../target")),
		set("regular", Regular, payload), set("raw/\xff", Regular, []byte{0xff}),
		set("e\u0301", Regular, []byte("NFD")), set("\u00e9", Regular, []byte("NFC")),
		set("literal\\name", Regular, []byte("backslash")), set("%2e%2e", Regular, []byte("percent")),
		set(strings.Repeat("l", 300), Regular, []byte("long component")),
	}
	core := newBuilder("core", c.Seed)
	core.add("root", nil, nil, []byte{0xff})
	core.add("files", []string{"root"}, sortedOps(files), nil)
	core.add("empty-commit", []string{"files"}, nil, nil)
	core.add("mode-only", []string{"empty-commit"}, []Operation{set("regular", Executable, payload)}, nil)
	core.add("delete", []string{"mode-only"}, []Operation{{Path: []byte("binary"), Delete: true}}, nil)
	m.Repositories = append(m.Repositories, core.repo)
	cross := newBuilder("criss-cross", c.Seed)
	cross.add("r", nil, nil, nil)
	cross.add("a", []string{"r"}, []Operation{set("left", Regular, []byte("L"))}, nil)
	cross.add("b", []string{"r"}, []Operation{set("right", Regular, []byte("R"))}, nil)
	cross.add("ab", []string{"a", "b"}, nil, nil)
	cross.add("ba", []string{"b", "a"}, nil, nil)
	cross.add("unrelated", nil, nil, nil)
	// Repeated parent IDs are valid source sequence data in the canonical v1
	// contract. Preserve them; only the oracle's reachability relation deduplicates.
	cross.add("repeated-parent", []string{"a", "a"}, nil, nil)
	m.Repositories = append(m.Repositories, cross.repo)
	wide := newBuilder("wide", c.Seed)
	var ops []Operation
	for i := 0; i < c.Width; i++ {
		ops = append(ops, set(fmt.Sprintf("wide/f%03d", i), Regular, []byte(fmt.Sprintf("%d:%d", c.Seed, i))))
	}
	wide.add("root", nil, ops, nil)
	m.Repositories = append(m.Repositories, wide.repo)
	chain := newBuilder("chain", c.Seed)
	for i := 0; i < c.Depth; i++ {
		var parents []string
		if i > 0 {
			parents = []string{fmt.Sprintf("c%02d", i-1)}
		}
		chain.add(fmt.Sprintf("c%02d", i), parents, nil, nil)
	}
	m.Repositories = append(m.Repositories, chain.repo)
	for i := range m.Repositories {
		r := &m.Repositories[i]
		var err error
		r.Trees, r.Queries, err = referenceRepository(*r)
		if err != nil {
			return Manifest{}, err
		}
	}
	m.Applications = applicationCases()
	m.Merges = mergeCases()
	m.Negatives = negativeCases()
	for _, r := range m.Repositories {
		for _, t := range r.Trees {
			for _, e := range t.Entries {
				switch {
				case bytes.Equal(e.Path, []byte("A")):
					m.HostDispositions = append(m.HostDispositions, Disposition{r.Name, t.Commit, "case-insensitive", "case collision", [][]byte{[]byte("A"), []byte("a")}})
				case bytes.Equal(e.Path, []byte("\u00e9")):
					m.HostDispositions = append(m.HostDispositions, Disposition{r.Name, t.Commit, "unicode-normalizing", "normalization collision", [][]byte{[]byte("e\u0301"), []byte("\u00e9")}})
				case bytes.Equal(e.Path, []byte("raw/\xff")):
					m.HostDispositions = append(m.HostDispositions, Disposition{r.Name, t.Commit, "utf8-only", "non-UTF-8 path", [][]byte{e.Path}})
				case len(e.Path) == 300:
					m.HostDispositions = append(m.HostDispositions, Disposition{r.Name, t.Commit, "component-limit-255", "component exceeds 255 bytes", [][]byte{e.Path}})
				case bytes.Equal(e.Path, []byte("CON")):
					m.HostDispositions = append(m.HostDispositions, Disposition{r.Name, t.Commit, "windows-reserved-name", "reserved device name; cannot materialize", [][]byte{e.Path}})
				case bytes.Equal(e.Path, []byte("literal\\name")):
					m.HostDispositions = append(m.HostDispositions, Disposition{r.Name, t.Commit, "windows-path-syntax", "backslash is not representable as a literal name", [][]byte{e.Path}})
				case e.Mode == Symlink:
					m.HostDispositions = append(m.HostDispositions, Disposition{r.Name, t.Commit, "safe-checkout", "reject checkout: root-level symlink escapes checkout root", [][]byte{e.Path}})
				}
			}
		}
	}
	return m, nil
}

type builder struct {
	repo Repository
	seed uint64
	ids  map[string]string
}

func newBuilder(name string, seed uint64) *builder {
	return &builder{repo: Repository{Name: name}, seed: seed, ids: map[string]string{}}
}
func (b *builder) add(label string, parents []string, ops []Operation, message []byte) {
	ids := []string{}
	for _, p := range parents {
		ids = append(ids, b.ids[p])
	}
	if ops == nil {
		ops = []Operation{}
	}
	if message == nil {
		message = []byte{}
	}
	// JSON has only fixed structs and ordered slices; source record format is
	// deliberately fixture-specific and versioned, not a canonical native frame.
	raw, err := json.Marshal(struct {
		Version, Repository, Label string
		Seed                       uint64
		Parents                    []string
		Operations                 []Operation
		Message                    []byte
	}{FixtureVersion, b.repo.Name, label, b.seed, ids, ops, message})
	if err != nil {
		panic(err)
	}
	id := "fixture-sha256:" + digest(raw)
	b.ids[label] = id
	b.repo.Commits = append(b.repo.Commits, Commit{id, label, ids, message, raw, ops})
}

// referenceRepository is intentionally cubic, capped at 32 nodes. It is a
// truth-table oracle, not an implementation/accelerator of a production query.
func referenceRepository(r Repository) ([]TreeOracle, []QueryOracle, error) {
	n := len(r.Commits)
	if n > MaxCommits {
		return nil, nil, fmt.Errorf("commit budget")
	}
	indices := map[string]int{}
	reach := make([][]bool, n)
	trees := []TreeOracle{}
	for i, c := range r.Commits {
		if len(c.RawRecord) > MaxSourceRecordBytes {
			return nil, nil, fmt.Errorf("source record budget")
		}
		if _, ok := indices[c.ID]; ok {
			return nil, nil, fmt.Errorf("duplicate ID")
		}
		indices[c.ID] = i
		reach[i] = make([]bool, n)
		reach[i][i] = true
	}
	for i, c := range r.Commits {
		var base []Entry
		for j, p := range c.Parents {
			k, ok := indices[p]
			if !ok || k >= i {
				return nil, nil, fmt.Errorf("missing/noncausal parent")
			}
			reach[k][i] = true
			if j == 0 {
				base = trees[k].Entries
			}
		}
		tree, outcome := referenceApply(base, c.Operations)
		if outcome != "accept" {
			return nil, nil, fmt.Errorf("source %s: %s", c.Label, outcome)
		}
		trees = append(trees, TreeOracle{c.ID, tree})
	}
	for k := 0; k < n; k++ {
		for i := 0; i < n; i++ {
			for j := 0; j < n; j++ {
				reach[i][j] = reach[i][j] || (reach[i][k] && reach[k][j])
			}
		}
	}
	queries := []QueryOracle{}
	for i, a := range r.Commits {
		for j, b := range r.Commits {
			bases := []string{}
			for k, node := range r.Commits {
				if !reach[k][i] || !reach[k][j] {
					continue
				}
				best := true
				for d := 0; d < n; d++ {
					if d != k && reach[k][d] && reach[d][i] && reach[d][j] {
						best = false
					}
				}
				if best {
					bases = append(bases, node.ID)
				}
			}
			sort.Strings(bases)
			queries = append(queries, QueryOracle{a.ID, b.ID, reach[i][j], bases})
		}
	}
	return trees, queries, nil
}

func validPath(p []byte) bool {
	if len(p) == 0 || len(p) > MaxPathBytes || bytes.IndexByte(p, 0) >= 0 {
		return false
	}
	for _, part := range bytes.Split(p, []byte{'/'}) {
		if len(part) == 0 || bytes.Equal(part, []byte(".")) || bytes.Equal(part, []byte("..")) {
			return false
		}
	}
	return true
}
func validMode(m uint32) bool { return m == Regular || m == Executable || m == Symlink }

// referenceApply scans complete small leaf lists. Deltas are simultaneous and
// additional merge parents do not union trees. It never touches host paths.
func referenceApply(base []Entry, ops []Operation) ([]Entry, string) {
	if len(base) > MaxEntries || len(ops) > MaxEntries {
		return nil, "resource_exhausted"
	}
	for i, o := range ops {
		if !validPath(o.Path) {
			return nil, "invalid_path"
		}
		if i > 0 && bytes.Compare(ops[i-1].Path, o.Path) >= 0 {
			return nil, "invalid_order"
		}
		if len(o.Content) > MaxContentBytes {
			return nil, "resource_exhausted"
		}
		if o.Delete {
			if o.Mode != 0 || len(o.Content) != 0 {
				return nil, "invalid_record"
			}
		} else if !validMode(o.Mode) {
			return nil, "unknown_mode"
		}
	}
	out := []Entry{}
	for _, e := range base {
		replaced := false
		for _, o := range ops {
			if bytes.Equal(e.Path, o.Path) {
				replaced = true
			}
		}
		if !replaced {
			out = append(out, e)
		}
	}
	for _, o := range ops {
		if !o.Delete {
			out = append(out, entry(string(o.Path), o.Mode, o.Content))
		}
	}
	sortedEntries(out)
	if len(out) > MaxEntries {
		return nil, "resource_exhausted"
	}
	for i, a := range out {
		for j, b := range out {
			if i != j && bytes.HasPrefix(b.Path, append(append([]byte{}, a.Path...), '/')) {
				return nil, "leaf_conflict"
			}
		}
	}
	return out, "accept"
}

// The contract's simultaneous-delta examples are literal, independent oracle
// rows; generation does not calculate these expected results from operations.
func applicationCases() []ApplicationInput {
	x := []byte("X")
	return []ApplicationInput{
		{"file-to-directory", []Entry{entry("a", Regular, x)}, []Operation{{Path: []byte("a"), Delete: true}, set("a/b", Regular, x)}, []Entry{entry("a/b", Regular, x)}, "accept"},
		{"directory-to-file", []Entry{entry("a/b", Regular, x), entry("a/c", Regular, x)}, []Operation{set("a", Regular, x), {Path: []byte("a/b"), Delete: true}, {Path: []byte("a/c"), Delete: true}}, []Entry{entry("a", Regular, x)}, "accept"},
		{"partial-directory-removal", []Entry{entry("a/b", Regular, x), entry("a/c", Regular, x)}, []Operation{set("a", Regular, x), {Path: []byte("a/b"), Delete: true}}, nil, "leaf_conflict"},
		{"absent-delete", []Entry{}, []Operation{{Path: []byte("a"), Delete: true}}, []Entry{}, "accept"},
		{"final-leaf-conflict", []Entry{}, []Operation{set("a", Regular, x), set("a/b", Regular, x)}, nil, "leaf_conflict"},
	}
}

func mergeCases() []MergeInput {
	e := func(s string) Entry { return entry("f", Regular, []byte(s)) }
	base := e("base\n")
	left := e("left\n")
	right := e("right\n")
	// Expected values are declared by hand, not calculated by a merger. The
	// bounded policy compares entire (mode,content) entries, including absence;
	// it intentionally makes no line/hunk/rename or virtual-base merge claim.
	return []MergeInput{
		{"unchanged", []Entry{base}, []Entry{base}, []Entry{base}, "whole-entry-v1", []Entry{base}, [][]byte{}},
		{"one-side", []Entry{base}, []Entry{left}, []Entry{base}, "whole-entry-v1", []Entry{left}, [][]byte{}},
		{"equal-edits", []Entry{base}, []Entry{left}, []Entry{left}, "whole-entry-v1", []Entry{left}, [][]byte{}},
		{"disjoint-paths", []Entry{}, []Entry{entry("a", Regular, []byte("A\n"))}, []Entry{entry("b", Executable, []byte("B"))}, "whole-entry-v1", []Entry{entry("a", Regular, []byte("A\n")), entry("b", Executable, []byte("B"))}, [][]byte{}},
		{"text-conflict", []Entry{base}, []Entry{left}, []Entry{right}, "whole-entry-v1", []Entry{}, [][]byte{[]byte("f")}},
		{"delete-modify", []Entry{base}, []Entry{}, []Entry{left}, "whole-entry-v1", []Entry{}, [][]byte{[]byte("f")}},
		{"both-delete", []Entry{base}, []Entry{}, []Entry{}, "whole-entry-v1", []Entry{}, [][]byte{}},
		{"mode-only", []Entry{base}, []Entry{entry("f", Executable, base.Content)}, []Entry{base}, "whole-entry-v1", []Entry{entry("f", Executable, base.Content)}, [][]byte{}},
		{"symlink-conflict", []Entry{entry("f", Symlink, []byte("x"))}, []Entry{entry("f", Symlink, []byte("y"))}, []Entry{entry("f", Symlink, []byte("z"))}, "whole-entry-v1", []Entry{}, [][]byte{[]byte("f")}},
		{"binary-conflict", []Entry{entry("f", Regular, []byte{0})}, []Entry{entry("f", Regular, []byte{0, 1})}, []Entry{entry("f", Regular, []byte{0, 2})}, "whole-entry-v1", []Entry{}, [][]byte{[]byte("f")}},
		{"newline-exact", []Entry{e("line")}, []Entry{e("line\n")}, []Entry{e("line")}, "whole-entry-v1", []Entry{e("line\n")}, [][]byte{}},
	}
}

// Negative wire records belong only to this fixture schema. Outcomes document
// what a consuming test must reject; this is not a native/Git format parser.
type pathRecord struct {
	Type       string
	Operations []Operation
}
type graphRecord struct{ Nodes []graphNode }
type graphNode struct {
	ID      string
	Parents []string
}

func negativeCases() []Negative {
	out := []Negative{}
	add := func(name, kind string, v any, want string) {
		b, e := json.Marshal(v)
		if e != nil {
			panic(e)
		}
		out = append(out, Negative{name, kind, b, want})
	}
	for i, p := range []string{"", "\x00", "/a", "a/", "a//b", ".", "..", "a/./b", "a/../b"} {
		add(fmt.Sprintf("path-%02d", i), "record", pathRecord{"file", []Operation{set(p, Regular, nil)}}, "invalid_path")
	}
	add("duplicate-path", "record", pathRecord{"file", []Operation{set("a", Regular, nil), set("a", Regular, nil)}}, "invalid_order")
	add("unsorted-paths", "record", pathRecord{"file", []Operation{set("b", Regular, nil), set("a", Regular, nil)}}, "invalid_order")
	add("leaf-prefix", "record", pathRecord{"file", []Operation{set("a", Regular, nil), set("a/b", Regular, nil)}}, "leaf_conflict")
	add("unknown-mode", "record", pathRecord{"file", []Operation{set("a", 0100600, nil)}}, "unknown_mode")
	add("gitlink", "record", pathRecord{"file", []Operation{set("submodule", 0160000, []byte("source target"))}}, "unsupported_gitlink")
	add("unknown-type", "record", pathRecord{"future-object", nil}, "unknown_type")
	add("delete-payload", "record", pathRecord{"file", []Operation{{Path: []byte("a"), Delete: true, Mode: Regular, Content: []byte("x")}}}, "invalid_record")
	out = append(out, Negative{"truncated-record", "record", []byte(`{"Type":"file"`), "malformed_record"}, Negative{"unknown-field", "record", []byte(`{"Type":"file","Unexpected":1}`), "malformed_record"}, Negative{"trailing-record", "record", []byte(`{"Type":"file"}{}`), "malformed_record"})
	add("missing-parent", "graph", graphRecord{[]graphNode{{"a", []string{"absent"}}}}, "missing_parent")
	add("self-link", "graph", graphRecord{[]graphNode{{"a", []string{"a"}}}}, "cycle")
	add("cycle", "graph", graphRecord{[]graphNode{{"a", []string{"b"}}, {"b", []string{"a"}}}}, "cycle")
	add("duplicate-node", "graph", graphRecord{[]graphNode{{"a", nil}, {"a", nil}}}, "duplicate_node")
	add("empty-link", "graph", graphRecord{[]graphNode{{"a", []string{""}}}}, "malformed_link")
	add("oversize-content", "record", pathRecord{"file", []Operation{set("a", Regular, make([]byte, MaxContentBytes+1))}}, "resource_exhausted")
	add("oversize-path", "record", pathRecord{"file", []Operation{set(strings.Repeat("p", MaxPathBytes+1), Regular, nil)}}, "invalid_path")
	return out
}

// JSON returns stable complete manifest bytes. It is an artifact format only;
// consumers must not infer native serialization or hash identities from it.
func (m Manifest) JSON() ([]byte, error) { return json.MarshalIndent(m, "", "  ") }
