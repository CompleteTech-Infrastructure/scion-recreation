package fixtures_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	f "canopy.local/canopy/tests/fixtures"
)

var config = f.Config{Seed: 20261015, Width: 32, Depth: 8}

func generate(t *testing.T) f.Manifest {
	t.Helper()
	m, err := f.Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func repo(t *testing.T, m f.Manifest, name string) f.Repository {
	t.Helper()
	for _, r := range m.Repositories {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("repository %q missing", name)
	return f.Repository{}
}
func node(t *testing.T, r f.Repository, label string) f.Commit {
	t.Helper()
	for _, c := range r.Commits {
		if c.Label == label {
			return c
		}
	}
	t.Fatalf("commit %q missing", label)
	return f.Commit{}
}
func tree(t *testing.T, r f.Repository, label string) []f.Entry {
	t.Helper()
	id := node(t, r, label).ID
	for _, v := range r.Trees {
		if v.Commit == id {
			return v.Entries
		}
	}
	t.Fatal("tree missing")
	return nil
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func find(t *testing.T, entries []f.Entry, path string) f.Entry {
	t.Helper()
	for _, e := range entries {
		if bytes.Equal(e.Path, []byte(path)) {
			return e
		}
	}
	t.Fatalf("path %x missing", path)
	return f.Entry{}
}

func TestGenerateDeterminism(t *testing.T) {
	m := generate(t)
	a, err := m.JSON()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := generate(t).JSON()
	if !bytes.Equal(a, b) {
		t.Fatal("same input changed manifest")
	}
	// This versioned fingerprint detects changes to complete manifest bytes.
	// It is a regression lock; the independent semantic assertions in the other
	// leaves establish the expected paths, trees, graph bases and merge outcomes.
	const golden = "83ee291b53bb48a969de9b2eebb118112d7565f946eb8877d4a581c8fa77ef54"
	if hash(a) != golden {
		t.Fatalf("manifest digest %s, want %s", hash(a), golden)
	}
	other := config
	other.Seed++
	changed, err := f.Generate(other)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := changed.JSON()
	if bytes.Equal(a, c) {
		t.Fatal("seed ignored")
	}
	var decoded f.Manifest
	if err := json.Unmarshal(a, &decoded); err != nil {
		t.Fatal(err)
	}
	round, _ := decoded.JSON()
	if !bytes.Equal(a, round) {
		t.Fatal("byte-exact JSON roundtrip failed")
	}
	if m.SchemaVersion != 1 || m.FixtureVersion != "adversarial-source-v1" || !strings.Contains(m.SourceIdentityScheme, "not Git/native") {
		t.Fatal("identity/version metadata missing")
	}
	for _, r := range m.Repositories {
		for _, c := range r.Commits {
			if c.ID != "fixture-sha256:"+hash(c.RawRecord) {
				t.Fatal("source ID not bound to raw bytes")
			}
			var raw struct {
				Version, Repository, Label string
				Seed                       uint64
				Parents                    []string
				Operations                 []f.Operation
				Message                    []byte
			}
			if err := json.Unmarshal(c.RawRecord, &raw); err != nil {
				t.Fatal(err)
			}
			if raw.Seed != config.Seed || raw.Version != m.FixtureVersion || raw.Repository != r.Name || raw.Label != c.Label || !reflect.DeepEqual(raw.Parents, c.Parents) || !reflect.DeepEqual(raw.Operations, c.Operations) || !bytes.Equal(raw.Message, c.Message) {
				t.Fatal("raw record cannot reconstruct source")
			}
		}
	}
	if dir := os.Getenv("CANOPY_FIXTURE_EVIDENCE_DIR"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), a, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGenerateBounds(t *testing.T) {
	for _, c := range []f.Config{{0, 0, 1}, {0, 65, 1}, {0, 1, 0}, {0, 1, 17}, {0, -1, -1}, {0, int(^uint(0) >> 1), 1}} {
		if _, err := f.Generate(c); err == nil {
			t.Fatalf("accepted bounds %+v", c)
		}
	}
	for _, c := range []f.Config{{0, 1, 1}, {^uint64(0), f.MaxWidth, f.MaxDepth}} {
		m, err := f.Generate(c)
		if err != nil {
			t.Fatal(err)
		}
		total := 0
		for _, r := range m.Repositories {
			for _, node := range r.Commits {
				if len(node.RawRecord) > f.MaxSourceRecordBytes {
					t.Fatal("source record byte budget")
				}
			}
			if len(r.Commits) > f.MaxCommits {
				t.Fatal("commit budget")
			}
			total += len(r.Commits)
			if len(r.Queries) != len(r.Commits)*len(r.Commits) {
				t.Fatal("query bound")
			}
			for _, tr := range r.Trees {
				if len(tr.Entries) > f.MaxEntries {
					t.Fatal("entry budget")
				}
				for _, e := range tr.Entries {
					if len(e.Path) > f.MaxPathBytes || len(e.Content) > f.MaxContentBytes {
						t.Fatal("byte budget")
					}
				}
			}
		}
		if total > f.MaxCommits {
			t.Fatalf("total fixture commits %d", total)
		}
		if len(m.Applications) != 5 {
			t.Fatal("application inventory")
		}
		if len(m.Merges) != 11 || len(m.Negatives) != 26 {
			t.Fatalf("fixture inventory %d merges, %d negatives", len(m.Merges), len(m.Negatives))
		}
	}
	t.Log("bounds: 5 repositories, <=30 commits total, <=128 leaves/tree, width<=64, depth<=16, path<=1024, content<=256; 11 merges, 26 explicit negatives")
}

func TestEmptyRootAndEmptyCommit(t *testing.T) {
	m := generate(t)
	empty := repo(t, m, "empty")
	if len(empty.Commits) != 0 || len(empty.Trees) != 0 || len(empty.Queries) != 0 {
		t.Fatal("empty repository contains history")
	}
	core := repo(t, m, "core")
	root := node(t, core, "root")
	if len(root.Parents) != 0 || len(tree(t, core, "root")) != 0 || !bytes.Equal(root.Message, []byte{255}) {
		t.Fatal("root fixture")
	}
	files, emptyCommit := node(t, core, "files"), node(t, core, "empty-commit")
	if len(emptyCommit.Operations) != 0 || !reflect.DeepEqual(emptyCommit.Parents, []string{files.ID}) || emptyCommit.ID == files.ID || !reflect.DeepEqual(tree(t, core, "files"), tree(t, core, "empty-commit")) {
		t.Fatal("empty commit lost identity or tree")
	}
}

// Independent reachability reference walks parent lists afresh for each query;
// it shares neither the generator's closure matrix nor its base filtering loop.
func ancestors(r f.Repository, id string) map[string]bool {
	byID := map[string]f.Commit{}
	for _, c := range r.Commits {
		byID[c.ID] = c
	}
	seen := map[string]bool{}
	todo := []string{id}
	for len(todo) > 0 {
		v := todo[0]
		todo = todo[1:]
		if seen[v] {
			continue
		}
		seen[v] = true
		todo = append(todo, byID[v].Parents...)
	}
	return seen
}
func TestDAGOracle(t *testing.T) {
	for _, r := range generate(t).Repositories {
		count := 0
		for _, q := range r.Queries {
			a, b := ancestors(r, q.Left), ancestors(r, q.Right)
			if q.LeftIsAncestor != b[q.Left] {
				t.Fatal("ancestry mismatch")
			}
			common := map[string]bool{}
			for id := range a {
				if b[id] {
					common[id] = true
				}
			}
			// Every non-best common ancestor is reached by at least one other common
			// ancestor. Delete those older ancestors from the candidate set.
			best := map[string]bool{}
			for id := range common {
				best[id] = true
			}
			for id := range common {
				for older := range ancestors(r, id) {
					if older != id {
						delete(best, older)
					}
				}
			}
			want := []string{}
			for id := range best {
				want = append(want, id)
			}
			sort.Strings(want)
			if !reflect.DeepEqual(want, q.BestCommonAncestors) {
				t.Fatalf("%s bases", r.Name)
			}
			count++
		}
		if count != len(r.Commits)*len(r.Commits) {
			t.Fatal("not all pairs")
		}
	}
}

func TestCrissCrossBases(t *testing.T) {
	r := repo(t, generate(t), "criss-cross")
	a, b, ab, ba := node(t, r, "a"), node(t, r, "b"), node(t, r, "ab"), node(t, r, "ba")
	if !reflect.DeepEqual(ab.Parents, []string{a.ID, b.ID}) || !reflect.DeepEqual(ba.Parents, []string{b.ID, a.ID}) {
		t.Fatal("parent order changed")
	}
	want := []string{a.ID, b.ID}
	sort.Strings(want)
	found := false
	for _, q := range r.Queries {
		if q.Left == ab.ID && q.Right == ba.ID {
			found = true
			if !reflect.DeepEqual(want, q.BestCommonAncestors) {
				t.Fatal("not all two best bases")
			}
		}
		if q.Left == ab.ID && q.Right == node(t, r, "unrelated").ID && len(q.BestCommonAncestors) != 0 {
			t.Fatal("unrelated bases")
		}
	}
	if !found {
		t.Fatal("criss-cross query absent")
	}
	if len(tree(t, r, "ab")) != 1 || string(tree(t, r, "ab")[0].Path) != "left" || string(tree(t, r, "ba")[0].Path) != "right" {
		t.Fatal("extra parent incorrectly unions trees")
	}
	if !reflect.DeepEqual(node(t, r, "repeated-parent").Parents, []string{a.ID, a.ID}) {
		t.Fatal("valid repeated parent normalized away")
	}
}

func TestWideTrees(t *testing.T) {
	m := generate(t)
	tr := tree(t, repo(t, m, "wide"), "root")
	if len(tr) != 32 {
		t.Fatal("wide count")
	}
	for i, e := range tr {
		if string(e.Path) != fmt.Sprintf("wide/f%03d", i) || string(e.Content) != fmt.Sprintf("20261015:%d", i) || e.Mode != f.Regular {
			t.Fatalf("wide entry %d", i)
		}
	}
	chain := repo(t, m, "chain")
	if len(chain.Commits) != 8 {
		t.Fatal("chain depth")
	}
	for i, c := range chain.Commits {
		if i > 0 && !reflect.DeepEqual(c.Parents, []string{chain.Commits[i-1].ID}) {
			t.Fatal("chain parent")
		}
	}
}

func TestBytesModesAndPaths(t *testing.T) {
	r := repo(t, generate(t), "core")
	tr := tree(t, r, "files")
	if len(tr) != 14 {
		t.Fatal("source entry count")
	}
	expected := map[string]struct {
		mode uint32
		data []byte
	}{"CON": {f.Regular, []byte("reserved host name")}, "A": {f.Regular, []byte("upper")}, "a": {f.Regular, []byte("lower")}, "binary": {f.Regular, []byte{0, 1, 255, 10, 0}}, "empty": {f.Regular, []byte{}}, "exec": {f.Executable, []byte("seed=20261015\n")}, "regular": {f.Regular, []byte("seed=20261015\n")}, "link": {f.Symlink, []byte("../target")}, "raw/\xff": {f.Regular, []byte{255}}, "e\u0301": {f.Regular, []byte("NFD")}, "\u00e9": {f.Regular, []byte("NFC")}, "literal\\name": {f.Regular, []byte("backslash")}, "%2e%2e": {f.Regular, []byte("percent")}, strings.Repeat("l", 300): {f.Regular, []byte("long component")}}
	for i, e := range tr {
		want, ok := expected[string(e.Path)]
		if !ok || e.Mode != want.mode || !bytes.Equal(e.Content, want.data) || e.ContentSHA256 != hash(want.data) {
			t.Fatalf("changed raw leaf %x", e.Path)
		}
		if i > 0 && bytes.Compare(tr[i-1].Path, e.Path) >= 0 {
			t.Fatal("byte order")
		}
	}
	changed := find(t, tree(t, r, "mode-only"), "regular")
	if changed.Mode != f.Executable || !bytes.Equal(changed.Content, expected["regular"].data) {
		t.Fatal("mode-only bytes")
	}
	if len(tree(t, r, "delete")) != 13 {
		t.Fatal("delete tree")
	}
	for _, e := range tree(t, r, "delete") {
		if string(e.Path) == "binary" {
			t.Fatal("deletion omitted")
		}
	}
}

func TestHostPathDispositions(t *testing.T) {
	m := generate(t)
	counts := map[string]int{}

	expected := map[string]struct {
		paths  [][]byte
		reason string
	}{
		"case-insensitive":      {[][]byte{[]byte("A"), []byte("a")}, "case collision"},
		"unicode-normalizing":   {[][]byte{[]byte("e\u0301"), []byte("\u00e9")}, "normalization collision"},
		"utf8-only":             {[][]byte{[]byte("raw/\xff")}, "non-UTF-8 path"},
		"component-limit-255":   {[][]byte{[]byte(strings.Repeat("l", 300))}, "component exceeds 255 bytes"},
		"safe-checkout":         {[][]byte{[]byte("link")}, "reject checkout: root-level symlink escapes checkout root"},
		"windows-reserved-name": {[][]byte{[]byte("CON")}, "reserved device name; cannot materialize"},
		"windows-path-syntax":   {[][]byte{[]byte("literal\\name")}, "backslash is not representable as a literal name"},
	}
	for _, d := range m.HostDispositions {
		want, ok := expected[d.Profile]
		if !ok || !reflect.DeepEqual(d.Paths, want.paths) || d.Reason != want.reason {
			t.Fatalf("host disposition misbound: %s", d.Profile)
		}
		counts[d.Profile]++
		if d.Repository != "core" || d.Commit == "" || d.Reason == "" || len(d.Paths) == 0 {
			t.Fatal("incomplete host disposition")
		}
		r := repo(t, m, d.Repository)
		var entries []f.Entry
		for _, tr := range r.Trees {
			if tr.Commit == d.Commit {
				entries = tr.Entries
			}
		}
		for _, p := range d.Paths {
			find(t, entries, string(p))
		}
	}
	for _, profile := range []string{"case-insensitive", "unicode-normalizing", "utf8-only", "component-limit-255", "safe-checkout", "windows-reserved-name", "windows-path-syntax"} {
		if counts[profile] != 4 {
			t.Fatalf("profile %s count %d", profile, counts[profile])
		}
	}
}

func same(a, b *f.Entry) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Mode == b.Mode && bytes.Equal(a.Content, b.Content)
}
func lookup(es []f.Entry, path string) *f.Entry {
	for i := range es {
		if string(es[i].Path) == path {
			return &es[i]
		}
	}
	return nil
}
func TestMergeOracle(t *testing.T) {
	names := []string{"unchanged", "one-side", "equal-edits", "disjoint-paths", "text-conflict", "delete-modify", "both-delete", "mode-only", "symlink-conflict", "binary-conflict", "newline-exact"}
	m := generate(t)
	if len(m.Merges) != len(names) {
		t.Fatal("merge inventory")
	}
	for i, merge := range m.Merges {
		if merge.Name != names[i] || merge.Policy != "whole-entry-v1" {
			t.Fatal("policy/inventory")
		}
		paths := map[string]bool{}
		for _, es := range [][]f.Entry{merge.Base, merge.Left, merge.Right} {
			for _, e := range es {
				paths[string(e.Path)] = true
			}
		}
		ordered := []string{}
		for p := range paths {
			ordered = append(ordered, p)
		}
		sort.Strings(ordered)
		out := []f.Entry{}
		conflicts := [][]byte{}
		for _, p := range ordered {
			base, left, right := lookup(merge.Base, p), lookup(merge.Left, p), lookup(merge.Right, p)
			var chosen *f.Entry
			switch {
			case same(left, right):
				chosen = left
			case same(base, left):
				chosen = right
			case same(base, right):
				chosen = left
			default:
				conflicts = append(conflicts, []byte(p))
			}
			if chosen != nil {
				out = append(out, *chosen)
			}
		}
		if !reflect.DeepEqual(out, merge.Expected) || !reflect.DeepEqual(conflicts, merge.Conflicts) {
			t.Fatalf("merge %s independent table mismatch", merge.Name)
		}
	}
}

// This strict fixture-schema decoder is an independent consumer oracle for the
// negative inventory; it makes no claim about a production parser's behavior.
func classify(n f.Negative) string {
	if len(n.Raw) > f.MaxRecordBytes {
		return "resource_exhausted"
	}
	dec := json.NewDecoder(bytes.NewReader(n.Raw))
	dec.DisallowUnknownFields()
	if n.InputKind == "record" {
		var r struct {
			Type       string
			Operations []f.Operation
		}
		if dec.Decode(&r) != nil || dec.Decode(new(any)) != io.EOF {
			return "malformed_record"
		}
		if r.Type != "file" {
			return "unknown_type"
		}
		if len(r.Operations) > f.MaxEntries {
			return "resource_exhausted"
		}
		for i, o := range r.Operations {
			p := string(o.Path)
			if len(p) == 0 || len(p) > f.MaxPathBytes || strings.ContainsRune(p, 0) {
				return "invalid_path"
			}
			for _, part := range strings.Split(p, "/") {
				if part == "" || part == "." || part == ".." {
					return "invalid_path"
				}
			}
			if i > 0 && bytes.Compare(r.Operations[i-1].Path, o.Path) >= 0 {
				return "invalid_order"
			}
			if len(o.Content) > f.MaxContentBytes {
				return "resource_exhausted"
			}
			if o.Delete {
				if o.Mode != 0 || len(o.Content) > 0 {
					return "invalid_record"
				}
			} else {
				switch o.Mode {
				case f.Regular, f.Executable, f.Symlink:
				case 0160000:
					return "unsupported_gitlink"
				default:
					return "unknown_mode"
				}
			}
		}
		for _, a := range r.Operations {
			for _, b := range r.Operations {
				if !a.Delete && !b.Delete && strings.HasPrefix(string(b.Path), string(a.Path)+"/") {
					return "leaf_conflict"
				}
			}
		}
		return "accept"
	}
	var r struct {
		Nodes []struct {
			ID      string
			Parents []string
		}
	}
	if dec.Decode(&r) != nil || dec.Decode(new(any)) != io.EOF {
		return "malformed_record"
	}
	if len(r.Nodes) > f.MaxCommits {
		return "resource_exhausted"
	}
	nodes := map[string][]string{}
	for _, v := range r.Nodes {
		if v.ID == "" {
			return "malformed_link"
		}
		if _, ok := nodes[v.ID]; ok {
			return "duplicate_node"
		}
		nodes[v.ID] = v.Parents
	}
	for _, parents := range nodes {
		for _, p := range parents {
			if p == "" {
				return "malformed_link"
			}
			if _, ok := nodes[p]; !ok {
				return "missing_parent"
			}
		}
	}
	// Bounded Kahn elimination detects cycles without sharing the generator's
	// graph relation or assuming the supplied node order is topological.
	done := map[string]bool{}
	for rounds := 0; rounds < len(nodes); rounds++ {
		for id, parents := range nodes {
			ready := true
			for _, p := range parents {
				if !done[p] {
					ready = false
				}
			}
			if ready {
				done[id] = true
			}
		}
	}
	if len(done) != len(nodes) {
		return "cycle"
	}
	return "accept"
}
func TestMalformedOutcomes(t *testing.T) {
	// Independent simultaneous tree application uses a leaf map and validates
	// only after all exact-path edits; reversing operations must give the same
	// result (serialization order validation is covered by negative records).
	appNames := []string{"file-to-directory", "directory-to-file", "partial-directory-removal", "absent-delete", "final-leaf-conflict"}
	for i, app := range generate(t).Applications {
		if app.Name != appNames[i] {
			t.Fatal("application name")
		}
		for _, reverse := range []bool{false, true} {
			leaves := map[string]f.Entry{}
			for _, e := range app.Base {
				leaves[string(e.Path)] = e
			}
			for n := 0; n < len(app.Operations); n++ {
				j := n
				if reverse {
					j = len(app.Operations) - 1 - n
				}
				o := app.Operations[j]
				if o.Delete {
					delete(leaves, string(o.Path))
				} else {
					leaves[string(o.Path)] = f.Entry{Path: o.Path, Mode: o.Mode, Content: o.Content, ContentSHA256: hash(o.Content)}
				}
			}
			out := []f.Entry{}
			conflict := false
			for p, e := range leaves {
				out = append(out, e)
				for q := range leaves {
					if strings.HasPrefix(q, p+"/") {
						conflict = true
					}
				}
			}
			sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].Path, out[j].Path) < 0 })
			if conflict {
				if app.Outcome != "leaf_conflict" || app.Expected != nil {
					t.Fatal("application conflict oracle")
				}
			} else if app.Outcome != "accept" || !reflect.DeepEqual(out, app.Expected) {
				t.Fatalf("application %s", app.Name)
			}
		}
	}

	m := generate(t)
	expected := map[string]string{"path-00": "invalid_path", "path-01": "invalid_path", "path-02": "invalid_path", "path-03": "invalid_path", "path-04": "invalid_path", "path-05": "invalid_path", "path-06": "invalid_path", "path-07": "invalid_path", "path-08": "invalid_path", "duplicate-path": "invalid_order", "unsorted-paths": "invalid_order", "leaf-prefix": "leaf_conflict", "unknown-mode": "unknown_mode", "gitlink": "unsupported_gitlink", "unknown-type": "unknown_type", "delete-payload": "invalid_record", "truncated-record": "malformed_record", "unknown-field": "malformed_record", "trailing-record": "malformed_record", "missing-parent": "missing_parent", "self-link": "cycle", "cycle": "cycle", "duplicate-node": "duplicate_node", "empty-link": "malformed_link", "oversize-content": "resource_exhausted", "oversize-path": "invalid_path"}
	if len(m.Negatives) != len(expected) {
		t.Fatal("negative inventory")
	}
	for _, n := range m.Negatives {
		want, ok := expected[n.Name]
		if !ok || want != n.Expected {
			t.Fatalf("negative outcome %s", n.Name)
		}
		delete(expected, n.Name)
		if got := classify(n); got != want {
			t.Fatalf("%s: got %s want %s", n.Name, got, want)
		}
	}
	if len(expected) != 0 {
		t.Fatal("missing negative")
	}
	// Controls ensure this oracle does not simply reject every record/graph.
	for _, raw := range []string{`{"Type":"file","Operations":[]}`, `{"Type":"file","Operations":[{"Path":"/w==","Mode":33188,"Content":"AA=="}]}`} {
		if classify(f.Negative{InputKind: "record", Raw: []byte(raw)}) != "accept" {
			t.Fatal("positive record rejected")
		}
	}
	if classify(f.Negative{InputKind: "graph", Raw: []byte(`{"Nodes":[{"ID":"a","Parents":[]},{"ID":"b","Parents":["a","a"]}]}`)}) != "accept" {
		t.Fatal("valid repeated parent rejected")
	}
}

// byteFieldPath is a route through exported struct fields and slice elements.
// It lets the tests mutate the public manifest graph without using the
// implementation's copy helpers as the oracle.
type byteFieldStep struct {
	field bool
	index int
}

type manifestByteField struct {
	name       string
	path       []byteFieldStep
	digestPath []byteFieldStep
}

var fixtureEntryType = reflect.TypeOf(f.Entry{})

func extendByteFieldPath(path []byteFieldStep, step byteFieldStep) []byteFieldStep {
	out := make([]byteFieldStep, len(path)+1)
	copy(out, path)
	out[len(path)] = step
	return out
}

func manifestByteFields(root reflect.Value) []manifestByteField {
	var fields []manifestByteField
	var walk func(reflect.Value, string, []byteFieldStep, []byteFieldStep)
	walk = func(value reflect.Value, name string, path, contentDigestPath []byteFieldStep) {
		switch value.Kind() {
		case reflect.Struct:
			var entryDigestPath []byteFieldStep
			if value.Type() == fixtureEntryType {
				for i := 0; i < value.NumField(); i++ {
					if value.Type().Field(i).Name == "ContentSHA256" {
						entryDigestPath = extendByteFieldPath(path, byteFieldStep{field: true, index: i})
						break
					}
				}
			}
			for i := 0; i < value.NumField(); i++ {
				fieldName := value.Type().Field(i).Name
				childDigestPath := []byteFieldStep(nil)
				if value.Type() == fixtureEntryType && fieldName == "Content" {
					childDigestPath = entryDigestPath
				}
				walk(value.Field(i), name+"."+fieldName, extendByteFieldPath(path, byteFieldStep{field: true, index: i}), childDigestPath)
			}
		case reflect.Slice:
			if value.Type().Elem().Kind() == reflect.Uint8 {
				if value.Len() > 0 {
					fields = append(fields, manifestByteField{name: name, path: path, digestPath: contentDigestPath})
				}
				return
			}
			for i := 0; i < value.Len(); i++ {
				walk(value.Index(i), fmt.Sprintf("%s[%d]", name, i), extendByteFieldPath(path, byteFieldStep{index: i}), nil)
			}
		}
	}
	walk(root, "$", nil, nil)
	return fields
}

func resolveByteField(root reflect.Value, path []byteFieldStep) reflect.Value {
	for _, step := range path {
		if step.field {
			root = root.Field(step.index)
		} else {
			root = root.Index(step.index)
		}
	}
	return root
}

func snapshotManifestThroughJSON(t *testing.T, manifest f.Manifest) f.Manifest {
	t.Helper()
	data, err := manifest.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var snapshot f.Manifest
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func setManifestByteFieldDigest(root reflect.Value, field manifestByteField, content []byte) {
	if len(field.digestPath) != 0 {
		resolveByteField(root, field.digestPath).SetString(hash(content))
	}
}

func verifyManifestEntryDigests(t *testing.T, root reflect.Value, name string) {
	t.Helper()
	if root.Type() == fixtureEntryType {
		content := root.FieldByName("Content").Bytes()
		got := root.FieldByName("ContentSHA256").String()
		if got != hash(content) {
			t.Fatalf("%s.ContentSHA256 = %s, want %s", name, got, hash(content))
		}
		return
	}
	switch root.Kind() {
	case reflect.Struct:
		for i := 0; i < root.NumField(); i++ {
			verifyManifestEntryDigests(t, root.Field(i), name+"."+root.Type().Field(i).Name)
		}
	case reflect.Slice:
		if root.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := 0; i < root.Len(); i++ {
			verifyManifestEntryDigests(t, root.Index(i), fmt.Sprintf("%s[%d]", name, i))
		}
	}
}

func assertManifestByteFieldCoverage(t *testing.T, fields []manifestByteField) {
	t.Helper()
	if len(fields) < 100 {
		t.Fatalf("byte-field walk found only %d mutable fields", len(fields))
	}
	seen := map[string]bool{}
	for _, field := range fields {
		seen[field.name] = true
	}
	for _, required := range []string{
		"$.Merges[0].Base[0].Path", "$.Merges[0].Left[0].Content", "$.Merges[1].Expected[0].Content",
		"$.Applications[0].Operations[0].Path", "$.Applications[0].Expected[0].Content",
		"$.Repositories[1].Commits[0].Message", "$.Repositories[1].Commits[0].RawRecord",
		"$.Repositories[1].Trees[1].Entries[0].Path", "$.Repositories[1].Trees[1].Entries[0].Content",
		"$.Negatives[0].Raw", "$.HostDispositions[0].Paths[0]",
	} {
		if !seen[required] {
			t.Fatalf("public mutable field %s was not covered", required)
		}
	}
}

func assertManifestSectionMutationIsolation(t *testing.T, section string) {
	t.Helper()
	manifest := generate(t)
	originalJSON, err := manifest.JSON()
	if err != nil {
		t.Fatal(err)
	}
	root := reflect.ValueOf(&manifest).Elem()
	prefix := "$." + section + "["
	var fields []manifestByteField
	for _, field := range manifestByteFields(root) {
		if strings.HasPrefix(field.name, prefix) {
			fields = append(fields, field)
		}
	}
	if len(fields) == 0 {
		t.Fatalf("no mutable byte fields found under %s", section)
	}

	for _, field := range fields {
		actual := resolveByteField(root, field.path)
		positions := []int{0}
		if actual.Len() > 1 {
			positions = append(positions, actual.Len()-1)
		}
		for _, position := range positions {
			oracle := snapshotManifestThroughJSON(t, manifest)
			oracleRoot := reflect.ValueOf(&oracle).Elem()
			oracleField := resolveByteField(oracleRoot, field.path)
			if !bytes.Equal(actual.Bytes(), oracleField.Bytes()) {
				t.Fatalf("JSON snapshot differs before mutation at %s", field.name)
			}
			old := byte(actual.Index(position).Uint())
			changed := old ^ 0xff
			actual.Index(position).SetUint(uint64(changed))
			oracleField.Index(position).SetUint(uint64(changed))
			setManifestByteFieldDigest(root, field, actual.Bytes())
			setManifestByteFieldDigest(oracleRoot, field, oracleField.Bytes())
			verifyManifestEntryDigests(t, root, "$")
			got, err := manifest.JSON()
			if err != nil {
				t.Fatal(err)
			}
			want, err := oracle.JSON()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("mutating %s changed another public field or sibling case", field.name)
			}
			actual.Index(position).SetUint(uint64(old))
			setManifestByteFieldDigest(root, field, actual.Bytes())
		}
	}
	verifyManifestEntryDigests(t, root, "$")
	finalJSON, err := manifest.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(finalJSON, originalJSON) {
		t.Fatal("mutation probes did not restore the original manifest")
	}
}

func TestManifestByteSlicesAreMutationIsolated(t *testing.T) {
	coverage := generate(t)
	assertManifestByteFieldCoverage(t, manifestByteFields(reflect.ValueOf(&coverage).Elem()))
	for _, section := range []string{"Repositories", "Applications", "Merges", "Negatives", "HostDispositions"} {
		section := section
		t.Run(section, func(t *testing.T) {
			assertManifestSectionMutationIsolation(t, section)
		})
	}
}

func TestGenerateCallsDoNotShareByteSlices(t *testing.T) {
	first, second := generate(t), generate(t)
	firstJSON, err := first.JSON()
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := second.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("independent calls changed manifest semantics")
	}
	firstRoot, secondRoot := reflect.ValueOf(&first).Elem(), reflect.ValueOf(&second).Elem()
	firstFields, secondFields := manifestByteFields(firstRoot), manifestByteFields(secondRoot)
	if len(firstFields) != len(secondFields) {
		t.Fatal("independent calls returned different byte-field graphs")
	}
	secondSnapshots := make([][]byte, len(secondFields))
	for i := range secondFields {
		if firstFields[i].name != secondFields[i].name {
			t.Fatalf("byte-field order differs at %d: %s / %s", i, firstFields[i].name, secondFields[i].name)
		}
		secondSnapshots[i] = append([]byte(nil), resolveByteField(secondRoot, secondFields[i].path).Bytes()...)
	}

	for _, field := range firstFields {
		actual := resolveByteField(firstRoot, field.path)
		positions := []int{0}
		if actual.Len() > 1 {
			positions = append(positions, actual.Len()-1)
		}
		for _, position := range positions {
			old := byte(actual.Index(position).Uint())
			actual.Index(position).SetUint(uint64(old ^ 0xff))
			setManifestByteFieldDigest(firstRoot, field, actual.Bytes())
			for i, sibling := range secondFields {
				if !bytes.Equal(resolveByteField(secondRoot, sibling.path).Bytes(), secondSnapshots[i]) {
					t.Fatalf("mutating first Generate result at %s changed second result field %s", field.name, sibling.name)
				}
			}
			unchanged, err := second.JSON()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(unchanged, secondJSON) {
				t.Fatalf("mutating first Generate result at %s changed second manifest bytes", field.name)
			}
			actual.Index(position).SetUint(uint64(old))
			setManifestByteFieldDigest(firstRoot, field, actual.Bytes())
		}
	}
	verifyManifestEntryDigests(t, firstRoot, "first")
	verifyManifestEntryDigests(t, secondRoot, "second")
}

func TestManifestJSONReturnsIndependentBytes(t *testing.T) {
	manifest := generate(t)
	first, err := manifest.JSON()
	if err != nil {
		t.Fatal(err)
	}
	second, err := manifest.JSON()
	if err != nil {
		t.Fatal(err)
	}
	firstSnapshot := append([]byte(nil), first...)
	secondSnapshot := append([]byte(nil), second...)
	if !bytes.Equal(firstSnapshot, secondSnapshot) {
		t.Fatal("repeated JSON calls differ")
	}
	first[0] ^= 0xff
	if !bytes.Equal(second, secondSnapshot) {
		t.Fatal("mutating one JSON result changed another result")
	}
	fresh, err := manifest.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fresh, secondSnapshot) {
		t.Fatal("mutating JSON bytes changed the manifest")
	}

	root := reflect.ValueOf(&manifest).Elem()
	fields := manifestByteFields(root)
	var pathField, contentField *manifestByteField
	for i := range fields {
		switch fields[i].name {
		case "$.Merges[1].Left[0].Path":
			pathField = &fields[i]
		case "$.Merges[1].Left[0].Content":
			contentField = &fields[i]
		}
	}
	if pathField == nil || contentField == nil {
		t.Fatal("merge input mutation fields missing")
	}
	for _, field := range []*manifestByteField{pathField, contentField} {
		value := resolveByteField(root, field.path)
		old := byte(value.Index(0).Uint())
		value.Index(0).SetUint(uint64(old ^ 0xff))
		setManifestByteFieldDigest(root, *field, value.Bytes())
		if !bytes.Equal(second, secondSnapshot) {
			t.Fatalf("mutating manifest field %s changed a prior JSON result", field.name)
		}
		value.Index(0).SetUint(uint64(old))
		setManifestByteFieldDigest(root, *field, value.Bytes())
	}
	verifyManifestEntryDigests(t, root, "$")
	restored, err := manifest.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, secondSnapshot) {
		t.Fatal("manifest mutation probes did not restore the original JSON")
	}
}
