package migration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

const prologue = "feature done\n"

// Literal oracle from read-only Git 2.54.0 fast-export of hand-framed loose
// objects, not from the parser. Export command, native fixture bytes/OIDs and
// raw stdout are retained in attempt evidence fixture-export.{json,stdout}.
// This tests export framing, not source fidelity, import or Git identity checks.
const literalExport = "feature done\n" +
	"blob\nmark :1\noriginal-oid 5fe60ed00b6f201a5543a9307665bed827911bac\ndata 19\n\x00\xff\n$(not executed)\r\n" +
	"reset refs/heads/main\n" +
	"commit refs/heads/main\nmark :2\noriginal-oid c8c4ff76d51aa3405a65c9fb6b8773a86f9633e1\nauthor A <a@b> 1 -0000\ncommitter C <c@d> 2 +0530\ndata 8\nmessage\nM 100644 :1 \"raw-\\377\"\n\n" +
	"commit refs/heads/main\nmark :3\noriginal-oid 6e3929182e0e18ff96230aad93d5e23eb93b3a98\nauthor A <a@b> 3 +0000\ncommitter C <c@d> 4 +0000\ndata 16\nno final newlinefrom :2\n\ndone\n"

func parserFor(t testing.TB, src io.Reader, limits GitStreamLimits) *GitStream {
	t.Helper()
	p, err := NewGitStream(context.Background(), src, "sha1", limits)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func parseAll(t testing.TB, input []byte, limits GitStreamLimits) ([]GitRecord, error) {
	t.Helper()
	p := parserFor(t, bytes.NewReader(input), limits)
	var records []GitRecord
	for i := 0; i <= limits.Records; i++ {
		r, err := p.Next()
		if err == io.EOF {
			return records, nil
		}
		if err != nil {
			return records, err
		}
		records = append(records, r)
	}
	t.Fatal("unbounded parser progress")
	return nil, nil
}

func rawHeader(r GitRecord, name string) [][]byte {
	var out [][]byte
	for _, h := range r.Headers {
		if h.Name == name {
			out = append(out, r.Raw[h.Value.Start:h.Value.End])
		}
	}
	return out
}

func checkDiagnostic(t testing.TB, input []byte, p *GitStream, err error) *GitDiagnostic {
	t.Helper()
	var d *GitDiagnostic
	if !errors.As(err, &d) {
		t.Fatalf("want structured diagnostic, got %T: %v", err, err)
	}
	if d.RestartOffset != 0 || !d.RestartRequiresReplay || d.RecordComplete || d.RecordStart < 0 || d.Offset < d.RecordStart || d.Offset > int64(len(input)) || d.CompletedOffset != d.RecordStart {
		t.Fatalf("unsafe/inconsistent boundary: %+v", d)
	}
	if !bytes.Equal(d.Raw, input[d.RecordStart:d.Offset]) || int64(len(d.Raw)) > p.limits.RecordBytes+1 {
		t.Fatalf("lossy or unbounded diagnostic: %+v", d)
	}
	if strings.Contains(err.Error(), "private-secret") {
		t.Fatal("error string disclosed protected source")
	}
	offset := p.offset
	for i := 0; i < 3; i++ {
		r, again := p.Next()
		if !reflect.DeepEqual(r, GitRecord{}) || again != err || p.offset != offset {
			t.Fatal("failure was not terminal")
		}
	}
	return d
}

func TestGitStreamLiteralExport(t *testing.T) {
	records, err := parseAll(t, []byte(literalExport), GitStreamHardLimits())
	if err != nil {
		t.Fatal(err)
	}
	var joined []byte
	var kinds []string
	var offset int64
	for _, r := range records {
		if r.Start != offset || r.End-r.Start != int64(len(r.Raw)) {
			t.Fatal("record gap/overlap")
		}
		offset = r.End
		joined = append(joined, r.Raw...)
		kinds = append(kinds, r.Kind)
	}
	if !bytes.Equal(joined, []byte(literalExport)) || !reflect.DeepEqual(kinds, []string{"feature", "blob", "reset", "commit", "commit", "done"}) {
		t.Fatalf("wrong stream: %v", kinds)
	}
	blob := records[1]
	if !blob.HasData || !bytes.Equal(blob.Raw[blob.Data.Start:blob.Data.End], []byte("\x00\xff\n$(not executed)\r")) {
		t.Fatal("blob payload changed")
	}
	c := records[3]
	if !bytes.Equal(c.Files[0].Path, []byte("raw-\xff")) || string(c.Raw[c.Data.Start:c.Data.End]) != "message\n" || string(rawHeader(c, "author")[0]) != "A <a@b> 1 -0000" {
		t.Fatal("raw metadata changed")
	}
	c = records[4]
	if string(c.Raw[c.Data.Start:c.Data.End]) != "no final newline" || string(rawHeader(c, "from")[0]) != ":2" {
		t.Fatal("counted message framing changed")
	}
}

func TestGitStreamRawMetadataAndCommands(t *testing.T) {
	ref := "refs/heads/raw-\xff"
	commit := "commit " + ref + "\nmark :18446744073709551615\noriginal-oid " + strings.Repeat("a", 40) + "\nauthor A\xff <x@y> -00001 -0000\ncommitter C <c@d> +0002 +2359\nencoding \xff\n" +
		"data 7\n\xff\x00\r\ndonfrom :8\nmerge :7\nmerge :7\nM 100644 :1 b\nM 100755 :2 a\nM 120000 " + strings.Repeat("b", 40) + " link\nD \"raw/\\377\\n\\t\\\\\\\"\"\ndeleteall\n\n"
	input := []byte(prologue + "reset " + ref + "\nfrom :7\n\n" + commit + "done\n")
	r, err := parseAll(t, input, GitStreamHardLimits())
	if err != nil {
		t.Fatal(err)
	}
	c := r[2]
	if !bytes.Equal(c.Raw, []byte(commit)) || !reflect.DeepEqual(rawHeader(c, "merge"), [][]byte{[]byte(":7"), []byte(":7")}) {
		t.Fatal("raw bytes/ordered duplicate parents changed")
	}
	if len(c.Files) != 5 || string(c.Files[0].Path) != "b" || string(c.Files[1].Path) != "a" || !bytes.Equal(c.Files[3].Path, []byte("raw/\xff\n\t\\\"")) || c.Files[4].Path != nil {
		t.Fatalf("commands changed: %+v", c.Files)
	}
	if !bytes.Equal(rawHeader(c, "encoding")[0], []byte{255}) || !bytes.Equal(c.Raw[c.Data.Start:c.Data.End], []byte{255, 0, 13, 10, 'd', 'o', 'n'}) {
		t.Fatal("metadata was transcoded")
	}
	// Returned slices remain owned and unchanged after later records/reallocation.
	before := sha256.Sum256(c.Raw)
	r[3].Raw[0] = 'X'
	if sha256.Sum256(c.Raw) != before {
		t.Fatal("records alias parser storage")
	}
}

func TestGitStreamAbsentAndEmptyMetadata(t *testing.T) {
	for _, encoding := range []string{"", "encoding \n"} {
		input := []byte(prologue + "blob\ndata 0\n\ncommit refs/heads/main\ncommitter <x> 0 +0000\n" + encoding + "data 0\n\ndone\n")
		r, err := parseAll(t, input, GitStreamHardLimits())
		if err != nil {
			t.Fatal(err)
		}
		c := r[2]
		if len(rawHeader(c, "author")) != 0 || !c.HasData || c.Data.Start != c.Data.End {
			t.Fatal("invented author/default data")
		}
		e := rawHeader(c, "encoding")
		if (len(e) == 0) != (encoding == "") || (len(e) > 0 && len(e[0]) != 0) {
			t.Fatal("absent/empty conflated")
		}
	}
}

func TestGitStreamSHA256Claims(t *testing.T) {
	input := []byte(prologue + "blob\noriginal-oid " + strings.Repeat("f", 64) + "\ndata 1\nx\ncommit refs/heads/m\ncommitter X <y> 0 +0000\ndata 0\nfrom " + strings.Repeat("a", 64) + "\nM 100644 " + strings.Repeat("b", 64) + " x\n\ndone\n")
	p, err := NewGitStream(context.Background(), bytes.NewReader(input), "sha256", GitStreamHardLimits())
	if err != nil {
		t.Fatal(err)
	}
	for {
		_, err = p.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = parseAll(t, input, GitStreamHardLimits())
	if err == nil {
		t.Fatal("accepted wrong source algorithm width")
	}
}

func TestGitStreamLiteralSHA256Export(t *testing.T) {
	// Separate real fast-export oracle: native SHA-256 fixture, same recorded
	// exporter and flags as the SHA-1 fixture; no object verification is implied.
	input := []byte(prologue + "blob\nmark :1\noriginal-oid 2cf8d83d9ee29543b34a87727421fdecb7e3f3a183d337639025de576db9ebb4\ndata 6\nhello\n\nreset refs/heads/main\ncommit refs/heads/main\nmark :2\noriginal-oid d31ee184b317ec81701fa756edac50c7c16237d93b706cdf8dfd25db1cd8e84e\nauthor A <a@b> 1 +0000\ncommitter C <c@d> 2 +0000\ndata 4\nmsg\nM 100644 :1 a\n\ndone\n")
	p, err := NewGitStream(context.Background(), bytes.NewReader(input), "sha256", GitStreamHardLimits())
	if err != nil {
		t.Fatal(err)
	}
	var joined []byte
	for {
		r, err := p.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		joined = append(joined, r.Raw...)
	}
	if !bytes.Equal(joined, input) {
		t.Fatal("SHA-256 export bytes lost")
	}
}

func TestGitStreamEveryTruncatedPrefixFails(t *testing.T) {
	input := []byte(literalExport)
	for n := 0; n < len(input); n++ {
		p := parserFor(t, bytes.NewReader(input[:n]), GitStreamHardLimits())
		for i := 0; i < 20; i++ {
			r, err := p.Next()
			if err != nil {
				if err == io.EOF {
					t.Fatalf("accepted truncated prefix %d", n)
				}
				if !reflect.DeepEqual(r, GitRecord{}) {
					t.Fatal("partial record escaped")
				}
				checkDiagnostic(t, input[:n], p, err)
				break
			}
			if i == 19 {
				t.Fatal("no terminal result")
			}
		}
	}
}

func TestGitStreamUnsupportedAndMalformed(t *testing.T) {
	base := "commit refs/heads/main\ncommitter private-secret <x@y> 1 +0000\ndata 0\n"
	cases := []struct{ name, body, code string }{
		{"tag", "tag v1\nfrom :1\ndata 0\n", "unsupported"},
		{"feature", "feature import-marks=/private-secret\n", "unsupported"},
		{"option", "option git import-marks=/private-secret\n", "unsupported"},
		{"shell", "$(touch private-secret)\n", "unsupported"},
		{"hook", "! /bin/sh private-secret\n", "unsupported"},
		{"progress", "progress private-secret\n", "unsupported"},
		{"checkpoint", "checkpoint\n", "unsupported"},
		{"gitlink", base + "M 160000 " + strings.Repeat("a", 40) + " private-secret\n\n", "unsupported"},
		{"mode", base + "M 100600 :1 x\n\n", "unsupported"},
		{"inline", base + "M 100644 inline x\ndata 0\n\n", "unsupported"},
		{"rename", base + "R a b\n\n", "unsupported"},
		{"copy", base + "C a b\n\n", "unsupported"},
		{"note", base + "N :1 :2\n\n", "unsupported"},
		{"gpgsig", "commit refs/heads/m\ncommitter X <x> 0 +0000\ngpgsig sha1 openpgp\ndata 0\n\n", "unsupported"},
		{"extra-header", base + "mergetag private-secret\n\n", "unsupported"},
		{"extra-pre-data-header", "commit refs/heads/m\ncommitter X <x> 0 +0000\nmergetag private-secret\ndata 0\n\n", "unsupported"},
		{"unknown-pre-data-header", "commit refs/heads/m\ncommitter X <x> 0 +0000\nfuture-header private-secret\ndata 0\n\n", "unsupported"},
		{"heredoc", "blob\ndata <<END\nprivate-secret\nEND\n", "unsupported"},
		{"negative-length", "blob\ndata -1\n", "unsupported"},
		{"length-overflow", "blob\ndata 18446744073709551616\n", "unsupported"},
		{"leading-zero", "blob\ndata 01\nx\n", "unsupported"},
		{"huge-length", "blob\ndata 18446744073709551615\n", "limit"},
		{"zero-mark", "blob\nmark :0\ndata 0\n\n", "malformed"},
		{"mark-overflow", "blob\nmark :18446744073709551616\ndata 0\n\n", "malformed"},
		{"mark-after-oid", "blob\noriginal-oid " + strings.Repeat("a", 40) + "\nmark :1\ndata 0\n\n", "malformed"},
		{"abbreviated-oid", "blob\noriginal-oid abcdef\ndata 0\n\n", "malformed"},
		{"uppercase-oid", "blob\noriginal-oid " + strings.Repeat("A", 40) + "\ndata 0\n\n", "malformed"},
		{"data-delimiter", "blob\ndata 1\nxX", "malformed"},
		{"bad-ref", "commit refs/heads/../secret\n", "malformed"},
		{"reset-target", "reset refs/heads/m\nfrom HEAD~1\n", "malformed"},
		{"parent-revspec", base + "from main^\n\n", "malformed"},
		{"file-revspec", base + "M 100644 HEAD:path x\n\n", "malformed"},
		{"duplicate-author", "commit refs/heads/m\nauthor X <x> 0 +0000\nauthor X <x> 0 +0000\n", "malformed"},
		{"missing-committer", "commit refs/heads/m\ndata 0\n\n", "malformed"},
		{"bad-seconds", "commit refs/heads/m\ncommitter X <x> 9223372036854775808 +0000\ndata 0\n\n", "malformed"},
		{"fractional-time", "commit refs/heads/m\ncommitter X <x> 1.2 +0000\ndata 0\n\n", "malformed"},
		{"bad-zone", "commit refs/heads/m\ncommitter X <x> 1 +2400\ndata 0\n\n", "malformed"},
		{"bad-zone-minutes", "commit refs/heads/m\ncommitter X <x> 1 -0060\ndata 0\n\n", "malformed"},
		{"nul-identity", "commit refs/heads/m\ncommitter X\x00 <x> 1 +0000\ndata 0\n\n", "malformed"},
		{"missing-identity-separator", "commit refs/heads/m\ncommitter X<x> 1 +0000\ndata 0\n\n", "malformed"},
		{"empty-file-path", base + "M 100644 :1 \n\n", "malformed"},
		{"empty-delete-path", base + "D \n\n", "malformed"},
		{"late-merge", base + "D x\nmerge :1\n\n", "unsupported"},
		{"comment", "# private-secret\n", "unsupported"},
		{"blank", "\n", "unsupported"},
	}
	for _, v := range cases {
		t.Run(v.name, func(t *testing.T) {
			input := []byte(prologue + v.body + "done\n")
			p := parserFor(t, bytes.NewReader(input), GitStreamHardLimits())
			for i := 0; i < 10; i++ {
				r, err := p.Next()
				if err != nil {
					if !reflect.DeepEqual(r, GitRecord{}) {
						t.Fatal("partial result")
					}
					d := checkDiagnostic(t, input, p, err)
					if d.Code != v.code {
						t.Fatalf("code %q want %q, reason %s", d.Code, v.code, d.Reason)
					}
					return
				}
			}
			t.Fatal("accepted malicious/unsupported stream")
		})
	}
	for _, input := range []string{"", "done\n", "feature done\r\ndone\n", prologue + "done\nprivate-secret", prologue + "done\ndone\n"} {
		_, err := parseAll(t, []byte(input), GitStreamHardLimits())
		if err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}

func TestGitStreamPaths(t *testing.T) {
	valid := []struct{ encoded, decoded string }{
		{"a b", "a b"}, {"literal\\name", "literal\\name"}, {"%2e%2e", "%2e%2e"}, {"CON", "CON"}, {"raw/\xff", "raw/\xff"}, {"e\u0301", "e\u0301"}, {"\u00e9", "\u00e9"},
		{`"\a\b\t\n\v\f\r\\\"\377"`, "\a\b\t\n\v\f\r\\\"\xff"},
		{strings.Repeat("x", 65535), strings.Repeat("x", 65535)},
		{strings.Repeat("a/", 1023) + "z", strings.Repeat("a/", 1023) + "z"},
	}
	for _, v := range valid {
		got, err := exportPath([]byte(v.encoded))
		if err != nil || string(got) != v.decoded {
			t.Fatalf("path %q got %x err %v", v.encoded, got, err)
		}
	}
	bad := []string{"", "/a", "a/", "a//b", ".", "..", "a/./b", "a/../b", "\x00", `"a\000b"`, `"\400"`, `"\777"`, `"\38"`, `"\x41"`, `"\1"`, `"abc\"`, `"a"tail`, `a"b`, strings.Repeat("x", 65536), strings.Repeat("a/", 1024) + "z"}
	for _, path := range bad {
		if _, err := exportPath([]byte(path)); err == nil {
			t.Fatalf("accepted invalid path %q", path)
		}
	}
	// Every encoded byte is invertible except NUL/slash, which violate a single
	// component. No host filesystem, shell, filter or Unicode library is involved.
	for c := 1; c < 256; c++ {
		if c == '/' {
			continue
		}
		encoded := fmt.Sprintf(`"x\%03o"`, c)
		got, err := exportPath([]byte(encoded))
		if err != nil || !bytes.Equal(got, []byte{'x', byte(c)}) {
			t.Fatalf("byte %d lost: %x %v", c, got, err)
		}
	}
}

func TestGitStreamBudgetsAtAndOverBoundary(t *testing.T) {
	input := []byte(prologue + "blob\ndata 4\nABCD\ndone\n")
	for _, which := range []string{"input", "record", "metadata", "data", "line", "commands", "records"} {
		t.Run(which, func(t *testing.T) {
			limits := GitStreamHardLimits()
			set := func(delta int) {
				switch which {
				case "input":
					limits.InputBytes = int64(len(input) + delta)
				case "record":
					limits.RecordBytes = int64(len("blob\ndata 4\nABCD\n") + delta)
				case "metadata":
					limits.MetadataBytes = int64(len(prologue) + delta)
				case "data":
					limits.DataBytes = int64(4 + delta)
				case "line":
					limits.LineBytes = len(prologue) + delta
				case "commands":
					limits.Commands = 2 + delta
				case "records":
					limits.Records = 3 + delta
				}
			}
			set(0)
			if _, err := parseAll(t, input, limits); err != nil {
				t.Fatalf("exact bound rejected: %v", err)
			}
			set(-1)
			p := parserFor(t, bytes.NewReader(input), limits)
			for {
				_, err := p.Next()
				if err != nil {
					if err == io.EOF {
						t.Fatal("over budget accepted")
					}
					d := checkDiagnostic(t, input, p, err)
					if d.Code != "limit" {
						t.Fatalf("wrong bound diagnostic: %+v", d)
					}
					break
				}
			}
		})
	}
	// A never-ending line must stop without draining the stream; physical
	// read-ahead is bounded separately from logical consumption and diagnostic.
	limits := GitStreamHardLimits()
	limits.InputBytes = 32
	limits.LineBytes = 20
	src := &countedReader{r: io.MultiReader(strings.NewReader(prologue), repeatReader{})}
	p := parserFor(t, src, limits)
	_, _ = p.Next()
	_, err := p.Next()
	var d *GitDiagnostic
	if !errors.As(err, &d) || src.n > limits.InputBytes+1 || int64(len(d.Raw)) > 21 {
		t.Fatalf("unbounded input: n=%d d=%+v", src.n, d)
	}
}

func TestGitStreamCumulativeAndResetBudgets(t *testing.T) {
	// Many individually small lines still consume the total metadata/work cap.
	body := "commit refs/heads/m\ncommitter X <y> 0 +0000\ndata 0\n" + strings.Repeat("D x\n", 64) + "\n"
	input := []byte(prologue + body + "done\n")
	for _, kind := range []string{"metadata", "commands"} {
		limits := GitStreamHardLimits()
		if kind == "metadata" {
			limits.MetadataBytes = int64(len(body) - 1)
		} else {
			limits.Commands = 67
		}
		_, err := parseAll(t, input, limits)
		var d *GitDiagnostic
		if !errors.As(err, &d) || d.Code != "limit" {
			t.Fatalf("cumulative %s not enforced: %v", kind, err)
		}
	}
	reset := "reset refs/heads/m\nfrom :1\n\n"
	input = []byte(prologue + reset + "done\n")
	for _, kind := range []string{"metadata", "commands"} {
		limits := GitStreamHardLimits()
		if kind == "metadata" {
			limits.MetadataBytes = int64(len(reset))
		} else {
			limits.Commands = 3
		}
		if _, err := parseAll(t, input, limits); err != nil {
			t.Fatalf("reset exact %s: %v", kind, err)
		}
		if kind == "metadata" {
			limits.MetadataBytes--
		} else {
			limits.Commands--
		}
		_, err := parseAll(t, input, limits)
		var d *GitDiagnostic
		if !errors.As(err, &d) || d.Code != "limit" {
			t.Fatalf("reset blank %s not counted: %v", kind, err)
		}
	}
}

func TestGitStreamEncodedPathLineBoundary(t *testing.T) {
	limits := GitStreamHardLimits()
	prefix := "M 100644 :1 "
	path := strings.Repeat("x", limits.LineBytes-len(prefix)-1)
	wrap := func(path string) []byte {
		return []byte(prologue + "commit refs/heads/m\ncommitter X <y> 0 +0000\ndata 0\n" + prefix + path + "\n\ndone\n")
	}
	r, err := parseAll(t, wrap(path), limits)
	if err != nil || len(r[1].Files[0].Path) != len(path) {
		t.Fatalf("exact encoded line boundary failed: %v", err)
	}
	for _, encoded := range []string{path + "x", `"` + strings.Repeat(`\377`, limits.LineBytes/4) + `"`} {
		_, err := parseAll(t, wrap(encoded), limits)
		var d *GitDiagnostic
		if !errors.As(err, &d) || d.Code != "limit" {
			t.Fatalf("encoded path cap is not operational exhaustion: %v", err)
		}
	}
}

type repeatReader struct{}

func (repeatReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 'x'
	}
	return len(b), nil
}

type countedReader struct {
	r io.Reader
	n int64
}

func (r *countedReader) Read(b []byte) (int, error) {
	n, e := r.r.Read(b)
	r.n += int64(n)
	return n, e
}

type chunkReader struct {
	b     []byte
	chunk int
	final error
}

func (r *chunkReader) Read(b []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, r.final
	}
	n := min(len(b), len(r.b), r.chunk)
	copy(b, r.b[:n])
	r.b = r.b[n:]
	if len(r.b) == 0 {
		return n, r.final
	}
	return n, nil
}

type idleReader struct{}

func (idleReader) Read([]byte) (int, error) { return 0, nil }

func TestGitStreamReaderErrorsAndCancellation(t *testing.T) {
	for _, chunk := range []int{1, 2, 7, 4096} {
		p := parserFor(t, &chunkReader{[]byte(literalExport), chunk, io.EOF}, GitStreamHardLimits())
		for {
			_, err := p.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("chunk %d: %v", chunk, err)
			}
		}
	}
	boom := errors.New("private-secret I/O error")
	for _, src := range []io.Reader{&chunkReader{[]byte(literalExport), 4096, boom}, idleReader{}} {
		p := parserFor(t, src, GitStreamHardLimits())
		for i := 0; i < 20; i++ {
			_, err := p.Next()
			if err != nil {
				if err == io.EOF {
					t.Fatal("swallowed source failure")
				}
				checkDiagnostic(t, []byte(literalExport), p, err)
				if !errors.Is(err, boom) && !errors.Is(err, io.ErrNoProgress) {
					t.Fatalf("lost cause: %v", err)
				}
				break
			}
			if i == 19 {
				t.Fatal("no terminal I/O failure")
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	p, err := NewGitStream(ctx, strings.NewReader(literalExport), "sha1", GitStreamHardLimits())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_, err = p.Next()
	checkDiagnostic(t, []byte(literalExport), p, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation")
	}
}

func TestGitStreamRestartIsReplayOnly(t *testing.T) {
	input := []byte(prologue + "blob\nmark :1\ndata 11\n\ndone\nblob\n\ncommit refs/heads/m\ncommitter X <y> 0 +0000\ndata 0\nfrom :2\nM 160000 :1 private-secret\n\ndone\n")
	r, err := parseAll(t, input, GitStreamHardLimits())
	if err == nil || len(r) != 2 {
		t.Fatalf("embedded done was treated as success: %v", err)
	}
	var first *GitDiagnostic
	if !errors.As(err, &first) {
		t.Fatal(err)
	}
	_, again := parseAll(t, input[first.RestartOffset:], GitStreamHardLimits())
	var second *GitDiagnostic
	if !errors.As(again, &second) || !reflect.DeepEqual(first, second) {
		t.Fatal("replay boundary changed observation")
	}
	if first.CompletedOffset <= 0 || first.RestartOffset != 0 {
		t.Fatal("missing safe full restart")
	}
	// An incomplete tail remains available verbatim at its exact input offset;
	// the parser neither discards it nor pretends it was durably captured.
	if !bytes.Equal(first.Raw, input[first.RecordStart:first.Offset]) {
		t.Fatal("diagnostic location lost")
	}
}

func TestGitStreamConstructorRejectsUnboundedLimits(t *testing.T) {
	h := GitStreamHardLimits()
	for i := 0; i < 7; i++ {
		for _, over := range []bool{false, true} {
			v := h
			fields := []*int64{&v.InputBytes, &v.RecordBytes, &v.MetadataBytes, &v.DataBytes}
			if i < 4 {
				if over {
					*fields[i]++
				} else {
					*fields[i] = 0
				}
			} else {
				ints := []*int{&v.LineBytes, &v.Commands, &v.Records}
				if over {
					*ints[i-4]++
				} else {
					*ints[i-4] = 0
				}
			}
			if _, err := NewGitStream(context.Background(), strings.NewReader(""), "sha1", v); err == nil {
				t.Fatal("unbounded/zero budget accepted")
			}
		}
	}
	for _, format := range []string{"", "SHA1", "sha512", "auto"} {
		if _, err := NewGitStream(context.Background(), strings.NewReader(""), format, h); err == nil {
			t.Fatal("guessed algorithm")
		}
	}
	if _, err := NewGitStream(nil, strings.NewReader(""), "sha1", h); err == nil {
		t.Fatal("nil context")
	}
	if _, err := NewGitStream(context.Background(), nil, "sha1", h); err == nil {
		t.Fatal("nil source")
	}
}

func TestGitStreamDeterministicAdversarialMutations(t *testing.T) {
	rng := rand.New(rand.NewSource(20261015))
	seed := []byte(literalExport)
	for i := 0; i < 512; i++ {
		b := bytes.Clone(seed)
		for j := 0; j < 1+rng.Intn(8); j++ {
			b[rng.Intn(len(b))] = byte(rng.Intn(256))
		}
		exerciseBoundedStream(t, b)
	}
}

func exerciseBoundedStream(t testing.TB, input []byte) {
	t.Helper()
	limits := GitStreamHardLimits()
	limits.InputBytes = 4096
	limits.RecordBytes = 1024
	limits.MetadataBytes = 768
	limits.DataBytes = 512
	limits.LineBytes = 256
	limits.Commands = 32
	limits.Records = 32
	p := parserFor(t, bytes.NewReader(input), limits)
	offset := int64(0)
	for i := 0; i <= limits.Records; i++ {
		r, err := p.Next()
		if err != nil {
			if err == io.EOF {
				if offset != int64(len(input)) {
					t.Fatal("accepted partial stream")
				}
			} else {
				checkDiagnostic(t, input, p, err)
			}
			return
		}
		if r.Start != offset || r.End > int64(len(input)) || !bytes.Equal(r.Raw, input[r.Start:r.End]) {
			t.Fatal("record bytes lost")
		}
		for _, h := range r.Headers {
			if h.Value.Start < 0 || h.Value.End < h.Value.Start || h.Value.End > len(r.Raw) {
				t.Fatal("invalid header span")
			}
		}
		if r.HasData && (r.Data.Start < 0 || r.Data.End < r.Data.Start || r.Data.End > len(r.Raw)) {
			t.Fatal("invalid data span")
		}
		for _, f := range r.Files {
			for _, s := range []GitSpan{f.Raw, f.Mode, f.Ref, f.PathRaw} {
				if s.Start < 0 || s.End < s.Start || s.End > len(r.Raw) {
					t.Fatal("invalid file span")
				}
			}
			if f.Kind != "deleteall" {
				decoded, err := exportPath(r.Raw[f.PathRaw.Start:f.PathRaw.End])
				if err != nil || !bytes.Equal(decoded, f.Path) {
					t.Fatal("raw path span lost lexical spelling")
				}
			}
		}
		offset = r.End
	}
	t.Fatal("record budget did not terminate")
}

func FuzzGitStreamBounded(f *testing.F) {
	for _, s := range []string{literalExport, prologue + "done\n", prologue + "blob\ndata 999999999999999999999999\n", prologue + "blob\ndata 4\ndone\ndone\n", prologue + "commit refs/heads/m\ncommitter X <y> 0 +0000\ndata 0\nM 160000 :1 x\n\ndone\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 8192 {
			return
		}
		exerciseBoundedStream(t, b)
	})
}
