// Package migration parses untrusted migration input without executing it.
package migration

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Git export profile v1 (LF is byte 0x0a; no CRLF normalization):
//
//	stream = "feature done" LF record* "done" LF EOF
//	blob   = "blob" LF [mark] [original-oid] data LF
//	commit = "commit " ref LF [mark] [original-oid] [author]
//	         committer [encoding] data [from] merge* file-command* LF
//	reset  = "reset " ref LF [from] [LF]
//	mark   = "mark :" positive-decimal LF
//	data   = "data " decimal LF <exactly decimal bytes>
//	file-command = "M " mode SP object-ref SP path LF | "D " path LF |
//	               "deleteall" LF
//
// This is a deliberately finite subset of Git fast-export, suitable for exports
// using --use-done-feature and raw dates. Decimal lengths have no sign/leading
// zeros (except 0); marks are positive U64. Object refs are marks or full lowercase
// hex OID claims of the explicitly supplied SHA-1/SHA-256 format, never expressions
// or revspecs. Modes are exactly 100644, 100755, 120000. Paths are relative raw
// bytes, either unquoted (no quote, LF or NUL) or Git C-quoted (\a\b\t\n\v\f\r,
// \\, \" and three-digit octal escapes <= 377). Slash alone separates components;
// empty/dot/dotdot components and paths above 65535 bytes/1024 components fail.
// Those are structural ceilings, not an advertised full-size path capability:
// the encoded command (prefix, escaping and LF included) must also fit LineBytes.
// Thus usable paths may be shorter, particularly with octal quoting or full OIDs.
// Names/refs, identities, dates, encoding, message, mode spelling and command order
// are retained in Raw. Dates use an I64 decimal second count and +/-HHMM (HH<=23,
// MM<=59); signed zero and leading zeros in dates are retained. No field defaults,
// sorting, deduplication, Unicode conversion or implicit parent inference occurs.
// Blob data has one mandatory separator LF; commit data has no extra delimiter,
// matching fast-export (a message's own final LF is counted payload). A commit
// always ends with a separate blank LF. Reset's final blank LF is optional.
//
// Unsupported features/records include tags, gitlinks, inline/heredoc data,
// rename/copy/note commands, aliases, progress/checkpoint/options and other feature
// declarations. A syntactically parsed blob is just bytes, including LFS pointers,
// hooks and symlink targets: nothing is followed, fetched, evaluated or imported.
// A missing done, trailing bytes, or unknown command always fails closed.
//
// Parsing establishes syntax only, not native Git OID validity, graph closure,
// original commit/signature fidelity, authorization, durable capture or migration
// acceptance. OriginalOID and object refs remain unverified claims. Fast-export
// is not complete native-object evidence. MIG-01's support matrix and unresolved
// blockers still apply, including annotated tags, LFS, extra headers and gitlinks.
// Callers must authorize input/diagnostic access and persist protected manifests
// under that policy before acknowledging capture; this parser creates no manifest,
// verified identity, target TID, stable blocker key or publication of its own.
const GitExportProfile = "git-fast-export-bounded-v1"

// GitStreamLimits are explicit admission budgets. All fields must be positive
// and may only tighten the hard ceilings returned by GitStreamHardLimits.
// InputBytes includes every framing byte. RecordBytes includes payload/framing;
// LineBytes includes LF. MetadataBytes includes all command/header/blank lines, but not counted data or
// its delimiter. Commands counts every command/header/blank line per record,
// including its first line. Records includes the prologue and done. Limits do
// not grow with previously returned records.
// These operational budgets are below canonical representability limits: a
// budget failure remains unresolved resource exhaustion, not proof that source
// semantics are invalid or excluded. A rejected length claim is not captured data.
//
// The parser keeps one raw record, bounded metadata descriptors/decoded paths and
// a 4096-byte read buffer; it keeps no history/mark/ref table and never spools.
// Raw allocation capacity is at most 2*RecordBytes+2. One extra byte may be read
// and captured to distinguish a limit violation from exact-limit EOF. Underlying
// read-ahead is capped at InputBytes+1. Retained results are the caller's budget.
// Callers must supply reader deadlines to bound blocking I/O; context checks
// cannot interrupt a Read already in progress. Instances are not concurrent-safe.
type GitStreamLimits struct {
	InputBytes, RecordBytes, MetadataBytes, DataBytes int64
	LineBytes, Commands, Records                      int
}

func GitStreamHardLimits() GitStreamLimits {
	return GitStreamLimits{1 << 30, 8 << 20, 256 << 10, 4 << 20, 64 << 10, 8192, 100000}
}

// GitSpan indexes exact bytes in a record's Raw, excluding the line ending.
type GitSpan struct{ Start, End int }

type GitHeader struct {
	Name  string
	Value GitSpan
}

type GitFileCommand struct {
	Kind    string
	Raw     GitSpan // complete command line, excluding LF
	Mode    GitSpan // absent for D/deleteall
	Ref     GitSpan // unverified mark/OID claim, absent for D/deleteall
	PathRaw GitSpan // exact quoted/unquoted spelling; absent for deleteall
	Path    []byte  // decoded bytes; nil for deleteall
}

// GitRecord owns Raw and Paths. Header/Data spans index Raw, even for invalid
// UTF-8 or embedded NUL data. Optional headers stay absent, not defaulted.
// Offsets are absolute in the original stream. Returned records are provisional
// until done+EOF is observed, and even then establish no ingestion/verification.
type GitRecord struct {
	Kind       string
	Start, End int64
	Raw        []byte
	Headers    []GitHeader
	Data       GitSpan
	HasData    bool
	Files      []GitFileCommand
}

// GitDiagnostic is a terminal, bounded, byte-lossless observation, not a durable
// unsupported-input manifest. Raw is every byte consumed in the failed record,
// including a possible one-byte limit probe (<= RecordBytes+1). [RecordStart,
// Offset) locates exactly Raw in the caller's same immutable, authorized input.
// RecordComplete is always false: the unconsumed tail is NOT claimed captured.
// No full-record digest, source OID verification or durable evidence is invented.
// Persist that input and its repository/snapshot/policy binding separately under
// MIG-01; observed identifier claims remain in Raw even if malformed/abbreviated.
//
// RestartOffset is always 0, with RestartRequiresReplay always true: the caller
// MUST separately retain and reopen the SAME immutable input to replay from its
// prologue with fresh parser/consumer staging. A one-shot reader alone supplies
// no restart capability. Offset describes logical consumption, not the position
// of the underlying reader (which may have read ahead). CompletedOffset is informational,
// NOT a continuation point: marks, implicit refs, counts and byte budgets are not
// checkpointed. Never skip the offending record, seek to Offset, or scan for a
// newline/done in data. A changed/repaired input is a new observation. Consumers
// must discard provisional effects or use separately verified idempotent replay.
// Error() is deliberately content-free; all diagnostic fields, including raw
// reader errors exposed by Cause/Unwrap, must remain protected.
// The returned diagnostic and its Raw are read-only observations. As with Go
// errors generally, callers must not mutate them (Next returns the same error).
type GitDiagnostic struct {
	Code, Reason                   string
	RecordStart, Offset            int64
	CompletedOffset, RestartOffset int64
	Raw                            []byte
	RecordComplete                 bool
	RestartRequiresReplay          bool
	Cause                          error
}

func (d *GitDiagnostic) Error() string { return "Git export rejected: " + d.Code }
func (d *GitDiagnostic) Unwrap() error { return d.Cause }

type GitStream struct {
	ctx                                context.Context
	r                                  *bufio.Reader
	limits                             GitStreamLimits
	oidWidth                           int
	offset, completed, start, metadata int64
	count, commands                    int
	started, done                      bool
	record                             GitRecord
	failure                            *GitDiagnostic
}

// NewGitStream accepts only explicit sha1 or sha256 source-format declarations;
// the declaration is a claim, not verification. No Git executable is used.
// Recovery requires the caller to retain a separately reopenable immutable copy
// of the input; an arbitrary io.Reader itself need not be replayable.
func NewGitStream(ctx context.Context, src io.Reader, format string, limits GitStreamLimits) (*GitStream, error) {
	if ctx == nil || src == nil {
		return nil, errors.New("nil Git stream context or reader")
	}
	h := GitStreamHardLimits()
	if limits.InputBytes <= 0 || limits.InputBytes > h.InputBytes ||
		limits.RecordBytes <= 0 || limits.RecordBytes > h.RecordBytes ||
		limits.MetadataBytes <= 0 || limits.MetadataBytes > h.MetadataBytes ||
		limits.DataBytes <= 0 || limits.DataBytes > h.DataBytes ||
		limits.LineBytes <= 0 || limits.LineBytes > h.LineBytes ||
		limits.Commands <= 0 || limits.Commands > h.Commands ||
		limits.Records <= 0 || limits.Records > h.Records {
		return nil, errors.New("invalid Git stream budgets")
	}
	width := 40
	if format == "sha256" {
		width = 64
	} else if format != "sha1" {
		return nil, errors.New("unsupported Git source format declaration")
	}
	return &GitStream{ctx: ctx, r: bufio.NewReaderSize(&io.LimitedReader{R: src, N: limits.InputBytes + 1}, 4096), limits: limits, oidWidth: width}, nil
}

func (p *GitStream) reject(code, reason string, cause error) error {
	if p.failure == nil {
		p.failure = &GitDiagnostic{Code: code, Reason: reason, RecordStart: p.start, Offset: p.offset, CompletedOffset: p.completed, Raw: p.record.Raw, RestartRequiresReplay: true, Cause: cause}
	}
	return p.failure
}

// readByte retains exact observations, including bytes triggering a budget.
func (p *GitStream) readByte() (byte, error) {
	if err := p.ctx.Err(); err != nil {
		return 0, p.reject("cancelled", "input cancelled", err)
	}
	b, err := p.r.ReadByte()
	if err != nil {
		if err == io.EOF {
			return 0, io.EOF
		}
		return 0, p.reject("io", "input read failed", err)
	}
	p.offset++
	if len(p.record.Raw) == cap(p.record.Raw) {
		capacity := min(max(256, 2*cap(p.record.Raw)), int(p.limits.RecordBytes)+1)
		raw := make([]byte, len(p.record.Raw), capacity)
		copy(raw, p.record.Raw)
		p.record.Raw = raw
	}
	p.record.Raw = append(p.record.Raw, b)
	if p.offset > p.limits.InputBytes {
		return 0, p.reject("limit", "input byte budget exceeded", nil)
	}
	if int64(len(p.record.Raw)) > p.limits.RecordBytes {
		return 0, p.reject("limit", "record byte budget exceeded", nil)
	}
	if err := p.ctx.Err(); err != nil {
		return 0, p.reject("cancelled", "input cancelled", err)
	}
	return b, nil
}

func (p *GitStream) line() ([]byte, GitSpan, error) {
	start := len(p.record.Raw)
	for {
		b, err := p.readByte()
		if err != nil {
			if err == io.EOF {
				err = p.reject("truncated", "missing complete command line or done", io.ErrUnexpectedEOF)
			}
			return nil, GitSpan{}, err
		}
		p.metadata++
		if p.metadata > p.limits.MetadataBytes || len(p.record.Raw)-start > p.limits.LineBytes {
			return nil, GitSpan{}, p.reject("limit", "metadata or line budget exceeded", nil)
		}
		if b == '\n' {
			s := GitSpan{start, len(p.record.Raw) - 1}
			return p.record.Raw[s.Start:s.End], s, nil
		}
	}
}

func (p *GitStream) command() ([]byte, GitSpan, error) {
	line, span, err := p.line()
	if err != nil {
		return nil, span, err
	}
	p.commands++
	if p.commands > p.limits.Commands {
		return nil, span, p.reject("limit", "command budget exceeded", nil)
	}
	return line, span, nil
}

func (p *GitStream) header(name string, span GitSpan) {
	p.record.Headers = append(p.record.Headers, GitHeader{name, GitSpan{span.Start + len(name) + 1, span.End}})
}

func decimal(b []byte, positive bool) bool {
	if len(b) == 0 || (len(b) > 1 && b[0] == '0') || (positive && b[0] == '0') {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(string(b), 10, 64)
	return err == nil
}

func (p *GitStream) oid(b []byte) bool {
	if len(b) != p.oidWidth {
		return false
	}
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (p *GitStream) objectRef(b []byte) bool {
	return (len(b) > 1 && b[0] == ':' && decimal(b[1:], true)) || p.oid(b)
}

func exportRef(b []byte) bool {
	if !bytes.HasPrefix(b, []byte("refs/")) || bytes.Contains(b, []byte("..")) || bytes.Contains(b, []byte("@{")) {
		return false
	}
	for _, c := range b {
		if c <= 32 || c == 127 || bytes.IndexByte([]byte("~^:?*[\\"), c) >= 0 {
			return false
		}
	}
	start := 0
	for i := 0; i <= len(b); i++ {
		if i == len(b) || b[i] == '/' {
			part := b[start:i]
			if len(part) == 0 || part[0] == '.' || part[len(part)-1] == '.' || bytes.HasSuffix(part, []byte(".lock")) {
				return false
			}
			start = i + 1
		}
	}
	return true
}

func identityDate(b []byte) bool {
	z := bytes.LastIndexByte(b, ' ')
	if z < 0 {
		return false
	}
	zone := b[z+1:]
	if len(zone) != 5 || (zone[0] != '+' && zone[0] != '-') {
		return false
	}
	for _, c := range zone[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	if (zone[1]-'0')*10+zone[2]-'0' > 23 || (zone[3]-'0')*10+zone[4]-'0' > 59 {
		return false
	}
	s := bytes.LastIndexByte(b[:z], ' ')
	if s < 0 {
		return false
	}
	seconds := b[s+1 : z]
	digits := seconds
	if len(digits) > 0 && (digits[0] == '-' || digits[0] == '+') {
		digits = digits[1:]
	}
	if len(digits) == 0 {
		return false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}
	if _, err := strconv.ParseInt(string(seconds), 10, 64); err != nil {
		return false
	}
	id := b[:s]
	open := bytes.IndexByte(id, '<')
	return len(id) > 0 && id[len(id)-1] == '>' && open >= 0 && (open == 0 || id[open-1] == ' ') && bytes.IndexByte(id, 0) < 0 && bytes.IndexByte(id[:len(id)-1], '>') < 0 && bytes.IndexByte(id[open+1:len(id)-1], '<') < 0
}

func (p *GitStream) data(line []byte, span GitSpan, delimiter bool) error {
	if !bytes.HasPrefix(line, []byte("data ")) {
		for _, known := range []string{"mark ", "original-oid ", "author ", "committer ", "encoding ", "from ", "merge "} {
			if bytes.HasPrefix(line, []byte(known)) {
				return p.reject("malformed", "misordered supported header before data", nil)
			}
		}
		return p.reject("unsupported", "unsupported record where counted data is required", nil)
	}
	b := line[5:]
	if !decimal(b, false) {
		return p.reject("unsupported", "only canonical counted data is supported", nil)
	}
	n, _ := strconv.ParseUint(string(b), 10, 64)
	reserve := uint64(0)
	if delimiter {
		reserve = 1
	}
	if n > uint64(p.limits.DataBytes) || n+reserve > uint64(p.limits.RecordBytes-int64(len(p.record.Raw))) || n+reserve > uint64(p.limits.InputBytes-p.offset) {
		return p.reject("limit", "declared data exceeds byte budget", nil)
	}
	p.header("data", span)
	start := len(p.record.Raw)
	for i := uint64(0); i < n; i++ {
		if _, err := p.readByte(); err != nil {
			if err == io.EOF {
				return p.reject("truncated", "incomplete counted data", io.ErrUnexpectedEOF)
			}
			return err
		}
	}
	p.record.Data = GitSpan{start, len(p.record.Raw)}
	p.record.HasData = true
	if !delimiter {
		return nil
	}
	bsep, err := p.readByte()
	if err != nil {
		if err == io.EOF {
			return p.reject("truncated", "missing data delimiter", io.ErrUnexpectedEOF)
		}
		return err
	}
	if bsep != '\n' {
		return p.reject("malformed", "data delimiter must be LF", nil)
	}
	return nil
}

// Next returns one syntactically complete provisional record. EOF means done
// and physical EOF were verified. Every failure is sticky; no partial record is
// returned with an error, and repeated Next calls consume no additional input.
func (p *GitStream) Next() (GitRecord, error) {
	if p.failure != nil {
		return GitRecord{}, p.failure
	}
	if p.done {
		return GitRecord{}, io.EOF
	}
	p.start = p.offset
	p.metadata = 0
	p.commands = 0
	p.record = GitRecord{Start: p.start}
	line, span, err := p.command()
	if err != nil {
		return GitRecord{}, err
	}
	p.count++
	if p.count > p.limits.Records {
		return GitRecord{}, p.reject("limit", "record count budget exceeded", nil)
	}
	if !p.started {
		if !bytes.Equal(line, []byte("feature done")) {
			return GitRecord{}, p.reject("unsupported", "required feature done prologue absent", nil)
		}
		p.record.Kind = "feature"
		p.started = true
	} else {
		switch {
		case bytes.Equal(line, []byte("done")):
			// Probe through the same bounded reader; trailing bytes remain in Raw.
			_, err = p.readByte()
			if err != io.EOF {
				if err == nil {
					err = p.reject("malformed", "trailing bytes after done", nil)
				}
				return GitRecord{}, err
			}
			if err = p.ctx.Err(); err != nil {
				return GitRecord{}, p.reject("cancelled", "input cancelled", err)
			}
			p.record.Kind = "done"
			p.done = true
		case bytes.Equal(line, []byte("blob")):
			p.record.Kind = "blob"
			err = p.blob()
		case bytes.HasPrefix(line, []byte("commit ")):
			p.record.Kind = "commit"
			if !exportRef(line[7:]) {
				err = p.reject("malformed", "invalid commit ref", nil)
			} else {
				p.header("commit", span)
				err = p.commit()
			}
		case bytes.HasPrefix(line, []byte("reset ")):
			p.record.Kind = "reset"
			if !exportRef(line[6:]) {
				err = p.reject("malformed", "invalid reset ref", nil)
			} else {
				p.header("reset", span)
				err = p.reset()
			}
		default:
			err = p.reject("unsupported", "unsupported top-level record", nil)
		}
		if err != nil {
			return GitRecord{}, err
		}
	}
	p.record.End = p.offset
	p.completed = p.offset
	return p.record, nil
}

func (p *GitStream) preamble() ([]byte, GitSpan, error) {
	line, span, err := p.command()
	if err != nil {
		return nil, span, err
	}
	if bytes.HasPrefix(line, []byte("mark ")) {
		if !bytes.HasPrefix(line, []byte("mark :")) || !decimal(line[6:], true) {
			return nil, span, p.reject("malformed", "invalid mark claim", nil)
		}
		p.header("mark", span)
		line, span, err = p.command()
		if err != nil {
			return nil, span, err
		}
	}
	if bytes.HasPrefix(line, []byte("original-oid ")) {
		if !p.oid(line[13:]) {
			return nil, span, p.reject("malformed", "invalid original-oid claim", nil)
		}
		p.header("original-oid", span)
		line, span, err = p.command()
	}
	return line, span, err
}

func (p *GitStream) blob() error {
	line, span, err := p.preamble()
	if err != nil {
		return err
	}
	return p.data(line, span, true)
}

func (p *GitStream) commit() error {
	line, span, err := p.preamble()
	if err != nil {
		return err
	}
	if bytes.HasPrefix(line, []byte("author ")) {
		if !identityDate(line[7:]) {
			return p.reject("malformed", "invalid author raw date or identity", nil)
		}
		p.header("author", span)
		line, span, err = p.command()
		if err != nil {
			return err
		}
	}
	if !bytes.HasPrefix(line, []byte("committer ")) || !identityDate(line[10:]) {
		return p.reject("malformed", "missing or malformed committer", nil)
	}
	p.header("committer", span)
	line, span, err = p.command()
	if err != nil {
		return err
	}
	if bytes.HasPrefix(line, []byte("gpgsig ")) {
		return p.reject("unsupported", "signature export records are unsupported", nil)
	}
	if bytes.HasPrefix(line, []byte("encoding ")) {
		if bytes.IndexByte(line[9:], 0) >= 0 {
			return p.reject("malformed", "invalid encoding bytes", nil)
		}
		p.header("encoding", span)
		line, span, err = p.command()
		if err != nil {
			return err
		}
	}
	if err = p.data(line, span, false); err != nil {
		return err
	}
	line, span, err = p.command()
	if err != nil {
		return err
	}
	if bytes.HasPrefix(line, []byte("from ")) {
		if !p.objectRef(line[5:]) {
			return p.reject("malformed", "invalid parent claim", nil)
		}
		p.header("from", span)
		line, span, err = p.command()
		if err != nil {
			return err
		}
	}
	for bytes.HasPrefix(line, []byte("merge ")) {
		if !p.objectRef(line[6:]) {
			return p.reject("malformed", "invalid merge parent claim", nil)
		}
		p.header("merge", span)
		line, span, err = p.command()
		if err != nil {
			return err
		}
	}
	for len(line) > 0 {
		if err = p.file(line, span); err != nil {
			return err
		}
		line, span, err = p.command()
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *GitStream) reset() error {
	b, err := p.peek(5)
	if err != nil && err != io.EOF {
		return err
	}
	if bytes.Equal(b, []byte("from ")) {
		line, span, err := p.command()
		if err != nil {
			return err
		}
		if !p.objectRef(line[5:]) {
			return p.reject("malformed", "invalid reset target claim", nil)
		}
		p.header("from", span)
	}
	b, err = p.peek(1)
	if err != nil && err != io.EOF {
		return err
	}
	if len(b) > 0 && b[0] == '\n' {
		_, _, err = p.command()
		return err
	}
	return nil
}

func (p *GitStream) peek(n int) ([]byte, error) {
	if err := p.ctx.Err(); err != nil {
		return nil, p.reject("cancelled", "input cancelled", err)
	}
	b, err := p.r.Peek(n)
	if cancel := p.ctx.Err(); cancel != nil {
		return nil, p.reject("cancelled", "input cancelled", cancel)
	}
	if err != nil && err != io.EOF {
		return nil, p.reject("io", "input read failed", err)
	}
	return b, err
}

func (p *GitStream) file(line []byte, span GitSpan) error {
	f := GitFileCommand{Raw: span}
	var path []byte
	switch {
	case bytes.Equal(line, []byte("deleteall")):
		f.Kind = "deleteall"
	case bytes.HasPrefix(line, []byte("D ")):
		f.Kind = "D"
		path = line[2:]
		f.PathRaw = GitSpan{span.Start + 2, span.End}
	case bytes.HasPrefix(line, []byte("M ")):
		f.Kind = "M"
		mode, rest, ok := bytes.Cut(line[2:], []byte{' '})
		if !ok {
			return p.reject("malformed", "missing file mode/ref/path", nil)
		}
		if !bytes.Equal(mode, []byte("100644")) && !bytes.Equal(mode, []byte("100755")) && !bytes.Equal(mode, []byte("120000")) {
			return p.reject("unsupported", "unsupported file mode including gitlink", nil)
		}
		ref, tail, ok := bytes.Cut(rest, []byte{' '})
		if !ok {
			return p.reject("malformed", "missing file ref/path", nil)
		}
		if bytes.Equal(ref, []byte("inline")) {
			return p.reject("unsupported", "inline data is unsupported", nil)
		}
		if !p.objectRef(ref) {
			return p.reject("malformed", "invalid file object claim", nil)
		}
		f.Mode = GitSpan{span.Start + 2, span.Start + 2 + len(mode)}
		f.Ref = GitSpan{f.Mode.End + 1, f.Mode.End + 1 + len(ref)}
		path = tail
		f.PathRaw = GitSpan{f.Ref.End + 1, span.End}
	default:
		return p.reject("unsupported", "unsupported commit command", nil)
	}
	if path != nil {
		var err error
		f.Path, err = exportPath(path)
		if err != nil {
			return p.reject("malformed", "invalid raw file path", nil)
		}
	}
	p.record.Files = append(p.record.Files, f)
	return nil
}

func exportPath(raw []byte) ([]byte, error) {
	bad := errors.New("invalid Git byte path")
	if bytes.IndexByte(raw, '\n') >= 0 {
		return nil, bad
	}
	path := make([]byte, 0, len(raw))
	if len(raw) > 0 && raw[0] == '"' {
		if len(raw) < 2 || raw[len(raw)-1] != '"' {
			return nil, bad
		}
		for i := 1; i < len(raw)-1; i++ {
			c := raw[i]
			if c == '"' {
				return nil, bad
			}
			if c == '\\' {
				i++
				if i >= len(raw)-1 {
					return nil, bad
				}
				c = raw[i]
				switch c {
				case 'a':
					c = 7
				case 'b':
					c = 8
				case 't':
					c = 9
				case 'n':
					c = 10
				case 'v':
					c = 11
				case 'f':
					c = 12
				case 'r':
					c = 13
				case '\\', '"':
				default:
					if c < '0' || c > '3' || i+2 >= len(raw)-1 || raw[i+1] < '0' || raw[i+1] > '7' || raw[i+2] < '0' || raw[i+2] > '7' {
						return nil, bad
					}
					c = (c-'0')*64 + (raw[i+1]-'0')*8 + raw[i+2] - '0'
					i += 2
				}
			}
			path = append(path, c)
		}
	} else {
		if bytes.IndexByte(raw, '"') >= 0 {
			return nil, bad
		}
		path = append(path, raw...)
	}
	if len(path) == 0 || len(path) > 65535 || bytes.IndexByte(path, 0) >= 0 {
		return nil, bad
	}
	if bytes.Count(path, []byte{'/'}) >= 1024 {
		return nil, bad
	}
	parts := bytes.Split(path, []byte{'/'})
	for _, part := range parts {
		if len(part) == 0 || bytes.Equal(part, []byte(".")) || bytes.Equal(part, []byte("..")) {
			return nil, bad
		}
	}
	return path, nil
}

// String avoids disclosing input content when a parser is logged accidentally.
func (p *GitStream) String() string { return fmt.Sprintf("GitStream(%s)", GitExportProfile) }
