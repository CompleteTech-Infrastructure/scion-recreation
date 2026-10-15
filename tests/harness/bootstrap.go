//go:build darwin || linux

// Package harness runs exact, required Go test leaves on local POSIX hosts.
// It does not discover tests, invoke Git, or select a backend implicitly.
package harness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"
)

const PinnedGoVersion = "go1.27.2"

type Suite string

const (
	Unit        Suite = "unit"
	Integration Suite = "integration"
)

// Case names are Go's emitted names, including slash-separated subtest names.
// Each entry must be a leaf: declaring a parent never selects its descendants.
type Case struct {
	Suite                        Suite
	PackageDir, ImportPath, Name string
}

type Limits struct {
	MaxOutputBytes, MaxEventBytes, MaxEvents, MaxNames int
	CleanupTimeout                                     time.Duration
}

func DefaultLimits() Limits {
	return Limits{8 << 20, 1 << 20, 65536, 4096, 2 * time.Second}
}

type Plan struct {
	Root, GoBinary, SourceRevision, ContractSHA256 string
	Cases                                          []Case
	Suite                                          Suite
	Seed                                           uint64
	Timeout                                        time.Duration
	Limits                                         Limits
}

type Command struct {
	Argv    []string
	Dir     string
	Env     []string // Only the deliberately inherited and fixed environment.
	Timeout time.Duration
	Limits  Limits
}

type Receipt struct {
	StartedAt, FinishedAt time.Time
	Started               bool
	PID                   int
	ExitCode              *int
	Signal                string
	Canceled, TimedOut    bool
	Cleanup               string
}

type Result struct {
	Command         Command
	Receipt         Receipt
	Required        Case
	Passed          bool
	Observed        map[string]string
	Stdout, Stderr  []byte
	OutputBytes     int64
	OutputTruncated bool
	Error           string
}

type Report struct {
	SourceRevision, ContractSHA256 string
	Suite                          Suite
	Seed                           uint64
	ToolSHA256                     string
	Toolchain                      Result
	Results                        []Result
	PassedRequired                 int
	Success                        bool
}

func cleanText(s string) bool {
	return s != "" && !strings.ContainsFunc(s, unicode.IsControl)
}

// ValidatePlan rejects ambiguous inventories before any process starts.
func ValidatePlan(p Plan) error {
	if p.Suite != Unit && p.Suite != Integration {
		return errors.New("invalid selected suite")
	}
	if !filepath.IsAbs(p.Root) || filepath.Clean(p.Root) != p.Root {
		return errors.New("root must be an absolute clean directory")
	}
	if !filepath.IsAbs(p.GoBinary) || !cleanText(p.GoBinary) {
		return errors.New("Go binary must be an absolute path")
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(p.SourceRevision) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(p.ContractSHA256) {
		return errors.New("source and contract digests required")
	}
	l := p.Limits
	if p.Timeout <= 0 || p.Timeout > 120*time.Second || l.MaxOutputBytes <= 0 || l.MaxOutputBytes > 8<<20 || l.MaxEventBytes <= 0 || l.MaxEventBytes > 1<<20 || l.MaxEvents <= 0 || l.MaxEvents > 65536 || l.MaxNames <= 0 || l.MaxNames > 4096 || l.CleanupTimeout <= 0 || l.CleanupTimeout > 2*time.Second {
		return errors.New("invalid execution limits")
	}
	if len(p.Cases) == 0 || len(p.Cases) > 4096 {
		return errors.New("manifest must contain 1..4096 cases")
	}
	dirs, imports, seen := map[string]string{}, map[string]string{}, map[string]bool{}
	selected := 0
	for _, c := range p.Cases {
		if c.Suite != Unit && c.Suite != Integration {
			return errors.New("invalid case suite")
		}
		if !strings.HasPrefix(c.PackageDir, "./") || c.PackageDir != "./"+filepath.ToSlash(filepath.Clean(strings.TrimPrefix(c.PackageDir, "./"))) || strings.Contains(c.PackageDir, "\\") || strings.Contains(c.PackageDir, "...") || !cleanText(c.PackageDir) {
			return errors.New("package must be one exact relative directory")
		}
		resolved, err := filepath.EvalSymlinks(filepath.Join(p.Root, c.PackageDir))
		if err != nil {
			return fmt.Errorf("package directory: %w", err)
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.IsDir() {
			return errors.New("package path is not a directory")
		}
		root, err := filepath.EvalSymlinks(p.Root)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return errors.New("package escapes root")
		}
		if !cleanText(c.ImportPath) || strings.ContainsAny(c.ImportPath, " \\|@") || !cleanText(c.Name) || len(c.Name) > 1024 {
			return errors.New("invalid import path or case name")
		}
		parts := strings.Split(c.Name, "/")
		top := []rune(parts[0])
		if !token.IsIdentifier(parts[0]) || !strings.HasPrefix(parts[0], "Test") || (len(top) > 4 && unicode.IsLower(top[4])) {
			return errors.New("case must be a Go Test name")
		}
		for _, part := range parts {
			if part == "" || strings.ContainsFunc(part, unicode.IsSpace) {
				return errors.New("case must use exact emitted name components")
			}
		}
		if d, ok := imports[c.ImportPath]; ok && d != c.PackageDir {
			return errors.New("import mapped to multiple directories")
		}
		if ip, ok := dirs[c.PackageDir]; ok && ip != c.ImportPath {
			return errors.New("directory mapped to multiple imports")
		}
		dirs[c.PackageDir], imports[c.ImportPath] = c.ImportPath, c.PackageDir
		key := c.ImportPath + "\x00" + c.Name
		if seen[key] {
			return errors.New("duplicate case")
		}
		for other := range seen {
			if strings.HasPrefix(other, key+"/") || strings.HasPrefix(key, other+"/") {
				return errors.New("manifest contains a parent and a leaf")
			}
		}
		seen[key] = true
		if c.Suite == p.Suite {
			selected++
		}
	}
	if selected == 0 {
		return errors.New("empty suite selection")
	}
	return nil
}

// CaseSeed uses the versioned, length-framed SHA-256 seed domain; no clock or
// process identity contributes entropy. The full 256 bits are exported to tests.
func CaseSeed(root uint64, importPath, exactName string) [32]byte {
	h := sha256.New()
	h.Write([]byte("CANOPY\x00HARNESS-SEED\x00V1\x00"))
	_ = binary.Write(h, binary.BigEndian, root)
	for _, s := range []string{importPath, exactName} {
		_ = binary.Write(h, binary.BigEndian, uint32(len(s)))
		h.Write([]byte(s))
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func selected(p Plan) []Case {
	var cases []Case
	for _, c := range p.Cases {
		if c.Suite == p.Suite {
			cases = append(cases, c)
		}
	}
	sort.Slice(cases, func(i, j int) bool {
		a, b := cases[i], cases[j]
		if a.PackageDir != b.PackageDir {
			return a.PackageDir < b.PackageDir
		}
		return a.Name < b.Name
	})
	return cases
}

func environment(seed uint64) []string {
	var env []string
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "GOCACHE"} {
		if v, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+v)
		}
	}
	env = append(env, "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOENV=off", "GOFLAGS=-mod=readonly", "GO111MODULE=on", "GOPRIVATE=", "GONOPROXY=none", "GONOSUMDB=none", "GOVCS=*:off", "CGO_ENABLED=0", fmt.Sprintf("CANOPY_TEST_SEED=%d", seed))
	sort.Strings(env)
	return env
}

func Commands(p Plan) ([]Command, error) {
	if err := ValidatePlan(p); err != nil {
		return nil, err
	}
	var commands []Command
	for _, c := range selected(p) {
		parts := strings.Split(c.Name, "/")
		for i, part := range parts {
			parts[i] = "^" + regexp.QuoteMeta(part) + "$"
		}
		seed := CaseSeed(p.Seed, c.ImportPath, c.Name)
		env := append(environment(p.Seed), "CANOPY_CASE_SEED="+hex.EncodeToString(seed[:]), "CANOPY_TEST_CASE="+c.Name)
		sort.Strings(env)
		commands = append(commands, Command{[]string{p.GoBinary, "test", "-json", "-count=1", "-trimpath", "-buildvcs=false", "-shuffle=off", "-parallel=1", "-timeout=" + p.Timeout.String(), "-run", strings.Join(parts, "/"), c.PackageDir}, p.Root, env, p.Timeout, p.Limits})
	}
	return commands, nil
}

type capture struct {
	mu        sync.Mutex
	out, err  []byte
	total     int64
	limit     int
	truncated bool
	cancel    context.CancelFunc
}

type streamWriter struct {
	capture *capture
	stderr  bool
}

func (w streamWriter) Write(b []byte) (int, error) {
	c := w.capture
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total += int64(len(b))
	n := min(len(b), c.limit-len(c.out)-len(c.err))
	if w.stderr {
		c.err = append(c.err, b[:n]...)
	} else {
		c.out = append(c.out, b[:n]...)
	}
	if n < len(b) {
		c.truncated = true
		c.cancel()
		return n, errors.New("output limit exceeded")
	}
	return n, nil
}

// waitable preserves the leader's PID until group cleanup. Calling Cmd.Wait
// first would reap the leader and allow its PGID to be reused before killpg.
// POSIX waitid(WNOWAIT) observes exit without consuming the eventual Cmd.Wait.
func waitable(ctx context.Context, pid int) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var info [32]uint64 // large enough and aligned for either host's siginfo_t
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, 1 /* P_PID */, uintptr(pid), uintptr(unsafe.Pointer(&info[0])), syscall.WEXITED|syscall.WNOHANG|syscall.WNOWAIT, 0, 0)
		if errno != 0 && errno != syscall.EINTR {
			return errno
		}
		if errno == 0 && info[0] != 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// execute is a narrow local binding, not an injectable executor. It owns a
// POSIX process group. Cleanup kills the group before reaping its leader;
// WaitDelay additionally bounds inherited pipe copying in exec.Cmd.Wait.
func execute(parent context.Context, command Command) Result {
	r := Result{Command: command, Receipt: Receipt{Cleanup: "not-started"}}
	ctx, cancel := context.WithTimeout(parent, command.Timeout)
	defer cancel()
	cap := &capture{limit: command.Limits.MaxOutputBytes, cancel: cancel}
	cmd := exec.CommandContext(ctx, command.Argv[0], command.Argv[1:]...)
	cmd.Dir, cmd.Env = command.Dir, command.Env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = streamWriter{cap, false}, streamWriter{cap, true}
	cmd.WaitDelay = command.Limits.CleanupTimeout
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	r.Receipt.StartedAt = time.Now().UTC()
	err := cmd.Start()
	if err == nil {
		r.Receipt.Started = true
		r.Receipt.PID = cmd.Process.Pid
		exitErr := waitable(ctx, cmd.Process.Pid)
		cleanup := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		err = errors.Join(exitErr, cmd.Wait())
		// Darwin reports EPERM for a group containing only a zombie leader.
		// Reap that confirmed exit and retry, as in the accepted build runner.
		if runtime.GOOS == "darwin" && errors.Is(cleanup, syscall.EPERM) {
			cleanup = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		r.Receipt.Cleanup = "complete"
		if cleanup != nil && !errors.Is(cleanup, syscall.ESRCH) {
			r.Receipt.Cleanup = "failed"
			err = errors.Join(err, fmt.Errorf("group cleanup: %w", cleanup))
		}
		code := cmd.ProcessState.ExitCode()
		r.Receipt.ExitCode = &code
		if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			r.Receipt.Signal = status.Signal().String()
		}
	}
	r.Receipt.FinishedAt = time.Now().UTC()
	r.Receipt.Canceled = errors.Is(parent.Err(), context.Canceled)
	r.Receipt.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	r.Stdout, r.Stderr, r.OutputBytes, r.OutputTruncated = cap.out, cap.err, cap.total, cap.truncated
	if cap.truncated {
		err = errors.Join(err, errors.New("output limit exceeded"))
	}
	if parent.Err() != nil {
		err = errors.Join(err, parent.Err())
	}
	if ctx.Err() == context.DeadlineExceeded {
		err = errors.Join(err, ctx.Err())
	}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}

type event struct {
	Time                                              *time.Time
	Action, Package, Test                             string
	Elapsed                                           *float64
	Output, OutputType, FailedBuild, Key, Value, Path string
}

// Go's pinned event schema is deliberately strict. In particular, JSON's
// last-key-wins behavior must not conceal a contradictory terminal outcome.
func decodeEvent(line []byte) (event, error) {
	var e event
	if !utf8.Valid(line) {
		return e, errors.New("non-UTF-8 event")
	}
	d := json.NewDecoder(bytes.NewReader(line))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return e, errors.New("event must be an object")
	}
	seen := map[string]bool{}
	for d.More() {
		tok, err = d.Token()
		if err != nil {
			return e, err
		}
		key, ok := tok.(string)
		if !ok || seen[strings.ToLower(key)] {
			return e, errors.New("duplicate event field")
		}
		seen[strings.ToLower(key)] = true
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return e, err
		}
	}
	if _, err = d.Token(); err != nil {
		return e, err
	}
	d = json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err = d.Decode(&e); err != nil {
		return e, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return e, errors.New("trailing event data")
	}
	return e, nil
}

func assess(r *Result, c Case) error {
	r.Required = c
	r.Observed = map[string]string{}
	var processErr error
	if r.Error != "" {
		processErr = errors.New(r.Error)
	}
	if r.Receipt.ExitCode == nil || *r.Receipt.ExitCode != 0 || r.Receipt.Cleanup != "complete" || r.OutputTruncated {
		processErr = errors.Join(processErr, errors.New("incomplete execution"))
	}
	outcomeErr := assessEvents(r, c)
	r.Passed = processErr == nil && outcomeErr == nil
	return errors.Join(processErr, outcomeErr)
}

func assessEvents(r *Result, c Case) error {
	if len(r.Stdout) == 0 || r.Stdout[len(r.Stdout)-1] != '\n' {
		return errors.New("empty or truncated JSON stream")
	}
	packageState := ""
	lines := bytes.SplitN(r.Stdout[:len(r.Stdout)-1], []byte{'\n'}, r.Command.Limits.MaxEvents+1)
	if len(lines) > r.Command.Limits.MaxEvents {
		return errors.New("event count limit")
	}
	for _, line := range lines {
		if len(line) > r.Command.Limits.MaxEventBytes {
			return errors.New("event byte limit")
		}
		e, err := decodeEvent(line)
		if err != nil {
			return fmt.Errorf("malformed event: %w", err)
		}
		if e.Package != c.ImportPath {
			return fmt.Errorf("unexpected package %q", e.Package)
		}
		if e.Test != "" && e.Test != c.Name && !strings.HasPrefix(c.Name, e.Test+"/") {
			return fmt.Errorf("unexpected test %q (required leaf %q)", e.Test, c.Name)
		}
		state := packageState
		if e.Test != "" {
			state = r.Observed[e.Test]
		}
		terminal := state == "pass" || state == "fail" || state == "skip"
		if e.Test != "" && e.Action != "output" && e.Action != "attr" && e.Action != "artifact" && e.Action != "artifacts" && packageState != "run" {
			return errors.New("test event outside running package")
		}
		switch e.Action {
		case "output", "attr", "artifact", "artifacts":
			// Metadata and output never supply evidence of test success.
			continue
		case "start":
			if e.Test != "" || state != "" {
				return errors.New("duplicate or invalid package start")
			}
			state = "run"
		case "run":
			if e.Test == "" || state != "" || packageState != "run" {
				return errors.New("duplicate or invalid test run")
			}
			state = "run"
			if parent, _, ok := strings.Cut(e.Test, "/"); ok {
				// All ancestor containers must themselves have been observed.
				parts := strings.Split(e.Test, "/")
				for depth := 1; depth < len(parts); depth++ {
					parent = strings.Join(parts[:depth], "/")
					s := r.Observed[parent]
					if s != "run" && s != "pause" {
						return errors.New("missing or finished ancestor")
					}
				}
			}
		case "pause":
			if e.Test == "" || state != "run" {
				return errors.New("invalid pause")
			}
			state = "pause"
		case "cont":
			if e.Test == "" || state != "pause" {
				return errors.New("invalid continue")
			}
			state = "run"
		case "pass", "fail", "skip":
			if terminal || state != "run" {
				return errors.New("duplicate, contradictory or unstarted terminal event")
			}
			state = e.Action
			for name, childState := range r.Observed {
				if (e.Test == "" || strings.HasPrefix(name, e.Test+"/")) && childState != "pass" && childState != "skip" && childState != "fail" {
					return errors.New("terminal event before child completion")
				}
			}
			if state != "pass" {
				if e.Test != "" {
					r.Observed[e.Test] = state
				}
				return fmt.Errorf("%s %s", state, e.Test)
			}
		default:
			return fmt.Errorf("unsupported event action %q", e.Action)
		}
		if e.Test == "" {
			packageState = state
		} else {
			r.Observed[e.Test] = state
		}
		if len(r.Observed) > r.Command.Limits.MaxNames {
			return errors.New("named state limit")
		}
	}
	if packageState != "pass" || r.Observed[c.Name] != "pass" {
		return errors.New("missing selected test or package pass")
	}
	for _, state := range r.Observed {
		if state != "pass" {
			return errors.New("unfinished test")
		}
	}
	return nil
}

// Run executes every selected leaf, retaining failed results instead of hiding
// them behind a later success. Provenance digests are caller assertions; Run
// deliberately never invokes Git or claims independent revision verification.
func Run(ctx context.Context, p Plan) (Report, error) {
	report := Report{SourceRevision: p.SourceRevision, ContractSHA256: p.ContractSHA256, Suite: p.Suite, Seed: p.Seed}
	commands, err := Commands(p)
	if err != nil {
		return report, err
	}
	cases := selected(p)
	for i, c := range cases {
		report.Results = append(report.Results, Result{Command: commands[i], Required: c, Error: "not started: toolchain validation incomplete"})
	}
	f, err := os.Open(p.GoBinary)
	if err != nil {
		return report, err
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	closeErr := f.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return report, err
	}
	report.ToolSHA256 = hex.EncodeToString(h.Sum(nil))
	report.Toolchain = execute(ctx, Command{[]string{p.GoBinary, "version"}, p.Root, environment(p.Seed), p.Timeout, p.Limits})
	if report.Toolchain.Error != "" {
		return report, errors.New(report.Toolchain.Error)
	}
	fields := strings.Fields(string(report.Toolchain.Stdout))
	if len(fields) != 4 || fields[0] != "go" || fields[1] != "version" || fields[2] != PinnedGoVersion {
		return report, errors.New("Go version does not match pin")
	}
	var failures []error
	for i, c := range cases {
		r := execute(ctx, commands[i])
		if err := assess(&r, c); err != nil {
			r.Error = err.Error()
			failures = append(failures, fmt.Errorf("%s: %w", c.Name, err))
		} else {
			report.PassedRequired++
		}
		report.Results[i] = r
	}
	report.Success = len(failures) == 0 && report.PassedRequired > 0
	return report, errors.Join(failures...)
}
