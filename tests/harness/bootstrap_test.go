//go:build darwin || linux

package harness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const fixtureImport = "fixture.local/harness"
const fixtureSource = `package fixture
import ("fmt"; "os"; "path/filepath"; "testing")
func TestPass(t *testing.T) { t.Attr("fixture", "real"); if err := os.WriteFile(filepath.Join(t.ArtifactDir(), "fixture.txt"), []byte("real artifact"), 0600); err != nil { t.Fatal(err) }; fmt.Println("seed="+os.Getenv("CANOPY_CASE_SEED")); fmt.Fprintln(os.Stderr,"fixture stderr") }
func TestSecond(t *testing.T) { fmt.Println("seed="+os.Getenv("CANOPY_CASE_SEED")) }
func TestSkipped(t *testing.T) { t.Skip("required skip fixture") }
func TestFailure(t *testing.T) { t.Fatal("real assertion fixture") }
func TestExit(t *testing.T) { os.Exit(7) }
func TestLiteral(t *testing.T) {
 for _, name := range []string{"a.b[+](x)|^$", "axb", "other"} { t.Run(name,func(t *testing.T){ t.Run("child?",func(t *testing.T){fmt.Println("literal leaf")}); t.Run("sibling",func(t *testing.T){}) }) }
}
func TestContainer(t *testing.T) { t.Run("undeclared",func(t *testing.T){}) }
func TestIntegrationOnly(t *testing.T) { fmt.Println("integration fixture") }
`

func planFor(t *testing.T) Plan {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string]string{"go.mod": "module " + fixtureImport + "\n\ngo 1.27.2\n", "fixture_test.go": fixtureSource} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// The zero values are synthetic fixture identifiers, never claimed commits.
	// Candidate evidence supplies the actual caller-verified identities.
	source, contract := os.Getenv("CANOPY_SOURCE_REVISION"), os.Getenv("CANOPY_CONTRACT_SHA256")
	if source == "" {
		source = strings.Repeat("0", 40)
	}
	if contract == "" {
		contract = strings.Repeat("0", 64)
	}
	return Plan{Root: dir, GoBinary: "/Users/completetech/github/.scion-run/toolchains/go/bin/go", SourceRevision: source, ContractSHA256: contract, Cases: []Case{{Unit, "./.", fixtureImport, "TestPass"}}, Suite: Unit, Seed: 20261015, Timeout: 20 * time.Second, Limits: DefaultLimits()}
}

func record(t *testing.T, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
	if dir := os.Getenv("CANOPY_HARNESS_EVIDENCE_DIR"); dir != "" {
		digest := sha256.Sum256(data)
		name := strings.ReplaceAll(t.Name(), "/", "__") + "-" + hex.EncodeToString(digest[:8]) + ".json"
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHarnessUnit(t *testing.T) {
	t.Run("ManifestValid", func(t *testing.T) {
		if err := ValidatePlan(planFor(t)); err != nil {
			t.Fatal(err)
		}
	})
	for _, tc := range []struct {
		name   string
		mutate func(*Plan)
	}{
		{"ManifestEmpty", func(p *Plan) { p.Cases = nil }},
		{"DuplicateCase", func(p *Plan) { p.Cases = append(p.Cases, p.Cases[0]) }},
		{"WrongSuite", func(p *Plan) { p.Suite = "invalid" }},
		{"EmptySuite", func(p *Plan) { p.Suite = Integration }},
		{"ParentAndLeaf", func(p *Plan) { c := p.Cases[0]; c.Name += "/leaf"; p.Cases = append(p.Cases, c) }},
		{"UnsafeDirectory", func(p *Plan) { p.Cases[0].PackageDir = "./../outside" }},
		{"InvalidLimits", func(p *Plan) { p.Limits.MaxOutputBytes = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := planFor(t)
			tc.mutate(&p)
			if err := ValidatePlan(p); err == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
	t.Run("LiteralSelectors", func(t *testing.T) {
		p := planFor(t)
		p.Cases[0].Name = "TestLiteral/a.b[+](x)|^$/child?"
		cmds, err := Commands(p)
		if err != nil {
			t.Fatal(err)
		}
		want := `^TestLiteral$/^a\.b\[\+\]\(x\)\|\^\$$/^child\?$`
		if cmds[0].Argv[10] != want {
			t.Fatalf("selector %q != %q", cmds[0].Argv[10], want)
		}
	})
	t.Run("SeedReplay", func(t *testing.T) {
		got := CaseSeed(20261015, "canopy.local/canopy/tests/harness", "TestHarnessUnit/SeedReplay")
		if hex.EncodeToString(got[:]) != "53bb26de9a8b750f0dc7b85529437cacf692807bad6863ec2d6ec2e62259edb6" {
			t.Fatalf("seed vector %x", got)
		}
		if got != CaseSeed(20261015, "canopy.local/canopy/tests/harness", "TestHarnessUnit/SeedReplay") {
			t.Fatal("unstable seed")
		}
	})
	t.Run("SeedSeparated", func(t *testing.T) {
		a := CaseSeed(20261015, fixtureImport, "TestPass")
		for _, b := range [][32]byte{CaseSeed(20261016, fixtureImport, "TestPass"), CaseSeed(20261015, fixtureImport, "TestSecond"), CaseSeed(20261015, "other", "TestPass")} {
			if a == b {
				t.Fatal("seed domains collide")
			}
		}
	})
	t.Run("OfflineEnvironment", func(t *testing.T) {
		t.Setenv("GOFLAGS", "-mod=mod")
		t.Setenv("GOPROXY", "https://invalid.example")
		t.Setenv("UNRELATED_SECRET", "must not inherit")
		cmds, err := Commands(planFor(t))
		if err != nil {
			t.Fatal(err)
		}
		env := strings.Join(cmds[0].Env, "\n")
		for _, s := range []string{"GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOENV=off", "GOFLAGS=-mod=readonly", "CANOPY_TEST_SEED=20261015"} {
			if !strings.Contains(env, s) {
				t.Fatal("missing " + s)
			}
		}
		if strings.Contains(env, "SECRET") || strings.Contains(env, "invalid.example") {
			t.Fatal("ambient environment leaked")
		}
	})
	t.Run("SymlinkEscape", func(t *testing.T) {
		p := planFor(t)
		if err := os.Symlink(t.TempDir(), filepath.Join(p.Root, "escape")); err != nil {
			t.Fatal(err)
		}
		p.Cases[0].PackageDir = "./escape"
		if ValidatePlan(p) == nil {
			t.Fatal("escaping package accepted")
		}
	})
	for _, tc := range []struct {
		name, body string
		pass       bool
	}{
		{"EventsPass", events("run", "pass"), true},
		{"Metadata", events("run", "attr", "artifacts", "pass"), true},
		{"MetadataOnly", events("attr", "artifacts"), false},
		{"MissingSelected", events(), false},
		{"RequiredSkip", events("run", "skip"), false},
		{"FailWithZeroExit", events("run", "fail"), false},
		{"Unfinished", events("run"), false},
		{"DuplicateTerminal", events("run", "pass", "pass"), false},
		{"ContradictoryTerminal", events("run", "pass", "fail"), false},
		{"MalformedTrailing", events("run", "pass") + "{broken\n", false},
		{"Truncated", strings.TrimSuffix(events("run", "pass"), "\n"), false},
		{"UnexpectedTest", strings.ReplaceAll(events("run", "pass"), "TestPass", "TestOther"), false},
		{"UnknownAction", events("run", "unknown", "pass"), false},
		{"MalformedElapsed", strings.ReplaceAll(events("run", "pass"), `"Action":"pass"`, `"Elapsed":"bad","Action":"pass"`), false},
		{"DuplicateJSONField", strings.ReplaceAll(events("run", "pass"), `"Action":"pass"`, `"Action":"fail","Action":"pass"`), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := eventResult(tc.body)
			err := assess(&r, Case{Unit, "./.", fixtureImport, "TestPass"})
			if (err == nil) != tc.pass {
				t.Fatalf("assessment %v", err)
			}
		})
	}
	t.Run("EventLimits", func(t *testing.T) {
		for _, mutate := range []func(*Limits){func(l *Limits) { l.MaxEventBytes = 8 }, func(l *Limits) { l.MaxEvents = 1 }, func(l *Limits) { l.MaxNames = 0 }} {
			r := eventResult(events("run", "pass"))
			mutate(&r.Command.Limits)
			if assess(&r, Case{Unit, "./.", fixtureImport, "TestPass"}) == nil {
				t.Fatal("limit ignored")
			}
		}
	})
}

func events(actions ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "{\"Action\":\"start\",\"Package\":%q}\n", fixtureImport)
	for _, a := range actions {
		fmt.Fprintf(&b, "{\"Action\":%q,\"Package\":%q,\"Test\":\"TestPass\"}\n", a, fixtureImport)
	}
	fmt.Fprintf(&b, "{\"Action\":\"pass\",\"Package\":%q}\n", fixtureImport)
	return b.String()
}

func eventResult(body string) Result {
	zero := 0
	return Result{Command: Command{Limits: DefaultLimits()}, Receipt: Receipt{ExitCode: &zero, Cleanup: "complete"}, Stdout: []byte(body)}
}

func TestHarnessIntegration(t *testing.T) {
	t.Run("BuildReplay", func(t *testing.T) {
		p := planFor(t)
		var sums [][32]byte
		for i := 0; i < 2; i++ {
			output := filepath.Join(t.TempDir(), "fixture.test")
			cmd := Command{[]string{p.GoBinary, "test", "-c", "-trimpath", "-buildvcs=false", "-o", output, "./."}, p.Root, environment(p.Seed), p.Timeout, p.Limits}
			r := execute(context.Background(), cmd)
			record(t, r)
			if r.Error != "" {
				t.Fatal(r.Error)
			}
			b, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			sums = append(sums, sha256.Sum256(b))
		}
		if sums[0] != sums[1] {
			t.Fatal("pinned builds differ")
		}
		record(t, map[string]any{"binary_sha256": fmt.Sprintf("%x", sums[0]), "builds": 2})
	})
	t.Run("RealGoJSON", func(t *testing.T) {
		p := planFor(t)
		report, err := Run(context.Background(), p)
		record(t, report)
		if err != nil || !report.Success || report.PassedRequired != 1 {
			t.Fatalf("real run: %v", err)
		}
		if !strings.Contains(string(report.Results[0].Stdout), "fixture stderr") {
			t.Fatal("raw output missing")
		}
	})
	// Each proxy runs the real pinned Go command, then changes only the selected
	// leaf's pass event. A fault must fail through Run, even with exit status 0.
	for _, tc := range []struct {
		name, mutation, wantError string
	}{
		{"RunRejectNegativeElapsed", `e["Elapsed"] = -1`, "Elapsed"},
		{"RunRejectNullElapsed", `e["Elapsed"] = None`, "Elapsed"},
		{"RunRejectStringElapsed", `e["Elapsed"] = "0"`, "Elapsed"},
		{"RunRejectBooleanElapsed", `e["Elapsed"] = False`, "Elapsed"},
		{"RunRejectObjectElapsed", `e["Elapsed"] = {}`, "Elapsed"},
		{"RunRejectOverflowElapsed", `e["Elapsed"] = 10 ** 400`, "malformed event"},
		{"RunRejectNullTime", `e["Time"] = None`, "Time"},
		{"RunRejectNumberTime", `e["Time"] = 1`, "Time"},
		{"RunRejectMalformedTime", `e["Time"] = "not a timestamp"`, "malformed event"},
		{"RunRejectBooleanOutput", `e["Output"] = False`, "Output"},
		{"RunRejectNumberOutput", `e["Output"] = 1`, "Output"},
		{"RunRejectArrayOutput", `e["Output"] = []`, "Output"},
		{"RunRejectObjectOutput", `e["Output"] = {}`, "Output"},
		{"RunRejectUnknownOutputType", `e["OutputType"] = "unknown"`, "OutputType"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runEventMutation(t, tc.mutation, tc.wantError)
		})
	}
	for _, field := range []string{"Action", "Package", "Test", "Output", "OutputType", "FailedBuild", "Key", "Value", "Path"} {
		t.Run("RunRejectNull"+field, func(t *testing.T) {
			runEventMutation(t, fmt.Sprintf("e[%q] = None", field), field)
		})
	}
	for _, tc := range []struct{ name, mutation string }{
		{"RunValidDelegatedStream", `pass`},
		{"RunValidOmittedOptionalFields", `e = {k: v for k, v in e.items() if k in ("Action", "Package", "Test")}`},
		{"RunValidStringFields", `e.update(Output="fixture string", OutputType="frame", FailedBuild="", Key="fixture", Value="value", Path="fixture.txt")`},
		{"RunValidZeroElapsed", `e["Elapsed"] = 0`},
		{"RunValidPositiveElapsed", `e["Elapsed"] = 0.25`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runEventMutation(t, tc.mutation, "")
		})
	}
	t.Run("DeterministicReplay", func(t *testing.T) {
		p := planFor(t)
		p.Cases = append(p.Cases, Case{Unit, "./.", fixtureImport, "TestSecond"})
		a, err := Run(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Run(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		for i := range a.Results {
			if !reflect.DeepEqual(a.Results[i].Command, b.Results[i].Command) {
				t.Fatal("command drift")
			}
			seed := CaseSeed(p.Seed, fixtureImport, a.Results[i].Required.Name)
			for _, r := range []Result{a.Results[i], b.Results[i]} {
				if !strings.Contains(string(r.Stdout), hex.EncodeToString(seed[:])) {
					t.Fatal("seed not consumed by actual fixture")
				}
			}
		}
		record(t, a)
		record(t, b)
	})
	t.Run("SuiteSeparation", func(t *testing.T) {
		p := planFor(t)
		p.Cases = append(p.Cases, Case{Integration, "./.", fixtureImport, "TestIntegrationOnly"})
		for _, suite := range []Suite{Unit, Integration} {
			p.Suite = suite
			r, err := Run(context.Background(), p)
			record(t, r)
			if err != nil || len(r.Results) != 1 || r.Results[0].Required.Suite != suite {
				t.Fatalf("suite selection %v", err)
			}
		}
	})
	t.Run("LiteralSubtest", func(t *testing.T) {
		p := planFor(t)
		p.Cases[0].Name = "TestLiteral/a.b[+](x)|^$/child?"
		r, err := Run(context.Background(), p)
		record(t, r)
		if err != nil || len(r.Results[0].Observed) != 3 {
			t.Fatalf("exact literal leaf: %v", err)
		}
	})
	for _, tc := range []struct{ name, selected string }{
		{"UnmatchedSelector", "TestDoesNotExist"}, {"RealSkipped", "TestSkipped"}, {"RealFailure", "TestFailure"}, {"ExitSeven", "TestExit"}, {"RejectContainer", "TestContainer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := planFor(t)
			p.Cases[0].Name = tc.selected
			r, err := Run(context.Background(), p)
			record(t, r)
			if err == nil || r.Success || r.PassedRequired != 0 {
				t.Fatal("negative fixture passed")
			}
			if r.Results[0].Receipt.Cleanup != "complete" {
				t.Fatal("negative outcome masked cleanup failure")
			}
		})
	}
	t.Run("BuildFailure", func(t *testing.T) {
		p := planFor(t)
		if err := os.WriteFile(filepath.Join(p.Root, "broken.go"), []byte("not Go source"), 0600); err != nil {
			t.Fatal(err)
		}
		r, err := Run(context.Background(), p)
		record(t, r)
		if err == nil || r.Success {
			t.Fatal("compile failure passed")
		}
	})
	for _, tc := range []struct{ name, mode string }{
		{"ProcessMalformed", "malformed"}, {"ProcessTruncated", "truncated"}, {"ProcessExitSeven", "exit7"}, {"OutputLimit", "flood"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := helperCommand(t, tc.mode)
			if tc.mode == "flood" {
				cmd.Limits.MaxOutputBytes = 1024
			}
			r := execute(context.Background(), cmd)
			err := assess(&r, Case{Unit, "./.", fixtureImport, "TestPass"})
			record(t, r)
			if err == nil {
				t.Fatal("negative process passed")
			}
			if r.Receipt.Cleanup != "complete" {
				t.Fatal("negative outcome masked cleanup failure")
			}
			if len(r.Stdout)+len(r.Stderr) > cmd.Limits.MaxOutputBytes {
				t.Fatal("unbounded capture")
			}
			if tc.mode == "exit7" && (r.Receipt.ExitCode == nil || *r.Receipt.ExitCode != 7) {
				t.Fatal("lost actual exit 7")
			}
			if tc.mode == "flood" && !r.OutputTruncated {
				t.Fatal("missing truncation flag")
			}
		})
	}
	t.Run("StdoutStderr", func(t *testing.T) {
		r := execute(context.Background(), helperCommand(t, "streams"))
		record(t, r)
		if r.Error != "" || string(r.Stdout) != "stdout fixture\n" || string(r.Stderr) != "stderr fixture\n" {
			t.Fatal("stream capture failed")
		}
	})
	t.Run("OutputBoundary", func(t *testing.T) {
		for _, size := range []int{1023, 1024, 1025} {
			cmd := helperCommand(t, "sized")
			cmd.Limits.MaxOutputBytes = 1024
			cmd.Env = append(cmd.Env, fmt.Sprintf("HARNESS_OUTPUT_BYTES=%d", size))
			r := execute(context.Background(), cmd)
			record(t, r)
			if len(r.Stdout) != min(size, 1024) || r.OutputTruncated != (size > 1024) || (r.Error == "") != (size <= 1024) || r.Receipt.Cleanup != "complete" {
				t.Fatalf("boundary %d failed", size)
			}
		}
	})
	t.Run("CancelBeforeStart", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := execute(ctx, helperCommand(t, "streams"))
		record(t, r)
		if r.Error == "" || r.Receipt.Started || !r.Receipt.Canceled {
			t.Fatal("canceled process started")
		}
	})
	for _, mode := range []string{"cancel-descendant", "leader-exit", "leader-closed-pipes", "deadline-descendant"} {
		t.Run(map[string]string{"cancel-descendant": "CancelOwnedDescendant", "leader-exit": "LeaderExitPipeCleanup", "leader-closed-pipes": "LeaderExitClosedPipes", "deadline-descendant": "DeadlineOwnedDescendant"}[mode], func(t *testing.T) {
			cmd := helperCommand(t, mode)
			pidfile := filepath.Join(t.TempDir(), "child.pid")
			cmd.Env = append(cmd.Env, "HARNESS_PID_FILE="+pidfile)
			if mode == "deadline-descendant" {
				cmd.Timeout = 2 * time.Second
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan Result, 1)
			go func() { done <- execute(ctx, cmd) }()
			var pid int
			deadline := time.Now().Add(5 * time.Second)
			for pid == 0 && time.Now().Before(deadline) {
				if b, err := os.ReadFile(pidfile); err == nil {
					pid, _ = strconv.Atoi(string(b))
				}
				time.Sleep(10 * time.Millisecond)
			}
			if pid == 0 {
				cancel()
				<-done
				t.Fatal("descendant did not start")
			}
			defer syscall.Kill(pid, syscall.SIGKILL)
			if mode == "cancel-descendant" {
				cancel()
			}
			var r Result
			select {
			case r = <-done:
			case <-time.After(6 * time.Second):
				t.Fatal("unbounded process/pipe wait")
			}
			record(t, r)
			if r.Receipt.Cleanup != "complete" {
				t.Fatal("group cleanup failed")
			}
			if mode == "cancel-descendant" && !r.Receipt.Canceled {
				t.Fatal("cancellation missing")
			}
			if mode == "deadline-descendant" && !r.Receipt.TimedOut {
				t.Fatal("deadline missing")
			}
			for time.Now().Before(deadline) {
				if !processAlive(pid) {
					record(t, map[string]any{"descendant_pid": pid, "alive_after_cleanup": false, "fixture_mode": mode, "verification": "kill(pid, 0) returned ESRCH"})
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatalf("owned descendant %d survived cleanup", pid)
		})
	}
}

func runEventMutation(t *testing.T, mutation, wantError string) {
	t.Helper()
	p := planFor(t)
	p.GoBinary = eventProxy(t, p.GoBinary, mutation)
	r, err := Run(context.Background(), p)
	record(t, r)
	if len(r.Results) != 1 {
		t.Fatalf("expected one selected result: %v", err)
	}
	result := r.Results[0]
	if result.Receipt.ExitCode == nil || *result.Receipt.ExitCode != 0 || result.Receipt.Cleanup != "complete" || result.OutputTruncated {
		t.Fatalf("proxy did not forward a complete successful real-Go process: %v", err)
	}
	if wantError == "" {
		if err != nil || !r.Success || r.PassedRequired != 1 || !result.Passed {
			t.Fatalf("valid event rejected: %v", err)
		}
	} else if err == nil || r.Success || r.PassedRequired != 0 || result.Passed || !strings.Contains(result.Error, "malformed event") || !strings.Contains(result.Error, wantError) {
		t.Fatalf("invalid supplied field accepted or wrong failure: success=%v passed=%d result=%+v error=%v", r.Success, r.PassedRequired, result, err)
	}
}

// Adapted from the read-only external review probe. Version, stderr, remaining
// events and real exit status are forwarded; exactly one pass must be targeted.
func eventProxy(t *testing.T, realGo, mutation string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "go-event-proxy")
	source := `#!/opt/homebrew/bin/python3
import json, subprocess, sys
p = subprocess.run([` + strconv.Quote(realGo) + `] + sys.argv[1:], capture_output=True)
if sys.argv[1:] == ["version"]:
 sys.stdout.buffer.write(p.stdout)
 sys.stderr.buffer.write(p.stderr)
 sys.exit(p.returncode)
changed = 0
for line in p.stdout.splitlines(keepends=True):
 e = json.loads(line)
 if e.get("Test") == "TestPass" and e.get("Action") == "pass":
  ` + mutation + `
  changed += 1
  line = (json.dumps(e, separators=(",", ":")) + "\n").encode()
 sys.stdout.buffer.write(line)
sys.stderr.buffer.write(p.stderr)
sys.exit(p.returncode if p.returncode or changed == 1 else 12)
`
	if err := os.WriteFile(path, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func helperCommand(t *testing.T, mode string) Command {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return Command{[]string{exe, "-test.run=^TestHarnessProcessFixture$"}, t.TempDir(), append(environment(20261015), "HARNESS_PROCESS_MODE="+mode), 10 * time.Second, DefaultLimits()}
}

func processAlive(pid int) bool {
	// Only ESRCH proves absence. Permission errors, unavailable observations,
	// and zombies remain live for this conservative check and fail the test.
	return syscall.Kill(pid, 0) != syscall.ESRCH
}

// This real child process fixture is inert during an ordinary suite run.
func TestHarnessProcessFixture(t *testing.T) {
	mode := os.Getenv("HARNESS_PROCESS_MODE")
	if mode == "" {
		return
	}
	switch mode {
	case "streams":
		fmt.Fprintln(os.Stdout, "stdout fixture")
		fmt.Fprintln(os.Stderr, "stderr fixture")
	case "malformed":
		fmt.Fprintln(os.Stdout, "{broken")
	case "truncated":
		fmt.Fprint(os.Stdout, strings.TrimSuffix(events("run", "pass"), "\n"))
	case "exit7":
		os.Exit(7)
	case "flood":
		for {
			fmt.Fprint(os.Stdout, strings.Repeat("x", 4096))
			fmt.Fprint(os.Stderr, strings.Repeat("y", 4096))
		}
	case "sized":
		n, err := strconv.Atoi(os.Getenv("HARNESS_OUTPUT_BYTES"))
		if err != nil {
			os.Exit(11)
		}
		fmt.Fprint(os.Stdout, strings.Repeat("x", n))
	case "child":
		if err := os.WriteFile(os.Getenv("HARNESS_PID_FILE"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(6)
		}
		for {
			time.Sleep(time.Second)
		}
	case "cancel-descendant", "leader-exit", "leader-closed-pipes", "deadline-descendant":
		exe, err := os.Executable()
		if err != nil {
			os.Exit(8)
		}
		cmd := exec.Command(exe, "-test.run=^TestHarnessProcessFixture$")
		cmd.Env = append(environment(20261015), "HARNESS_PROCESS_MODE=child", "HARNESS_PID_FILE="+os.Getenv("HARNESS_PID_FILE"))
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if mode == "leader-closed-pipes" {
			cmd.Stdout, cmd.Stderr = nil, nil
		}
		if err := cmd.Start(); err != nil {
			os.Exit(9)
		}
		for {
			if _, err := os.Stat(os.Getenv("HARNESS_PID_FILE")); err == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if mode == "leader-exit" || mode == "leader-closed-pipes" {
			os.Exit(0)
		}
		for {
			time.Sleep(time.Second)
		}
	default:
		os.Exit(10)
	}
	os.Exit(0)
}
