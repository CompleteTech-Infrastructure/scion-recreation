package policy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/storage/metadata"
	"github.com/jackc/pgx/v5"
)

// Check closed lower / open upper boundaries at nanosecond precision, with
// both uncertainty and the admission budget. Extreme clocks must fail closed.
func TestPolicyReviewTimeInterval(t *testing.T) {
	claims := authz.SessionClaims{NotBeforeUnix: 100, ExpiresAtUnix: 200}
	for _, tc := range []struct {
		name             string
		now              time.Time
		bound            time.Duration
		admit, committed bool
	}{
		{"lower-uncertain", time.Unix(100, 0), time.Second, false, false},
		{"lower-one-ns-early", time.Unix(101, -1), time.Second, false, false},
		{"lower-inclusive", time.Unix(101, 0), time.Second, true, true},
		{"lower-zero-error", time.Unix(100, 0), 0, true, true},
		{"admission-last-ns", time.Unix(194, -1), time.Second, true, true},
		{"admission-expiry-exclusive", time.Unix(194, 0), time.Second, false, true},
		{"commit-last-ns", time.Unix(199, -1), time.Second, false, true},
		{"commit-expiry-exclusive", time.Unix(199, 0), time.Second, false, false},
		{"zero-clock", time.Time{}, time.Second, false, false},
		{"negative-clock", time.Unix(-1, 0), time.Second, false, false},
		{"overflow-clock", time.Unix(math.MaxInt64, 0), time.Second, false, false},
		{"underflow-clock", time.Unix(math.MinInt64, 0), time.Second, false, false},
		{"year-10000", time.Unix(253402300800, 0), time.Second, false, false},
		{"negative-bound", time.Unix(150, 0), -1, false, false},
		{"excess-bound", time.Unix(150, 0), 2 * time.Second, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Store{clockError: tc.bound, now: func() (time.Time, error) { return tc.now, nil }}
			if a, c := s.safeTime(context.Background(), claims), committedTime(context.Background(), s, claims); a != tc.admit || c != tc.committed {
				t.Fatalf("admit=%v committed=%v want=%v/%v", a, c, tc.admit, tc.committed)
			}
		})
	}
	s := &Store{now: func() (time.Time, error) { return time.Unix(150, 0), errors.New("unknown clock") }}
	if s.safeTime(context.Background(), claims) || committedTime(context.Background(), s, claims) {
		t.Fatal("unknown clock admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.safeTime(ctx, claims) || committedTime(ctx, s, claims) {
		t.Fatal("canceled context admitted")
	}
}

func repairSignSession(t *testing.T, f *managementFixture, target ActorCredentials) {
	t.Helper()
	b, err := authz.SessionTranscript(target.Session.Claims)
	if err != nil {
		t.Fatal(err)
	}
	target.Session.Signature = ed25519.Sign(f.session, b)
}

func TestPolicyReviewSignedLowerBound(t *testing.T) {
	f := managementSetup(t)
	ctx := context.Background()
	admin, writer := f.credentials("admin", 1), f.credentials("writer", 2)
	admin.Session.Claims.NotBeforeUnix = f.clock.Load()
	repairSignSession(t, f, admin)
	bc := f.config(f.roles.Bootstrap)
	bc.Trust.ClockError = time.Second
	b, err := OpenBootstrap(ctx, bc)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	before := policyCounts(t, f)
	if r, e := b.Bootstrap(ctx, BootstrapRequest{Target: admin, Policy: f.policy(admin, writer), RequestID: fixtureRequest(1)}); e == nil || r != (Receipt{}) {
		t.Fatal("premature bootstrap", r, e)
	}
	if after := policyCounts(t, f); after != before {
		t.Fatal("premature bootstrap mutated durable state", before, after)
	}
	// At the exact conservative lower bound bootstrap and authentication work.
	f.clock.Add(1)
	if _, err = b.Bootstrap(ctx, BootstrapRequest{Target: admin, Policy: f.policy(admin, writer), RequestID: fixtureRequest(1)}); err != nil {
		t.Fatal(err)
	}
	ac := f.config(f.roles.Admin)
	ac.Trust.ClockError = time.Second
	a, err := OpenAdmin(ctx, ac)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	sc := f.config(f.roles.Serving)
	sc.Trust.ClockError = time.Second
	s, err := Open(ctx, sc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	authenticateFixture(t, s, admin)
	target := f.credentials("target", 221)
	target.Session.Claims.NotBeforeUnix = f.clock.Load()
	repairSignSession(t, f, target)
	before = policyCounts(t, f)
	request := Enrollment{Target: target, RequestID: fixtureRequest(221)}
	if r, e := a.Enroll(ctx, admin, request); e == nil || r != (Receipt{}) {
		t.Fatal("premature enrollment", r, e)
	}
	if after := policyCounts(t, f); after != before {
		t.Fatal("premature enrollment mutated durable state", before, after)
	}
	f.clock.Add(1)
	if _, err = a.Enroll(ctx, admin, request); err != nil {
		t.Fatal(err)
	}
	authenticateFixture(t, s, target)
	// The enrolled state does not excuse a subsequently uncertain lower bound.
	f.clock.Add(-1)
	mustDenyAuthentication(t, s, target)
	t.Log("actual signed bootstrap/enrollment/authentication reject premature uncertainty; exact lower boundary succeeds")
}

func TestPolicyReviewPostCommitLowerBoundUnknown(t *testing.T) {
	f := managementSetup(t)
	admin, _, s, _, _ := f.bootstrap(t)
	ctx := context.Background()
	target := f.credentials("postcommit-target", 222)
	target.Session.Claims.NotBeforeUnix = f.clock.Load() - 1
	repairSignSession(t, f, target)
	request := Enrollment{Target: target, RequestID: fixtureRequest(222)}
	cfg := f.config(f.roles.Admin)
	cfg.Trust.ClockError = time.Second
	observed := false
	cfg.Trust.Now = func() (time.Time, error) {
		// Separate real connection: this row becomes visible only after COMMIT.
		var visible bool
		if e := f.db.QueryRow(ctx, "SELECT EXISTS(SELECT FROM scion_policy.admin_results WHERE request_id=$1)", request.RequestID[:]).Scan(&visible); e != nil {
			return time.Time{}, e
		}
		if visible {
			observed = true
			return time.Unix(target.Session.Claims.NotBeforeUnix, 0), nil
		}
		return time.Unix(f.clock.Load(), 0), nil
	}
	a, err := OpenAdmin(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if r, e := a.Enroll(ctx, admin, request); r != (Receipt{}) || !errors.Is(e, metadata.ErrOutcomeUnknown) || !errors.Is(e, authz.ErrUnauthenticated) {
		t.Fatal("postcommit uncertainty misreported", r, e)
	}
	if !observed {
		t.Fatal("never observed committed result")
	}
	// This cannot be reported as rollback: the durable enrollment is present.
	authenticateFixture(t, s, target)
	t.Log("actual commit visible before conservative postcommit failure; zero receipt and outcome unknown, durable target retained")
}

// Only this helper's unique persistent cluster is stopped or reconfigured.
// An immediate server crash is not a power-loss or physical WAL-expiry test.
type repairCluster struct {
	bin, data, socket string
	started           bool
}

func repairOwnedCluster(t *testing.T) *repairCluster {
	t.Helper()
	bin := os.Getenv("SCION_POLICY_RESTART_PG_BIN")
	if bin == "" {
		t.Skip("requires selected disposable PostgreSQL binaries; skip is not crash evidence")
	}
	if os.Geteuid() == 0 {
		t.Fatal("requires unprivileged PostgreSQL")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	var fs syscall.Statfs_t
	if err = syscall.Statfs(home, &fs); err != nil || uint64(fs.Type) != 0x9123683e {
		t.Fatal("requires persistent HOME btrfs", err, fs.Type)
	}
	c := &repairCluster{bin: bin}
	c.data, err = os.MkdirTemp(home, ".scion-policy-repair-")
	if err != nil {
		t.Fatal(err)
	}
	c.socket, err = os.MkdirTemp("/tmp", "sprr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if c.started {
			c.run(t, "pg_ctl", "-D", c.data, "-m", "immediate", "-w", "-t", "15", "stop")
		}
		if t.Failed() {
			t.Log("preserved owned cluster", c.data, c.socket)
			return
		}
		if e := os.RemoveAll(c.data); e != nil {
			t.Error(e)
		}
		if e := os.RemoveAll(c.socket); e != nil {
			t.Error(e)
		}
	})
	c.run(t, "initdb", "-D", c.data, "-L", filepath.Join(filepath.Dir(bin), "share", "postgresql"), "-A", "trust", "--no-locale", "--encoding=UTF8")
	conf := fmt.Sprintf("\nlisten_addresses=''\nunix_socket_directories='%s'\nunix_socket_permissions=0700\nport=55494\nfsync=on\nsynchronous_commit=on\nfull_page_writes=on\nwal_writer_delay=10s\n", c.socket)
	file, err := os.OpenFile(filepath.Join(c.data, "postgresql.conf"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteString(conf)
	ce := file.Close()
	if err != nil || ce != nil {
		t.Fatal(err, ce)
	}
	c.start(t)
	t.Setenv("SCION_POSTGRES_TEST_DSN", fmt.Sprintf("host=%s port=55494 dbname=postgres sslmode=disable", c.socket))
	return c
}
func (c *repairCluster) run(t *testing.T, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.Join(c.bin, name), args...).CombinedOutput()
	t.Logf("UTC=%s owned command=%s args=%q exit=%v output=%s", time.Now().UTC().Format(time.RFC3339Nano), name, args, err, out)
	if err != nil {
		t.Fatal(err)
	}
}
func (c *repairCluster) start(t *testing.T) {
	t.Helper()
	c.run(t, "pg_ctl", "-D", c.data, "-l", filepath.Join(c.data, "server.log"), "-w", "-t", "20", "start")
	c.started = true
}
func (c *repairCluster) crash(t *testing.T, f *managementFixture) {
	t.Helper()
	closeConnection(f.db)
	closeConnection(f.admin)
	c.run(t, "pg_ctl", "-D", c.data, "-m", "immediate", "-w", "-t", "15", "stop")
	c.started = false
	c.start(t)
	var err error
	f.admin, err = pgx.Connect(context.Background(), os.Getenv("SCION_POSTGRES_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	f.db, err = pgx.Connect(context.Background(), f.dsn(f.admin.Config().User))
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile(filepath.Join(c.data, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("owned full PostgreSQL recovery log:\n%s", log)
	if !strings.Contains(string(log), "database system was interrupted") || !strings.Contains(string(log), "redo done at") {
		t.Fatal("no real WAL crash recovery")
	}
}

func TestPolicyReviewHostileDSNDurableCrash(t *testing.T) {
	c := repairOwnedCluster(t)
	f := managementSetup(t)
	ctx := context.Background()
	// This default applies only to the unique fixture database, not the shared
	// primary or another test. An unmodified restricted connection observes off.
	if _, err := f.db.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{f.name}.Sanitize()+" SET synchronous_commit = off"); err != nil {
		t.Fatal(err)
	}
	raw, err := pgx.Connect(ctx, f.dsn(f.roles.Admin))
	if err != nil {
		t.Fatal(err)
	}
	var defaultCommit string
	err = raw.QueryRow(ctx, "SHOW synchronous_commit").Scan(&defaultCommit)
	closeConnection(raw)
	if err != nil || defaultCommit != "off" {
		t.Fatal("async database default not active", defaultCommit, err)
	}
	t.Log("actual unmodified restricted-role database default synchronous_commit", defaultCommit)
	// managementSetup creates only a unique disposable installation. Remove
	// that empty policy schema to exercise actual first-provision acknowledgement
	// with a hostile DSN and asynchronous database default, then crash at once.
	if _, err = f.db.Exec(ctx, "DROP SCHEMA scion_policy CASCADE"); err != nil {
		t.Fatal(err)
	}
	binding, err := Provision(ctx, ProvisionConfig{DSN: f.dsn(f.admin.Config().User) + " synchronous_commit=off options='-c synchronous_commit=off'", Roles: f.roles})
	if err != nil || binding == (DatabaseBinding{}) {
		t.Fatal("hostile DSN Provision", binding, err)
	}
	c.crash(t, f)
	f.binding = binding
	if h, e := Open(ctx, f.config(f.roles.Serving)); e != nil {
		t.Fatal("lost acknowledged installation binding/catalog", e)
	} else {
		h.Close()
	}
	t.Log("hostile async DSN/database default: acknowledged Provision binding/catalog survives immediate owned-server crash")
	admin, writer := f.credentials("admin", 1), f.credentials("writer", 2)
	bc := f.config(f.roles.Bootstrap)
	bc.DSN += " synchronous_commit=off"
	b, err := OpenBootstrap(ctx, bc)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	initial := f.policy(admin, writer)
	br, err := b.Bootstrap(ctx, BootstrapRequest{Target: admin, Policy: initial, RequestID: fixtureRequest(1)})
	if err != nil || br == (Receipt{}) {
		t.Fatal("hostile DSN bootstrap", br, err)
	}
	c.crash(t, f)
	s, err := Open(ctx, f.config(f.roles.Serving))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, err := OpenAdmin(ctx, f.config(f.roles.Admin))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	authenticateFixture(t, s, admin)
	checkResult := func(r Receipt) {
		t.Helper()
		if got, e := a.GetAdminResult(ctx, admin, AdminResultQuery{Operation: r.Operation, RequestID: r.RequestID}); e != nil || got != r {
			t.Fatal("lost acknowledged result", r, got, e)
		}
		assertReceiptAudit(t, f, admin, r)
	}
	checkResult(br)
	var version, data, fsync, fullPage, delay string
	if err := f.db.QueryRow(ctx, "SELECT current_setting('server_version'),current_setting('data_directory'),current_setting('fsync'),current_setting('full_page_writes'),current_setting('wal_writer_delay')").Scan(&version, &data, &fsync, &fullPage, &delay); err != nil {
		t.Fatal(err)
	}
	if version != "18.6" || data != c.data || fsync != "on" || fullPage != "on" || delay != "10s" {
		t.Fatal("unexpected actual server", version, data, fsync, fullPage, delay)
	}
	t.Log("backend PostgreSQL", version, "persistent HOME btrfs", data, "fsync/full_page_writes on; wal_writer_delay", delay)
	// Exercise both direct startup GUC and the options=-c form on each role.
	for _, suffix := range []string{" synchronous_commit=off", " options='-c synchronous_commit=off'"} {
		for _, role := range []string{f.roles.Serving, f.roles.Admin, f.roles.Bootstrap} {
			cfg := f.config(role)
			cfg.DSN += suffix
			h, err := open(ctx, cfg, role)
			if err != nil {
				t.Fatal("hostile DSN normalization", err)
			}
			if err = h.runTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
				var got string
				if e := tx.QueryRow(ctx, "SHOW synchronous_commit").Scan(&got); e != nil {
					return e
				}
				if got != "on" {
					return fmt.Errorf("effective synchronous_commit=%s", got)
				}
				t.Log("actual restricted role backend synchronous_commit", got, "DSN suffix", suffix)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			h.Close()
		}
	}
	cfg := f.config(f.roles.Admin)
	cfg.DSN += " synchronous_commit=off"
	hostile, err := OpenAdmin(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer hostile.Close()
	er, err := hostile.Enroll(ctx, admin, Enrollment{Target: writer, RequestID: fixtureRequest(2)})
	if err != nil || er == (Receipt{}) {
		t.Fatal("hostile DSN enrollment", er, err)
	}
	// No subsequent synchronous application write before the immediate crash.
	c.crash(t, f)
	authenticateFixture(t, s, writer)
	if got, e := a.GetAdminResult(ctx, admin, AdminResultQuery{Operation: 2, RequestID: fixtureRequest(2)}); e != nil || got != er {
		t.Fatal("lost acknowledged enrollment/result", got, e)
	}
	assertReceiptAudit(t, f, admin, er)
	// A separate hostile options startup setting must not lose a revocation.
	cfg = f.config(f.roles.Admin)
	cfg.DSN += " options='-c synchronous_commit=off'"
	hostile2, err := OpenAdmin(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer hostile2.Close()
	rr, err := hostile2.RevokeSession(ctx, admin, SessionRevocation{SessionID: writer.Session.Claims.Session, RequestID: fixtureRequest(3)})
	if err != nil || rr == (Receipt{}) {
		t.Fatal("hostile DSN revocation", rr, err)
	}
	c.crash(t, f)
	mustDenyAuthentication(t, s, writer)
	if got, e := a.GetAdminResult(ctx, admin, AdminResultQuery{Operation: 4, RequestID: fixtureRequest(3)}); e != nil || got != rr {
		t.Fatal("lost terminal revocation/result", got, e)
	}
	assertReceiptAudit(t, f, admin, rr)
	// CAS also uses the same private runtime transaction despite an async
	// database default and options DSN. Crash before another application write.
	next := nextFixturePolicy(t, initial)
	cas, err := hostile2.CompareAndSwapPolicy(ctx, admin, fixtureHead(t, f, initial), next, fixtureRequest(4))
	if err != nil || cas == (Receipt{}) {
		t.Fatal("hostile DSN CAS", cas, err)
	}
	c.crash(t, f)
	checkResult(cas)
	if got, e := a.GetPolicy(ctx, admin, fixtureHead(t, f, next)); e != nil || got.Repository.Version != next.Repository.Version {
		t.Fatal("lost acknowledged policy", got, e)
	}
	cr, err := hostile.RevokeCredential(ctx, admin, CredentialRevocation{CredentialHash: writer.Session.Claims.CredentialHash, RequestID: fixtureRequest(5)})
	if err != nil || cr == (Receipt{}) {
		t.Fatal("hostile DSN credential revocation", cr, err)
	}
	c.crash(t, f)
	checkResult(cr)
	mustDenyAuthentication(t, s, writer)
	var revoked bool
	if err = f.db.QueryRow(ctx, "SELECT revoked FROM scion_policy.credential_state WHERE credential_hash=$1", writer.Session.Claims.CredentialHash[:]).Scan(&revoked); err != nil || !revoked {
		t.Fatal("lost terminal credential revocation", revoked, err)
	}
	for _, r := range []Receipt{br, er, rr, cas, cr} {
		checkResult(r)
	}
	t.Log("hostile async DSNs/database default: bootstrap, enrollment, CAS, session and credential revocation each survive an immediate owned-server crash with exact result/audit")

	// Change only this owned server. Existing handles and fresh opens must fail
	// before any application state changes, even for authenticated read/retry.
	before := policyCounts(t, f)
	unprovisioned := managementSetup(t)
	if _, err = unprovisioned.db.Exec(ctx, "DROP SCHEMA scion_policy CASCADE"); err != nil {
		t.Fatal(err)
	}
	pc := ProvisionConfig{DSN: unprovisioned.dsn(unprovisioned.admin.Config().User) + " options='-c synchronous_commit=off'", Roles: unprovisioned.roles}
	for _, setting := range []string{"fsync", "full_page_writes"} {
		for _, value := range []string{"off", "on"} {
			if _, err = f.db.Exec(ctx, "ALTER SYSTEM SET "+setting+" = '"+value+"'"); err != nil {
				t.Fatal(err)
			}
			if _, err = f.db.Exec(ctx, "SELECT pg_reload_conf()"); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				var got string
				if err = f.db.QueryRow(ctx, "SELECT current_setting($1)", setting).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if got == value {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("configuration reload not observed", setting, got)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if value == "on" {
				authenticateFixture(t, s, admin)
				continue
			}
			t.Log("actual owned server unsafe setting", setting, value)
			if got, e := Provision(ctx, pc); !errors.Is(e, metadata.ErrFailedPrecondition) || got != (DatabaseBinding{}) {
				t.Fatal("unsafe durability admitted Provision", got, e)
			}
			var schemaExists bool
			if err = unprovisioned.db.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_namespace WHERE nspname='scion_policy')").Scan(&schemaExists); err != nil || schemaExists {
				t.Fatal("unsafe Provision executed DDL", schemaExists, err)
			}
			mustDenyAuthentication(t, s, admin)
			if r, e := a.Enroll(ctx, admin, Enrollment{Target: f.credentials("denied", 230), RequestID: fixtureRequest(230)}); !errors.Is(e, metadata.ErrFailedPrecondition) || r != (Receipt{}) {
				t.Fatal("unsafe durability admitted enrollment", r, e)
			}
			if r, e := a.GetAdminResult(ctx, admin, AdminResultQuery{Operation: 2, RequestID: fixtureRequest(2)}); !errors.Is(e, metadata.ErrFailedPrecondition) || r != (Receipt{}) {
				t.Fatal("unsafe durability admitted read", r, e)
			}
			if h, e := OpenAdmin(ctx, f.config(f.roles.Admin)); !errors.Is(e, metadata.ErrFailedPrecondition) || h != nil {
				if h != nil {
					h.Close()
				}
				t.Fatal("unsafe durability admitted new handle", e)
			}
			if after := policyCounts(t, f); after != before {
				t.Fatal("unsafe operation changed state", before, after)
			}
		}
	}
	if got, e := Provision(ctx, pc); e != nil || got == (DatabaseBinding{}) {
		t.Fatal("safe configuration did not restore legitimate Provision", got, e)
	}
}
