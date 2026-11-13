package policy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"canopy.local/canopy/internal/authz"
	"github.com/jackc/pgx/v5"
)

// This opt-in test owns its entire server and never controls the shared test
// DSN's server. An immediate PostgreSQL shutdown exercises WAL crash recovery;
// it does not simulate power loss, physical WAL expiry, cloud, or scale.
func TestPolicyAcknowledgedStateSurvivesServerCrash(t *testing.T) {
	bin := os.Getenv("SCION_POLICY_RESTART_PG_BIN")
	if bin == "" {
		t.Skip("requires an explicitly selected disposable PostgreSQL toolchain; skip is not restart evidence")
	}
	if os.Geteuid() == 0 {
		t.Fatal("disposable PostgreSQL must run as an unprivileged user")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	var fs syscall.Statfs_t
	if err = syscall.Statfs(home, &fs); err != nil || uint64(fs.Type) != 0x9123683e {
		t.Fatal("restart qualification requires persistent HOME btrfs", err, fs.Type)
	}
	data, err := os.MkdirTemp(home, ".scion-policy-restart-")
	if err != nil {
		t.Fatal(err)
	}
	socket, err := os.MkdirTemp("/tmp", "spr-")
	if err != nil {
		t.Fatal(err)
	}
	// Registered first: fixture/handle cleanup must run while the server is up.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		out, e := exec.CommandContext(ctx, filepath.Join(bin, "pg_ctl"), "-D", data, "-m", "immediate", "-w", "-t", "15", "stop").CombinedOutput()
		t.Logf("owned cluster cleanup exit=%v output=%s", e, out)
		if t.Failed() {
			t.Log("preserved failed cluster evidence", data, socket)
			return
		}
		if e != nil {
			t.Error("owned server cleanup", e)
			return
		}
		if e = os.RemoveAll(data); e != nil {
			t.Error(e)
		}
		if e = os.RemoveAll(socket); e != nil {
			t.Error(e)
		}
	})
	run := func(name string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, e := exec.CommandContext(ctx, filepath.Join(bin, name), args...).CombinedOutput()
		t.Logf("UTC=%s owned command=%s args=%q exit=%v output=%s", time.Now().UTC().Format(time.RFC3339Nano), name, args, e, out)
		if e != nil {
			t.Fatalf("owned %s failed: %v", name, e)
		}
		return string(out)
	}
	run("initdb", "-D", data, "-L", filepath.Join(filepath.Dir(bin), "share", "postgresql"), "-A", "trust", "--no-locale", "--encoding=UTF8")
	conf := fmt.Sprintf("\nlisten_addresses=''\nunix_socket_directories='%s'\nunix_socket_permissions=0700\nport=55491\nfsync=on\nsynchronous_commit=on\nfull_page_writes=on\n", socket)
	file, err := os.OpenFile(filepath.Join(data, "postgresql.conf"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteString(conf)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	start := func() { run("pg_ctl", "-D", data, "-l", filepath.Join(data, "server.log"), "-w", "-t", "20", "start") }
	start()
	t.Setenv("SCION_POSTGRES_TEST_DSN", fmt.Sprintf("host=%s port=55491 dbname=postgres sslmode=disable", socket))
	f := managementSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var version, actualData, fsync, syncCommit, fullPage, listen, socketMode string
	var beforeStart time.Time
	if err = f.db.QueryRow(ctx, "SELECT current_setting('server_version'),current_setting('data_directory'),current_setting('fsync'),current_setting('synchronous_commit'),current_setting('full_page_writes'),current_setting('listen_addresses'),current_setting('unix_socket_permissions'),pg_postmaster_start_time()").Scan(&version, &actualData, &fsync, &syncCommit, &fullPage, &listen, &socketMode, &beforeStart); err != nil {
		t.Fatal(err)
	}
	if version != "18.6" || actualData != data || fsync != "on" || syncCommit != "on" || fullPage != "on" || listen != "" || socketMode != "0700" {
		t.Fatal("unexpected actual durability/server settings", version, actualData, fsync, syncCommit, fullPage, listen, socketMode)
	}
	t.Log("backend PostgreSQL", version, "persistent HOME btrfs data", data, "socket", socket, "fsync/synchronous_commit/full_page_writes on; identity00..1f/session99 policy-local-v1/session-v1")
	admin, writer, s, a, b := f.bootstrap(t)
	initial := f.policy(admin, writer)
	br := BootstrapRequest{Target: admin, Policy: initial, RequestID: fixtureRequest(1)}
	bootstrap, err := b.Bootstrap(ctx, br)
	if err != nil || bootstrap == (Receipt{}) {
		t.Fatal("acknowledged bootstrap retry", bootstrap, err)
	}
	enroll := Enrollment{Target: writer, RequestID: fixtureRequest(2)}
	er, err := a.Enroll(ctx, admin, enroll)
	if err != nil || er == (Receipt{}) {
		t.Fatal("acknowledged signed enrollment", er, err)
	}
	authenticateFixture(t, s, writer)
	sibling := f.credentials("writer", 3)
	enrollFixture(t, a, admin, sibling, 3)
	replacement := f.credentials("admin", 4)
	enrollFixture(t, a, admin, replacement, 4)
	next := nextFixturePolicy(t, initial)
	next.Paths.Rules = []authz.PathRule{{Principal: writer.Session.Claims.Principal, Selector: authz.PathSelector{Path: []byte{0xff, '/', 'x'}}, Allow: []authz.PathAction{authz.PathRead}}}
	expected := fixtureHead(t, f, initial)
	cas, err := a.CompareAndSwapPolicy(ctx, admin, expected, next, fixtureRequest(5))
	if err != nil || cas == (Receipt{}) {
		t.Fatal("acknowledged CAS", cas, err)
	}
	sr := SessionRevocation{SessionID: writer.Session.Claims.Session, RequestID: fixtureRequest(6)}
	revokedSession, err := a.RevokeSession(ctx, admin, sr)
	if err != nil || revokedSession == (Receipt{}) {
		t.Fatal("acknowledged session revocation", revokedSession, err)
	}
	cr := CredentialRevocation{CredentialHash: writer.Session.Claims.CredentialHash, RequestID: fixtureRequest(7)}
	revokedCredential, err := a.RevokeCredential(ctx, admin, cr)
	if err != nil || revokedCredential == (Receipt{}) {
		t.Fatal("acknowledged credential revocation", revokedCredential, err)
	}
	mustDenyAuthentication(t, s, writer)
	mustDenyAuthentication(t, s, sibling)
	authenticateFixture(t, s, replacement)
	// Compare every durable row, including exact immutable bodies, tombstones,
	// audit/result payloads and capacity accounting, across real server recovery.
	snapshot := func() string {
		t.Helper()
		var rows []string
		for _, table := range []string{"installation", "tenant_keys", "bootstrap_capacity", "management_capacity", "credential_state", "session_state", "policy_versions", "policy_head", "admin_results", "audit"} {
			var body string
			if e := f.db.QueryRow(ctx, "SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb)::text FROM scion_policy."+table+" x").Scan(&body); e != nil {
				t.Fatal(table, e)
			}
			rows = append(rows, table+":"+body)
		}
		return strings.Join(rows, "\n")
	}
	before := snapshot()
	t.Logf("acknowledged durable state SHA256=%x counts=%s", sha256.Sum256([]byte(before)), policyCounts(t, f))
	// Stage real signed target rows and a next policy/result/audit in one tx,
	// observe them inside that tx, then crash without ever sending COMMIT.
	tx, err := f.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	phantom := f.credentials("interrupted", 90)
	if err = insertCredential(ctx, tx, *phantom.Identity, *phantom.Session); err != nil {
		t.Fatal(err)
	}
	verified, err := a.store.verifyInTx(ctx, tx, *phantom.Identity, *phantom.Session, false)
	if err != nil {
		t.Fatal("real signed staged target verification", err)
	}
	if err = insertSession(ctx, tx, verified); err != nil {
		t.Fatal(err)
	}
	pending := nextFixturePolicy(t, next)
	body, err := authz.EncodePolicySnapshot(pending)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	head := fixtureHead(t, f, next)
	if _, err = tx.Exec(ctx, "SELECT scion_policy.cas_policy($1,$2,$3,$4,$5,$6)", []byte(f.tenant), f.repo[:], versionBytes(head.Version), head.Digest[:], body, digest[:]); err != nil {
		t.Fatal(err)
	}
	actor, err := a.store.verifyInTx(ctx, tx, *admin.Identity, *admin.Session, true)
	if err != nil {
		t.Fatal(err)
	}
	pendingResult := Receipt{RequestID: fixtureRequest(90), TenantHash: sha256.Sum256([]byte(f.tenant)), Repository: f.repo, Operation: 5, PolicyVersion: pending.Repository.Version, PolicyDigest: digest}
	if err = recordResult(ctx, tx, actor, f.tenant, pendingResult, fixtureRequest(91), false); err != nil {
		t.Fatal(err)
	}
	var staged bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM scion_policy.session_state WHERE session_id=$1) AND EXISTS(SELECT FROM scion_policy.admin_results WHERE request_id=$2) AND EXISTS(SELECT FROM scion_policy.audit WHERE request_id=$2) AND EXISTS(SELECT FROM scion_policy.policy_head WHERE version=$3)`, phantom.Session.Claims.Session[:], pendingResult.RequestID[:], versionBytes(pending.Repository.Version)).Scan(&staged); err != nil || !staged {
		t.Fatal("interrupted bundle not actually staged", staged, err)
	}
	// pg_ctl identifies only the PID in this test's unique data directory.
	run("pg_ctl", "-D", data, "-m", "immediate", "-w", "-t", "15", "stop")
	start()
	reconnect := func(dsn string) *pgx.Conn {
		t.Helper()
		c, e := pgx.Connect(ctx, dsn)
		if e != nil {
			t.Fatal("post-recovery reconnect", e)
		}
		return c
	}
	closeConnection(f.db)
	closeConnection(f.admin)
	f.admin = reconnect(os.Getenv("SCION_POSTGRES_TEST_DSN"))
	f.db = reconnect(f.dsn(f.admin.Config().User))
	var afterStart time.Time
	if err = f.db.QueryRow(ctx, "SELECT pg_postmaster_start_time()").Scan(&afterStart); err != nil || !afterStart.After(beforeStart) {
		t.Fatal("server did not actually restart", beforeStart, afterStart, err)
	}
	walLog, err := os.ReadFile(filepath.Join(data, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("owned full PostgreSQL server log:\n%s", walLog)
	if !strings.Contains(string(walLog), "database system was interrupted") || !strings.Contains(string(walLog), "redo starts at") || !strings.Contains(string(walLog), "redo done at") {
		t.Fatal("actual WAL crash recovery was not observed")
	}
	if after := snapshot(); after != before {
		t.Fatalf("durable rows changed across crash before=%s after=%s", before, after)
	}
	t.Logf("recovered durable state SHA256=%x; all ten tables byte-equivalent JSON; interrupted bundle absent", sha256.Sum256([]byte(before)))
	// Existing production handles reconnect per operation; a fresh signed session
	// must authenticate before recovering the same principal's historical result.
	authenticateFixture(t, s, admin)
	authenticateFixture(t, s, replacement)
	mustDenyAuthentication(t, s, writer)
	mustDenyAuthentication(t, s, sibling)
	mustDenyAuthentication(t, s, phantom)
	for _, r := range []Receipt{bootstrap, er, cas, revokedSession, revokedCredential} {
		if got, e := a.GetAdminResult(ctx, replacement, AdminResultQuery{Operation: r.Operation, RequestID: r.RequestID}); e != nil || got != r {
			t.Fatal("authenticated recovered result", r, got, e)
		}
		if got, e := a.GetAdminResult(ctx, writer, AdminResultQuery{Operation: r.Operation, RequestID: r.RequestID}); e == nil || got != (Receipt{}) {
			t.Fatal("revoked actor recovered result", got, e)
		}
	}
	if got, e := a.CompareAndSwapPolicy(ctx, replacement, expected, next, fixtureRequest(5)); e != nil || got != cas {
		t.Fatal("recovered exact CAS retry", got, e)
	}
	if got, e := a.RevokeSession(ctx, replacement, sr); e != nil || got != revokedSession {
		t.Fatal("recovered exact session revocation retry", got, e)
	}
	if got, e := a.RevokeCredential(ctx, replacement, cr); e != nil || got != revokedCredential {
		t.Fatal("recovered exact credential revocation retry", got, e)
	}
	if got, e := a.GetPolicy(ctx, replacement, fixtureHead(t, f, next)); e != nil {
		t.Fatal("recovered current policy", e)
	} else if bytes, e := authz.EncodePolicySnapshot(got); e != nil || sha256.Sum256(bytes) != cas.PolicyDigest {
		t.Fatal("recovered policy canonical bytes", e)
	}
	if r, e := a.GetAdminResult(ctx, replacement, AdminResultQuery{Operation: 5, RequestID: fixtureRequest(90)}); e == nil || r != (Receipt{}) {
		t.Fatal("uncommitted result became visible", r, e)
	}
	if r, e := a.Enroll(ctx, replacement, Enrollment{Target: sibling, RequestID: fixtureRequest(92)}); e == nil || r != (Receipt{}) {
		t.Fatal("terminal credential resurrected after restart", r, e)
	}
	if after := snapshot(); after != before {
		t.Fatal("authenticated reads/retries/denials changed durable recovered state")
	}
}
