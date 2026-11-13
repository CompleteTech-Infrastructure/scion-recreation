package policy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/storage/metadata"
)

func policyCounts(t *testing.T, f *managementFixture) string {
	t.Helper()
	var counts string
	e := f.db.QueryRow(context.Background(), `SELECT jsonb_build_array((SELECT count(*) FROM scion_policy.credential_state),(SELECT count(*) FROM scion_policy.session_state),(SELECT count(*) FROM scion_policy.policy_versions),(SELECT count(*) FROM scion_policy.policy_head),(SELECT count(*) FROM scion_policy.admin_results),(SELECT count(*) FROM scion_policy.audit),(SELECT coalesce(sum(rows_used),0) FROM scion_policy.management_capacity),(SELECT coalesce(sum(bytes_used),0) FROM scion_policy.management_capacity))::text`).Scan(&counts)
	if e != nil {
		t.Fatal(e)
	}
	return counts
}
func TestPolicyEnrollmentReplayAndAuthorization(t *testing.T) {
	f := managementSetup(t)
	admin, writer, s, a, b := f.bootstrap(t)
	ctx := context.Background()
	initial := policyCounts(t, f)
	bootstrap := BootstrapRequest{Target: admin, Policy: f.policy(admin, writer), RequestID: fixtureRequest(1)}
	first, e := b.Bootstrap(ctx, bootstrap)
	if e != nil || first == (Receipt{}) {
		t.Fatal("offline exact retry", e)
	}
	if after := policyCounts(t, f); after != initial {
		t.Fatal("bootstrap replay consumed quota", initial, after)
	}
	changed := bootstrap
	changed.Policy.Repository.Roles = append([]authz.RepositoryRole(nil), bootstrap.Policy.Repository.Roles...)
	changed.Policy.Repository.Roles[1].Allow = []authz.RepositoryCapability{authz.RepositoryRead}
	if r, e := b.Bootstrap(ctx, changed); !errors.Is(e, metadata.ErrConflict) || r != (Receipt{}) {
		t.Fatal("changed bootstrap accepted", e)
	}
	request := Enrollment{Target: writer, RequestID: fixtureRequest(2)}
	first, e = a.Enroll(ctx, admin, request)
	if e != nil || first.TargetSession != writer.Session.Claims.Session || first.TargetCredentialHash != writer.Session.Claims.CredentialHash {
		t.Fatal("signed enrollment receipt targets", first, e)
	}
	assertReceiptAudit(t, f, admin, first)
	before := policyCounts(t, f)
	if second, e := a.Enroll(ctx, admin, request); e != nil || second != first {
		t.Fatal("exact replay", second, e)
	}
	if after := policyCounts(t, f); after != before {
		t.Fatal("replay duplicate durable rows/quota", before, after)
	}
	request.Target = f.credentials("other", 3)
	if r, e := a.Enroll(ctx, admin, request); !errors.Is(e, metadata.ErrConflict) || r != (Receipt{}) {
		t.Fatal("same-key different payload", r, e)
	}
	if r, e := a.Enroll(ctx, writer, Enrollment{Target: f.credentials("target", 4), RequestID: fixtureRequest(3)}); e == nil || r != (Receipt{}) {
		t.Fatal("writer selfadmin", r, e)
	}
	if after := policyCounts(t, f); after != before {
		t.Fatal("denial mutated state", before, after)
	}
	// A new real signed/enrolled session may recover its same principal's result
	// only after current authentication and current old-head admin authorization.
	newAdmin := f.credentials("admin", 60)
	if _, e := a.Enroll(ctx, admin, Enrollment{Target: newAdmin, RequestID: fixtureRequest(60)}); e != nil {
		t.Fatal(e)
	}
	if second, e := a.Enroll(ctx, newAdmin, Enrollment{Target: writer, RequestID: fixtureRequest(2)}); e != nil || second != first {
		t.Fatal("reauthenticated session result recovery", second, e)
	}
	_ = s.Close()
	reopened, e := Open(ctx, f.config(f.roles.Serving))
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if _, e = reopened.Authenticate(ctx, writer.Identity, writer.Session); e != nil {
		t.Fatal("actual close/reopen persistence", e)
	}
	var nilAdmin *Admin
	if r, e := nilAdmin.Enroll(ctx, admin, Enrollment{Target: writer, RequestID: fixtureRequest(9)}); e == nil || r != (Receipt{}) {
		t.Fatal("nil admin")
	}
}
func TestPolicyEnrollmentRollbackAndTerminalState(t *testing.T) {
	f := managementSetup(t)
	admin, _, s, a, _ := f.bootstrap(t)
	ctx := context.Background()
	for i, kind := range []string{"identity-signature", "session-signature", "cross-repo", "cross-tenant", "expired"} {
		target := f.credentials(kind, byte(10+i))
		switch kind {
		case "identity-signature":
			target.Identity.Signature[0] ^= 1
		case "session-signature":
			target.Session.Signature[0] ^= 1
		case "cross-repo":
			target.Session.Claims.Repository[0] ^= 1
		case "cross-tenant":
			target.Session.Claims.Tenant = "different"
		case "expired":
			target.Session.Claims.ExpiresAtUnix = f.clock.Load() - 1
		}
		before := policyCounts(t, f)
		r, e := a.Enroll(ctx, admin, Enrollment{Target: target, RequestID: fixtureRequest(byte(10 + i))})
		if e == nil || r != (Receipt{}) {
			t.Fatal("bad target accepted", kind, r, e)
		}
		if after := policyCounts(t, f); after != before {
			t.Fatal("bad target left durable rows", kind, before, after)
		}
	}
	target := f.credentials("terminal", 20)
	request := Enrollment{Target: target, RequestID: fixtureRequest(20)}
	if _, e := a.Enroll(ctx, admin, request); e != nil {
		t.Fatal(e)
	}
	if _, e := f.db.Exec(ctx, "UPDATE scion_policy.credential_state SET revoked=true WHERE credential_hash=$1", target.Session.Claims.CredentialHash[:]); e != nil {
		t.Fatal(e)
	}
	mustDenyAuthentication(t, s, target)
	before := policyCounts(t, f)
	if r, e := a.Enroll(ctx, admin, request); e == nil || r != (Receipt{}) {
		t.Fatal("revoked retry revived credential", r, e)
	}
	if after := policyCounts(t, f); after != before {
		t.Fatal("revoked replay mutation")
	}
	if _, e := f.db.Exec(ctx, "UPDATE scion_policy.credential_state SET revoked=false WHERE credential_hash=$1", target.Session.Claims.CredentialHash[:]); e == nil {
		t.Fatal("terminal revoke reset")
	}
	if _, e := f.db.Exec(ctx, "UPDATE scion_policy.session_state SET expires=expires+1"); e == nil {
		t.Fatal("session validity extension")
	}
}
func TestPolicyEnrollmentConcurrentExactRequest(t *testing.T) {
	f := managementSetup(t)
	admin, _, s, a, _ := f.bootstrap(t)
	target := f.credentials("simultaneous", 30)
	request := Enrollment{Target: target, RequestID: fixtureRequest(30)}
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan Receipt, 2)
	failures := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, e := a.Enroll(context.Background(), admin, request)
			results <- r
			failures <- e
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for range 2 {
		if e := <-failures; e != nil {
			t.Fatal("concurrent exact request", e)
		}
	}
	var first Receipt
	for r := range results {
		if first == (Receipt{}) {
			first = r
		}
		if r != first || r == (Receipt{}) {
			t.Fatal("concurrent replay changed receipt")
		}
	}
	var n int
	if e := f.db.QueryRow(context.Background(), "SELECT count(*) FROM scion_policy.session_state WHERE session_id=$1", target.Session.Claims.Session[:]).Scan(&n); e != nil || n != 1 {
		t.Fatal("duplicate session", n, e)
	}
	if _, e := s.Authenticate(context.Background(), target.Identity, target.Session); e != nil {
		t.Fatal(e)
	}
}
func TestPolicyEnrollmentAuditFailureRollsBack(t *testing.T) {
	f := managementSetup(t)
	admin, _, s, a, _ := f.bootstrap(t)
	ctx := context.Background()
	target := f.credentials("blocked-audit", 40)
	before := policyCounts(t, f)
	lock, e := f.db.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Rollback(context.Background())
	if _, e = lock.Exec(ctx, "LOCK scion_policy.audit IN ACCESS EXCLUSIVE MODE"); e != nil {
		t.Fatal(e)
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		r, e := a.Enroll(work, admin, Enrollment{Target: target, RequestID: fixtureRequest(40)})
		if r != (Receipt{}) {
			e = fmt.Errorf("nonzero failed receipt: %v", r)
		}
		done <- e
	}()
	observed := false
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		var waiting bool
		if _, e = f.db.Exec(ctx, "SELECT pg_catalog.pg_stat_clear_snapshot()"); e != nil {
			t.Fatal(e)
		}
		e = f.db.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_catalog.pg_locks l JOIN pg_catalog.pg_class c ON c.oid=l.relation JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_stat_activity a ON a.pid=l.pid WHERE n.nspname='scion_policy' AND c.relname='audit' AND NOT l.granted AND a.datname=$1 AND a.usename=$2)`, f.name, f.roles.Admin).Scan(&waiting)
		if e != nil {
			t.Fatal(e)
		}
		if waiting {
			observed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if e = <-done; e == nil {
		t.Fatal("blocked audit reported success")
	}
	if !observed {
		t.Fatal("did not reach actual audit insertion lock")
	}
	if e = lock.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	if after := policyCounts(t, f); after != before {
		t.Fatal("audit failure partial state/capacity", before, after)
	}
	mustDenyAuthentication(t, s, target)
}
func TestPolicyMaximumRawTenantAndCollision(t *testing.T) {
	f := managementSetup(t)
	raw := make([]byte, 4096)
	_, _ = rand.New(rand.NewSource(287)).Read(raw)
	f.tenant = string(raw)
	admin, _, s, a, _ := f.bootstrap(t)
	subject := make([]byte, 4096)
	_, _ = rand.New(rand.NewSource(288)).Read(subject)
	target := f.credentials(string(subject), 50)
	target.Session.Claims.Generation = ^uint64(0)
	frame, e := authz.SessionTranscript(target.Session.Claims)
	if e != nil {
		t.Fatal(e)
	}
	target.Session.Signature = ed25519.Sign(f.session, frame)
	if _, e := s.Authenticate(context.Background(), admin.Identity, admin.Session); e != nil {
		t.Fatal("4096 incompressible signed tenant", e)
	}
	if _, e := a.Enroll(context.Background(), admin, Enrollment{Target: target, RequestID: fixtureRequest(50)}); e != nil {
		t.Fatal("4096 tenant enrollment", e)
	}
	if _, e := s.Authenticate(context.Background(), target.Identity, target.Session); e != nil {
		t.Fatal(e)
	}
	// Privileged fixture corruption keeps the namespace key but changes raw data.
	// Constraint/immutable guard must reject this; no collision-based authority.
	if _, e := f.db.Exec(context.Background(), "UPDATE scion_policy.tenant_keys SET raw=$1", bytes.Repeat([]byte{1}, 4096)); e == nil {
		t.Fatal("wrong raw namespace mapping changed")
	}
	proof := *target.Session
	proof.Claims.Tenant = string(append([]byte(nil), raw...))
	changed := []byte(proof.Claims.Tenant)
	changed[4095] ^= 1
	proof.Claims.Tenant = string(changed)
	transcript, e := authz.SessionTranscript(proof.Claims)
	if e != nil {
		t.Fatal(e)
	}
	proof.Signature = ed25519.Sign(f.session, transcript)
	mustDenyAuthentication(t, s, ActorCredentials{target.Identity, &proof})
}

func TestPolicyInvalidBootstrapLeavesNoNamespaceOrCapacity(t *testing.T) {
	f := managementSetup(t)
	ctx := context.Background()
	admin, writer := f.credentials("admin", 1), f.credentials("writer", 2)
	b, e := OpenBootstrap(ctx, f.config(f.roles.Bootstrap))
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	admin.Session.Signature[0] ^= 1
	before := policyCounts(t, f)
	if r, e := b.Bootstrap(ctx, BootstrapRequest{Target: admin, Policy: f.policy(admin, writer), RequestID: fixtureRequest(70)}); e == nil || r != (Receipt{}) {
		t.Fatal("invalid signed bootstrap", r, e)
	}
	if after := policyCounts(t, f); after != before {
		t.Fatal("failed bootstrap left state", before, after)
	}
	var tenants, repositories int
	if e = f.db.QueryRow(ctx, "SELECT (SELECT count(*) FROM scion_policy.tenant_keys),(SELECT repositories FROM scion_policy.bootstrap_capacity WHERE singleton)").Scan(&tenants, &repositories); e != nil || tenants != 0 || repositories != 0 {
		t.Fatal("failed bootstrap left namespace/capacity", tenants, repositories, e)
	}
	admin.Session.Signature[0] ^= 1
	if _, e = f.db.Exec(ctx, "UPDATE scion_policy.bootstrap_capacity SET repositories=1024"); e != nil {
		t.Fatal(e)
	}
	if r, e := b.Bootstrap(ctx, BootstrapRequest{Target: admin, Policy: f.policy(admin, writer), RequestID: fixtureRequest(71)}); e == nil || r != (Receipt{}) {
		t.Fatal("installation repo-capacity bypass", r, e)
	}
	if e = f.db.QueryRow(ctx, "SELECT count(*) FROM scion_policy.tenant_keys").Scan(&tenants); e != nil || tenants != 0 {
		t.Fatal("capacity failure left namespace", tenants, e)
	}

}

// Inspect only fixture-admin data after a real signed operation. This proves
// that the opaque public receipt is the exact result retained by its audit.
func assertReceiptAudit(t *testing.T, f *managementFixture, actor ActorCredentials, want Receipt) {
	t.Helper()
	p := actor.Session.Claims.Principal
	var body, session, proof, oldVersion, newVersion, oldHash, newHash []byte
	var links int
	err := f.db.QueryRow(context.Background(), `SELECT r.receipt,a.session_id,a.proof_hash,a.old_version,a.new_version,a.old_hash,a.new_hash,count(*) OVER() FROM scion_policy.admin_results r JOIN scion_policy.audit a ON (a.tenant,a.repo,a.actor,a.operation,a.request_id,a.intent_digest,a.actor_issuer,a.actor_subject,a.actor_class)=(r.tenant,r.repo,r.actor,r.operation,r.request_id,r.intent,r.actor_issuer,r.actor_subject,r.actor_class) WHERE r.repo=$1 AND r.operation=$2 AND r.request_id=$3 AND r.actor_issuer=$4 AND r.actor_subject=$5 AND r.actor_class=$6 AND a.success`, want.Repository[:], int16(want.Operation), want.RequestID[:], []byte(p.Issuer), []byte(p.Subject), []byte(p.Class)).Scan(&body, &session, &proof, &oldVersion, &newVersion, &oldHash, &newHash, &links)
	got, decodeErr := decodeReceipt(body)
	transcript, _ := authz.SessionTranscript(actor.Session.Claims)
	h := sha256.New()
	h.Write(transcript)
	h.Write(actor.Session.Signature)
	if err != nil || decodeErr != nil || got != want || len(body) != len(receiptDomain)+186 || links != 1 || !bytes.Equal(session, actor.Session.Claims.Session[:]) || !bytes.Equal(proof, h.Sum(nil)) || !bytes.Equal(newVersion, versionBytes(want.PolicyVersion)) || !bytes.Equal(newHash, want.PolicyDigest[:]) {
		t.Fatal("receipt/audit linkage", got, want, links, err, decodeErr)
	}
	if want.Operation == operationBootstrap {
		if oldVersion != nil || oldHash != nil {
			t.Fatal("bootstrap fabricated a prior policy")
		}
	}
}
