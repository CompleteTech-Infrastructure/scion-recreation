package policy

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/storage/metadata"
	"github.com/jackc/pgx/v5"
)

func enrollFixture(t *testing.T, a *Admin, admin, target ActorCredentials, id byte) {
	t.Helper()
	if r, e := a.Enroll(context.Background(), admin, Enrollment{Target: target, RequestID: fixtureRequest(id)}); e != nil || r == (Receipt{}) {
		t.Fatal("signed fixture enrollment", r, e)
	}
}
func authenticateFixture(t *testing.T, s *Store, actor ActorCredentials) {
	t.Helper()
	if c, e := s.Authenticate(context.Background(), actor.Identity, actor.Session); e != nil || c == nil {
		t.Fatal("actual enrolled authentication", e)
	}
}
func waitPolicyLock(t *testing.T, f *managementFixture, role, fragment string, done <-chan error) {
	t.Helper()
	for until := time.Now().Add(2 * time.Second); time.Now().Before(until); {
		var waiting bool
		if e := f.admin.QueryRow(context.Background(), "SELECT EXISTS(SELECT FROM pg_catalog.pg_stat_activity WHERE datname=$1 AND usename=$2 AND wait_event_type='Lock' AND position($3 in query)>0)", f.name, role, fragment).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			return
		}
		select {
		case e := <-done:
			t.Fatal("operation finished before observed database lock", e)
		default:
		}
		time.Sleep(3 * time.Millisecond)
	}
	t.Fatal("actual database lock wait was not observed", fragment)
}

func TestPolicyRevocationTerminalScopeAndFreshReplay(t *testing.T) {
	f := managementSetup(t)
	admin, writer, s, a, b := f.bootstrap(t)
	ctx := context.Background()
	second := f.credentials("writer", 3)
	enrollFixture(t, a, admin, writer, 2)
	enrollFixture(t, a, admin, second, 3)
	q := SessionRevocation{SessionID: writer.Session.Claims.Session, RequestID: fixtureRequest(4)}
	r, e := a.RevokeSession(ctx, admin, q)
	if e != nil || r.Operation != 4 || r.TargetSession != q.SessionID || r.TargetCredentialHash != writer.Session.Claims.CredentialHash {
		t.Fatal("session revoke", r, e)
	}
	assertReceiptAudit(t, f, admin, r)
	mustDenyAuthentication(t, s, writer)
	authenticateFixture(t, s, second)
	if again, e := a.RevokeSession(ctx, admin, q); e != nil || again != r {
		t.Fatal("exact revocation replay", again, e)
	}
	wrong := q
	wrong.SessionID = second.Session.Claims.Session
	if got, e := a.RevokeSession(ctx, admin, wrong); got != (Receipt{}) || !errors.Is(e, metadata.ErrConflict) {
		t.Fatal("changed target reused mutation key", got, e)
	}
	if got, e := a.RevokeSession(ctx, second, SessionRevocation{SessionID: admin.Session.Claims.Session, RequestID: fixtureRequest(5)}); got != (Receipt{}) || e == nil {
		t.Fatal("writer revoked administrator", got, e)
	}
	if got, e := a.Enroll(ctx, admin, Enrollment{Target: writer, RequestID: fixtureRequest(6)}); got != (Receipt{}) || e == nil {
		t.Fatal("revoked session resurrected", got, e)
	}
	// A separately signed repository using the SAME credential is independent.
	originalRepo := f.repo
	f.repo[0] = 9
	otherAdmin, otherWriter := f.credentials("admin", 21), f.credentials("writer", 22)
	if otherWriter.Session.Claims.CredentialHash != writer.Session.Claims.CredentialHash {
		t.Fatal("fixture did not reuse exact credential across repositories")
	}
	if _, e := b.Bootstrap(ctx, BootstrapRequest{Target: otherAdmin, Policy: f.policy(otherAdmin, otherWriter), RequestID: fixtureRequest(21)}); e != nil {
		t.Fatal("other repository bootstrap", e)
	}
	enrollFixture(t, a, otherAdmin, otherWriter, 22)
	f.repo = originalRepo
	credential := CredentialRevocation{CredentialHash: writer.Session.Claims.CredentialHash, RequestID: fixtureRequest(7)}
	cr, e := a.RevokeCredential(ctx, admin, credential)
	if e != nil || cr.Operation != 3 || cr.TargetSession != ([32]byte{}) || cr.TargetCredentialHash != credential.CredentialHash {
		t.Fatal("credential revoke", cr, e)
	}
	assertReceiptAudit(t, f, admin, cr)
	mustDenyAuthentication(t, s, second)
	authenticateFixture(t, s, otherWriter)
	if again, e := a.RevokeCredential(ctx, admin, credential); e != nil || again != cr {
		t.Fatal("credential replay", again, e)
	}
	third := f.credentials("writer", 4)
	if got, e := a.Enroll(ctx, admin, Enrollment{Target: third, RequestID: fixtureRequest(8)}); got != (Receipt{}) || e == nil {
		t.Fatal("revoked credential admitted a new session", got, e)
	}
	replacement := f.credentials("admin", 5)
	enrollFixture(t, a, admin, replacement, 9)
	if _, e := a.RevokeSession(ctx, admin, SessionRevocation{SessionID: admin.Session.Claims.Session, RequestID: fixtureRequest(10)}); e != nil {
		t.Fatal("self-session revocation", e)
	}
	mustDenyAuthentication(t, s, admin)
	if got, e := a.RevokeCredential(ctx, replacement, credential); e != nil || got != cr {
		t.Fatal("fresh same-principal session could not recover exact result", got, e)
	}
	if _, e := a.RevokeCredential(ctx, replacement, CredentialRevocation{CredentialHash: replacement.Session.Claims.CredentialHash, RequestID: fixtureRequest(11)}); e != nil {
		t.Fatal("self-credential revocation", e)
	}
	mustDenyAuthentication(t, s, replacement)
	if got, e := a.RevokeCredential(ctx, replacement, credential); got != (Receipt{}) || e == nil {
		t.Fatal("revoked actor recovered historical result", got, e)
	}
}

func TestPolicyRevocationFailureAtomicity(t *testing.T) {
	f := managementSetup(t)
	admin, writer, s, a, _ := f.bootstrap(t)
	enrollFixture(t, a, admin, writer, 2)
	ctx := context.Background()
	for _, q := range []SessionRevocation{{}, {RequestID: fixtureRequest(2)}, {SessionID: fixtureRequest(90), RequestID: fixtureRequest(3)}} {
		before := policyCounts(t, f)
		if got, e := a.RevokeSession(ctx, admin, q); got != (Receipt{}) || e == nil {
			t.Fatal("invalid/missing target succeeded", got, e)
		}
		if after := policyCounts(t, f); after != before {
			t.Fatal("failed revoke changed durable state", before, after)
		}
	}
	before := policyCounts(t, f)
	lock, e := f.db.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Rollback(context.Background())
	if _, e = lock.Exec(ctx, "LOCK TABLE scion_policy.audit IN ACCESS EXCLUSIVE MODE"); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		got, err := a.RevokeSession(ctx, admin, SessionRevocation{SessionID: writer.Session.Claims.Session, RequestID: fixtureRequest(5)})
		if got != (Receipt{}) {
			err = fmt.Errorf("audit failure returned receipt")
		}
		done <- err
	}()
	waitPolicyLock(t, f, f.roles.Admin, "record_admin_result", done)
	if e = <-done; e == nil {
		t.Fatal("audit lock failure committed revocation")
	}
	if e = lock.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	if after := policyCounts(t, f); after != before {
		t.Fatal("audit failure changed rows/capacity", before, after)
	}
	authenticateFixture(t, s, writer)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, e := a.RevokeCredential(canceled, admin, CredentialRevocation{CredentialHash: writer.Session.Claims.CredentialHash, RequestID: fixtureRequest(6)}); got != (Receipt{}) || e == nil {
		t.Fatal("canceled revoke succeeded", got, e)
	}
}

func TestPolicySharedGuardsFenceRevocation(t *testing.T) {
	f := managementSetup(t)
	admin, writer, s, a, _ := f.bootstrap(t)
	enrollFixture(t, a, admin, writer, 2)
	ctx := context.Background()
	entered, release, done := make(chan struct{}, 2), make(chan struct{}), make(chan error, 2)
	for range 2 {
		go func() {
			done <- s.runTx(ctx, func(work context.Context, tx pgx.Tx) error {
				if _, _, e := loadHead(work, tx, writer.Session.Claims); e != nil {
					return e
				}
				for _, q := range []struct {
					sql string
					id  [32]byte
				}{{"SELECT 1 FROM scion_policy.lock_credential_shared($1,$2,$3)", writer.Session.Claims.CredentialHash}, {"SELECT 1 FROM scion_policy.lock_session_shared($1,$2,$3)", writer.Session.Claims.Session}} {
					if e := managementExec(work, tx, q.sql, []byte(f.tenant), f.repo[:], q.id[:]); e != nil {
						return e
					}
				}
				if _, e := s.verifyInTx(work, tx, *writer.Identity, *writer.Session, true); e != nil {
					return e
				}
				entered <- struct{}{}
				<-release
				return nil
			})
		}()
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	for range 2 {
		select {
		case <-entered:
		case e := <-done:
			t.Fatal("compatible guard failed before rendezvous", e)
		case <-time.After(4 * time.Second):
			t.Fatal("two shared guards could not overlap")
		}
	}
	revoked := make(chan error, 1)
	go func() {
		_, e := a.RevokeCredential(ctx, admin, CredentialRevocation{CredentialHash: writer.Session.Claims.CredentialHash, RequestID: fixtureRequest(3)})
		revoked <- e
	}()
	waitPolicyLock(t, f, f.roles.Admin, "lock_credential_exclusive", revoked)
	close(release)
	for range 2 {
		if e := <-done; e != nil {
			t.Fatal("shared guard completion", e)
		}
	}
	if e := <-revoked; e != nil {
		t.Fatal("revocation after guards", e)
	}
	mustDenyAuthentication(t, s, writer)
	// This is a real policy-row guard test, not a publication implementation.
	if got, e := s.Authenticate(ctx, writer.Identity, writer.Session); got != nil || !errors.Is(e, authz.ErrUnauthenticated) {
		t.Fatal("update-first old authorization", e)
	}
}

func TestPolicyRevocationExpiryAndCancellationDuringLockWait(t *testing.T) {
	f := managementSetup(t)
	admin, writer, s, a, _ := f.bootstrap(t)
	enrollFixture(t, a, admin, writer, 2)
	for _, mode := range []string{"expiry", "cancellation"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			before, oldClock := policyCounts(t, f), f.clock.Load()
			lock, e := f.db.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer lock.Rollback(context.Background())
			if _, e = lock.Exec(ctx, "SELECT 1 FROM scion_policy.lock_credential_exclusive($1,$2,$3)", []byte(f.tenant), f.repo[:], writer.Session.Claims.CredentialHash[:]); e != nil {
				t.Fatal(e)
			}
			work, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				got, e := a.RevokeCredential(work, admin, CredentialRevocation{CredentialHash: writer.Session.Claims.CredentialHash, RequestID: fixtureRequest(80)})
				if got != (Receipt{}) {
					e = fmt.Errorf("failed freshness returned a receipt")
				}
				done <- e
			}()
			waitPolicyLock(t, f, f.roles.Admin, "lock_credential_exclusive", done)
			if mode == "expiry" {
				f.clock.Store(admin.Session.Claims.ExpiresAtUnix)
				if e = lock.Rollback(ctx); e != nil {
					t.Fatal(e)
				}
			} else {
				cancel()
			}
			if e = <-done; e == nil {
				t.Fatal("revocation succeeded after lost freshness")
			}
			if mode == "cancellation" {
				if e = lock.Rollback(ctx); e != nil {
					t.Fatal(e)
				}
			}
			f.clock.Store(oldClock)
			if after := policyCounts(t, f); after != before {
				t.Fatal("freshness failure changed state", before, after)
			}
			authenticateFixture(t, s, writer)
		})
	}
}

func TestPolicyRevocationRejectsCorruptRetainedCredentialTarget(t *testing.T) {
	for _, session := range []bool{false, true} {
		t.Run(fmt.Sprint("session=", session), func(t *testing.T) {
			f := managementSetup(t)
			admin, writer, _, a, _ := f.bootstrap(t)
			enrollFixture(t, a, admin, writer, 2)
			ctx := context.Background()
			mutate := func() (Receipt, error) {
				if session {
					return a.RevokeSession(ctx, admin, SessionRevocation{SessionID: writer.Session.Claims.Session, RequestID: fixtureRequest(3)})
				}
				return a.RevokeCredential(ctx, admin, CredentialRevocation{CredentialHash: writer.Session.Claims.CredentialHash, RequestID: fixtureRequest(3)})
			}
			r, err := mutate()
			if err != nil || r.TargetCredentialHash != writer.Session.Claims.CredentialHash {
				t.Fatal("signed target revoke", r, err)
			}
			assertReceiptAudit(t, f, admin, r)
			// Privileged fixture corruption is a negative probe, never a positive
			// admission path. Restore the trigger before current catalog checks.
			bad := r
			bad.TargetCredentialHash[0] ^= 1
			if _, err := f.db.Exec(ctx, "ALTER TABLE scion_policy.admin_results DISABLE TRIGGER USER"); err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.Exec(ctx, "UPDATE scion_policy.admin_results SET receipt=$1 WHERE request_id=$2", encodeReceipt(bad), r.RequestID[:]); err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.Exec(ctx, "ALTER TABLE scion_policy.admin_results ENABLE TRIGGER USER"); err != nil {
				t.Fatal(err)
			}
			before := policyCounts(t, f)
			if got, err := mutate(); got != (Receipt{}) || !errors.Is(err, metadata.ErrCorruptData) {
				t.Fatal("corrupt retained target was replayed", got, err)
			}
			if after := policyCounts(t, f); after != before {
				t.Fatal("corrupt replay changed durable state", before, after)
			}
		})
	}
}
