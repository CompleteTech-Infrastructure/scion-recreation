package policy

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/storage/metadata"
	"github.com/jackc/pgx/v5"
)

// These tests require the isolated, independently signed PG18 fixture. A skip
// or an offline compile does not establish any database behavior.
func TestTerminalGuardManagementCredentialFence(t *testing.T) {
	f, s, _, _, _ := guardFixture(t)
	admin, target := f.credentials("admin", 1), f.credentials("admin", 3)
	a, err := OpenAdmin(context.Background(), f.config(f.roles.Admin))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	enrollFixture(t, a, admin, target, 31)
	ctx, err := s.Authenticate(context.Background(), target.Identity, target.Session)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := s.MetadataScope(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := metadata.NewPublicationStatusIntent(ctx, scope, "terminal-fence")
	if err != nil {
		t.Fatal(err)
	}
	tx := guardTx(t, f, pgx.TxOptions{})
	g := adversarialGuard(t, s, ctx, tx, scope, intent)
	done := make(chan error, 1)
	work, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		_, e := a.RevokeCredential(work, admin, CredentialRevocation{CredentialHash: target.Session.Claims.CredentialHash, RequestID: fixtureRequest(32)})
		done <- e
	}()
	waitPolicyLock(t, f, f.roles.Admin, "lock_credential_exclusive", done)
	if err := g.RequireRepository(ctx, tx, scope, intent, authz.RepositoryMetadataRead); err != nil {
		t.Fatal(err)
	}
	if err := g.Finalize(ctx, tx, scope, intent); err != nil {
		t.Fatal("finalize while revocation waits:", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("guarded commit:", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("revocation after commit:", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revocation did not finish")
	}
	tx2 := guardTx(t, f, pgx.TxOptions{})
	if next, err := s.RecheckCurrent(ctx, tx2, scope, intent); err == nil {
		next.Close()
		t.Fatal("stale context admitted after revocation")
	}
	if _, err := s.Authenticate(context.Background(), target.Identity, target.Session); err == nil {
		t.Fatal("revoked credential reauthenticated")
	}
}

func TestTerminalGuardSignedSessionSubstitutions(t *testing.T) {
	f, s, ctx, scope, intent := guardFixture(t)
	actor := f.credentials("admin", 1)
	cases := map[string]func(*authz.SessionProof){
		"generation": func(p *authz.SessionProof) { p.Claims.Generation++ },
		"session":    func(p *authz.SessionProof) { p.Claims.Session[0]++ },
		"principal":  func(p *authz.SessionProof) { p.Claims.Principal.Subject = "writer" },
		"interval":   func(p *authz.SessionProof) { p.Claims.ExpiresAtUnix-- },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := *actor.Session
			mutate(&p)
			transcript, err := authz.SessionTranscript(p.Claims)
			if err != nil {
				t.Fatal(err)
			}
			p.Signature = ed25519.Sign(f.session, transcript)
			if _, err := s.Authenticate(context.Background(), actor.Identity, &p); err == nil {
				t.Fatal("validly signed substituted session authenticated")
			}
		})
	}
	// The authentic tuple still admits a real guard after the failed substitutions.
	tx := guardTx(t, f, pgx.TxOptions{})
	g := adversarialGuard(t, s, ctx, tx, scope, intent)
	if err := g.Finalize(ctx, tx, scope, intent); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalGuardTransactionRoleDrift(t *testing.T) {
	f, s, ctx, scope, intent := guardFixture(t)
	// Use a disposable role with no capabilities, and grant only SET. Remove the
	// membership after switching: PostgreSQL retains the active role, while the
	// protected role catalog returns to its original state.
	role := f.name + "_drift"
	quotedRole := pgx.Identifier{role}.Sanitize()
	serving := pgx.Identifier{f.roles.Serving}.Sanitize()
	if _, err := f.admin.Exec(context.Background(), "CREATE ROLE "+quotedRole+" NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
		t.Fatal("create drift role:", err)
	}
	t.Cleanup(func() {
		if _, err := f.admin.Exec(context.Background(), "REVOKE "+quotedRole+" FROM "+serving); err != nil {
			t.Error("revoke drift role during cleanup:", err)
		}
		if _, err := f.admin.Exec(context.Background(), "DROP ROLE "+quotedRole); err != nil {
			t.Error("drop drift role:", err)
		}
	})
	// A previously unopened relation forces a fresh relation lock after the
	// grant. PostgreSQL processes shared catalog invalidations when acquiring
	// that lock; another command alone need not invalidate membership caches.
	probe := pgx.Identifier{"public", f.name + "_probe"}.Sanitize()
	if _, err := f.db.Exec(ctx, "CREATE TABLE "+probe+" (n integer)"); err != nil {
		t.Fatal("create invalidation probe:", err)
	}
	t.Cleanup(func() {
		if _, err := f.db.Exec(context.Background(), "DROP TABLE "+probe); err != nil {
			t.Error("drop invalidation probe:", err)
		}
	})
	if _, err := f.db.Exec(ctx, "GRANT SELECT ON "+probe+" TO "+serving); err != nil {
		t.Fatal("grant probe access:", err)
	}
	tx := guardTx(t, f, pgx.TxOptions{})
	g := adversarialGuard(t, s, ctx, tx, scope, intent)
	if _, err := f.admin.Exec(context.Background(), "GRANT "+quotedRole+" TO "+serving+" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"); err != nil {
		t.Fatal("grant SET role:", err)
	}
	if _, err := tx.Exec(ctx, "SELECT n FROM "+probe+" LIMIT 0"); err != nil {
		t.Fatal("acquire probe relation lock:", err)
	}
	var canSet bool
	if err := tx.QueryRow(ctx, "SELECT pg_has_role(session_user, $1, 'SET')", role).Scan(&canSet); err != nil || !canSet {
		t.Fatalf("fixture SET membership not visible after probe lock: %v (allowed=%t)", err, canSet)
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+quotedRole); err != nil {
		t.Fatal("set drift role:", err)
	}
	if _, err := f.admin.Exec(context.Background(), "REVOKE "+quotedRole+" FROM "+serving); err != nil {
		t.Fatal("revoke temporary SET membership:", err)
	}
	var current, session string
	if err := tx.QueryRow(ctx, "SELECT current_user, session_user").Scan(&current, &session); err != nil {
		t.Fatal(err)
	}
	if current != role || session != f.roles.Serving {
		t.Fatalf("role drift not established: %s %s", current, session)
	}
	control := guardTx(t, f, pgx.TxOptions{})
	if err := verifyPolicyCatalog(ctx, control, f.binding, f.roles, f.roles.Serving); err != nil {
		t.Fatal("catalog not restored after temporary grant:", err)
	}
	if g.Finalize(ctx, tx, scope, intent) == nil {
		t.Fatal("changed transaction role admitted")
	}
}

func TestTerminalGuardDatabaseOwnerDrift(t *testing.T) {
	f, s, ctx, scope, intent := guardFixture(t)
	tx := guardTx(t, f, pgx.TxOptions{})
	g := adversarialGuard(t, s, ctx, tx, scope, intent)
	// The fixture database is isolated; change only its owner, not policy objects.
	if _, err := f.admin.Exec(context.Background(), "ALTER DATABASE "+pgx.Identifier{f.name}.Sanitize()+" OWNER TO "+pgx.Identifier{f.roles.Admin}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	var owner string
	if err := f.admin.QueryRow(context.Background(), "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=$1", f.name).Scan(&owner); err != nil || owner != f.roles.Admin {
		t.Fatalf("owner drift not established: %q %v", owner, err)
	}
	if g.Finalize(ctx, tx, scope, intent) == nil {
		t.Fatal("changed database owner admitted")
	}
}
