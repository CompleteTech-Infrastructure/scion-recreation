package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/storage/metadata"
	"github.com/jackc/pgx/v5"
)

func adversarialGuard(t *testing.T, s *Store, ctx context.Context, tx pgx.Tx, scope metadata.Scope, intent metadata.OperationIntent) *CurrentGuard {
	t.Helper()
	g, err := s.RecheckCurrent(ctx, tx, scope, intent)
	if err != nil {
		t.Fatal("guard admission:", err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func TestAdversarialGuardScopeAndContext(t *testing.T) {
	f, s, ctx, scope, intent := guardFixture(t)
	claims := ctx.Value(authenticatedKey{}).(authenticated).session.Claims()
	index := principalIndex(claims.Principal)
	if scope.Repository != claims.Repository || scope.Principal != string(index[:]) || scope.Session != string(claims.Session[:]) || len(scope.Principal) != 32 || len(scope.Session) != 32 {
		t.Fatal("scope does not derive signed selectors")
	}
	cases := map[string]func(*metadata.Scope){
		"repository": func(v *metadata.Scope) { v.Repository[0] ^= 0xff },
		"principal":  func(v *metadata.Scope) { v.Principal = string(make([]byte, 32)) },
		"session":    func(v *metadata.Scope) { v.Session = string(make([]byte, 32)) },
		"version":    func(v *metadata.Scope) { v.PolicyVersion++ },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bad := scope
			mutate(&bad)
			tx := guardTx(t, f, pgx.TxOptions{})
			if g, err := s.RecheckCurrent(ctx, tx, bad, intent); err == nil {
				g.Close()
				t.Fatal("substituted scope admitted")
			}
		})
	}
	t.Run("different context", func(t *testing.T) {
		tx := guardTx(t, f, pgx.TxOptions{})
		g := adversarialGuard(t, s, ctx, tx, scope, intent)
		derived := context.WithValue(ctx, struct{}{}, "extra")
		if g.RequireRepository(derived, tx, scope, intent, authz.RepositoryMetadataRead) == nil {
			t.Fatal("derived context admitted")
		}
		if g.Finalize(ctx, tx, scope, intent) == nil {
			t.Fatal("context denial was not sticky")
		}
	})
	t.Run("different transaction", func(t *testing.T) {
		tx := guardTx(t, f, pgx.TxOptions{})
		other := guardTx(t, f, pgx.TxOptions{})
		g := adversarialGuard(t, s, ctx, tx, scope, intent)
		if g.Finalize(ctx, other, scope, intent) == nil {
			t.Fatal("different transaction admitted")
		}
		if g.Finalize(ctx, tx, scope, intent) == nil {
			t.Fatal("transaction denial was not sticky")
		}
	})
	t.Run("different store", func(t *testing.T) {
		other, err := Open(context.Background(), f.config(f.roles.Serving))
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		tx := guardTx(t, f, pgx.TxOptions{})
		if _, err := other.MetadataScope(ctx, 0); err == nil {
			t.Fatal("foreign authenticated context derived scope")
		}
		if g, err := other.RecheckCurrent(ctx, tx, scope, intent); err == nil {
			g.Close()
			t.Fatal("foreign store admitted")
		}
	})
}

func TestAdversarialGuardTerminalSessionFence(t *testing.T) {
	f, s, ctx, scope, intent := guardFixture(t)
	tx := guardTx(t, f, pgx.TxOptions{})
	g := adversarialGuard(t, s, ctx, tx, scope, intent)
	id := ctx.Value(authenticatedKey{}).(authenticated).session.Claims().Session
	done := make(chan error, 1)
	go func() {
		_, err := f.db.Exec(context.Background(), "UPDATE scion_policy.session_state SET revoked=true WHERE session_id=$1", id[:])
		done <- err
	}()
	adversarialWaitForLock(t, f, done, "UPDATE scion_policy.session_state%")
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("Close released caller transaction fence: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revocation remained blocked")
	}
	tx2 := guardTx(t, f, pgx.TxOptions{})
	if g, err := s.RecheckCurrent(ctx, tx2, scope, intent); err == nil {
		g.Close()
		t.Fatal("terminal session admitted")
	}
}

func adversarialWaitForLock(t *testing.T, f *managementFixture, done <-chan error, query string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := f.admin.QueryRow(context.Background(), "SELECT EXISTS (SELECT FROM pg_catalog.pg_stat_activity WHERE datname=$1 AND wait_event_type='Lock' AND query LIKE $2)", f.name, query).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("operation completed before fence released: %v", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("operation did not reach a lock wait")
}

func TestAdversarialGuardPolicyCASFence(t *testing.T) {
	f, s, ctx, scope, intent := guardFixture(t)
	admin, writer := f.credentials("admin", 1), f.credentials("writer", 2)
	p := f.policy(admin, writer)
	p.Repository.Roles[0].Allow = append(p.Repository.Roles[0].Allow, authz.RepositoryMetadataRead, authz.RepositoryRead)
	p.Paths.Rules = []authz.PathRule{
		{Principal: admin.Session.Claims.Principal, Selector: authz.PathSelector{Root: true}, Allow: []authz.PathAction{authz.PathTraverse}},
		{Principal: admin.Session.Claims.Principal, Selector: authz.PathSelector{Path: []byte("public")}, Allow: []authz.PathAction{authz.PathRead}},
	}
	a, err := OpenAdmin(context.Background(), f.config(f.roles.Admin))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	tx := guardTx(t, f, pgx.TxOptions{})
	g := adversarialGuard(t, s, ctx, tx, scope, intent)
	expected, next := fixtureHead(t, f, p), nextFixturePolicy(t, p)
	done := make(chan error, 1)
	go func() {
		_, err := a.CompareAndSwapPolicy(context.Background(), admin, expected, next, fixtureRequest(77))
		done <- err
	}()
	// The management path locks the HEAD through its security-definer function.
	adversarialWaitForLock(t, f, done, "%lock_head%")
	if err := g.Finalize(ctx, tx, scope, intent); err != nil {
		t.Fatal("guard lost old policy while fenced:", err)
	}
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("CAS after fence:", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CAS remained blocked")
	}
	tx2 := guardTx(t, f, pgx.TxOptions{})
	if g, err := s.RecheckCurrent(ctx, tx2, scope, intent); err == nil {
		g.Close()
		t.Fatal("old policy version admitted after CAS")
	}
}

func TestAdversarialGuardAdmissionAndCancellation(t *testing.T) {
	f, _, _, _, _ := guardFixture(t)
	cfg := f.config(f.roles.Serving)
	cfg.Limits.MaxConcurrentOps = 1
	s, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	actor := f.credentials("admin", 1)
	ctx, err := s.Authenticate(context.Background(), actor.Identity, actor.Session)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := s.MetadataScope(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := metadata.NewPublicationStatusIntent(ctx, scope, "admission")
	if err != nil {
		t.Fatal(err)
	}
	tx1 := guardTx(t, f, pgx.TxOptions{})
	tx2 := guardTx(t, f, pgx.TxOptions{})
	g := adversarialGuard(t, s, ctx, tx1, scope, intent)
	if other, err := s.RecheckCurrent(ctx, tx2, scope, intent); !errors.Is(err, metadata.ErrResourceExhausted) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("finite admission: %v", err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal("double close:", err)
	}
	g2 := adversarialGuard(t, s, ctx, tx2, scope, intent)
	if err := g2.Finalize(ctx, tx2, scope, intent); err != nil {
		t.Fatal("slot not reusable:", err)
	}
	if err := g2.Close(); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if other, err := s.RecheckCurrent(canceled, tx2, scope, intent); err == nil {
		other.Close()
		t.Fatal("canceled admission")
	}
	g3 := adversarialGuard(t, s, ctx, tx2, scope, intent)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if g3.Finalize(ctx, tx2, scope, intent) == nil {
		t.Fatal("closed owner admitted finalization")
	}
	if err := g3.Close(); err != nil {
		t.Fatal(err)
	}
	if len(s.slots) != 0 {
		t.Fatal("guard slot leaked")
	}
	// Close releases admission, not the caller-owned transaction.
	var one int
	if err := tx2.QueryRow(context.Background(), "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("caller transaction lost: %d %v", one, err)
	}
}

func TestAdversarialGuardTransactionControls(t *testing.T) {
	f, s, ctx, scope, intent := guardFixture(t)
	tests := []struct{ name, sql string }{
		{"statement timeout", "SET LOCAL statement_timeout='3s'"},
		{"lock timeout", "SET LOCAL lock_timeout='2s'"},
		{"idle timeout", "SET LOCAL idle_in_transaction_session_timeout='6s'"},
		{"total timeout", "SET LOCAL transaction_timeout='6s'"},
		{"durability", "SET LOCAL synchronous_commit=off"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tx := guardTx(t, f, pgx.TxOptions{})
			g := adversarialGuard(t, s, ctx, tx, scope, intent)
			if _, err := tx.Exec(ctx, tc.sql); err != nil {
				t.Fatal(err)
			}
			if g.Finalize(ctx, tx, scope, intent) == nil {
				t.Fatal("weakened transaction admitted")
			}
		})
	}
	t.Run("canceled original context", func(t *testing.T) {
		base, cancel := context.WithCancel(context.Background())
		actor := f.credentials("admin", 1)
		signed, err := s.Authenticate(base, actor.Identity, actor.Session)
		if err != nil {
			t.Fatal(err)
		}
		sc, err := s.MetadataScope(signed, 0)
		if err != nil {
			t.Fatal(err)
		}
		in, err := metadata.NewPublicationStatusIntent(signed, sc, "cancel")
		if err != nil {
			t.Fatal(err)
		}
		tx := guardTx(t, f, pgx.TxOptions{})
		g := adversarialGuard(t, s, signed, tx, sc, in)
		cancel()
		if g.Finalize(signed, tx, sc, in) == nil {
			t.Fatal("canceled guard admitted")
		}
		if err := g.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAdversarialGuardCatalogAndDatabaseDrift(t *testing.T) {
	t.Run("catalog", func(t *testing.T) {
		f, s, ctx, scope, intent := guardFixture(t)
		tx := guardTx(t, f, pgx.TxOptions{})
		g := adversarialGuard(t, s, ctx, tx, scope, intent)
		// Change a protected schema ACL within this unique fixture DB.
		if _, err := f.db.Exec(context.Background(), "GRANT USAGE ON SCHEMA scion_policy TO PUBLIC"); err != nil {
			t.Fatal(err)
		}
		if g.Finalize(ctx, tx, scope, intent) == nil {
			t.Fatal("catalog drift admitted")
		}
	})
	t.Run("database", func(t *testing.T) {
		f, s, ctx, scope, intent := guardFixture(t)
		other := managementSetup(t)
		// The other fixture's serving role is distinct; use the first serving role
		// against that database so role and database identity are independently tested.
		conn, err := pgx.Connect(context.Background(), other.dsn(f.roles.Serving))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(context.Background())
		tx, err := conn.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if g, err := s.RecheckCurrent(ctx, tx, scope, intent); err == nil {
			g.Close()
			t.Fatal("foreign database admitted")
		}
	})
}

func TestAdversarialGuardPathAdmissionBounds(t *testing.T) {
	f, s, ctx, scope, intent := guardFixture(t)
	t.Run("count", func(t *testing.T) {
		tx := guardTx(t, f, pgx.TxOptions{})
		g := adversarialGuard(t, s, ctx, tx, scope, intent)
		for i := 0; i < 4096; i++ {
			if err := g.RequirePath(ctx, tx, scope, intent, authz.PathSelector{Path: []byte("public")}, authz.PathRead); err != nil {
				t.Fatalf("action %d: %v", i, err)
			}
		}
		if err := g.RequirePath(ctx, tx, scope, intent, authz.PathSelector{Path: []byte("public")}, authz.PathRead); !errors.Is(err, metadata.ErrResourceExhausted) {
			t.Fatalf("action limit: %v", err)
		}
		if g.Finalize(ctx, tx, scope, intent) == nil {
			t.Fatal("limit denial not sticky")
		}
	})
	t.Run("bytes", func(t *testing.T) {
		tx := guardTx(t, f, pgx.TxOptions{})
		g := adversarialGuard(t, s, ctx, tx, scope, intent)
		err := g.RequirePath(ctx, tx, scope, intent, authz.PathSelector{Path: make([]byte, (1<<20)+1)}, authz.PathRead)
		if !errors.Is(err, metadata.ErrResourceExhausted) {
			t.Fatalf("byte limit: %v", err)
		}
		if g.Finalize(ctx, tx, scope, intent) == nil {
			t.Fatal("byte denial not sticky")
		}
	})
}
