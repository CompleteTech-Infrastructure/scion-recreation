package policy

import (
	"context"
	"reflect"
	"testing"
	"time"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/storage/metadata"
	"github.com/jackc/pgx/v5"
)

// This fixture uses the independently signed credentials and isolated PG18
// provisioning in runtime_test.go. A skip is not database qualification.
func guardFixture(t *testing.T) (*managementFixture, *Store, context.Context, metadata.Scope, metadata.OperationIntent) {
	t.Helper()
	f := managementSetup(t)
	admin, writer := f.credentials("admin", 1), f.credentials("writer", 2)
	p := f.policy(admin, writer)
	p.Repository.Roles[0].Allow = append(p.Repository.Roles[0].Allow, authz.RepositoryMetadataRead, authz.RepositoryRead)
	p.Paths.Rules = []authz.PathRule{
		{Principal: admin.Session.Claims.Principal, Selector: authz.PathSelector{Root: true}, Allow: []authz.PathAction{authz.PathTraverse}},
		{Principal: admin.Session.Claims.Principal, Selector: authz.PathSelector{Path: []byte("public")}, Allow: []authz.PathAction{authz.PathRead}},
	}
	b, err := OpenBootstrap(context.Background(), f.config(f.roles.Bootstrap))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if _, err = b.Bootstrap(context.Background(), BootstrapRequest{Target: admin, Policy: p, RequestID: fixtureRequest(1)}); err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), f.config(f.roles.Serving))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx, err := s.Authenticate(context.Background(), admin.Identity, admin.Session)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := s.MetadataScope(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := metadata.NewPublicationStatusIntent(ctx, scope, "actual-key")
	if err != nil {
		t.Fatal(err)
	}
	return f, s, ctx, scope, intent
}
func guardTx(t *testing.T, f *managementFixture, opts pgx.TxOptions) pgx.Tx {
	t.Helper()
	c, err := pgx.Connect(context.Background(), f.dsn(f.roles.Serving))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	tx, err := c.BeginTx(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return tx
}
func TestCurrentGuardSignedBindingAndStickyDenial(t *testing.T) {
	f, s, ctx, scope, intent := guardFixture(t)
	tx := guardTx(t, f, pgx.TxOptions{})
	g, err := s.RecheckCurrent(ctx, tx, scope, intent)
	if err != nil {
		t.Fatal("signed guard", err)
	}
	defer g.Close()
	if err = g.RequireRepository(ctx, tx, scope, intent, authz.RepositoryMetadataRead); err != nil {
		t.Fatal(err)
	}
	if err = g.Finalize(ctx, tx, scope, intent); err != nil {
		t.Fatal(err)
	}
	var copied CurrentGuard
	reflect.ValueOf(&copied).Elem().Set(reflect.ValueOf(g).Elem())
	if copied.Finalize(ctx, tx, scope, intent) == nil {
		t.Fatal("copied guard accepted")
	}
	other, _ := metadata.NewPublicationStatusIntent(ctx, scope, "other")
	if g.RequireRepository(ctx, tx, scope, other, authz.RepositoryMetadataRead) == nil {
		t.Fatal("substituted intent")
	}
	if g.Finalize(ctx, tx, scope, intent) == nil {
		t.Fatal("denial not sticky")
	}
	if err = g.Close(); err != nil {
		t.Fatal(err)
	}
	if g.Finalize(ctx, tx, scope, intent) == nil {
		t.Fatal("closed guard")
	}
}
func TestCurrentGuardRejectsTransactionsAndSelectors(t *testing.T) {
	f, s, ctx, scope, intent := guardFixture(t)
	for _, opts := range []pgx.TxOptions{{AccessMode: pgx.ReadOnly}, {IsoLevel: pgx.RepeatableRead}} {
		tx := guardTx(t, f, opts)
		if g, e := s.RecheckCurrent(ctx, tx, scope, intent); e == nil {
			g.Close()
			t.Fatal("unsafe transaction accepted", opts)
		}
	}
	tx := guardTx(t, f, pgx.TxOptions{})
	wrongVersion := scope
	wrongVersion.PolicyVersion++
	if g, e := s.RecheckCurrent(ctx, tx, wrongVersion, intent); e == nil {
		g.Close()
		t.Fatal("wrong policy version")
	}
	foreign, e := f.db.Begin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer foreign.Rollback(context.Background())
	if g, e := s.RecheckCurrent(ctx, foreign, scope, intent); e == nil {
		g.Close()
		t.Fatal("foreign role")
	}
	closed := guardTx(t, f, pgx.TxOptions{})
	if e := closed.Rollback(context.Background()); e != nil {
		t.Fatal(e)
	}
	if g, e := s.RecheckCurrent(ctx, closed, scope, intent); e == nil {
		g.Close()
		t.Fatal("closed transaction")
	}
	bad := scope
	bad.Principal = "forged"
	if g, e := s.RecheckCurrent(ctx, tx, bad, intent); e == nil {
		g.Close()
		t.Fatal("forged selector")
	}
	if g, e := s.RecheckCurrent(context.Background(), tx, scope, intent); e == nil {
		g.Close()
		t.Fatal("unsigned context")
	}
	nested, err := tx.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer nested.Rollback(context.Background())
	if g, e := s.RecheckCurrent(ctx, nested, scope, intent); e == nil {
		g.Close()
		t.Fatal("nested transaction")
	}
}
func TestCurrentGuardDefaultDenyAndClock(t *testing.T) {
	f, s, ctx, scope, intent := guardFixture(t)
	tx := guardTx(t, f, pgx.TxOptions{})
	g, err := s.RecheckCurrent(ctx, tx, scope, intent)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if err := g.RequirePath(ctx, tx, scope, intent, authz.PathSelector{Path: []byte("public")}, authz.PathRead); err != nil {
		t.Fatal("signed allowed path", err)
	}
	if g.RequirePath(ctx, tx, scope, intent, authz.PathSelector{Path: []byte("private")}, authz.PathRead) == nil {
		t.Fatal("default path allowed")
	}
	if g.Finalize(ctx, tx, scope, intent) == nil {
		t.Fatal("path denial not sticky")
	}
	tx2 := guardTx(t, f, pgx.TxOptions{})
	g2, err := s.RecheckCurrent(ctx, tx2, scope, intent)
	if err != nil {
		t.Fatal(err)
	}
	defer g2.Close()
	f.clockError.Store(true)
	if g2.Finalize(ctx, tx2, scope, intent) == nil {
		t.Fatal("unknown clock accepted")
	}
}

// Two real shared guards must coexist and fence a terminal credential update.
func TestCurrentGuardSharedOverlapAndRevocationFence(t *testing.T) {
	f, s, ctx, scope, intent := guardFixture(t)
	tx1 := guardTx(t, f, pgx.TxOptions{})
	tx2 := guardTx(t, f, pgx.TxOptions{})
	g1, e := s.RecheckCurrent(ctx, tx1, scope, intent)
	if e != nil {
		t.Fatal(e)
	}
	defer g1.Close()
	g2, e := s.RecheckCurrent(ctx, tx2, scope, intent)
	if e != nil {
		t.Fatal("shared guard overlap", e)
	}
	defer g2.Close()
	a := ctx.Value(authenticatedKey{}).(authenticated)
	hash := a.session.Claims().CredentialHash
	started, done := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		_, err := f.db.Exec(context.Background(), "UPDATE scion_policy.credential_state SET revoked=true WHERE credential_hash=$1", hash[:])
		done <- err
	}()
	<-started
	waiting := false
	for until := time.Now().Add(time.Second); time.Now().Before(until); {
		if err := f.admin.QueryRow(context.Background(), "SELECT EXISTS (SELECT FROM pg_catalog.pg_stat_activity WHERE datname=$1 AND wait_event_type='Lock' AND query LIKE 'UPDATE scion_policy.credential_state%')", f.name).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("revocation crossed shared fences: %v", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("revocation did not reach credential lock")
	}
	if e = tx1.Rollback(context.Background()); e != nil {
		t.Fatal(e)
	}
	select {
	case err := <-done:
		t.Fatalf("revocation crossed second fence: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if e = tx2.Rollback(context.Background()); e != nil {
		t.Fatal(e)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revocation did not proceed")
	}
	tx3 := guardTx(t, f, pgx.TxOptions{})
	if g, e := s.RecheckCurrent(ctx, tx3, scope, intent); e == nil {
		g.Close()
		t.Fatal("revoked credential admitted")
	}
}
