package policy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/storage/metadata"
	"github.com/jackc/pgx/v5"
)

// Only schema initialization uses these denied dependencies. They authorize no
// request and never stand in for the concrete policy credential checker.
type deniedFoundation struct{}

func (deniedFoundation) Authorize(context.Context, metadata.Scope, string) error {
	return metadata.ErrPermissionDenied
}
func (deniedFoundation) Recheck(context.Context, pgx.Tx, metadata.Scope, string) error {
	return metadata.ErrPermissionDenied
}
func (deniedFoundation) Publication(context.Context, metadata.Scope, metadata.PublishRequest) (metadata.PostgresRetention, error) {
	return nil, metadata.ErrPermissionDenied
}
func (deniedFoundation) Derived(context.Context, metadata.Scope, metadata.DerivedWrite) (metadata.PostgresRetention, error) {
	return nil, metadata.ErrPermissionDenied
}

type managementFixture struct {
	admin              *pgx.Conn
	db                 *pgx.Conn
	name, host, tenant string
	port               uint16
	roles              RoleNames
	binding            DatabaseBinding
	clock              atomic.Int64
	clockError         atomic.Bool
	identity, session  ed25519.PrivateKey
	repo               [16]byte
}

func quoteFixture(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, "\\", "\\\\"), "'", "\\'") + "'"
}
func (f *managementFixture) dsn(role string) string {
	return fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=disable", quoteFixture(f.host), f.port, quoteFixture(role), quoteFixture(f.name))
}
func managementSetup(t *testing.T) *managementFixture {
	t.Helper()
	dsn := os.Getenv("SCION_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("requires real isolated PostgreSQL18 fixture; skip is not persistence evidence")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(cfg.Host, "/") {
		t.Fatal("fixture requires explicit local Unix PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("fixture admin connect", err)
	}
	name := fmt.Sprintf("scion_policy_q_%d", time.Now().UnixNano())
	f := &managementFixture{admin: admin, name: name, host: cfg.Host, port: cfg.Port, tenant: "tenant\x00\xff", identity: ed25519.NewKeyFromSeed([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}), session: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, 32))}
	f.repo[0] = 1
	f.clock.Store(time.Now().UTC().Truncate(time.Second).Unix())
	f.roles = RoleNames{name + "_owner", name + "_fn", name + "_serve", name + "_admin", name + "_boot"}
	created := []string{}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if f.db != nil {
			_ = f.db.Close(cleanup)
		}
		if _, e := f.admin.Exec(cleanup, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); e != nil {
			t.Error("fixture database cleanup", e)
		}
		for _, r := range created {
			if _, e := f.admin.Exec(cleanup, "DROP ROLE "+pgx.Identifier{r}.Sanitize()); e != nil {
				t.Error("fixture role cleanup", r, e)
			}
		}
		_ = f.admin.Close(cleanup)
	})
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	for i, r := range roleList(f.roles) {
		login := " NOLOGIN"
		if i >= 2 {
			login = " LOGIN"
		}
		if _, err = admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{r}.Sanitize()+login+" NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
			t.Fatal(err)
		}
		created = append(created, r)
	}
	// ConnectConfig uses the actual changed database; ConnString does not.
	cfg.Database = name
	f.db, err = pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	foundation, err := metadata.OpenPostgres(ctx, f.dsn(cfg.User), deniedFoundation{}, deniedFoundation{})
	if err != nil {
		t.Fatal(err)
	}
	err = foundation.InitializeSchema(ctx)
	_ = foundation.Close()
	if err != nil {
		t.Fatal(err)
	}
	f.binding, err = Provision(ctx, ProvisionConfig{DSN: f.dsn(cfg.User), Roles: f.roles})
	if err != nil {
		t.Fatal("real policy Provision", err)
	}
	var version string
	if err = f.db.QueryRow(ctx, "SELECT version()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Log("actual fixture", name, "server", version, "Ed25519 identity seed00..1f/session99; tenant raw 00ff; schema policy-local-v1/session-v1")
	return f
}
func (f *managementFixture) config(role string) OpenConfig {
	return OpenConfig{DSN: f.dsn(role), Binding: f.binding, Roles: f.roles, Trust: TrustConfig{Audience: "authority", IdentityKeys: map[string]map[string]ed25519.PublicKey{"identity": {"key": f.identity.Public().(ed25519.PublicKey)}}, SessionKeys: map[string]map[string]ed25519.PublicKey{"session": {"key": f.session.Public().(ed25519.PublicKey)}}, ClockErrorKnown: true, Now: func() (time.Time, error) {
		if f.clockError.Load() {
			return time.Time{}, errors.New("fixture clock error")
		}
		return time.Unix(f.clock.Load(), 0), nil
	}}}
}

// This identity signing vector is independently framed, not copied through a
// permissive resolver or supplied as an Identity authorization assertion.
func (f *managementFixture) credentials(subject string, id byte) ActorCredentials {
	now := f.clock.Load()
	c := authz.IdentityClaims{Issuer: "identity", KeyID: "key", Subject: subject, Audience: "authority", Class: authz.Human, NotBeforeUnix: now - 60, ExpiresAtUnix: now + 1800}
	b := []byte("CANOPY\x00INTERNAL-IDENTITY\x00V1\x00")
	for _, s := range []string{c.Issuer, c.KeyID, c.Subject, string(c.Class), c.Audience} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
		b = append(b, s...)
	}
	b = binary.BigEndian.AppendUint64(b, uint64(c.NotBeforeUnix))
	b = binary.BigEndian.AppendUint64(b, uint64(c.ExpiresAtUnix))
	identity := &authz.IdentityCredential{Claims: c, Signature: ed25519.Sign(f.identity, b)}
	hash, err := authz.IdentityCredentialHash(identity)
	if err != nil {
		panic(err)
	}
	p := &authz.SessionProof{Version: 1, Claims: authz.SessionClaims{AuthorityIssuer: "session", KeyID: "key", Principal: authz.PrincipalID{Issuer: c.Issuer, Subject: c.Subject, Class: c.Class}, CredentialHash: hash, Audience: c.Audience, Tenant: f.tenant, Repository: f.repo, NotBeforeUnix: now - 30, ExpiresAtUnix: now + 900}}
	p.Claims.Session[0] = id
	b, err = authz.SessionTranscript(p.Claims)
	if err != nil {
		panic(err)
	}
	p.Signature = ed25519.Sign(f.session, b)
	return ActorCredentials{Identity: identity, Session: p}
}
func fixtureRequest(id byte) [32]byte { var v [32]byte; v[0] = id; return v }
func (f *managementFixture) policy(admin, writer ActorCredentials) authz.PolicySnapshot {
	scope := authz.RepositoryScope{TenantID: admin.Session.Claims.Tenant, RepositoryID: hex.EncodeToString(f.repo[:])}
	return authz.PolicySnapshot{Repository: authz.RepositoryPolicy{Scope: scope, Roles: []authz.RepositoryRole{{Name: "admin", Allow: []authz.RepositoryCapability{authz.RepositoryAdmin}}, {Name: "writer", Allow: []authz.RepositoryCapability{authz.RepositoryWrite}}}, Members: []authz.RepositoryMember{{Principal: admin.Session.Claims.Principal, Active: true, Roles: []string{"admin"}}, {Principal: writer.Session.Claims.Principal, Active: true, Roles: []string{"writer"}}}}, Paths: authz.PathPolicy{Scope: scope}}
}
func (f *managementFixture) bootstrap(t *testing.T) (ActorCredentials, ActorCredentials, *Store, *Admin, *Bootstrap) {
	t.Helper()
	ctx := context.Background()
	admin, writer := f.credentials("admin", 1), f.credentials("writer", 2)
	b, err := OpenBootstrap(ctx, f.config(f.roles.Bootstrap))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	r, err := b.Bootstrap(ctx, BootstrapRequest{Target: admin, Policy: f.policy(admin, writer), RequestID: fixtureRequest(1)})
	if err != nil || r == (Receipt{}) || r.TargetSession != admin.Session.Claims.Session || r.TargetCredentialHash != admin.Session.Claims.CredentialHash {
		t.Fatal("actual signed bootstrap", r, err)
	}
	assertReceiptAudit(t, f, admin, r)
	s, err := Open(ctx, f.config(f.roles.Serving))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	a, err := OpenAdmin(ctx, f.config(f.roles.Admin))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return admin, writer, s, a, b
}
func mustDenyAuthentication(t *testing.T, s *Store, actor ActorCredentials) {
	t.Helper()
	got, err := s.Authenticate(context.Background(), actor.Identity, actor.Session)
	if got != nil || !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("nonuniform authentication denial ctx=%v err=%v", got, err)
	}
}
func TestPolicyRuntimeActualSignedAuthentication(t *testing.T) {
	f := managementSetup(t)
	admin, writer, s, a, _ := f.bootstrap(t)
	ctx := context.Background()
	got, err := s.Authenticate(ctx, admin.Identity, admin.Session)
	if err != nil || got == nil {
		t.Fatal("enrolled signed admin", err)
	}
	record, ok := got.Value(authenticatedKey{}).(authenticated)
	if !ok || record.owner != s || !s.verifier.Owns(record.session) || record.binding != f.binding {
		t.Fatal("private authenticated provenance")
	}
	mustDenyAuthentication(t, s, writer)
	if r, e := a.Enroll(ctx, admin, Enrollment{Target: writer, RequestID: fixtureRequest(2)}); e != nil || r == (Receipt{}) {
		t.Fatal("actual admin enroll", r, e)
	}
	if _, e := s.Authenticate(ctx, writer.Identity, writer.Session); e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(*ActorCredentials){"signature": func(c *ActorCredentials) { c.Session.Signature[0] ^= 1 }, "credential": func(c *ActorCredentials) { c.Identity.Signature[0] ^= 1 }, "tenant": func(c *ActorCredentials) { c.Session.Claims.Tenant = "other" }, "repository": func(c *ActorCredentials) { c.Session.Claims.Repository[0] ^= 1 }, "generation": func(c *ActorCredentials) { c.Session.Claims.Generation++ }, "subject": func(c *ActorCredentials) { c.Session.Claims.Principal.Subject = "other" }} {
		t.Run(name, func(t *testing.T) {
			c, p, e := snapshot(admin.Identity, admin.Session)
			if e != nil {
				t.Fatal(e)
			}
			actor := ActorCredentials{&c, &p}
			mutate(&actor)
			mustDenyAuthentication(t, s, actor)
		})
	}
	for _, state := range []string{"zero", "error", "expired"} {
		old := f.clock.Load()
		switch state {
		case "zero":
			f.clock.Store(0)
		case "error":
			f.clockError.Store(true)
		case "expired":
			f.clock.Store(admin.Session.Claims.ExpiresAtUnix)
		}
		mustDenyAuthentication(t, s, admin)
		f.clock.Store(old)
		f.clockError.Store(false)
	}
	if value, e := s.Authenticate(nil, admin.Identity, admin.Session); e != authz.ErrUnauthenticated || value != nil {
		t.Fatal("nil context", e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if value, e := s.Authenticate(canceled, admin.Identity, admin.Session); e != authz.ErrUnauthenticated || value != nil {
		t.Fatal("canceled", e)
	}
	var nilStore *Store
	mustDenyAuthentication(t, nilStore, admin)
	if _, e := f.db.Exec(ctx, "UPDATE scion_policy.session_state SET revoked=true WHERE session_id=$1", admin.Session.Claims.Session[:]); e != nil {
		t.Fatal(e)
	}
	mustDenyAuthentication(t, s, admin)
}
func TestPolicyRuntimeBoundsAndClose(t *testing.T) {
	f := managementSetup(t)
	_, _, s, _, _ := f.bootstrap(t)
	ctx := context.Background()
	for name, mutate := range map[string]func(*OpenConfig){"unknown-clock": func(c *OpenConfig) { c.Trust.ClockErrorKnown = false }, "negative-clock": func(c *OpenConfig) { c.Trust.ClockError = -1 }, "excess-clock": func(c *OpenConfig) { c.Trust.ClockError = 2 * time.Second }, "slots": func(c *OpenConfig) { c.Limits.MaxConcurrentOps = 17 }, "wrong-db": func(c *OpenConfig) { c.Binding.Database += "other" }, "wrong-install": func(c *OpenConfig) { c.Binding.Installation[0] ^= 1 }, "wrong-catalog": func(c *OpenConfig) { c.Binding.CatalogFingerprint[0] ^= 1 }} {
		t.Run(name, func(t *testing.T) {
			c := f.config(f.roles.Serving)
			mutate(&c)
			if got, e := Open(ctx, c); e == nil || got != nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
	if got, e := Open(nil, f.config(f.roles.Serving)); e == nil || got != nil {
		t.Fatal("nil open")
	}
	entered, release, done := make(chan struct{}, 16), make(chan struct{}), make(chan error, 16)
	for range 16 {
		go func() {
			done <- s.runTx(ctx, func(context.Context, pgx.Tx) error { entered <- struct{}{}; <-release; return nil })
		}()
	}
	for range 16 {
		select {
		case <-entered:
		case e := <-done:
			t.Fatal("concurrent admission failed", e)
		case <-time.After(4 * time.Second):
			t.Fatal("independent transaction rendezvous")
		}
	}
	if e := s.runTx(ctx, func(context.Context, pgx.Tx) error { return nil }); !errors.Is(e, metadata.ErrResourceExhausted) {
		t.Fatal("17th admitted", e)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() { defer wg.Done(); _ = s.Close() }()
	}
	wg.Wait()
	close(release)
	for range 16 {
		if e := <-done; e != nil {
			t.Fatal("active transaction", e)
		}
	}
	if e := s.runTx(ctx, func(context.Context, pgx.Tx) error { return nil }); !errors.Is(e, metadata.ErrUnavailable) {
		t.Fatal("closed", e)
	}
}

func TestPolicyRuntimeRevocationWinsAndContextCannotAuthenticate(t *testing.T) {
	f := managementSetup(t)
	admin, _, s, _, _ := f.bootstrap(t)
	ctx := context.Background()
	valid, err := s.Authenticate(ctx, admin.Identity, admin.Session)
	if err != nil {
		t.Fatal(err)
	}
	// The private record and public identity cannot replace actual credentials.
	for _, forged := range []context.Context{valid, context.WithValue(ctx, authenticatedKey{}, authenticated{owner: s, binding: f.binding}), context.WithValue(ctx, authz.Identity{}, authz.Identity{Principal: admin.Session.Claims.Principal})} {
		if got, e := s.Authenticate(forged, nil, nil); got != nil || e != authz.ErrUnauthenticated {
			t.Fatal("context supplied authentication", e)
		}
	}
	lock, err := f.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(context.Background())
	if _, err = lock.Exec(ctx, "UPDATE scion_policy.credential_state SET revoked=true WHERE credential_hash=$1", admin.Session.Claims.CredentialHash[:]); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		got, e := s.Authenticate(ctx, admin.Identity, admin.Session)
		if got != nil {
			e = fmt.Errorf("revoked authentication context returned")
		}
		done <- e
	}()
	waiting := false
	for until := time.Now().Add(900 * time.Millisecond); time.Now().Before(until); {
		if err = f.admin.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_catalog.pg_stat_activity WHERE datname=$1 AND usename=$2 AND wait_event_type='Lock' AND query LIKE '%lock_credential_shared%')", f.name, f.roles.Serving).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("authentication never attempted actual shared credential guard")
	}
	if err = lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if e := <-done; e != authz.ErrUnauthenticated {
		t.Fatal("old credential state authorized after revoke committed", e)
	}
}

func TestPolicyConcurrentRealAuthenticationsReachSharedGuard(t *testing.T) {
	f := managementSetup(t)
	admin, _, s, _, _ := f.bootstrap(t)
	ctx := context.Background()
	lock, e := f.db.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Rollback(context.Background())
	if _, e = lock.Exec(ctx, "UPDATE scion_policy.credential_state SET revoked=revoked WHERE credential_hash=$1", admin.Session.Claims.CredentialHash[:]); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 2)
	for range 2 {
		go func() {
			got, e := s.Authenticate(ctx, admin.Identity, admin.Session)
			if e == nil && got == nil {
				e = errors.New("missing context")
			}
			done <- e
		}()
	}
	count := 0
	for until := time.Now().Add(900 * time.Millisecond); time.Now().Before(until); {
		if e = f.admin.QueryRow(ctx, "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE datname=$1 AND usename=$2 AND wait_event_type='Lock' AND query LIKE '%lock_credential_shared%'", f.name, f.roles.Serving).Scan(&count); e != nil {
			t.Fatal(e)
		}
		if count == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if count != 2 {
		t.Fatal("two genuine authentications did not independently enter shared-guard SQL", count)
	}
	if e = lock.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if e = <-done; e != nil {
			t.Fatal("compatible authenticated read failed", e)
		}
	}
}

// Observe a real PostgreSQL CommandComplete("COMMIT") acknowledgement, including
// split reads. This fixture changes only its clock, never backend responses.
type commitClockConnection struct {
	net.Conn
	tail    []byte
	once    sync.Once
	advance func()
}

func (c *commitClockConnection) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	pattern := []byte{'C', 0, 0, 0, 11, 'C', 'O', 'M', 'M', 'I', 'T', 0}
	bridge := append(append([]byte(nil), c.tail...), b[:min(n, len(pattern)-1)]...)
	if bytes.Contains(b[:n], pattern) || bytes.Contains(bridge, pattern) {
		c.once.Do(c.advance)
	}
	if n >= len(pattern)-1 {
		c.tail = append(c.tail[:0], b[n-len(pattern)+1:n]...)
	} else {
		c.tail = append(c.tail, b[:n]...)
		if len(c.tail) >= len(pattern) {
			c.tail = c.tail[len(c.tail)-len(pattern)+1:]
		}
	}
	return n, e
}
func TestPolicyAuthenticationExpiryAfterActualCommitAcknowledgement(t *testing.T) {
	f := managementSetup(t)
	admin, _, s, _, _ := f.bootstrap(t)
	var observed atomic.Bool
	s.config.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, e := (&net.Dialer{}).DialContext(ctx, network, address)
		if e != nil {
			return nil, e
		}
		return &commitClockConnection{Conn: conn, advance: func() { observed.Store(true); f.clock.Store(admin.Session.Claims.ExpiresAtUnix) }}, nil
	}
	got, e := s.Authenticate(context.Background(), admin.Identity, admin.Session)
	if !observed.Load() || got != nil || e != authz.ErrUnauthenticated {
		t.Fatal("post-COMMIT expiry returned authentication", observed.Load(), got, e)
	}
}
