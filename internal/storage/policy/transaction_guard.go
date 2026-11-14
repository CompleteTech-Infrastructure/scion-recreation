package policy

import (
	"bytes"
	"context"
	"encoding/binary"
	"reflect"
	"sync"
	"time"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/storage/metadata"
	"github.com/jackc/pgx/v5"
)

// MetadataScope derives selectors from this Store's authenticated record. The
// explicit policy version (including zero) is an expectation, never authority.
func (s *Store) MetadataScope(ctx context.Context, version uint64) (metadata.Scope, error) {
	a, err := s.guardAuthentication(ctx)
	if err != nil {
		return metadata.Scope{}, err
	}
	c := a.session.Claims()
	p := principalIndex(c.Principal)
	return metadata.Scope{Repository: c.Repository, Principal: string(p[:]), Session: string(c.Session[:]), PolicyVersion: version}, nil
}

func (s *Store) guardAuthentication(ctx context.Context) (authenticated, error) {
	if s == nil || ctx == nil || !reflect.ValueOf(ctx).Comparable() || ctx.Err() != nil || s.closed.Load() || s.role != s.roles.Serving {
		return authenticated{}, metadata.ErrPermissionDenied
	}
	a, ok := ctx.Value(authenticatedKey{}).(authenticated)
	if !ok || a.owner != s || a.binding != s.binding || !s.verifier.Owns(a.session) || !s.safeTime(ctx, a.session.Claims()) {
		return authenticated{}, metadata.ErrPermissionDenied
	}
	return a, nil
}

// currentRealTx deliberately accepts only pgx/v5's pinned concrete root dbTx.
// No interface method on an untrusted wrapper is invoked. Nested transactions,
// roots that created nested transactions, and custom COMMIT commands deny.
// Reflection reads scalars only; it neither uses unsafe nor modifies pgx state.
func currentRealTx(tx pgx.Tx) bool {
	v := reflect.ValueOf(tx)
	if !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() {
		return false
	}
	t := v.Type().Elem()
	if t.PkgPath() != "github.com/jackc/pgx/v5" || t.Name() != "dbTx" {
		return false
	}
	v = v.Elem()
	closed, nested, commit := v.FieldByName("closed"), v.FieldByName("savepointNum"), v.FieldByName("commitQuery")
	return closed.IsValid() && closed.Kind() == reflect.Bool && !closed.Bool() &&
		nested.IsValid() && nested.Kind() == reflect.Int64 && nested.Int() == 0 &&
		commit.IsValid() && commit.Kind() == reflect.String && commit.String() == ""
}

// CurrentGuard is an opaque, noncopyable, bounded current-policy component. It
// is not PostgresIntentAuthorization, a native-object grant or delivery lease.
// The trusted caller owns SQL commit/rollback and MUST Close on every path.
type CurrentGuard struct {
	self                 *CurrentGuard
	mu                   sync.Mutex
	owner                *Store
	ctx, work            context.Context
	cancel               context.CancelFunc
	tx                   pgx.Tx
	scope                metadata.Scope
	intent               metadata.OperationIntent
	actor                authenticated
	xid                  string
	repository           *authz.RepositoryPolicyEngine
	paths                *authz.PathPolicyEngine
	failed               error
	closed               bool
	pathCount, pathBytes int
}

// RecheckCurrent holds shared HEAD -> credential -> session fences in the
// caller's SAME real transaction. No transaction is committed or rolled back.
func (s *Store) RecheckCurrent(ctx context.Context, tx pgx.Tx, scope metadata.Scope, intent metadata.OperationIntent) (*CurrentGuard, error) {
	a, err := s.guardAuthentication(ctx)
	if err != nil || !currentRealTx(tx) || intent.Validate() != nil || intent.Repository() != scope.Repository {
		return nil, metadata.ErrPermissionDenied
	}
	want, err := s.MetadataScope(ctx, scope.PolicyVersion)
	if err != nil || scope != want {
		return nil, metadata.ErrPermissionDenied
	}
	select {
	case s.slots <- struct{}{}:
	default:
		return nil, metadata.ErrResourceExhausted
	}
	work, cancel := context.WithTimeout(ctx, transactionBudget)
	g := &CurrentGuard{owner: s, ctx: ctx, work: work, cancel: cancel, tx: tx, scope: scope, intent: intent, actor: a}
	g.self = g
	ok := false
	defer func() {
		if !ok {
			_ = g.Close()
		}
	}()
	// Set transaction-local safety settings, then check elapsed server time from
	// the original BEGIN. Tightening now must never renew an old transaction.
	if _, err = tx.Exec(work, `SELECT
 set_config('statement_timeout', (CASE WHEN current_setting('statement_timeout')::interval = interval '0' THEN 2000 ELSE least(extract(epoch FROM current_setting('statement_timeout')::interval)*1000, 2000) END)::bigint::text||'ms', true),
 set_config('lock_timeout', (CASE WHEN current_setting('lock_timeout')::interval = interval '0' THEN 1000 ELSE least(extract(epoch FROM current_setting('lock_timeout')::interval)*1000, 1000) END)::bigint::text||'ms', true),
 set_config('idle_in_transaction_session_timeout', (CASE WHEN current_setting('idle_in_transaction_session_timeout')::interval = interval '0' THEN 5000 ELSE least(extract(epoch FROM current_setting('idle_in_transaction_session_timeout')::interval)*1000, 5000) END)::bigint::text||'ms', true),
 set_config('transaction_timeout', (CASE WHEN current_setting('transaction_timeout')::interval = interval '0' THEN 5000 ELSE least(extract(epoch FROM current_setting('transaction_timeout')::interval)*1000, 5000) END)::bigint::text||'ms', true),
 set_config('synchronous_commit','on',true)`); err != nil {
		return nil, failure(work)
	}
	var age float64
	if err = tx.QueryRow(work, `SELECT extract(epoch FROM (clock_timestamp()-transaction_timestamp()))::double precision`).Scan(&age); err != nil || age < 0 || age >= 5 {
		return nil, metadata.ErrFailedPrecondition
	}
	cancel()
	g.work, g.cancel = context.WithTimeout(ctx, transactionBudget-time.Duration(age*float64(time.Second)))
	// PostgreSQL's total timer is also bounded by the remaining original budget.
	if _, err = tx.Exec(g.work, `SELECT pg_catalog.set_config('transaction_timeout', least(extract(epoch FROM current_setting('transaction_timeout')::interval)*1000, greatest(1,floor(extract(epoch FROM (transaction_timestamp()+interval '5 seconds'-clock_timestamp()))*1000)))::bigint::text||'ms',true)`); err != nil {
		return nil, failure(g.work)
	}
	if err = g.verifyTransaction(); err != nil {
		return nil, err
	}
	p, _, err := loadHead(g.work, tx, a.session.Claims())
	if err != nil {
		return nil, err
	}
	if p.Repository.Version != scope.PolicyVersion {
		return nil, metadata.ErrPermissionDenied
	}
	if err = g.enrolled(); err != nil {
		return nil, err
	}
	c := a.session.Claims()
	g.repository, err = authz.NewRepositoryPolicy(p.Repository, c.Audience, s.now)
	if err != nil {
		return nil, metadata.ErrCorruptData
	}
	g.paths, err = authz.NewPathPolicy(p.Paths, g.repository)
	if err != nil {
		return nil, metadata.ErrCorruptData
	}
	minimum := authz.RepositoryMetadataRead
	if intent.Kind() == metadata.IntentPublication {
		minimum = authz.RepositoryWrite
	}
	if err = g.requireRepository(minimum); err != nil {
		return nil, err
	}
	if _, err = s.guardAuthentication(ctx); err != nil || !s.safeTime(g.work, c) {
		return nil, metadata.ErrPermissionDenied
	}
	ok = true
	return g, nil
}

func (g *CurrentGuard) verifyTransaction() error {
	if !currentRealTx(g.tx) {
		return metadata.ErrPermissionDenied
	}
	var isolation, readOnly, user, session, statement, lock, idle, total, xid string
	var age float64
	err := g.tx.QueryRow(g.work, `SELECT current_setting('transaction_isolation'),current_setting('transaction_read_only'),current_user,session_user,current_setting('statement_timeout'),current_setting('lock_timeout'),current_setting('idle_in_transaction_session_timeout'),current_setting('transaction_timeout'),pg_current_xact_id()::text,extract(epoch FROM (clock_timestamp()-transaction_timestamp()))::double precision`).Scan(&isolation, &readOnly, &user, &session, &statement, &lock, &idle, &total, &xid, &age)
	if err != nil {
		return failure(g.work)
	}
	// Durations use PostgreSQL's own conversion, avoiding aliases and units.
	var bounded bool
	err = g.tx.QueryRow(g.work, `SELECT current_setting('statement_timeout')::interval>interval '0' AND current_setting('statement_timeout')::interval<=interval '2 seconds' AND current_setting('lock_timeout')::interval>interval '0' AND current_setting('lock_timeout')::interval<=interval '1 second' AND current_setting('idle_in_transaction_session_timeout')::interval>interval '0' AND current_setting('idle_in_transaction_session_timeout')::interval<=interval '5 seconds' AND current_setting('transaction_timeout')::interval>interval '0' AND current_setting('transaction_timeout')::interval<=interval '5 seconds'`).Scan(&bounded)
	if err != nil || !bounded || isolation != "read committed" || readOnly != "off" || user != g.owner.roles.Serving || session != user || age < 0 || age >= 5 || (g.xid != "" && g.xid != xid) {
		return metadata.ErrFailedPrecondition
	}
	g.xid = xid
	id, err := metadata.VerifyPostgresDatabase(g.work, g.tx)
	if err != nil {
		return err
	}
	b := g.owner.binding
	if id.Database != b.Database || id.OID != b.DatabaseOID || id.MetadataFingerprint != b.MetadataFingerprint {
		return metadata.ErrFailedPrecondition
	}
	if err = verifyPolicyCatalog(g.work, g.tx, b, g.owner.roles, g.owner.role); err != nil {
		return err
	}
	return durableSettings(g.work, g.tx)
}

func (g *CurrentGuard) enrolled() error {
	c := g.actor.session.Claims()
	var issuer, subject, class []byte
	var start, end int64
	var revoked bool
	err := g.tx.QueryRow(g.work, `SELECT * FROM scion_policy.lock_credential_shared($1,$2,$3)`, []byte(c.Tenant), c.Repository[:], c.CredentialHash[:]).Scan(&issuer, &subject, &class, &start, &end, &revoked)
	if err != nil || revoked || !bytes.Equal(issuer, []byte(c.Principal.Issuer)) || !bytes.Equal(subject, []byte(c.Principal.Subject)) || !bytes.Equal(class, []byte(c.Principal.Class)) || start != g.actor.credential.NotBeforeUnix || end != g.actor.credential.ExpiresAtUnix || g.actor.credential.Issuer != c.Principal.Issuer || g.actor.credential.Subject != c.Principal.Subject || g.actor.credential.Class != c.Principal.Class || start > c.NotBeforeUnix || end < c.ExpiresAtUnix {
		return metadata.ErrPermissionDenied
	}
	var credential, generation, proof []byte
	err = g.tx.QueryRow(g.work, `SELECT * FROM scion_policy.lock_session_shared($1,$2,$3)`, []byte(c.Tenant), c.Repository[:], c.Session[:]).Scan(&credential, &issuer, &subject, &class, &generation, &proof, &start, &end, &revoked)
	hash := g.actor.session.ProofHash()
	if err != nil || revoked || !bytes.Equal(credential, c.CredentialHash[:]) || !bytes.Equal(issuer, []byte(c.Principal.Issuer)) || !bytes.Equal(subject, []byte(c.Principal.Subject)) || !bytes.Equal(class, []byte(c.Principal.Class)) || len(generation) != 8 || binary.BigEndian.Uint64(generation) != c.Generation || !bytes.Equal(proof, hash[:]) || start != c.NotBeforeUnix || end != c.ExpiresAtUnix {
		return metadata.ErrPermissionDenied
	}
	return nil
}

func (g *CurrentGuard) valid(ctx context.Context, tx pgx.Tx, scope metadata.Scope, intent metadata.OperationIntent) error {
	if g.closed || g.failed != nil || ctx == nil || !reflect.ValueOf(ctx).Comparable() || ctx != g.ctx || !currentRealTx(tx) || tx != g.tx || scope != g.scope || intent != g.intent || g.work.Err() != nil {
		return metadata.ErrPermissionDenied
	}
	a, err := g.owner.guardAuthentication(ctx)
	if err != nil || a != g.actor {
		return metadata.ErrPermissionDenied
	}
	return nil
}

func (g *CurrentGuard) identity() authz.Identity {
	c := g.actor.session.Claims()
	return authz.Identity{Principal: c.Principal, Audience: c.Audience, ExpiresAt: time.Unix(c.ExpiresAtUnix, 0)}
}
func (g *CurrentGuard) requireRepository(capability authz.RepositoryCapability) error {
	_, err := g.repository.Evaluate(g.work, g.identity(), policyScope(g.actor.session.Claims()), g.scope.PolicyVersion, capability)
	if err != nil {
		return metadata.ErrPermissionDenied
	}
	return nil
}

// RequireRepository records a sticky denial. All methods require the original
// exact context, transaction, selectors and complete immutable operation intent.
func (g *CurrentGuard) RequireRepository(ctx context.Context, tx pgx.Tx, scope metadata.Scope, intent metadata.OperationIntent, capability authz.RepositoryCapability) error {
	if g == nil || g.self != g {
		return metadata.ErrPermissionDenied
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	err := g.valid(ctx, tx, scope, intent)
	if err == nil {
		err = g.requireRepository(capability)
	}
	if err != nil {
		g.failed = err
	}
	return err
}

// RequirePath admits at most 4096 actions and 1 MiB aggregate path bytes. It
// evaluates actual ROOT/ancestor/target rights, without any storage lookup.
func (g *CurrentGuard) RequirePath(ctx context.Context, tx pgx.Tx, scope metadata.Scope, intent metadata.OperationIntent, selection authz.PathSelector, action authz.PathAction) error {
	if g == nil || g.self != g {
		return metadata.ErrPermissionDenied
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	err := g.valid(ctx, tx, scope, intent)
	if err == nil && (g.pathCount >= 4096 || len(selection.Path) > (1<<20)-g.pathBytes) {
		err = metadata.ErrResourceExhausted
	}
	if err == nil {
		g.pathCount++
		g.pathBytes += len(selection.Path)
		_, err = g.paths.Evaluate(g.work, g.identity(), policyScope(g.actor.session.Claims()), scope.PolicyVersion, selection, action)
		if err != nil {
			err = metadata.ErrPermissionDenied
		}
	}
	if err != nil {
		g.failed = err
	}
	return err
}

// Finalize checks immediate commit admission; it cannot prove WAL expiry time.
// It does not release fences or admission. Close is still mandatory afterwards.
func (g *CurrentGuard) Finalize(ctx context.Context, tx pgx.Tx, scope metadata.Scope, intent metadata.OperationIntent) error {
	if g == nil || g.self != g {
		return metadata.ErrPermissionDenied
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	err := g.valid(ctx, tx, scope, intent)
	if err == nil {
		err = g.verifyTransaction()
	}
	if err == nil && !g.owner.safeTime(g.work, g.actor.session.Claims()) {
		err = metadata.ErrPermissionDenied
	}
	if err != nil {
		g.failed = err
	}
	return err
}

// Close invalidates the guard and releases its Store slot exactly once. SQL
// fences remain held by the caller's transaction until its commit/rollback.
func (g *CurrentGuard) Close() error {
	if g == nil || g.self != g {
		return metadata.ErrPermissionDenied
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.closed {
		g.closed = true
		g.cancel()
		<-g.owner.slots
	}
	return nil
}
