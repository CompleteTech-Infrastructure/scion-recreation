// Package policy composes signed authentication with durable primary state.
package policy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"time"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/storage/metadata"
	"github.com/jackc/pgx/v5"
)

// TrustConfig is trusted deployment configuration, never request input. Now
// must be bounded and trustworthy. ClockErrorKnown explicitly distinguishes a
// configured error bound from an absent one; this does not measure that bound.
type TrustConfig struct {
	Audience                  string
	IdentityKeys, SessionKeys map[string]map[string]ed25519.PublicKey
	Now                       authz.IdentityClock
	ClockError                time.Duration
	ClockErrorKnown           bool
}

// DatabaseBinding pins one logical installation and catalog outside that DB.
// It does not attest physical hardware or WAL continuity across replacement.
type DatabaseBinding struct {
	Database                                              string
	DatabaseOID                                           uint32
	Installation, MetadataFingerprint, CatalogFingerprint [32]byte
}
type RoleNames struct{ Owner, FunctionOwner, Serving, Admin, Bootstrap string }

// Limits bounds admitted operations per handle. Zero selects sixteen; queues
// and idle connection caches are absent. Other serving/job budgets are separate.
type Limits struct{ MaxConcurrentOps int }
type OpenConfig struct {
	DSN     string
	Binding DatabaseBinding
	Roles   RoleNames
	Trust   TrustConfig
	Limits  Limits
}

// Store owns its private connection configuration and verification roots. It
// accepts no caller-selected authentication/revocation implementation.
type Store struct {
	config     *pgx.ConnConfig
	binding    DatabaseBinding
	roles      RoleNames
	role       string
	verifier   *authz.SessionVerifier
	now        authz.IdentityClock
	clockError time.Duration
	slots      chan struct{}
	closed     atomic.Bool
}

// Admin and Bootstrap require separate restricted database identities. Their
// management methods are implemented separately; no raw SQL callback is public.
type Admin struct{ store *Store }
type Bootstrap struct{ store *Store }

const transactionBudget = 5 * time.Second

// Open never creates schema, enrolls credentials or grants permissions.
func Open(ctx context.Context, c OpenConfig) (*Store, error) { return open(ctx, c, c.Roles.Serving) }
func OpenAdmin(ctx context.Context, c OpenConfig) (*Admin, error) {
	s, err := open(ctx, c, c.Roles.Admin)
	if err != nil {
		return nil, err
	}
	return &Admin{s}, nil
}
func OpenBootstrap(ctx context.Context, c OpenConfig) (*Bootstrap, error) {
	s, err := open(ctx, c, c.Roles.Bootstrap)
	if err != nil {
		return nil, err
	}
	return &Bootstrap{s}, nil
}
func open(ctx context.Context, c OpenConfig, role string) (*Store, error) {
	if ctx == nil || c.Trust.Now == nil || !c.Trust.ClockErrorKnown || c.Trust.ClockError < 0 || c.Trust.ClockError > time.Second || role == "" ||
		c.Binding.Database == "" || c.Binding.DatabaseOID == 0 || c.Binding.Installation == ([32]byte{}) || c.Binding.MetadataFingerprint == ([32]byte{}) || c.Binding.CatalogFingerprint == ([32]byte{}) {
		return nil, metadata.ErrFailedPrecondition
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n := c.Limits.MaxConcurrentOps
	if n == 0 {
		n = 16
	}
	if n < 1 || n > 16 {
		return nil, metadata.ErrFailedPrecondition
	}
	cfg, err := pgx.ParseConfig(c.DSN)
	if err != nil {
		return nil, metadata.ErrFailedPrecondition
	}
	cfg.Tracer = nil
	cfg.ConnectTimeout = time.Second
	for k, v := range map[string]string{"statement_timeout": "2000", "lock_timeout": "1000", "idle_in_transaction_session_timeout": "5000", "transaction_timeout": "5000", "search_path": "pg_catalog,pg_temp"} {
		cfg.RuntimeParams[k] = v
	}
	s := &Store{config: cfg, binding: c.Binding, roles: c.Roles, role: role, now: c.Trust.Now, clockError: c.Trust.ClockError, slots: make(chan struct{}, n)}
	resolver, err := authz.NewIdentityResolver(c.Trust.Audience, c.Trust.IdentityKeys, c.Trust.Now, s.credentialCheck)
	if err != nil {
		return nil, metadata.ErrFailedPrecondition
	}
	s.verifier, err = authz.NewSessionVerifier(resolver, c.Trust.Audience, c.Trust.SessionKeys, c.Trust.Now)
	if err != nil {
		return nil, metadata.ErrFailedPrecondition
	}
	if err = s.runTx(ctx, func(context.Context, pgx.Tx) error { return nil }); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	if s != nil {
		s.closed.Store(true)
	}
	return nil
}
func (a *Admin) Close() error {
	if a != nil {
		return a.store.Close()
	}
	return nil
}
func (b *Bootstrap) Close() error {
	if b != nil {
		return b.store.Close()
	}
	return nil
}

func failure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return metadata.ErrUnavailable
}
func closeConnection(c *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = c.Close(ctx)
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		closeConnection(tx.Conn())
	}
}

// runTx is package-private so request code cannot choose arbitrary SQL under a
// serving identity. Independent operations own independent connections. Close
// prevents admission; active operations finish within their existing deadline.
func (s *Store) runTx(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	if ctx == nil || s == nil || s.config == nil || fn == nil {
		return metadata.ErrFailedPrecondition
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed.Load() {
		return metadata.ErrUnavailable
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return metadata.ErrResourceExhausted
	}
	if s.closed.Load() {
		return metadata.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, transactionBudget)
	defer cancel()
	connectCtx, stop := context.WithTimeout(ctx, time.Second)
	conn, err := pgx.ConnectConfig(connectCtx, s.config)
	stop()
	if err != nil {
		return failure(ctx)
	}
	defer closeConnection(conn)
	var sessionUser, currentUser, statement, lock, idle, total string
	err = conn.QueryRow(ctx, `SELECT session_user,current_user,current_setting('statement_timeout'),current_setting('lock_timeout'),current_setting('idle_in_transaction_session_timeout'),current_setting('transaction_timeout')`).Scan(&sessionUser, &currentUser, &statement, &lock, &idle, &total)
	if err != nil {
		return failure(ctx)
	}
	if sessionUser != s.role || currentUser != s.role || statement != "2s" || lock != "1s" || idle != "5s" || total != "5s" {
		return metadata.ErrFailedPrecondition
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return failure(ctx)
	}
	defer rollback(tx)
	actual, err := metadata.VerifyPostgresDatabase(ctx, tx)
	if err != nil {
		return err
	}
	if actual.Database != s.binding.Database || actual.OID != s.binding.DatabaseOID || actual.MetadataFingerprint != s.binding.MetadataFingerprint {
		return metadata.ErrFailedPrecondition
	}
	if err = verifyPolicyCatalog(ctx, tx, s.binding, s.roles, s.role); err != nil {
		return err
	}
	if err = fn(ctx, tx); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return errors.Join(metadata.ErrOutcomeUnknown, failure(ctx))
	}
	return nil
}

type lookupKey struct{}
type credentialLookup struct {
	owner      *Store
	tx         pgx.Tx
	credential authz.IdentityClaims
	claims     authz.SessionClaims
	shared     bool
}
type authenticatedKey struct{}
type authenticated struct {
	owner   *Store
	session authz.VerifiedSession
	binding DatabaseBinding
}

// snapshot performs bounded structural validation before copying signatures.
// It is not authentication. The transport owner must not concurrently mutate
// its inputs while this function snapshots them.
func snapshot(c *authz.IdentityCredential, p *authz.SessionProof) (authz.IdentityCredential, authz.SessionProof, error) {
	if c == nil || p == nil || len(c.Signature) != ed25519.SignatureSize || len(p.Signature) != ed25519.SignatureSize || p.Version != 1 {
		return authz.IdentityCredential{}, authz.SessionProof{}, authz.ErrUnauthenticated
	}
	digest, err := authz.IdentityCredentialHash(c)
	if err != nil || digest != p.Claims.CredentialHash {
		return authz.IdentityCredential{}, authz.SessionProof{}, authz.ErrUnauthenticated
	}
	if _, err := authz.SessionTranscript(p.Claims); err != nil {
		return authz.IdentityCredential{}, authz.SessionProof{}, authz.ErrUnauthenticated
	}
	a, b := *c, *p
	a.Signature = append([]byte(nil), c.Signature...)
	b.Signature = append([]byte(nil), p.Signature...)
	return a, b, nil
}

// credentialCheck runs only through this Store's fixed verifier. The private
// descriptor is installed by the package after snapshotting actual proofs.
// Signature verification precedes all credential-state lookup. A missing row
// never enrolls itself, and no caller-supplied boolean becomes authority.
func (s *Store) credentialCheck(ctx context.Context, c authz.IdentityClaims) (authz.RevocationState, error) {
	d, ok := ctx.Value(lookupKey{}).(credentialLookup)
	if !ok || d.owner != s || d.tx == nil || c != d.credential {
		return authz.RevocationUnknown, authz.ErrUnauthenticated
	}
	var issuer, subject, class []byte
	var start, end int64
	var revoked bool
	query := `SELECT * FROM scion_policy.read_credential($1,$2,$3)`
	if d.shared {
		query = `SELECT * FROM scion_policy.lock_credential_shared($1,$2,$3)`
	}
	err := d.tx.QueryRow(ctx, query, []byte(d.claims.Tenant), d.claims.Repository[:], d.claims.CredentialHash[:]).Scan(&issuer, &subject, &class, &start, &end, &revoked)
	if err != nil || revoked || !bytes.Equal(issuer, []byte(c.Issuer)) || !bytes.Equal(subject, []byte(c.Subject)) || !bytes.Equal(class, []byte(c.Class)) || start != c.NotBeforeUnix || end != c.ExpiresAtUnix {
		return authz.RevocationUnknown, authz.ErrUnauthenticated
	}
	return authz.RevocationActive, nil
}

// safeTime is a conservative final-admission check. It does not prove the
// physical WAL commit instant precedes expiry or establish a freshness lease.
func (s *Store) safeTime(ctx context.Context, c authz.SessionClaims) bool {
	now, err := s.now()
	if err != nil || now.IsZero() || now.Unix() <= 0 || now.Unix() > 253402300799 || ctx.Err() != nil {
		return false
	}
	return !now.Before(time.Unix(c.NotBeforeUnix, 0)) && now.Before(time.Unix(c.ExpiresAtUnix, 0).Add(-s.clockError-transactionBudget))
}

// verifyInTx is private composition for authenticated reads and the separately
// implemented trusted enrollment flow. Existing=false never returns a public
// authenticated context; it permits checking a newly staged target credential
// before its session row has been inserted, within the SAME owned transaction.
func (s *Store) verifyInTx(ctx context.Context, tx pgx.Tx, c authz.IdentityCredential, p authz.SessionProof, existing bool) (authz.VerifiedSession, error) {
	return s.verifySessionInTx(ctx, tx, c, p, existing, false)
}

// Only Authenticate selects shared=true, locking one credential before its one
// session. Management callers collect and lock ALL actor/target credentials
// before ALL sessions, then use verifyInTx for reads under those held locks.
func (s *Store) verifySessionInTx(ctx context.Context, tx pgx.Tx, c authz.IdentityCredential, p authz.SessionProof, existing, shared bool) (authz.VerifiedSession, error) {
	zero := authz.VerifiedSession{}
	ctx = context.WithValue(ctx, lookupKey{}, credentialLookup{s, tx, c.Claims, p.Claims, shared})
	verified, err := s.verifier.VerifySession(ctx, &c, &p)
	if err != nil || !s.verifier.Owns(verified) || !s.safeTime(ctx, verified.Claims()) {
		return zero, authz.ErrUnauthenticated
	}
	if existing {
		var credential, issuer, subject, class, generation, proof []byte
		var start, end int64
		var revoked bool
		claims := verified.Claims()
		hash := verified.ProofHash()
		query := `SELECT * FROM scion_policy.read_session($1,$2,$3)`
		if shared {
			query = `SELECT * FROM scion_policy.lock_session_shared($1,$2,$3)`
		}
		err = tx.QueryRow(ctx, query, []byte(claims.Tenant), claims.Repository[:], claims.Session[:]).Scan(&credential, &issuer, &subject, &class, &generation, &proof, &start, &end, &revoked)
		if err != nil || revoked || !bytes.Equal(credential, claims.CredentialHash[:]) || !bytes.Equal(issuer, []byte(claims.Principal.Issuer)) || !bytes.Equal(subject, []byte(claims.Principal.Subject)) || !bytes.Equal(class, []byte(claims.Principal.Class)) || len(generation) != 8 || binary.BigEndian.Uint64(generation) != claims.Generation || !bytes.Equal(proof, hash[:]) || start != claims.NotBeforeUnix || end != claims.ExpiresAtUnix {
			return zero, authz.ErrUnauthenticated
		}
	}
	if !s.safeTime(ctx, verified.Claims()) {
		return zero, authz.ErrUnauthenticated
	}
	return verified, nil
}

// Authenticate verifies both actual signatures and the exact enrolled current
// credential/session state. The opaque context grants no object, path or policy
// right. Consumers must reauthenticate/recheck current policy in their own
// transaction and before delivery; this context is not a reusable allow lease.
// Authentication failures return one redacted class and no context.
func (s *Store) Authenticate(ctx context.Context, c *authz.IdentityCredential, p *authz.SessionProof) (context.Context, error) {
	if s == nil || ctx == nil {
		return nil, authz.ErrUnauthenticated
	}
	credential, proof, err := snapshot(c, p)
	if err != nil {
		return nil, authz.ErrUnauthenticated
	}
	var verified authz.VerifiedSession
	err = s.runTx(ctx, func(work context.Context, tx pgx.Tx) error {
		var e error
		verified, e = s.verifySessionInTx(work, tx, credential, proof, true, true)
		return e
	})
	if err != nil || !s.verifier.Owns(verified) || !s.safeTime(ctx, verified.Claims()) {
		return nil, authz.ErrUnauthenticated
	}
	return context.WithValue(ctx, authenticatedKey{}, authenticated{s, verified, s.binding}), nil
}
