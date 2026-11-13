package policy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/storage/metadata"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ActorCredentials carries actual signed proofs, never a caller's Identity or
// rights. Inputs and policy slices must not be concurrently mutated while a
// management method snapshots them. No successful method extends validity.
type ActorCredentials struct {
	Identity *authz.IdentityCredential
	Session  *authz.SessionProof
}
type Enrollment struct {
	Target    ActorCredentials
	RequestID [32]byte
}
type BootstrapRequest struct {
	Target    ActorCredentials
	Policy    authz.PolicySnapshot
	RequestID [32]byte
}

// Receipt describes one historical committed management result. It is neither
// authentication, membership, a current-policy decision nor an object grant.
type Receipt struct {
	RequestID, TenantHash [32]byte
	Repository            [16]byte
	Operation             uint16
	PolicyVersion         uint64
	PolicyDigest          [32]byte
	TargetSession         [32]byte
	TargetCredentialHash  [32]byte
}

const (
	operationBootstrap uint16 = 1
	operationEnroll    uint16 = 2
	receiptDomain             = "CANOPY\x00POLICY-RECEIPT\x00V1\x00"
)

func versionBytes(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }
func frame(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}
func principalIndex(p authz.PrincipalID) [32]byte {
	b := []byte("CANOPY\x00POLICY-ACTOR\x00V1\x00")
	for _, s := range []string{p.Issuer, p.Subject, string(p.Class)} {
		b = frame(b, s)
	}
	return sha256.Sum256(b)
}
func encodeReceipt(r Receipt) []byte {
	b := append([]byte(receiptDomain), r.RequestID[:]...)
	b = append(b, r.TenantHash[:]...)
	b = append(b, r.Repository[:]...)
	b = binary.BigEndian.AppendUint16(b, r.Operation)
	b = binary.BigEndian.AppendUint64(b, r.PolicyVersion)
	b = append(b, r.PolicyDigest[:]...)
	b = append(b, r.TargetSession[:]...)
	return append(b, r.TargetCredentialHash[:]...)
}
func decodeReceipt(b []byte) (Receipt, error) {
	var r Receipt
	if len(b) != len(receiptDomain)+186 || !bytes.HasPrefix(b, []byte(receiptDomain)) {
		return r, metadata.ErrCorruptData
	}
	b = b[len(receiptDomain):]
	copy(r.RequestID[:], b[:32])
	copy(r.TenantHash[:], b[32:64])
	copy(r.Repository[:], b[64:80])
	r.Operation = binary.BigEndian.Uint16(b[80:82])
	r.PolicyVersion = binary.BigEndian.Uint64(b[82:90])
	copy(r.PolicyDigest[:], b[90:122])
	copy(r.TargetSession[:], b[122:154])
	copy(r.TargetCredentialHash[:], b[154:186])
	return r, nil
}

func managementError(ctx context.Context, err error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	var p *pgconn.PgError
	if errors.As(err, &p) {
		switch p.Code {
		case "23505", "23514", "40001":
			return metadata.ErrConflict
		case "54000":
			return metadata.ErrResourceExhausted
		}
	}
	return metadata.ErrUnavailable
}
func managementExec(ctx context.Context, tx pgx.Tx, sql string, args ...any) error {
	_, err := tx.Exec(ctx, sql, args...)
	if err != nil {
		return managementError(ctx, err)
	}
	return nil
}
func policyScope(c authz.SessionClaims) authz.RepositoryScope {
	return authz.RepositoryScope{TenantID: c.Tenant, RepositoryID: hex.EncodeToString(c.Repository[:])}
}
func requireAdmin(ctx context.Context, s *Store, v authz.VerifiedSession, p authz.PolicySnapshot) error {
	c := v.Claims()
	if !s.verifier.Owns(v) || !s.safeTime(ctx, c) || p.Repository.Scope != policyScope(c) {
		return metadata.ErrPermissionDenied
	}
	e, err := authz.NewRepositoryPolicy(p.Repository, c.Audience, s.now)
	if err != nil {
		return metadata.ErrCorruptData
	}
	_, err = e.Evaluate(ctx, authz.Identity{Principal: c.Principal, Audience: c.Audience, ExpiresAt: time.Unix(c.ExpiresAtUnix, 0)}, p.Repository.Scope, p.Repository.Version, authz.RepositoryAdmin)
	if err != nil {
		return metadata.ErrPermissionDenied
	}
	return nil
}

func loadHead(ctx context.Context, tx pgx.Tx, c authz.SessionClaims) (authz.PolicySnapshot, [32]byte, error) {
	var p authz.PolicySnapshot
	var zero [32]byte
	var version, digest, body []byte
	err := tx.QueryRow(ctx, `SELECT * FROM scion_policy.lock_head_shared($1,$2)`, []byte(c.Tenant), c.Repository[:]).Scan(&version, &digest, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, zero, metadata.ErrPermissionDenied
	}
	if err != nil {
		return p, zero, managementError(ctx, err)
	}
	if len(version) != 8 || len(digest) != 32 || len(body) > authz.MaxPolicyEncoding {
		return p, zero, metadata.ErrCorruptData
	}
	h := sha256.Sum256(body)
	if !bytes.Equal(h[:], digest) {
		return p, zero, metadata.ErrCorruptData
	}
	p, err = authz.DecodePolicySnapshot(body)
	if err != nil || p.Repository.Scope != policyScope(c) || p.Repository.Version != binary.BigEndian.Uint64(version) {
		return authz.PolicySnapshot{}, zero, metadata.ErrCorruptData
	}
	return p, h, nil
}

// Lock only this fixed pair, coalescing actor/target identities and acquiring
// heads, sorted credentials, then sorted sessions. A target that is also the
// actor is exclusive immediately; there are no shared-to-exclusive upgrades.
func lockEnrollment(ctx context.Context, tx pgx.Tx, a, b authz.SessionClaims) error {
	for _, entry := range []struct {
		values            [2][32]byte
		target            [32]byte
		shared, exclusive string
	}{
		{[2][32]byte{a.CredentialHash, b.CredentialHash}, b.CredentialHash, "lock_credential_shared", "lock_credential_exclusive"},
		{[2][32]byte{a.Session, b.Session}, b.Session, "lock_session_shared", "lock_session_exclusive"},
	} {
		ids := entry.values
		if bytes.Compare(ids[0][:], ids[1][:]) > 0 {
			ids[0], ids[1] = ids[1], ids[0]
		}
		for i, id := range ids {
			if i > 0 && id == ids[i-1] {
				continue
			}
			name := entry.shared
			if id == entry.target {
				name = entry.exclusive
			}
			if err := managementExec(ctx, tx, "SELECT 1 FROM scion_policy."+name+"($1,$2,$3)", []byte(a.Tenant), a.Repository[:], id[:]); err != nil {
				return err
			}
		}
	}
	return nil
}

func insertCredential(ctx context.Context, tx pgx.Tx, c authz.IdentityCredential, p authz.SessionProof) error {
	a := p.Claims
	return managementExec(ctx, tx, `SELECT scion_policy.insert_credential_if_absent($1,$2,$3,$4,$5,$6,$7,$8)`, []byte(a.Tenant), a.Repository[:], a.CredentialHash[:], []byte(c.Claims.Issuer), []byte(c.Claims.Subject), []byte(c.Claims.Class), c.Claims.NotBeforeUnix, c.Claims.ExpiresAtUnix)
}
func insertSession(ctx context.Context, tx pgx.Tx, v authz.VerifiedSession) error {
	c := v.Claims()
	h := v.ProofHash()
	return managementExec(ctx, tx, `SELECT scion_policy.insert_session_if_absent($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, []byte(c.Tenant), c.Repository[:], c.Session[:], c.CredentialHash[:], []byte(c.Principal.Issuer), []byte(c.Principal.Subject), []byte(c.Principal.Class), versionBytes(c.Generation), h[:], c.NotBeforeUnix, c.ExpiresAtUnix)
}

// Intent v1 binds the exact signed target and optional canonical bootstrap
// policy. Actor index is the separate stable result namespace; actor session
// and current policy head are deliberately reauthenticated rather than hashed
// into a retry's immutable intent. SessionTranscript already carries V1 domain.
func enrollmentIntent(op uint16, request [32]byte, p authz.SessionProof, policy *[32]byte) [32]byte {
	b := []byte("CANOPY\x00POLICY-MANAGEMENT-INTENT\x00V1\x00")
	b = binary.BigEndian.AppendUint16(b, op)
	b = append(b, request[:]...)
	b = frame(b, p.Claims.Tenant)
	b = append(b, p.Claims.Repository[:]...)
	b = append(b, p.Claims.CredentialHash[:]...)
	t, _ := authz.SessionTranscript(p.Claims)
	h := sha256.New()
	h.Write(t)
	h.Write(p.Signature)
	b = append(b, h.Sum(nil)...)
	if policy == nil {
		b = append(b, 0)
	} else {
		b = append(b, 1)
		b = append(b, policy[:]...)
	}
	return sha256.Sum256(b)
}
func priorResult(ctx context.Context, tx pgx.Tx, tenant string, actor authz.PrincipalID, expected Receipt, intent [32]byte) (Receipt, bool, error) {
	var stored, body []byte
	index := principalIndex(actor)
	err := tx.QueryRow(ctx, `SELECT * FROM scion_policy.read_admin_result($1,$2,$3,$4,$5,$6,$7,$8)`, []byte(tenant), expected.Repository[:], index[:], int16(expected.Operation), expected.RequestID[:], []byte(actor.Issuer), []byte(actor.Subject), []byte(actor.Class)).Scan(&stored, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, managementError(ctx, err)
	}
	if !bytes.Equal(stored, intent[:]) {
		return Receipt{}, false, metadata.ErrConflict
	}
	r, err := decodeReceipt(body)
	if err != nil || r.RequestID != expected.RequestID || r.TenantHash != expected.TenantHash || r.Repository != expected.Repository || r.Operation != expected.Operation || r.TargetSession != expected.TargetSession || r.TargetCredentialHash != expected.TargetCredentialHash {
		return Receipt{}, false, metadata.ErrCorruptData
	}
	return r, true, nil
}

func recordResult(ctx context.Context, tx pgx.Tx, actor authz.VerifiedSession, tenant string, r Receipt, intent [32]byte, bootstrap bool) error {
	var audit [32]byte
	if _, err := rand.Read(audit[:]); err != nil {
		return metadata.ErrUnavailable
	}
	c := actor.Claims()
	index := principalIndex(c.Principal)
	proof := actor.ProofHash()
	var oldVersion, oldHash []byte
	if !bootstrap {
		oldVersion = versionBytes(r.PolicyVersion)
		oldHash = r.PolicyDigest[:]
	}
	return managementExec(ctx, tx, `SELECT scion_policy.record_admin_result($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, []byte(tenant), r.Repository[:], index[:], int16(r.Operation), r.RequestID[:], intent[:], encodeReceipt(r), audit[:], c.Session[:], proof[:], true, oldVersion, versionBytes(r.PolicyVersion), oldHash, r.PolicyDigest[:], []byte(c.Principal.Issuer), []byte(c.Principal.Subject), []byte(c.Principal.Class))
}

// After commit, test actual validity with clock uncertainty, not another whole
// transaction's remaining budget. Failure cannot undo a sent commit: callers
// receive an unknown outcome and zero receipt, never an assertion of rollback.
func committedTime(ctx context.Context, s *Store, c authz.SessionClaims) bool {
	now, err := s.now()
	return err == nil && !now.IsZero() && now.Unix() > 0 && now.Unix() <= 253402300799 && ctx.Err() == nil &&
		!now.Before(time.Unix(c.NotBeforeUnix, 0)) && now.Before(time.Unix(c.ExpiresAtUnix, 0).Add(-s.clockError))
}

// Bootstrap is a trusted offline action under the separately provisioned DB
// role. It can initialize only an absent repository at version zero; possession
// of that handle is not available to a serving request. Actual signed initial
// administrator verification, state, policy, result and audit share one tx.
func (b *Bootstrap) Bootstrap(ctx context.Context, r BootstrapRequest) (Receipt, error) {
	var zero Receipt
	if b == nil || b.store == nil || b.store.role != b.store.roles.Bootstrap || r.RequestID == ([32]byte{}) {
		return zero, metadata.ErrFailedPrecondition
	}
	s := b.store
	c, p, err := snapshot(r.Target.Identity, r.Target.Session)
	if err != nil {
		return zero, err
	}
	body, err := authz.EncodePolicySnapshot(r.Policy)
	if err != nil {
		return zero, metadata.ErrInvalidArgument
	}
	policy, err := authz.DecodePolicySnapshot(body)
	if err != nil || policy.Repository.Scope != policyScope(p.Claims) || policy.Repository.Version != 0 {
		return zero, metadata.ErrInvalidArgument
	}
	h := sha256.Sum256(body)
	intent := enrollmentIntent(operationBootstrap, r.RequestID, p, &h)
	result := Receipt{RequestID: r.RequestID, TenantHash: sha256.Sum256([]byte(p.Claims.Tenant)), Repository: p.Claims.Repository, Operation: operationBootstrap, PolicyDigest: h, TargetSession: p.Claims.Session}
	err = s.runTx(ctx, func(work context.Context, tx pgx.Tx) error {
		if err := managementExec(work, tx, `SELECT scion_policy.begin_bootstrap($1,$2)`, []byte(p.Claims.Tenant), p.Claims.Repository[:]); err != nil {
			return err
		}
		if err := insertCredential(work, tx, c, p); err != nil {
			return err
		}
		verified, err := s.verifyInTx(work, tx, c, p, false)
		if err != nil {
			return err
		}
		result.TargetCredentialHash = verified.Claims().CredentialHash
		if err = requireAdmin(work, s, verified, policy); err != nil {
			return err
		}
		prior, ok, err := priorResult(work, tx, verified.Claims().Tenant, verified.Claims().Principal, result, intent)
		if err != nil {
			return err
		}
		if ok {
			if _, err = s.verifyInTx(work, tx, c, p, true); err != nil {
				return err
			}
			if prior.PolicyVersion != 0 || prior.PolicyDigest != h {
				return metadata.ErrCorruptData
			}
			if !s.safeTime(work, verified.Claims()) || !s.safeTime(work, p.Claims) {
				return authz.ErrUnauthenticated
			}
			result = prior
			return nil
		}
		if err = insertSession(work, tx, verified); err != nil {
			return err
		}
		if err = managementExec(work, tx, `SELECT scion_policy.bootstrap_head($1,$2,$3,$4)`, []byte(p.Claims.Tenant), p.Claims.Repository[:], body, h[:]); err != nil {
			return err
		}
		if err = recordResult(work, tx, verified, p.Claims.Tenant, result, intent, true); err != nil {
			return err
		}
		if !s.safeTime(work, verified.Claims()) {
			return authz.ErrUnauthenticated
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	if !committedTime(ctx, s, p.Claims) {
		return zero, errors.Join(metadata.ErrOutcomeUnknown, authz.ErrUnauthenticated)
	}
	return result, nil
}

// Enroll requires a fresh signed, enrolled old-policy administrator and a real
// signed target. It creates no membership or path right. The ordered shared
// policy and state locks fence concurrent policy/revocation changes through
// commit. An uncertain commit returns a zero receipt and may be retried exactly.
func (a *Admin) Enroll(ctx context.Context, actor ActorCredentials, r Enrollment) (Receipt, error) {
	var zero Receipt
	if a == nil || a.store == nil || a.store.role != a.store.roles.Admin || r.RequestID == ([32]byte{}) {
		return zero, metadata.ErrFailedPrecondition
	}
	s := a.store
	ac, ap, err := snapshot(actor.Identity, actor.Session)
	if err != nil {
		return zero, err
	}
	tc, tp, err := snapshot(r.Target.Identity, r.Target.Session)
	if err != nil {
		return zero, err
	}
	if ap.Claims.Tenant != tp.Claims.Tenant || ap.Claims.Repository != tp.Claims.Repository {
		return zero, metadata.ErrPermissionDenied
	}
	intent := enrollmentIntent(operationEnroll, r.RequestID, tp, nil)
	// Target fields here are replay expectations only. Actual dual verification
	// below is required before returning any receipt or recording a new result.
	result := Receipt{RequestID: r.RequestID, TenantHash: sha256.Sum256([]byte(ap.Claims.Tenant)), Repository: ap.Claims.Repository, Operation: operationEnroll, TargetSession: tp.Claims.Session, TargetCredentialHash: tp.Claims.CredentialHash}
	err = s.runTx(ctx, func(work context.Context, tx pgx.Tx) error {
		verified, err := s.verifyInTx(work, tx, ac, ap, true)
		if err != nil {
			return err
		}
		policy, hash, err := loadHead(work, tx, verified.Claims())
		if err != nil {
			return err
		}
		if err = requireAdmin(work, s, verified, policy); err != nil {
			return err
		}
		if err = lockEnrollment(work, tx, ap.Claims, tp.Claims); err != nil {
			return err
		}
		verified, err = s.verifyInTx(work, tx, ac, ap, true)
		if err != nil {
			return err
		}
		if err = requireAdmin(work, s, verified, policy); err != nil {
			return err
		}
		prior, ok, err := priorResult(work, tx, verified.Claims().Tenant, verified.Claims().Principal, result, intent)
		if err != nil {
			return err
		}
		if ok {
			if _, err = s.verifyInTx(work, tx, tc, tp, true); err != nil {
				return err
			}
			if !s.safeTime(work, verified.Claims()) || !s.safeTime(work, tp.Claims) {
				return authz.ErrUnauthenticated
			}
			result = prior
			return nil
		}
		if err = insertCredential(work, tx, tc, tp); err != nil {
			return err
		}
		target, err := s.verifyInTx(work, tx, tc, tp, false)
		if err != nil {
			return err
		}
		result.TargetCredentialHash = target.Claims().CredentialHash
		if err = insertSession(work, tx, target); err != nil {
			return err
		}
		// An absent target cannot be row-locked. An identical concurrent request
		// may commit while insert-if-absent waits; recheck its exact result now.
		prior, ok, err = priorResult(work, tx, verified.Claims().Tenant, verified.Claims().Principal, result, intent)
		if err != nil {
			return err
		}
		if ok {
			if _, err = s.verifyInTx(work, tx, tc, tp, true); err != nil {
				return err
			}
			if !s.safeTime(work, verified.Claims()) || !s.safeTime(work, tp.Claims) {
				return authz.ErrUnauthenticated
			}
			result = prior
			return nil
		}
		result.PolicyVersion = policy.Repository.Version
		result.PolicyDigest = hash
		if err = recordResult(work, tx, verified, ap.Claims.Tenant, result, intent, false); err != nil {
			return err
		}
		if !s.safeTime(work, verified.Claims()) || !s.safeTime(work, target.Claims()) {
			return authz.ErrUnauthenticated
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	if !committedTime(ctx, s, ap.Claims) || !committedTime(ctx, s, tp.Claims) {
		return zero, errors.Join(metadata.ErrOutcomeUnknown, authz.ErrUnauthenticated)
	}
	return result, nil
}
