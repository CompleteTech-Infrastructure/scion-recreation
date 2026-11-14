package policy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/storage/metadata"
	"github.com/jackc/pgx/v5"
)

// HeadExpectation is an exact immutable head, including version zero. Its raw
// tenant and repository must equal the signed actor's scope; it grants no rights.
type HeadExpectation struct {
	Tenant     string
	Repository [16]byte
	Version    uint64
	Digest     [32]byte
}

// AdminResultQuery selects only this authenticated actor's retained result.
// Operation is the internal management namespace: bootstrap=1, enrollment=2,
// credential revocation=3, session revocation=4, policy CAS=5.
type AdminResultQuery struct {
	Operation uint16
	RequestID [32]byte
}

const operationPolicyCAS uint16 = 5

func adminStore(a *Admin) (*Store, error) {
	if a == nil || a.store == nil || a.store.role != a.store.roles.Admin {
		return nil, metadata.ErrFailedPrecondition
	}
	return a.store, nil
}

// lockPolicyActor is called only after the head lock. Credential and session
// locks are compatible across readers and are held through commit. Management
// callers never upgrade a shared head or take a credential after a session.
func lockPolicyActor(ctx context.Context, tx pgx.Tx, c authz.SessionClaims) error {
	if err := managementExec(ctx, tx, `SELECT 1 FROM scion_policy.lock_credential_shared($1,$2,$3)`, []byte(c.Tenant), c.Repository[:], c.CredentialHash[:]); err != nil {
		return err
	}
	return managementExec(ctx, tx, `SELECT 1 FROM scion_policy.lock_session_shared($1,$2,$3)`, []byte(c.Tenant), c.Repository[:], c.Session[:])
}

func loadExclusiveHead(ctx context.Context, tx pgx.Tx, c authz.SessionClaims) (authz.PolicySnapshot, [32]byte, error) {
	var zero [32]byte
	var version, digest, body []byte
	err := tx.QueryRow(ctx, `SELECT * FROM scion_policy.lock_head_exclusive($1,$2)`, []byte(c.Tenant), c.Repository[:]).Scan(&version, &digest, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.PolicySnapshot{}, zero, metadata.ErrPermissionDenied
	}
	if err != nil {
		return authz.PolicySnapshot{}, zero, managementError(ctx, err)
	}
	if len(version) != 8 || len(digest) != 32 || len(body) > authz.MaxPolicyEncoding {
		return authz.PolicySnapshot{}, zero, metadata.ErrCorruptData
	}
	hash := sha256.Sum256(body)
	p, err := authz.DecodePolicySnapshot(body)
	if err != nil || !bytes.Equal(hash[:], digest) || p.Repository.Scope != policyScope(c) || p.Repository.Version != binary.BigEndian.Uint64(version) {
		return authz.PolicySnapshot{}, zero, metadata.ErrCorruptData
	}
	return p, hash, nil
}

// policyUpdateIntent binds the complete immutable request, not the retry's
// session or current head. The latter are freshly authenticated on every call.
// The policy digest covers complete canonical repository AND path policies.
func policyUpdateIntent(request [32]byte, expected HeadExpectation, next [32]byte) [32]byte {
	b := []byte("CANOPY\x00POLICY-CAS-INTENT\x00V1\x00")
	b = binary.BigEndian.AppendUint16(b, operationPolicyCAS)
	b = append(b, request[:]...)
	b = frame(b, expected.Tenant)
	b = append(b, expected.Repository[:]...)
	b = binary.BigEndian.AppendUint64(b, expected.Version)
	b = append(b, expected.Digest[:]...)
	return sha256.Sum256(append(b, next[:]...))
}

func recordPolicyResult(ctx context.Context, tx pgx.Tx, actor authz.VerifiedSession, receipt Receipt, intent [32]byte, oldVersion uint64, oldHash [32]byte) error {
	var audit [32]byte
	if _, err := rand.Read(audit[:]); err != nil {
		return metadata.ErrUnavailable
	}
	c := actor.Claims()
	index, proof := principalIndex(c.Principal), actor.ProofHash()
	return managementExec(ctx, tx, `SELECT scion_policy.record_admin_result($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, []byte(c.Tenant), c.Repository[:], index[:], int16(operationPolicyCAS), receipt.RequestID[:], intent[:], encodeReceipt(receipt), audit[:], c.Session[:], proof[:], true, versionBytes(oldVersion), versionBytes(receipt.PolicyVersion), oldHash[:], receipt.PolicyDigest[:], []byte(c.Principal.Issuer), []byte(c.Principal.Subject), []byte(c.Principal.Class))
}

// CompareAndSwapPolicy authorizes against the locked OLD head and atomically
// retains the immutable successor, head, result and audit. The repository
// evaluator forbids increasing the acting administrator's effective approval or
// administration rights, including by removing denies. No path policy can be
// replaced at the same version. An unknown commit returns no successful receipt.
func (a *Admin) CompareAndSwapPolicy(ctx context.Context, actor ActorCredentials, expected HeadExpectation, next authz.PolicySnapshot, requestID [32]byte) (Receipt, error) {
	var zero Receipt
	s, err := adminStore(a)
	if err != nil {
		return zero, err
	}
	credential, proof, err := snapshot(actor.Identity, actor.Session)
	if err != nil {
		return zero, err
	}
	c := proof.Claims
	if requestID == ([32]byte{}) || expected.Tenant != c.Tenant || expected.Repository != c.Repository || next.Repository.Scope != policyScope(c) {
		return zero, metadata.ErrInvalidArgument
	}
	body, err := authz.EncodePolicySnapshot(next)
	if err != nil {
		return zero, metadata.ErrInvalidArgument
	}
	// Decode the owned bytes before entering the transaction: caller-owned maps
	// and slices cannot change which snapshot is authorized or stored.
	next, err = authz.DecodePolicySnapshot(body)
	if err != nil {
		return zero, metadata.ErrInvalidArgument
	}
	nextHash := sha256.Sum256(body)
	intent := policyUpdateIntent(requestID, expected, nextHash)
	result := Receipt{RequestID: requestID, TenantHash: sha256.Sum256([]byte(c.Tenant)), Repository: c.Repository, Operation: operationPolicyCAS, PolicyVersion: next.Repository.Version, PolicyDigest: nextHash}
	err = s.runTx(ctx, func(work context.Context, tx pgx.Tx) error {
		verified, err := s.verifyInTx(work, tx, credential, proof, true)
		if err != nil {
			return err
		}
		old, hash, err := loadExclusiveHead(work, tx, verified.Claims())
		if err != nil {
			return err
		}
		if err = lockPolicyActor(work, tx, verified.Claims()); err != nil {
			return err
		}
		verified, err = s.verifyInTx(work, tx, credential, proof, true)
		if err != nil {
			return err
		}
		if err = requireAdmin(work, s, verified, old); err != nil {
			return err
		}
		prior, ok, err := priorResult(work, tx, c.Tenant, c.Principal, result, intent)
		if err != nil {
			return err
		}
		if ok {
			if prior.PolicyVersion != result.PolicyVersion || prior.PolicyDigest != result.PolicyDigest {
				return metadata.ErrCorruptData
			}
			result = prior
			if !s.safeTime(work, verified.Claims()) {
				return authz.ErrUnauthenticated
			}
			return nil
		}
		if expected.Version != old.Repository.Version || expected.Digest != hash || expected.Version == ^uint64(0) || next.Repository.Version != expected.Version+1 {
			return metadata.ErrConflict
		}
		engine, err := authz.NewRepositoryPolicy(old.Repository, c.Audience, s.now)
		if err != nil {
			return metadata.ErrCorruptData
		}
		identity := authz.Identity{Principal: verified.Claims().Principal, Audience: c.Audience, ExpiresAt: time.Unix(c.ExpiresAtUnix, 0)}
		if err = engine.Update(work, identity, old.Repository.Scope, expected.Version, next.Repository); err != nil {
			return metadata.ErrPermissionDenied
		}
		if err = managementExec(work, tx, `SELECT scion_policy.cas_policy($1,$2,$3,$4,$5,$6)`, []byte(c.Tenant), c.Repository[:], versionBytes(expected.Version), hash[:], body, nextHash[:]); err != nil {
			return err
		}
		if err = recordPolicyResult(work, tx, verified, result, intent, old.Repository.Version, hash); err != nil {
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
	if !committedTime(ctx, s, c) {
		return zero, errors.Join(metadata.ErrOutcomeUnknown, authz.ErrUnauthenticated)
	}
	return result, nil
}

// readAsAdmin performs fresh signed authentication and old-policy administration
// checks under shared head/credential/session guards. Its callback is private
// fixed composition, never a serving caller's SQL or authorization callback.
func readAsAdmin(ctx context.Context, s *Store, credential authz.IdentityCredential, proof authz.SessionProof, fn func(context.Context, pgx.Tx, authz.PolicySnapshot, [32]byte) error) error {
	return s.runTx(ctx, func(work context.Context, tx pgx.Tx) error {
		verified, err := s.verifyInTx(work, tx, credential, proof, true)
		if err != nil {
			return err
		}
		p, hash, err := loadHead(work, tx, verified.Claims())
		if err != nil {
			return err
		}
		if err = lockPolicyActor(work, tx, verified.Claims()); err != nil {
			return err
		}
		verified, err = s.verifyInTx(work, tx, credential, proof, true)
		if err != nil {
			return err
		}
		if err = requireAdmin(work, s, verified, p); err != nil {
			return err
		}
		if err = fn(work, tx, p, hash); err != nil {
			return err
		}
		if !s.safeTime(work, verified.Claims()) {
			return authz.ErrUnauthenticated
		}
		return nil
	})
}

// GetPolicy returns an owned complete policy only to a current administrator
// naming the exact current head. It is not exposed by the serving Store.
func (a *Admin) GetPolicy(ctx context.Context, actor ActorCredentials, expected HeadExpectation) (authz.PolicySnapshot, error) {
	var zero authz.PolicySnapshot
	s, err := adminStore(a)
	if err != nil {
		return zero, err
	}
	credential, proof, err := snapshot(actor.Identity, actor.Session)
	if err != nil {
		return zero, err
	}
	if expected.Tenant != proof.Claims.Tenant || expected.Repository != proof.Claims.Repository {
		return zero, metadata.ErrPermissionDenied
	}
	var result authz.PolicySnapshot
	err = readAsAdmin(ctx, s, credential, proof, func(_ context.Context, _ pgx.Tx, p authz.PolicySnapshot, hash [32]byte) error {
		if expected.Version != p.Repository.Version || expected.Digest != hash {
			return metadata.ErrConflict
		}
		result = p
		return nil
	})
	if err != nil {
		return zero, err
	}
	if !committedTime(ctx, s, proof.Claims) {
		return zero, authz.ErrUnauthenticated
	}
	return result, nil
}

// GetAdminResult authenticates the actor again under CURRENT policy before
// reading its historical result. The receipt cannot revive old policy rights.
func (a *Admin) GetAdminResult(ctx context.Context, actor ActorCredentials, query AdminResultQuery) (Receipt, error) {
	var zero Receipt
	s, err := adminStore(a)
	if err != nil {
		return zero, err
	}
	if query.Operation < 1 || query.Operation > operationPolicyCAS || query.RequestID == ([32]byte{}) {
		return zero, metadata.ErrInvalidArgument
	}
	credential, proof, err := snapshot(actor.Identity, actor.Session)
	if err != nil {
		return zero, err
	}
	var result Receipt
	err = readAsAdmin(ctx, s, credential, proof, func(work context.Context, tx pgx.Tx, _ authz.PolicySnapshot, _ [32]byte) error {
		c := proof.Claims
		index := principalIndex(c.Principal)
		var intent, body []byte
		err := tx.QueryRow(work, `SELECT * FROM scion_policy.read_admin_result($1,$2,$3,$4,$5,$6,$7,$8)`, []byte(c.Tenant), c.Repository[:], index[:], int16(query.Operation), query.RequestID[:], []byte(c.Principal.Issuer), []byte(c.Principal.Subject), []byte(c.Principal.Class)).Scan(&intent, &body)
		if errors.Is(err, pgx.ErrNoRows) {
			return metadata.ErrPermissionDenied
		}
		if err != nil {
			return managementError(work, err)
		}
		r, err := decodeReceipt(body)
		if err != nil || len(intent) != 32 || r.RequestID != query.RequestID || r.Operation != query.Operation || r.TenantHash != sha256.Sum256([]byte(c.Tenant)) || r.Repository != c.Repository || (r.Operation == operationPolicyCAS && r.TargetSession != ([32]byte{})) {
			return metadata.ErrCorruptData
		}
		result = r
		return nil
	})
	if err != nil {
		return zero, err
	}
	if !committedTime(ctx, s, proof.Claims) {
		return zero, authz.ErrUnauthenticated
	}
	return result, nil
}
