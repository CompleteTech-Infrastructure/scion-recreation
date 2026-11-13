package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/storage/metadata"
	"github.com/jackc/pgx/v5"
)

// CredentialRevocation and SessionRevocation identify a target only within the
// authenticated actor's signed tenant/repository. Digests and session IDs are
// identifiers, never authorization. Revocation is terminal; replacement requires
// a new signed credential or session, not an update of the revoked identity.
type CredentialRevocation struct{ CredentialHash, RequestID [32]byte }
type SessionRevocation struct{ SessionID, RequestID [32]byte }

const (
	operationRevokeCredential uint16 = 3
	operationRevokeSession    uint16 = 4
)

// RevokeCredential fences every enrolled session using this credential in this
// repository by changing their shared credential state. It never enumerates or
// updates an unbounded set of sessions. Unrelated repositories are unaffected.
func (a *Admin) RevokeCredential(ctx context.Context, actor ActorCredentials, r CredentialRevocation) (Receipt, error) {
	return a.revoke(ctx, actor, r.RequestID, r.CredentialHash, operationRevokeCredential)
}

// RevokeSession changes only the exact session's terminal state. A publication
// holding its shared guard must finish before revocation can commit; subsequent
// guarded authorization observes the revoked state. This method does not itself
// implement publication guards or grant freshness at any serving tier.
func (a *Admin) RevokeSession(ctx context.Context, actor ActorCredentials, r SessionRevocation) (Receipt, error) {
	return a.revoke(ctx, actor, r.RequestID, r.SessionID, operationRevokeSession)
}

// The immutable intent binds the exact target, namespace, operation and request
// ID. The actor's principal is a separate result namespace. A replacement actor
// session can recover an identical result only after fresh current-admin checks;
// its session and the mutable policy head do not change a retry's intent.
func revocationIntent(c authz.SessionClaims, request, target [32]byte, operation uint16) [32]byte {
	b := []byte("CANOPY\x00POLICY-REVOCATION-INTENT\x00V1\x00")
	b = binary.BigEndian.AppendUint16(b, operation)
	b = append(b, request[:]...)
	b = frame(b, c.Tenant)
	b = append(b, c.Repository[:]...)
	b = append(b, target[:]...)
	return sha256.Sum256(b)
}

func sessionCredential(ctx context.Context, tx pgx.Tx, c authz.SessionClaims, session [32]byte) ([32]byte, error) {
	var zero [32]byte
	var stored []byte
	err := tx.QueryRow(ctx, "SELECT credential_hash FROM scion_policy.read_session($1,$2,$3)", []byte(c.Tenant), c.Repository[:], session[:]).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, metadata.ErrPermissionDenied
	}
	if err != nil {
		return zero, managementError(ctx, err)
	}
	if len(stored) != len(zero) {
		return zero, metadata.ErrCorruptData
	}
	copy(zero[:], stored)
	if zero == ([32]byte{}) {
		return zero, metadata.ErrCorruptData
	}
	return zero, nil
}

// All credentials precede all sessions; within each group, sort and coalesce
// actor/target IDs. An actor that is the target is exclusive immediately, never
// upgraded from SHARE. The head was already locked by loadHead. For credential
// revocation the target's child sessions are intentionally not enumerated.
func lockRevocation(ctx context.Context, tx pgx.Tx, actor authz.SessionClaims, credential, session [32]byte, operation uint16) error {
	groups := []struct {
		ids       [2][32]byte
		count     int
		exclusive [32]byte
		sharedSQL string
		writeSQL  string
	}{
		{ids: [2][32]byte{actor.CredentialHash, credential}, count: 2,
			sharedSQL: "SELECT 1 FROM scion_policy.lock_credential_shared($1,$2,$3)",
			writeSQL:  "SELECT 1 FROM scion_policy.lock_credential_exclusive($1,$2,$3)"},
		{ids: [2][32]byte{actor.Session, session}, count: 1,
			sharedSQL: "SELECT 1 FROM scion_policy.lock_session_shared($1,$2,$3)",
			writeSQL:  "SELECT 1 FROM scion_policy.lock_session_exclusive($1,$2,$3)"},
	}
	if operation == operationRevokeCredential {
		groups[0].exclusive = credential
	} else {
		groups[1].count = 2
		groups[1].exclusive = session
	}
	for _, group := range groups {
		if group.count == 2 && bytes.Compare(group.ids[0][:], group.ids[1][:]) > 0 {
			group.ids[0], group.ids[1] = group.ids[1], group.ids[0]
		}
		for i := 0; i < group.count; i++ {
			id := group.ids[i]
			if i > 0 && id == group.ids[i-1] {
				continue
			}
			sql := group.sharedSQL
			if id == group.exclusive {
				sql = group.writeSQL
			}
			var present int
			err := tx.QueryRow(ctx, sql, []byte(actor.Tenant), actor.Repository[:], id[:]).Scan(&present)
			if errors.Is(err, pgx.ErrNoRows) {
				return metadata.ErrPermissionDenied
			}
			if err != nil {
				return managementError(ctx, err)
			}
		}
	}
	return nil
}

func (a *Admin) revoke(ctx context.Context, actor ActorCredentials, request, target [32]byte, operation uint16) (Receipt, error) {
	var zero Receipt
	if a == nil || a.store == nil || a.store.role != a.store.roles.Admin {
		return zero, metadata.ErrFailedPrecondition
	}
	if request == ([32]byte{}) || target == ([32]byte{}) || (operation != operationRevokeCredential && operation != operationRevokeSession) {
		return zero, metadata.ErrInvalidArgument
	}
	s := a.store
	credential, proof, err := snapshot(actor.Identity, actor.Session)
	if err != nil {
		return zero, err
	}
	c := proof.Claims
	intent := revocationIntent(c, request, target, operation)
	result := Receipt{RequestID: request, TenantHash: sha256.Sum256([]byte(c.Tenant)), Repository: c.Repository, Operation: operation}
	if operation == operationRevokeSession {
		result.TargetSession = target
	}
	err = s.runTx(ctx, func(work context.Context, tx pgx.Tx) error {
		verified, err := s.verifyInTx(work, tx, credential, proof, true)
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
		targetCredential := target
		var targetSession [32]byte
		if operation == operationRevokeSession {
			targetSession = target
			// Protected target discovery follows actual actor/current-policy
			// authorization. It returns no target metadata to the requester.
			targetCredential, err = sessionCredential(work, tx, c, target)
			if err != nil {
				return err
			}
		}
		if err = lockRevocation(work, tx, c, targetCredential, targetSession, operation); err != nil {
			return err
		}
		verified, err = s.verifyInTx(work, tx, credential, proof, true)
		if err != nil {
			return err
		}
		if err = requireAdmin(work, s, verified, policy); err != nil {
			return err
		}
		if operation == operationRevokeSession {
			locked, err := sessionCredential(work, tx, c, target)
			if err != nil {
				return err
			}
			if locked != targetCredential {
				return metadata.ErrCorruptData
			}
			targetCredential = locked
		}
		// Persist the authorized credential target before replay validation.
		// For session revocation this is the binding re-read under its lock.
		result.TargetCredentialHash = targetCredential
		prior, found, err := priorResult(work, tx, c.Tenant, verified.Claims().Principal, result, intent)
		if err != nil {
			return err
		}
		if found {
			if !s.safeTime(work, verified.Claims()) {
				return authz.ErrUnauthenticated
			}
			result = prior
			return nil
		}
		sql := "SELECT scion_policy.revoke_credential($1,$2,$3)"
		if operation == operationRevokeSession {
			sql = "SELECT scion_policy.revoke_session($1,$2,$3)"
		}
		if err = managementExec(work, tx, sql, []byte(c.Tenant), c.Repository[:], target[:]); err != nil {
			return err
		}
		result.PolicyVersion, result.PolicyDigest = policy.Repository.Version, hash
		if err = recordResult(work, tx, verified, c.Tenant, result, intent, false); err != nil {
			return err
		}
		// Self-revocation was authorized under the locked old state. Rechecking
		// the revoked row here would reject that intended mutation; only the
		// signed proof's time/cancellation gate remains before commit.
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
