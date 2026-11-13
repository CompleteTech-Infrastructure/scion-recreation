package authz

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
)

// SessionClaims is an internal session-v1 statement, not an authorization grant.
// Issuers are trusted configuration; a request cannot install signing keys.
type SessionClaims struct {
	AuthorityIssuer, KeyID       string
	Principal                    PrincipalID
	CredentialHash               [32]byte
	Audience, Tenant             string
	Repository                   [16]byte
	Session                      [32]byte
	Generation                   uint64
	NotBeforeUnix, ExpiresAtUnix int64
}

type SessionProof struct {
	Version   uint8
	Claims    SessionClaims
	Signature []byte
}

// VerifiedSession cannot be constructed outside authz. It establishes signature
// authenticity only: durable credential/session enrollment, revocation and every
// operation's current policy must still be checked by the concrete authority.
type VerifiedSession struct {
	owner     *SessionVerifier
	claims    SessionClaims
	proofHash [32]byte
}

func (s VerifiedSession) Claims() SessionClaims { return s.claims }
func (s VerifiedSession) ProofHash() [32]byte   { return s.proofHash }

type SessionVerifier struct {
	identity *IdentityResolver
	audience string
	keys     map[string]map[string]ed25519.PublicKey
	now      IdentityClock
}

// Owns checks verifier provenance, not current validity or policy permission.
func (v *SessionVerifier) Owns(s VerifiedSession) bool { return v != nil && s.owner == v }

func NewSessionVerifier(identity *IdentityResolver, audience string, keys map[string]map[string]ed25519.PublicKey, now IdentityClock) (*SessionVerifier, error) {
	if identity == nil || identity.now == nil || identity.check == nil || !boundedIdentityClaim(audience) || now == nil || len(keys) == 0 {
		return nil, ErrUnauthenticated
	}
	v := &SessionVerifier{identity: identity, audience: audience, now: now, keys: make(map[string]map[string]ed25519.PublicKey)}
	for issuer, ids := range keys {
		if !boundedIdentityClaim(issuer) || len(ids) == 0 {
			return nil, ErrUnauthenticated
		}
		v.keys[issuer] = make(map[string]ed25519.PublicKey)
		for id, key := range ids {
			if !boundedIdentityClaim(id) || len(key) != ed25519.PublicKeySize {
				return nil, ErrUnauthenticated
			}
			v.keys[issuer][id] = append(ed25519.PublicKey(nil), key...)
		}
	}
	return v, nil
}

// SessionTranscript freezes the internal signing format. All seven strings are
// raw uint32-BE length-framed bytes, followed by credential hash, repository,
// session, uint64-BE generation, and int64-BE start/end seconds. No normalization
// or JSON is involved. Its returned bytes are owned by the caller.
func SessionTranscript(c SessionClaims) ([]byte, error) {
	fields := []string{c.AuthorityIssuer, c.KeyID, c.Principal.Issuer, c.Principal.Subject, string(c.Principal.Class), c.Audience, c.Tenant}
	for _, s := range fields {
		if !boundedIdentityClaim(s) {
			return nil, ErrUnauthenticated
		}
	}
	switch c.Principal.Class {
	case Human, BuildJob, ModelWorker, ServiceAccount:
	default:
		return nil, ErrUnauthenticated
	}
	if c.Repository == ([16]byte{}) || c.Session == ([32]byte{}) || c.CredentialHash == ([32]byte{}) || c.NotBeforeUnix <= 0 || c.ExpiresAtUnix <= c.NotBeforeUnix || c.ExpiresAtUnix > maxIdentityUnix || c.ExpiresAtUnix-c.NotBeforeUnix > 3600 {
		return nil, ErrUnauthenticated
	}
	b := []byte("CANOPY\x00INTERNAL-SESSION\x00V1\x00")
	for _, s := range fields {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
		b = append(b, s...)
	}
	b = append(b, c.CredentialHash[:]...)
	b = append(b, c.Repository[:]...)
	b = append(b, c.Session[:]...)
	b = binary.BigEndian.AppendUint64(b, c.Generation)
	b = binary.BigEndian.AppendUint64(b, uint64(c.NotBeforeUnix))
	b = binary.BigEndian.AppendUint64(b, uint64(c.ExpiresAtUnix))
	if len(b)+ed25519.SignatureSize+1 > 32768 {
		return nil, ErrUnauthenticated
	}
	return b, nil
}

// VerifySession verifies both real signatures and their exact binding. It never
// enrolls a session, installs a context value, grants paths or extends validity.
// Inputs must not be concurrently mutated by their transport owner.
func (v *SessionVerifier) VerifySession(ctx context.Context, credential *IdentityCredential, proof *SessionProof) (VerifiedSession, error) {
	deny := VerifiedSession{}
	if v == nil || v.identity == nil || v.now == nil || ctx == nil || ctx.Err() != nil || credential == nil || proof == nil || proof.Version != 1 || len(proof.Signature) != ed25519.SignatureSize {
		return deny, ErrUnauthenticated
	}
	if len(credential.Signature) != ed25519.SignatureSize {
		return deny, ErrUnauthenticated
	}
	credentialSnapshot := *credential
	credentialSnapshot.Signature = append([]byte(nil), credential.Signature...)
	credential = &credentialSnapshot
	proofSnapshot := *proof
	proofSnapshot.Signature = append([]byte(nil), proof.Signature...)
	proof = &proofSnapshot
	c := proof.Claims
	transcript, err := SessionTranscript(c)
	if err != nil || c.Audience != v.audience {
		return deny, ErrUnauthenticated
	}
	key := v.keys[c.AuthorityIssuer][c.KeyID]
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, transcript, proof.Signature) {
		return deny, ErrUnauthenticated
	}
	identity, err := v.identity.Resolve(ctx, credential)
	if err != nil || identity.Principal != c.Principal || c.NotBeforeUnix < credential.Claims.NotBeforeUnix || c.ExpiresAtUnix > credential.Claims.ExpiresAtUnix {
		return deny, ErrUnauthenticated
	}
	h := sha256.New()
	h.Write(identityTranscript(credential.Claims))
	h.Write(credential.Signature)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	if digest != c.CredentialHash {
		return deny, ErrUnauthenticated
	}
	now, err := v.now()
	if err != nil || now.IsZero() || now.Unix() < c.NotBeforeUnix || now.Unix() >= c.ExpiresAtUnix || ctx.Err() != nil {
		return deny, ErrUnauthenticated
	}
	h.Reset()
	h.Write(transcript)
	h.Write(proof.Signature)
	copy(digest[:], h.Sum(nil))
	return VerifiedSession{owner: v, claims: c, proofHash: digest}, nil
}
