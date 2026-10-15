// Package authz contains internal security building blocks.
package authz

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"time"
)

// ErrUnauthenticated is the only resolver error, including configuration and
// dependency failures. It deliberately carries no credential or claim details.
var ErrUnauthenticated = errors.New("unauthenticated")

type PrincipalClass string

const (
	Human          PrincipalClass = "human"
	BuildJob       PrincipalClass = "build_job"
	ModelWorker    PrincipalClass = "model_worker"
	ServiceAccount PrincipalClass = "service_account"
)

// PrincipalID is a tuple, never a concatenated name or an authorization grant.
// Subject is opaque exact bytes in a string; no normalization is performed.
type PrincipalID struct {
	Issuer, Subject string
	Class           PrincipalClass
}

// IdentityClaims and IdentityCredential are internal inputs from a transport
// adapter, not a public token envelope, JWT/OIDC profile, or issuance API.
// Both time claims are mandatory UTC Unix seconds. The interval is [start,end).
type IdentityClaims struct {
	Issuer, KeyID, Subject, Audience string
	Class                            PrincipalClass
	NotBeforeUnix, ExpiresAtUnix     int64
}

type IdentityCredential struct {
	Claims    IdentityClaims
	Signature []byte
}

type Identity struct {
	Principal PrincipalID
	Audience  string
	ExpiresAt time.Time
}

type RevocationState uint8

const (
	RevocationUnknown RevocationState = iota
	RevocationActive
	RevocationRevoked
)

// RevocationCheck must establish current credential status for these exact
// authenticated claims. No store, propagation, freshness bound or session is
// implemented here. Missing, failed and indeterminate checks fail closed.
type RevocationCheck func(context.Context, IdentityClaims) (RevocationState, error)
type IdentityClock func() (time.Time, error)

type IdentityResolver struct {
	audience string
	keys     map[string]map[string]ed25519.PublicKey
	now      IdentityClock
	check    RevocationCheck
}

const maxIdentityClaimBytes = 4096
const maxIdentityUnix = 253402300799 // last second of year 9999

func boundedIdentityClaim(s string) bool { return len(s) > 0 && len(s) <= maxIdentityClaimBytes }

// NewIdentityResolver snapshots trusted keys supplied by trusted configuration.
// Issuer/key IDs are exact lookup keys; credentials cannot discover or add keys.
func NewIdentityResolver(audience string, issuers map[string]map[string]ed25519.PublicKey, now IdentityClock, check RevocationCheck) (*IdentityResolver, error) {
	if !boundedIdentityClaim(audience) || len(issuers) == 0 || now == nil || check == nil {
		return nil, ErrUnauthenticated
	}
	r := &IdentityResolver{audience: audience, keys: make(map[string]map[string]ed25519.PublicKey), now: now, check: check}
	for issuer, keys := range issuers {
		if !boundedIdentityClaim(issuer) || len(keys) == 0 {
			return nil, ErrUnauthenticated
		}
		r.keys[issuer] = make(map[string]ed25519.PublicKey)
		for id, key := range keys {
			if !boundedIdentityClaim(id) || len(key) != ed25519.PublicKeySize {
				return nil, ErrUnauthenticated
			}
			r.keys[issuer][id] = append(ed25519.PublicKey(nil), key...)
		}
	}
	return r, nil
}

func validIdentityClaims(c IdentityClaims) bool {
	if !boundedIdentityClaim(c.Issuer) || !boundedIdentityClaim(c.KeyID) || !boundedIdentityClaim(c.Subject) || !boundedIdentityClaim(c.Audience) {
		return false
	}
	switch c.Class {
	case Human, BuildJob, ModelWorker, ServiceAccount:
	default:
		return false
	}
	return c.NotBeforeUnix > 0 && c.ExpiresAtUnix > c.NotBeforeUnix && c.ExpiresAtUnix <= maxIdentityUnix
}

// identityTranscript is an internal, versioned purpose domain followed by five
// uint32 big-endian length-prefixed byte strings (issuer,key,subject,class,
// audience), then two signed int64 big-endian seconds (start,end). Framing is
// unambiguous even for embedded NULs/non-UTF-8; limits precede allocation.
// This purpose cannot substitute for object authorship or an object grant.
func identityTranscript(c IdentityClaims) []byte {
	b := []byte("CANOPY\x00INTERNAL-IDENTITY\x00V1\x00")
	for _, s := range []string{c.Issuer, c.KeyID, c.Subject, string(c.Class), c.Audience} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
		b = append(b, s...)
	}
	b = binary.BigEndian.AppendUint64(b, uint64(c.NotBeforeUnix))
	return binary.BigEndian.AppendUint64(b, uint64(c.ExpiresAtUnix))
}

func (r *IdentityResolver) validTime(c IdentityClaims) bool {
	now, err := r.now()
	return err == nil && !now.IsZero() && !now.Before(time.Unix(c.NotBeforeUnix, 0)) && now.Before(time.Unix(c.ExpiresAtUnix, 0))
}

// Resolve authenticates only; it establishes no policy rights, delegation or
// session. All external failures have the same safe shape. Only verified claims
// reach the revocation dependency, and validity is checked again after lookup.
func (r *IdentityResolver) Resolve(ctx context.Context, credential *IdentityCredential) (Identity, error) {
	deny := Identity{}
	if r == nil || r.now == nil || r.check == nil || r.audience == "" || ctx == nil || ctx.Err() != nil || credential == nil {
		return deny, ErrUnauthenticated
	}
	c := credential.Claims
	if !validIdentityClaims(c) || c.Audience != r.audience || len(credential.Signature) != ed25519.SignatureSize {
		return deny, ErrUnauthenticated
	}
	key := r.keys[c.Issuer][c.KeyID]
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, identityTranscript(c), credential.Signature) || !r.validTime(c) {
		return deny, ErrUnauthenticated
	}
	state, err := r.check(ctx, c)
	if err != nil || state != RevocationActive || ctx.Err() != nil || !r.validTime(c) {
		return deny, ErrUnauthenticated
	}
	return Identity{Principal: PrincipalID{Issuer: c.Issuer, Subject: c.Subject, Class: c.Class}, Audience: c.Audience, ExpiresAt: time.Unix(c.ExpiresAtUnix, 0)}, nil
}
