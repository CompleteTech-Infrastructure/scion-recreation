package authz

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Independently framed fixture, with separate deterministic session seed 99.
func sessionVector(c SessionClaims) []byte {
	var b bytes.Buffer
	b.WriteString("CANOPY\x00INTERNAL-SESSION\x00V1\x00")
	for _, s := range []string{c.AuthorityIssuer, c.KeyID, c.Principal.Issuer, c.Principal.Subject, string(c.Principal.Class), c.Audience, c.Tenant} {
		binary.Write(&b, binary.BigEndian, uint32(len(s)))
		b.WriteString(s)
	}
	b.Write(c.CredentialHash[:])
	b.Write(c.Repository[:])
	b.Write(c.Session[:])
	binary.Write(&b, binary.BigEndian, c.Generation)
	binary.Write(&b, binary.BigEndian, c.NotBeforeUnix)
	binary.Write(&b, binary.BigEndian, c.ExpiresAtUnix)
	return b.Bytes()
}

func sessionFixture(t *testing.T) (*SessionVerifier, *IdentityCredential, *SessionProof, ed25519.PrivateKey) {
	t.Helper()
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, 32))
	credential := vectorCredential(vectorClaims())
	h := sha256.New()
	h.Write(vectorTranscript(credential.Claims))
	h.Write(credential.Signature)
	c := SessionClaims{AuthorityIssuer: "session-issuer", KeyID: "session-key", Principal: PrincipalID{"issuer-A", "opaque-secret-subject", Human}, Audience: "authority", Tenant: "tenant\x00\xff", NotBeforeUnix: 110, ExpiresAtUnix: 190, Generation: 0}
	copy(c.CredentialHash[:], h.Sum(nil))
	c.Repository[0] = 1
	c.Session[0] = 2
	p := &SessionProof{Version: 1, Claims: c, Signature: ed25519.Sign(k, sessionVector(c))}
	v, err := NewSessionVerifier(vectorResolver(t, "authority"), "authority", map[string]map[string]ed25519.PublicKey{"session-issuer": {"session-key": k.Public().(ed25519.PublicKey)}}, func() (time.Time, error) { return time.Unix(150, 0), nil })
	if err != nil {
		t.Fatal(err)
	}
	return v, credential, p, k
}

func sessionDenied(t *testing.T, v *SessionVerifier, ctx context.Context, c *IdentityCredential, p *SessionProof) {
	t.Helper()
	got, err := v.VerifySession(ctx, c, p)
	if got != (VerifiedSession{}) || err != ErrUnauthenticated {
		t.Fatalf("denial shape: %v %v", got, err)
	}
}

func TestSessionAuthenticityAndProvenance(t *testing.T) {
	v, c, p, _ := sessionFixture(t)
	if digest, err := IdentityCredentialHash(c); err != nil || digest != p.Claims.CredentialHash {
		t.Fatal("credential hash mismatch")
	}
	for _, bad := range []*IdentityCredential{nil, {}, {Claims: c.Claims, Signature: []byte{1}}} {
		if digest, err := IdentityCredentialHash(bad); err != ErrUnauthenticated || digest != ([32]byte{}) {
			t.Fatal("malformed credential hash")
		}
	}
	want := sessionVector(p.Claims)
	got, err := SessionTranscript(p.Claims)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("transcript differs from independent framing")
	}
	s, err := v.VerifySession(context.Background(), c, p)
	if err != nil || s.Claims() != p.Claims || !v.Owns(s) || v.Owns(VerifiedSession{}) {
		t.Fatal("exact proof failed")
	}
	other, _, _, _ := sessionFixture(t)
	if other.Owns(s) || (*SessionVerifier)(nil).Owns(VerifiedSession{}) {
		t.Fatal("foreign/zero provenance")
	}
	digest := sha256.Sum256(append(want, p.Signature...))
	if s.ProofHash() != digest {
		t.Fatal("proof digest")
	}
	p.Claims.Tenant = "changed"
	c.Signature[0] ^= 1
	if s.Claims().Tenant != "tenant\x00\xff" {
		t.Fatal("mutable alias")
	}
}

func TestSessionFrozenTranscriptAndClasses(t *testing.T) {
	c := SessionClaims{AuthorityIssuer: "s", KeyID: "k", Principal: PrincipalID{"i", "p", Human}, Audience: "a", Tenant: "t", NotBeforeUnix: 100, ExpiresAtUnix: 200}
	c.CredentialHash[0] = 3
	c.Repository[0] = 1
	c.Session[0] = 2
	b, err := SessionTranscript(c)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(b)) != "0c97743a8de9312c27dab0c05bc08db940ad5977df0e398819926c65c0c2889c" {
		t.Fatal("frozen session-v1 transcript changed")
	}
	for _, class := range []PrincipalClass{Human, BuildJob, ModelWorker, ServiceAccount} {
		v, credential, p, k := sessionFixture(t)
		credential.Claims.Class = class
		credential.Signature = ed25519.Sign(vectorKey(), vectorTranscript(credential.Claims))
		p.Claims.Principal.Class = class
		h := sha256.New()
		h.Write(vectorTranscript(credential.Claims))
		h.Write(credential.Signature)
		copy(p.Claims.CredentialHash[:], h.Sum(nil))
		p.Signature = ed25519.Sign(k, sessionVector(p.Claims))
		if _, err := v.VerifySession(context.Background(), credential, p); err != nil {
			t.Fatal(class, err)
		}
	}
}

func TestSessionRejectsClaimsAndSubstitutions(t *testing.T) {
	mutations := map[string]func(*SessionClaims){
		"issuer": func(c *SessionClaims) { c.AuthorityIssuer = "other" }, "key": func(c *SessionClaims) { c.KeyID = "other" },
		"principalissuer": func(c *SessionClaims) { c.Principal.Issuer = "issuer-B" }, "subject": func(c *SessionClaims) { c.Principal.Subject += "x" },
		"class": func(c *SessionClaims) { c.Principal.Class = BuildJob }, "unknownclass": func(c *SessionClaims) { c.Principal.Class = "unknown" },
		"credential": func(c *SessionClaims) { c.CredentialHash[0] ^= 1 }, "audience": func(c *SessionClaims) { c.Audience = "regional" },
		"emptytenant": func(c *SessionClaims) { c.Tenant = "" }, "oversize": func(c *SessionClaims) { c.Tenant = strings.Repeat("t", 4097) },
		"zerorepo": func(c *SessionClaims) { c.Repository = [16]byte{} }, "zerosession": func(c *SessionClaims) { c.Session = [32]byte{} },
		"notyet": func(c *SessionClaims) { c.NotBeforeUnix = 151 }, "expired": func(c *SessionClaims) { c.ExpiresAtUnix = 150 },
		"beforeidentity": func(c *SessionClaims) { c.NotBeforeUnix = 99 }, "afteridentity": func(c *SessionClaims) { c.ExpiresAtUnix = 201 },
		"toolong": func(c *SessionClaims) { c.ExpiresAtUnix = c.NotBeforeUnix + 3601 }, "overflow": func(c *SessionClaims) { c.ExpiresAtUnix = 1<<63 - 1 },
		"negative": func(c *SessionClaims) { c.NotBeforeUnix = -1 }, "reversed": func(c *SessionClaims) { c.ExpiresAtUnix = c.NotBeforeUnix },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			v, c, p, k := sessionFixture(t)
			mutate(&p.Claims)
			p.Signature = ed25519.Sign(k, sessionVector(p.Claims))
			sessionDenied(t, v, context.Background(), c, p)
		})
	}
	for _, kind := range []string{"signature", "version", "identitysig", "identitypurpose", "missingidentity", "missingproof", "nilcontext", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			v, c, p, k := sessionFixture(t)
			ctx := context.Background()
			switch kind {
			case "signature":
				p.Signature[0] ^= 1
			case "version":
				p.Version = 2
			case "identitysig":
				c.Signature[0] ^= 1
			case "identitypurpose":
				p.Signature = ed25519.Sign(k, vectorTranscript(c.Claims))
			case "missingidentity":
				c = nil
			case "missingproof":
				p = nil
			case "nilcontext":
				ctx = nil
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			sessionDenied(t, v, ctx, c, p)
		})
	}
}

func TestSessionClockAndKeySnapshot(t *testing.T) {
	v, c, p, k := sessionFixture(t)
	key := k.Public().(ed25519.PublicKey)
	keys := map[string]map[string]ed25519.PublicKey{"session-issuer": {"session-key": key}}
	v, err := NewSessionVerifier(v.identity, "authority", keys, v.now)
	if err != nil {
		t.Fatal(err)
	}
	key[0] ^= 1
	delete(keys, "session-issuer")
	if _, err = v.VerifySession(context.Background(), c, p); err != nil {
		t.Fatal("configuration aliases keys")
	}
	for _, at := range []int64{109, 190, 0} {
		v.now = func() (time.Time, error) { return time.Unix(at, 0), nil }
		sessionDenied(t, v, context.Background(), c, p)
	}
	v.now = func() (time.Time, error) { return time.Time{}, errors.New("private failure") }
	sessionDenied(t, v, context.Background(), c, p)
	v.now = func() (time.Time, error) { return time.Unix(110, 0), nil }
	if _, err = v.VerifySession(context.Background(), c, p); err != nil {
		t.Fatal("inclusive start")
	}
	ctx, cancel := context.WithCancel(context.Background())
	v.now = func() (time.Time, error) { cancel(); return time.Unix(150, 0), nil }
	sessionDenied(t, v, ctx, c, p)
	for _, bad := range []map[string]map[string]ed25519.PublicKey{nil, {}, {"": {"key": k.Public().(ed25519.PublicKey)}}, {"issuer": {"": k.Public().(ed25519.PublicKey)}}, {"issuer": {"key": nil}}} {
		if _, err := NewSessionVerifier(v.identity, "authority", bad, v.now); err != ErrUnauthenticated {
			t.Fatal("invalid configuration")
		}
	}
	var zero SessionVerifier
	sessionDenied(t, &zero, context.Background(), c, p)
}

func TestSessionSnapshotsBeforeIdentityCallback(t *testing.T) {
	v, c, p, _ := sessionFixture(t)
	original := p.Claims
	v.identity.check = func(context.Context, IdentityClaims) (RevocationState, error) {
		c.Claims.Subject = "substituted"
		c.Signature[0] ^= 1
		p.Claims.Tenant = "substituted"
		p.Signature[0] ^= 1
		return RevocationActive, nil
	}
	got, err := v.VerifySession(context.Background(), c, p)
	if err != nil || got.Claims() != original {
		t.Fatal("callback changed verified input snapshot", err)
	}
}

func TestSessionRejectsCrossAudienceIdentity(t *testing.T) {
	v, c, p, k := sessionFixture(t)
	v.identity = vectorResolver(t, "regional")
	c.Claims.Audience = "regional"
	c.Signature = ed25519.Sign(vectorKey(), vectorTranscript(c.Claims))
	h := sha256.New()
	h.Write(vectorTranscript(c.Claims))
	h.Write(c.Signature)
	copy(p.Claims.CredentialHash[:], h.Sum(nil))
	p.Signature = ed25519.Sign(k, sessionVector(p.Claims))
	sessionDenied(t, v, context.Background(), c, p)
}
