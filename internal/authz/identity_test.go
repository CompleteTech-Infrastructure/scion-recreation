package authz

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Deterministic local vectors exercise real Ed25519, not a fake verifier or an
// external issuer integration. This independent transcript encoder freezes only
// the internal purpose. It does not claim a public token interoperability profile.
func vectorTranscript(c IdentityClaims) []byte {
	var b bytes.Buffer
	b.WriteString("CANOPY\x00INTERNAL-IDENTITY\x00V1\x00")
	for _, s := range []string{c.Issuer, c.KeyID, c.Subject, string(c.Class), c.Audience} {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(s)))
		b.WriteString(s)
	}
	_ = binary.Write(&b, binary.BigEndian, c.NotBeforeUnix)
	_ = binary.Write(&b, binary.BigEndian, c.ExpiresAtUnix)
	return b.Bytes()
}

func vectorKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}
func vectorClaims() IdentityClaims {
	return IdentityClaims{Issuer: "issuer-A", KeyID: "key-1", Subject: "opaque-secret-subject", Class: Human, Audience: "authority", NotBeforeUnix: 100, ExpiresAtUnix: 200}
}
func vectorCredential(c IdentityClaims) *IdentityCredential {
	return &IdentityCredential{Claims: c, Signature: ed25519.Sign(vectorKey(), vectorTranscript(c))}
}
func vectorResolver(t *testing.T, audience string) *IdentityResolver {
	t.Helper()
	key := vectorKey().Public().(ed25519.PublicKey)
	r, err := NewIdentityResolver(audience, map[string]map[string]ed25519.PublicKey{"issuer-A": {"key-1": key}, "issuer-B": {"key-1": key}}, func() (time.Time, error) { return time.Unix(150, 0), nil }, func(context.Context, IdentityClaims) (RevocationState, error) { return RevocationActive, nil })
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func requireDenied(t *testing.T, r *IdentityResolver, c *IdentityCredential) {
	t.Helper()
	got, err := r.Resolve(context.Background(), c)
	if got != (Identity{}) || err != ErrUnauthenticated || fmt.Sprintf("%+v", err) != "unauthenticated" {
		t.Fatal("failure must return zero identity and fixed safe error")
	}
	if c != nil {
		for _, secret := range []string{c.Claims.Subject, c.Claims.Issuer, c.Claims.KeyID, c.Claims.Audience, string(c.Signature), hex.EncodeToString(c.Signature), hex.EncodeToString(vectorKey()), string(vectorTranscript(c.Claims))} {
			if secret != "" && strings.Contains(err.Error(), secret) {
				t.Fatal("sensitive failure diagnostic")
			}
		}
	}
}

func TestIdentityResolvesClassesAndExactAudience(t *testing.T) {
	for _, class := range []PrincipalClass{Human, BuildJob, ModelWorker, ServiceAccount} {
		t.Run(string(class), func(t *testing.T) {
			for _, audience := range []string{"authority", "regional", "Authority", "authority\x00regional"} {
				c := vectorClaims()
				c.Class = class
				c.Audience = audience
				got, err := vectorResolver(t, audience).Resolve(context.Background(), vectorCredential(c))
				if err != nil || got.Principal != (PrincipalID{c.Issuer, c.Subject, class}) || got.Audience != audience || !got.ExpiresAt.Equal(time.Unix(200, 0)) {
					t.Fatal("valid authenticated identity did not resolve exactly")
				}
			}
		})
	}
}

func TestIdentityRejectsMissingAndMalformedClaims(t *testing.T) {
	r := vectorResolver(t, "authority")
	t.Run("credential", func(t *testing.T) { requireDenied(t, r, nil) })
	cases := []struct {
		name   string
		mutate func(*IdentityClaims)
	}{
		{"issuer", func(c *IdentityClaims) { c.Issuer = "" }}, {"key", func(c *IdentityClaims) { c.KeyID = "" }},
		{"subject", func(c *IdentityClaims) { c.Subject = "" }}, {"class", func(c *IdentityClaims) { c.Class = "" }},
		{"unknown_class", func(c *IdentityClaims) { c.Class = "node_daemon" }}, {"audience", func(c *IdentityClaims) { c.Audience = "" }},
		{"start", func(c *IdentityClaims) { c.NotBeforeUnix = 0 }}, {"end", func(c *IdentityClaims) { c.ExpiresAtUnix = 0 }},
		{"negative", func(c *IdentityClaims) { c.NotBeforeUnix = -1 }}, {"empty_interval", func(c *IdentityClaims) { c.ExpiresAtUnix = c.NotBeforeUnix }},
		{"reversed_interval", func(c *IdentityClaims) { c.ExpiresAtUnix = 99 }}, {"overflow_time", func(c *IdentityClaims) { c.ExpiresAtUnix = 1<<63 - 1 }},
		{"oversize_issuer", func(c *IdentityClaims) { c.Issuer = strings.Repeat("i", 4097) }}, {"oversize_key", func(c *IdentityClaims) { c.KeyID = strings.Repeat("k", 4097) }},
		{"oversize_subject", func(c *IdentityClaims) { c.Subject = strings.Repeat("s", 4097) }}, {"oversize_audience", func(c *IdentityClaims) { c.Audience = strings.Repeat("a", 4097) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { c := vectorClaims(); tc.mutate(&c); requireDenied(t, r, vectorCredential(c)) })
	}
}

func TestIdentityRejectsForgeryAndSubstitution(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*IdentityCredential)
	}{
		{"unsigned", func(c *IdentityCredential) { c.Signature = nil }}, {"short_signature", func(c *IdentityCredential) { c.Signature = c.Signature[:63] }},
		{"long_signature", func(c *IdentityCredential) { c.Signature = append(c.Signature, 0) }}, {"forged", func(c *IdentityCredential) { c.Signature = make([]byte, 64) }},
		{"tampered_signature", func(c *IdentityCredential) { c.Signature[0] ^= 1 }},
		{"attacker_key", func(c *IdentityCredential) {
			c.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, 32)), vectorTranscript(c.Claims))
		}},
		{"issuer", func(c *IdentityCredential) { c.Claims.Issuer = "issuer-B" }}, {"key", func(c *IdentityCredential) { c.Claims.KeyID = "unknown" }},
		{"subject", func(c *IdentityCredential) { c.Claims.Subject = "another-secret-subject" }}, {"class", func(c *IdentityCredential) { c.Claims.Class = ServiceAccount }},
		{"audience", func(c *IdentityCredential) { c.Claims.Audience = "regional" }}, {"start", func(c *IdentityCredential) { c.Claims.NotBeforeUnix = 99 }},
		{"end", func(c *IdentityCredential) { c.Claims.ExpiresAtUnix = 201 }},
		{"other_purpose", func(c *IdentityCredential) {
			c.Signature = ed25519.Sign(vectorKey(), append([]byte("CANOPY\x00NATIVE-SIGNATURE\x00"), vectorTranscript(c.Claims)...))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := vectorCredential(vectorClaims())
			tc.mutate(c)
			requireDenied(t, vectorResolver(t, "authority"), c)
		})
	}
}

func TestIdentityRejectsUnknownTrustAndWrongAudience(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*IdentityClaims)
	}{
		{"unknown_issuer", func(c *IdentityClaims) { c.Issuer = "untrusted" }}, {"unknown_key", func(c *IdentityClaims) { c.KeyID = "untrusted" }},
		{"wrong_audience", func(c *IdentityClaims) { c.Audience = "regional" }}, {"audience_case", func(c *IdentityClaims) { c.Audience = "Authority" }},
		{"audience_prefix", func(c *IdentityClaims) { c.Audience = "authority\x00regional" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := vectorClaims()
			tc.mutate(&c)
			requireDenied(t, vectorResolver(t, "authority"), vectorCredential(c))
		})
	}
}

func TestIdentityValidityBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		now  time.Time
		pass bool
	}{
		{"before_start", time.Unix(99, 999999999), false}, {"at_start", time.Unix(100, 0), true},
		{"before_expiry", time.Unix(199, 999999999), true}, {"at_expiry", time.Unix(200, 0), false}, {"after_expiry", time.Unix(201, 0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := vectorResolver(t, "authority")
			r.now = func() (time.Time, error) { return tc.now, nil }
			c := vectorCredential(vectorClaims())
			if tc.pass {
				if _, err := r.Resolve(context.Background(), c); err != nil {
					t.Fatal(err)
				}
			} else {
				requireDenied(t, r, c)
			}
		})
	}
}

func TestIdentityFailsClosedOnDependencies(t *testing.T) {
	for _, name := range []string{"revoked", "indeterminate", "unknown_state", "revocation_error", "clock_error", "zero_clock", "expired_during_lookup", "canceled_during_lookup", "nil_resolver", "zero_resolver"} {
		t.Run(name, func(t *testing.T) {
			r := vectorResolver(t, "authority")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "revoked":
				r.check = func(context.Context, IdentityClaims) (RevocationState, error) { return RevocationRevoked, nil }
			case "indeterminate":
				r.check = func(context.Context, IdentityClaims) (RevocationState, error) { return RevocationUnknown, nil }
			case "unknown_state":
				r.check = func(context.Context, IdentityClaims) (RevocationState, error) { return 99, nil }
			case "revocation_error":
				r.check = func(context.Context, IdentityClaims) (RevocationState, error) {
					return RevocationActive, errors.New("secret-lookup-diagnostic")
				}
			case "clock_error":
				r.now = func() (time.Time, error) { return time.Unix(150, 0), errors.New("secret-clock-diagnostic") }
			case "zero_clock":
				r.now = func() (time.Time, error) { return time.Time{}, nil }
			case "expired_during_lookup":
				r.check = func(context.Context, IdentityClaims) (RevocationState, error) {
					r.now = func() (time.Time, error) { return time.Unix(200, 0), nil }
					return RevocationActive, nil
				}
			case "canceled_during_lookup":
				r.check = func(context.Context, IdentityClaims) (RevocationState, error) { cancel(); return RevocationActive, nil }
			case "nil_resolver":
				r = nil
			case "zero_resolver":
				r = &IdentityResolver{}
			}
			got, err := r.Resolve(ctx, vectorCredential(vectorClaims()))
			if got != (Identity{}) || err != ErrUnauthenticated || err.Error() != "unauthenticated" {
				t.Fatal("dependency failure leaked or succeeded")
			}
		})
	}
}

func TestIdentityIssuerScopeAndFraming(t *testing.T) {
	r := vectorResolver(t, "authority")
	c := vectorClaims()
	a, err := r.Resolve(context.Background(), vectorCredential(c))
	if err != nil {
		t.Fatal(err)
	}
	c.Issuer = "issuer-B"
	b, err := r.Resolve(context.Background(), vectorCredential(c))
	if err != nil || a.Principal == b.Principal {
		t.Fatal("issuer scoped subjects collapsed")
	}
	c.Subject = "\x00\xffa/b"
	b, err = r.Resolve(context.Background(), vectorCredential(c))
	if err != nil || b.Principal.Subject != c.Subject {
		t.Fatal("opaque subject was normalized")
	}
	x := vectorClaims()
	y := x
	x.Issuer = "a"
	x.KeyID = "bc"
	y.Issuer = "ab"
	y.KeyID = "c"
	if bytes.Equal(identityTranscript(x), identityTranscript(y)) {
		t.Fatal("ambiguous framing")
	}
	c = IdentityClaims{Issuer: "i", KeyID: "k", Subject: "s", Class: Human, Audience: "a", NotBeforeUnix: 1, ExpiresAtUnix: 2}
	const want = "43414e4f505900494e5445524e414c2d4944454e54495459005631000000000169000000016b00000001730000000568756d616e000000016100000000000000010000000000000002"
	if hex.EncodeToString(identityTranscript(c)) != want || !bytes.Equal(identityTranscript(c), vectorTranscript(c)) {
		t.Fatal("internal transcript vector changed")
	}
}

func TestIdentityTrustConfiguration(t *testing.T) {
	for _, name := range []string{"no_issuers", "empty_issuer", "no_keys", "empty_key_id", "invalid_key", "no_clock", "no_revocation", "no_audience"} {
		t.Run(name, func(t *testing.T) {
			keys := map[string]map[string]ed25519.PublicKey{"issuer-A": {"key-1": vectorKey().Public().(ed25519.PublicKey)}}
			clock := IdentityClock(func() (time.Time, error) { return time.Unix(150, 0), nil })
			check := RevocationCheck(func(context.Context, IdentityClaims) (RevocationState, error) { return RevocationActive, nil })
			audience := "authority"
			switch name {
			case "no_issuers":
				keys = nil
			case "empty_issuer":
				keys[""] = keys["issuer-A"]
			case "no_keys":
				keys["issuer-A"] = nil
			case "empty_key_id":
				keys["issuer-A"][""] = keys["issuer-A"]["key-1"]
			case "invalid_key":
				keys["issuer-A"]["key-1"] = nil
			case "no_clock":
				clock = nil
			case "no_revocation":
				check = nil
			case "no_audience":
				audience = ""
			}
			if r, err := NewIdentityResolver(audience, keys, clock, check); r != nil || err != ErrUnauthenticated {
				t.Fatal("unconfigured trust accepted")
			}
		})
	}
}

func TestIdentityTrustSnapshotAndLookupBoundary(t *testing.T) {
	key := vectorKey().Public().(ed25519.PublicKey)
	keys := map[string]map[string]ed25519.PublicKey{"issuer-A": {"key-1": key}}
	calls := 0
	r, err := NewIdentityResolver("authority", keys, func() (time.Time, error) { return time.Unix(150, 0), nil }, func(_ context.Context, c IdentityClaims) (RevocationState, error) {
		calls++
		if c != vectorClaims() {
			t.Fatal("lookup received substituted claims")
		}
		return RevocationActive, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	key[0] ^= 1
	delete(keys, "issuer-A")
	if _, err = r.Resolve(context.Background(), vectorCredential(vectorClaims())); err != nil || calls != 1 {
		t.Fatal("trusted key snapshot changed")
	}
	c := vectorCredential(vectorClaims())
	c.Signature[0] ^= 1
	requireDenied(t, r, c)
	if calls != 1 {
		t.Fatal("unverified claims reached lookup")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = r.Resolve(ctx, vectorCredential(vectorClaims())); err != ErrUnauthenticated || calls != 1 {
		t.Fatal("canceled request reached lookup")
	}
	if _, err = r.Resolve(nil, vectorCredential(vectorClaims())); err != ErrUnauthenticated {
		t.Fatal("nil context accepted")
	}
}
