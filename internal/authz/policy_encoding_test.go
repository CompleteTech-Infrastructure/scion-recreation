package authz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func policyFixture() PolicySnapshot {
	p := PrincipalID{"issuer", "\xffsubject", Human}
	s := RepositoryScope{"tenant", "repo"}
	return PolicySnapshot{RepositoryPolicy{s, ^uint64(0), []RepositoryRole{{"writer", []RepositoryCapability{RepositoryWrite, RepositoryRead}, nil}}, []RepositoryMember{{p, true, []string{"writer"}}}}, PathPolicy{s, ^uint64(0), []PathRule{{p, PathSelector{Root: true}, []PathAction{PathTraverse}, nil}, {p, PathSelector{Path: []byte("a")}, []PathAction{PathRead, PathWrite}, nil}, {p, PathSelector{Path: []byte("a")}, nil, []PathAction{PathWrite}}}}}
}
func TestPolicyEncodingCanonical(t *testing.T) {
	p := policyFixture()
	b, e := EncodePolicySnapshot(p)
	if e != nil {
		t.Fatal(e)
	}
	d, e := DecodePolicySnapshot(b)
	if e != nil {
		t.Fatal(e)
	}
	if len(d.Paths.Rules) != 2 || d.Repository.Version != ^uint64(0) {
		t.Fatal("lost duplicate union or version")
	}
	got := sha256.Sum256(b)
	if hex.EncodeToString(got[:]) != "d7364766a117aec1deeeb1cb9204e7a71ad74a8abac659d31827e50f10596400" {
		t.Fatal("fixture identity drift")
	}
	// Input order and capability order do not change the binary identity.
	p.Paths.Rules[0], p.Paths.Rules[2] = p.Paths.Rules[2], p.Paths.Rules[0]
	p.Repository.Roles[0].Allow[0], p.Repository.Roles[0].Allow[1] = p.Repository.Roles[0].Allow[1], p.Repository.Roles[0].Allow[0]
	again, e := EncodePolicySnapshot(p)
	if e != nil || !bytes.Equal(b, again) {
		t.Fatal("not deterministic", e)
	}
	// Neither encoding nor decoding retains mutable aliases.
	p.Paths.Rules[0].Selector.Path[0] = 'z'
	before := append([]byte(nil), b...)
	d.Paths.Rules[1].Selector.Path[0] = 'x'
	if !bytes.Equal(b, before) {
		t.Fatal("alias")
	}
	now := time.Unix(100, 0)
	clock := func() (time.Time, error) { return now, nil }
	orig := policyFixture()
	decoded, e := DecodePolicySnapshot(before)
	if e != nil {
		t.Fatal(e)
	}
	for _, snapshot := range []PolicySnapshot{orig, decoded} {
		r, e := NewRepositoryPolicy(snapshot.Repository, "aud", clock)
		if e != nil {
			t.Fatal(e)
		}
		paths, e := NewPathPolicy(snapshot.Paths, r)
		if e != nil {
			t.Fatal(e)
		}
		id := Identity{orig.Repository.Members[0].Principal, "aud", now.Add(time.Hour)}
		for _, a := range []PathAction{PathRead, PathWrite} {
			decision, e := paths.Evaluate(context.Background(), id, orig.Repository.Scope, orig.Repository.Version, PathSelector{Path: []byte("a")}, a)
			if (a == PathRead && (e != nil || !decision.Allowed)) || (a == PathWrite && e == nil) {
				t.Fatalf("semantics %s %v %v", a, decision, e)
			}
		}
	}
}
func TestPolicyEncodingRejectsMalformed(t *testing.T) {
	b, e := EncodePolicySnapshot(policyFixture())
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < len(b); i++ {
		if _, e := DecodePolicySnapshot(b[:i]); e != ErrPolicyEncoding {
			t.Fatalf("truncation %d: %v", i, e)
		}
	}
	for _, bad := range [][]byte{append(append([]byte(nil), b...), 0), bytes.Repeat([]byte{0}, MaxPolicyEncoding+1), append([]byte(policyMagic), 255, 255, 255, 255)} {
		if _, e := DecodePolicySnapshot(bad); e != ErrPolicyEncoding {
			t.Fatal("accepted malformed", e)
		}
	}
	// Every bit mutation either rejects or produces another stable canonical body.
	for i := range b {
		for bit := byte(1); bit != 0; bit <<= 1 {
			mut := append([]byte(nil), b...)
			mut[i] ^= bit
			d, e := DecodePolicySnapshot(mut)
			if e == nil {
				round, e := EncodePolicySnapshot(d)
				if e != nil || !bytes.Equal(round, mut) {
					t.Fatal("accepted noncanonical")
				}
			}
		}
	}
}
func TestPolicyEncodingInvalidInputs(t *testing.T) {
	cases := []func(*PolicySnapshot){
		func(p *PolicySnapshot) { p.Paths.Scope.RepositoryID = "other" },
		func(p *PolicySnapshot) { p.Paths.Version-- },
		func(p *PolicySnapshot) { p.Repository.Roles = append(p.Repository.Roles, p.Repository.Roles[0]) },
		func(p *PolicySnapshot) { p.Repository.Members = append(p.Repository.Members, p.Repository.Members[0]) },
		func(p *PolicySnapshot) { p.Repository.Roles[0].Allow = []RepositoryCapability{"unknown"} },
		func(p *PolicySnapshot) { p.Paths.Rules[0].Principal.Class = "unknown" },
		func(p *PolicySnapshot) { p.Paths.Rules[0].Selector.Path = []byte("root") },
		func(p *PolicySnapshot) { p.Paths.Rules[0].Allow = []PathAction{"unknown"} },
		func(p *PolicySnapshot) { p.Paths.Rules[1].Selector.Path = []byte("../bad") },
		func(p *PolicySnapshot) { p.Repository.Members[0].Roles = []string{"absent"} },
		func(p *PolicySnapshot) { p.Repository.Scope.TenantID = "" },
	}
	for i, change := range cases {
		p := policyFixture()
		change(&p)
		b, e := EncodePolicySnapshot(p)
		if e != ErrPolicyEncoding || b != nil {
			t.Fatalf("case%d: %x %v", i, b, e)
		}
	}
}

func TestPolicyEncodingVectorAndBounds(t *testing.T) {
	scope := RepositoryScope{"t", "r"}
	p := PolicySnapshot{Repository: RepositoryPolicy{Scope: scope}, Paths: PathPolicy{Scope: scope}}
	b, e := EncodePolicySnapshot(p)
	if e != nil {
		t.Fatal(e)
	}
	if hex.EncodeToString(b) != "43414e4f505900504f4c4943592d4c4f43414c00563100000000017400000001720000000000000000000000000000000000000000" {
		t.Fatal("independent struct vector mismatch")
	}
	for _, offset := range []int{41, 45, 49} {
		bad := append([]byte(nil), b...)
		for i := 0; i < 4; i++ {
			bad[offset+i] = 255
		}
		if _, e := DecodePolicySnapshot(bad); e != ErrPolicyEncoding {
			t.Fatal("malicious count")
		}
	}
	p.Repository.Roles = make([]RepositoryRole, 65)
	if _, e := EncodePolicySnapshot(p); e != ErrPolicyEncoding {
		t.Fatal("role count bound")
	}
	p = policyFixture()
	p.Paths.Rules = make([]PathRule, 4097)
	if _, e := EncodePolicySnapshot(p); e != ErrPolicyEncoding {
		t.Fatal("rule count bound")
	}
}
