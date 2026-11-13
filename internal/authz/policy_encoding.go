package authz

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
)

// PolicySnapshot is complete trusted configuration, never authentication proof.
// Both policies must name the same scope and version. Callers must not mutate
// inputs concurrently with encoding. Decoded values retain no input aliases.
type PolicySnapshot struct {
	Repository RepositoryPolicy
	Paths      PathPolicy
}

var ErrPolicyEncoding = errors.New("invalid policy encoding")

const policyMagic = "CANOPY\x00POLICY-LOCAL\x00V1\x00"
const MaxPolicyEncoding = 3 << 20

var policyClasses = []PrincipalClass{Human, BuildJob, ModelWorker, ServiceAccount}
var policyCaps = []RepositoryCapability{RepositoryRead, RepositoryWrite, RepositoryApprove, RepositoryAdmin, RepositoryMetadataRead, RepositoryHistoryRead}
var policyActions = []PathAction{PathTraverse, PathList, PathRead, PathWrite}

func policyPrincipalLess(a, b PrincipalID) bool {
	if a.Issuer != b.Issuer {
		return a.Issuer < b.Issuer
	}
	if a.Subject != b.Subject {
		return a.Subject < b.Subject
	}
	return a.Class < b.Class
}

// Encoding v1: magic; scope tenant/repository; shared u64 version; role count
// and roles(name,allow,deny); member count and members(principal,active,role
// count,names); rule count and rules(principal,root,path,allow,deny). Counts and
// byte lengths are u32 BE; version u64 BE; flags/masks/class are single bytes.
// Principal is issuer,subject,class (human=1,build_job=2,model_worker=3,service=4).
// Roles/references sort by raw name; principals sort issuer,subject,class bytes;
// rules sort principal then ROOT first then raw path. Masks use evaluator bit
// order. Duplicate selectors combine allow/deny union; other duplicates reject.
// No normalization, wall-clock validity, persistence or authorization is implied.
func EncodePolicySnapshot(p PolicySnapshot) ([]byte, error) {
	s, err := repositoryCompile(p.Repository)
	if err != nil || p.Paths.Scope != p.Repository.Scope || p.Paths.Version != p.Repository.Version {
		return nil, ErrPolicyEncoding
	}
	paths, err := NewPathPolicy(p.Paths, &RepositoryPolicyEngine{current: s})
	if err != nil {
		return nil, ErrPolicyEncoding
	}
	var b bytes.Buffer
	b.WriteString(policyMagic)
	put32 := func(n int) { var v [4]byte; binary.BigEndian.PutUint32(v[:], uint32(n)); b.Write(v[:]) }
	str := func(s string) { put32(len(s)); b.WriteString(s) }
	principal := func(p PrincipalID) {
		str(p.Issuer)
		str(p.Subject)
		for i, c := range policyClasses {
			if c == p.Class {
				b.WriteByte(byte(i + 1))
				return
			}
		}
	}
	str(p.Repository.Scope.TenantID)
	str(p.Repository.Scope.RepositoryID)
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], p.Repository.Version)
	b.Write(v[:])
	roles := append([]RepositoryRole(nil), p.Repository.Roles...)
	sort.Slice(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })
	put32(len(roles))
	for _, r := range roles {
		str(r.Name)
		a, _ := repositoryBits(r.Allow)
		d, _ := repositoryBits(r.Deny)
		b.WriteByte(a)
		b.WriteByte(d)
	}
	members := append([]RepositoryMember(nil), p.Repository.Members...)
	sort.Slice(members, func(i, j int) bool { return policyPrincipalLess(members[i].Principal, members[j].Principal) })
	put32(len(members))
	for _, m := range members {
		principal(m.Principal)
		if m.Active {
			b.WriteByte(1)
		} else {
			b.WriteByte(0)
		}
		names := append([]string(nil), m.Roles...)
		sort.Strings(names)
		put32(len(names))
		for _, n := range names {
			str(n)
		}
	}
	type rule struct {
		p      PrincipalID
		path   string
		rights pathRights
	}
	rules := make([]rule, 0, len(p.Paths.Rules))
	for p, rs := range paths.rules {
		for path, r := range rs {
			rules = append(rules, rule{p, path, r})
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].p != rules[j].p {
			return policyPrincipalLess(rules[i].p, rules[j].p)
		}
		return rules[i].path < rules[j].path
	})
	put32(len(rules))
	for _, r := range rules {
		principal(r.p)
		if r.path == "" {
			b.WriteByte(1)
		} else {
			b.WriteByte(0)
		}
		str(r.path)
		b.WriteByte(r.rights.allow)
		b.WriteByte(r.rights.deny)
	}
	if b.Len() > MaxPolicyEncoding {
		return nil, ErrPolicyEncoding
	}
	return b.Bytes(), nil
}

type policyReader struct {
	b   []byte
	bad bool
}

func (r *policyReader) take(n int) []byte {
	if r.bad || n < 0 || n > len(r.b) {
		r.bad = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *policyReader) byte() byte {
	b := r.take(1)
	if len(b) == 0 {
		return 0
	}
	return b[0]
}
func (r *policyReader) count(max int) int {
	b := r.take(4)
	if len(b) != 4 {
		return 0
	}
	n := uint64(binary.BigEndian.Uint32(b))
	if n > uint64(max) {
		r.bad = true
		return 0
	}
	return int(n)
}
func (r *policyReader) str(max int) string { n := r.count(max); return string(r.take(n)) }
func (r *policyReader) principal() PrincipalID {
	p := PrincipalID{Issuer: r.str(4096), Subject: r.str(4096)}
	c := r.byte()
	if c < 1 || c > 4 {
		r.bad = true
	} else {
		p.Class = policyClasses[c-1]
	}
	return p
}
func (r *policyReader) flag() bool {
	b := r.byte()
	if b > 1 {
		r.bad = true
	}
	return b == 1
}
func (r *policyReader) caps() []RepositoryCapability {
	b := r.byte()
	if b&^63 != 0 {
		r.bad = true
	}
	var out []RepositoryCapability
	for i, c := range policyCaps {
		if b&(1<<i) != 0 {
			out = append(out, c)
		}
	}
	return out
}
func (r *policyReader) actions() []PathAction {
	b := r.byte()
	if b&^15 != 0 {
		r.bad = true
	}
	var out []PathAction
	for i, c := range policyActions {
		if b&(1<<i) != 0 {
			out = append(out, c)
		}
	}
	return out
}

// DecodePolicySnapshot rejects all noncanonical encodings and checks counts
// before allocating. The body and every evaluator aggregate remain bounded.
func DecodePolicySnapshot(b []byte) (PolicySnapshot, error) {
	var p PolicySnapshot
	if len(b) > MaxPolicyEncoding || !bytes.HasPrefix(b, []byte(policyMagic)) {
		return p, ErrPolicyEncoding
	}
	r := policyReader{b: b[len(policyMagic):]}
	p.Repository.Scope = RepositoryScope{r.str(4096), r.str(4096)}
	v := r.take(8)
	if len(v) != 8 {
		return PolicySnapshot{}, ErrPolicyEncoding
	}
	p.Repository.Version = binary.BigEndian.Uint64(v)
	for n := r.count(64); n > 0 && !r.bad; n-- {
		p.Repository.Roles = append(p.Repository.Roles, RepositoryRole{Name: r.str(4096), Allow: r.caps(), Deny: r.caps()})
	}
	for n := r.count(4096); n > 0 && !r.bad; n-- {
		m := RepositoryMember{Principal: r.principal(), Active: r.flag()}
		for k := r.count(64); k > 0 && !r.bad; k-- {
			m.Roles = append(m.Roles, r.str(4096))
		}
		p.Repository.Members = append(p.Repository.Members, m)
	}
	p.Paths.Scope = p.Repository.Scope
	p.Paths.Version = p.Repository.Version
	for n := r.count(4096); n > 0 && !r.bad; n-- {
		p.Paths.Rules = append(p.Paths.Rules, PathRule{Principal: r.principal(), Selector: PathSelector{Root: r.flag(), Path: []byte(r.str(65535))}, Allow: r.actions(), Deny: r.actions()})
	}
	if r.bad || len(r.b) != 0 {
		return PolicySnapshot{}, ErrPolicyEncoding
	}
	canonical, err := EncodePolicySnapshot(p)
	if err != nil || !bytes.Equal(canonical, b) {
		return PolicySnapshot{}, ErrPolicyEncoding
	}
	return p, nil
}
