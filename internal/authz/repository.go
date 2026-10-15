package authz

import (
	"context"
	"errors"
	"sync"
)

type RepositoryScope struct{ TenantID, RepositoryID string }
type RepositoryCapability string

const (
	RepositoryRead    RepositoryCapability = "read"
	RepositoryWrite   RepositoryCapability = "write"
	RepositoryApprove RepositoryCapability = "approve"
	RepositoryAdmin   RepositoryCapability = "administer-policy"
)

type RepositoryRole struct {
	Name        string
	Allow, Deny []RepositoryCapability
}

type RepositoryMember struct {
	Principal PrincipalID
	Active    bool
	Roles     []string
}

// RepositoryPolicy is an internal configuration input, not a wire format.
// Names are opaque exact bytes. Roles grant only their explicit capabilities;
// any applicable deny wins. Membership alone confers no capability or path right.
// Limits: 64 roles, 4096 members, 64 role assignments/member, 4096 bytes/name,
// and 1 MiB total scope/principal/role-name bytes including repeated references.
type RepositoryPolicy struct {
	Scope   RepositoryScope
	Version uint64
	Roles   []RepositoryRole
	Members []RepositoryMember
}

type RepositoryDecision struct {
	Allowed       bool
	PolicyVersion uint64
}

var (
	ErrRepositoryPolicy = errors.New("invalid repository policy")
	ErrRepositoryDenied = errors.New("repository authorization denied")
)

type repositoryRights struct{ allow, deny uint8 }
type repositorySnapshot struct {
	scope   RepositoryScope
	version uint64
	members map[PrincipalID]repositoryRights
}

// RepositoryPolicyEngine holds one authoritative local policy head. The mutex
// protects only policy metadata publication; it is not a repository commit lock.
// Durable audit/storage, sessions, path rights and deployed revocation are adapter
// responsibilities. Decisions are valid only for the named version at evaluation.
// An engine must not be copied after first use.
type RepositoryPolicyEngine struct {
	mu       sync.RWMutex
	current  *repositorySnapshot
	audience string
	now      IdentityClock
}

func repositoryBounded(s string) bool { return len(s) > 0 && len(s) <= 4096 }
func repositoryScopeValid(s RepositoryScope) bool {
	return repositoryBounded(s.TenantID) && repositoryBounded(s.RepositoryID)
}
func repositoryPrincipalValid(p PrincipalID) bool {
	if !repositoryBounded(p.Issuer) || !repositoryBounded(p.Subject) {
		return false
	}
	switch p.Class {
	case Human, BuildJob, ModelWorker, ServiceAccount:
		return true
	}
	return false
}
func repositoryBit(c RepositoryCapability) uint8 {
	switch c {
	case RepositoryRead:
		return 1
	case RepositoryWrite:
		return 2
	case RepositoryApprove:
		return 4
	case RepositoryAdmin:
		return 8
	}
	return 0
}
func repositoryBits(caps []RepositoryCapability) (uint8, bool) {
	if len(caps) > 4 {
		return 0, false
	}
	var bits uint8
	for _, c := range caps {
		b := repositoryBit(c)
		if b == 0 || bits&b != 0 {
			return 0, false
		}
		bits |= b
	}
	return bits, true
}
func repositoryCompile(p RepositoryPolicy) (*repositorySnapshot, error) {
	if !repositoryScopeValid(p.Scope) || len(p.Roles) > 64 || len(p.Members) > 4096 {
		return nil, ErrRepositoryPolicy
	}
	roles := make(map[string]repositoryRights, len(p.Roles))
	bytes := len(p.Scope.TenantID) + len(p.Scope.RepositoryID)
	for _, r := range p.Roles {
		if !repositoryBounded(r.Name) {
			return nil, ErrRepositoryPolicy
		}
		bytes += len(r.Name)
		if bytes > 1<<20 {
			return nil, ErrRepositoryPolicy
		}
		a, okA := repositoryBits(r.Allow)
		d, okD := repositoryBits(r.Deny)
		_, duplicate := roles[r.Name]
		if duplicate || !okA || !okD {
			return nil, ErrRepositoryPolicy
		}
		roles[r.Name] = repositoryRights{a, d}
	}
	s := &repositorySnapshot{p.Scope, p.Version, make(map[PrincipalID]repositoryRights, len(p.Members))}
	for _, m := range p.Members {
		if !repositoryPrincipalValid(m.Principal) || len(m.Roles) > 64 {
			return nil, ErrRepositoryPolicy
		}
		bytes += len(m.Principal.Issuer) + len(m.Principal.Subject)
		if bytes > 1<<20 {
			return nil, ErrRepositoryPolicy
		}
		_, duplicate := s.members[m.Principal]
		if duplicate {
			return nil, ErrRepositoryPolicy
		}
		seen := make(map[string]bool, len(m.Roles))
		var rights repositoryRights
		for _, name := range m.Roles {
			if !repositoryBounded(name) {
				return nil, ErrRepositoryPolicy
			}
			bytes += len(name)
			if bytes > 1<<20 {
				return nil, ErrRepositoryPolicy
			}
			r, ok := roles[name]
			if !ok || seen[name] {
				return nil, ErrRepositoryPolicy
			}
			seen[name] = true
			rights.allow |= r.allow
			rights.deny |= r.deny
		}
		if !m.Active {
			rights = repositoryRights{}
		}
		s.members[m.Principal] = rights
	}
	return s, nil
}

// NewRepositoryPolicy bootstraps from trusted authority configuration only.
// Request handlers must retain this engine and use Update, never reconstruct it
// from requester-provided policy. Compilation retains no mutable input aliases.
// A zero version is valid; each update must increment exactly once without wrap.
func NewRepositoryPolicy(initial RepositoryPolicy, audience string, now IdentityClock) (*RepositoryPolicyEngine, error) {
	s, err := repositoryCompile(initial)
	if err != nil || !repositoryBounded(audience) || now == nil {
		return nil, ErrRepositoryPolicy
	}
	return &RepositoryPolicyEngine{current: s, audience: audience, now: now}, nil
}

func repositoryEffective(s *repositorySnapshot, p PrincipalID) uint8 {
	r := s.members[p]
	return r.allow &^ r.deny
}

// repositoryIdentity accepts only authenticated IdentityResolver outputs supplied
// by a trusted adapter. A caller-created Identity is not authentication proof.
// The injected clock is trusted, bounded and must not reenter this engine.
func (e *RepositoryPolicyEngine) repositoryIdentity(ctx context.Context, i Identity) bool {
	if ctx == nil || ctx.Err() != nil || e.now == nil || !repositoryPrincipalValid(i.Principal) || i.Audience != e.audience {
		return false
	}
	now, err := e.now()
	return err == nil && !now.IsZero() && !i.ExpiresAt.IsZero() && now.Before(i.ExpiresAt) && ctx.Err() == nil
}

// Evaluate fails closed with a uniform zero decision on every denied input.
// It checks the current head, not a caller-supplied or cached policy snapshot.
func (e *RepositoryPolicyEngine) Evaluate(ctx context.Context, identity Identity, scope RepositoryScope, expectedVersion uint64, capability RepositoryCapability) (RepositoryDecision, error) {
	if e == nil || !repositoryScopeValid(scope) || repositoryBit(capability) == 0 {
		return RepositoryDecision{}, ErrRepositoryDenied
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	s := e.current
	if s == nil || s.scope != scope || s.version != expectedVersion || !e.repositoryIdentity(ctx, identity) || repositoryEffective(s, identity.Principal)&repositoryBit(capability) == 0 {
		return RepositoryDecision{}, ErrRepositoryDenied
	}
	return RepositoryDecision{true, s.version}, nil
}

// Update atomically publishes one immutable next version. Authorization always
// uses the old head. Even an administrator cannot increase its own effective
// approval/admin rights via membership, role definitions or removal of denies.
// Failure leaves the current head unchanged. Persistence/CAS across processes
// must be provided by an authority adapter before this can serve deployments.
func (e *RepositoryPolicyEngine) Update(ctx context.Context, identity Identity, scope RepositoryScope, expectedVersion uint64, next RepositoryPolicy) error {
	if e == nil || !repositoryScopeValid(scope) || next.Scope != scope || expectedVersion == ^uint64(0) || next.Version != expectedVersion+1 {
		return ErrRepositoryDenied
	}
	// Authenticate and authorize before bounded compilation. Recheck the exact
	// immutable head and identity after compilation to close publication races.
	e.mu.RLock()
	s := e.current
	allowed := s != nil && s.scope == scope && s.version == expectedVersion && e.repositoryIdentity(ctx, identity) && repositoryEffective(s, identity.Principal)&repositoryBit(RepositoryAdmin) != 0
	e.mu.RUnlock()
	if !allowed {
		return ErrRepositoryDenied
	}
	n, err := repositoryCompile(next)
	if err != nil {
		return ErrRepositoryDenied
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.current != s || !e.repositoryIdentity(ctx, identity) {
		return ErrRepositoryDenied
	}
	old := repositoryEffective(s, identity.Principal)
	if (repositoryEffective(n, identity.Principal)&^old)&(repositoryBit(RepositoryAdmin)|repositoryBit(RepositoryApprove)) != 0 {
		return ErrRepositoryDenied
	}
	e.current = n
	return nil
}
