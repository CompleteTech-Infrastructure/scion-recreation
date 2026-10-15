package authz

import (
	"context"
	"errors"

	"canopy.local/canopy/internal/model"
)

type PathAction string

const (
	PathTraverse PathAction = "traverse"
	PathList     PathAction = "list"
	PathRead     PathAction = "read"
	PathWrite    PathAction = "write"
)

// PathSelector is either explicit ROOT (Root=true, no Path bytes), or a
// canonical nonempty relative byte path. The zero value is invalid.
type PathSelector struct {
	Root bool
	Path []byte
}

type PathRule struct {
	Principal   PrincipalID
	Selector    PathSelector
	Allow, Deny []PathAction
}

// PathPolicy is trusted, already resolved authority configuration, not request
// input or a wire format. Rules bind exact principals; groups/roles must be
// resolved before construction. Repository membership/capabilities remain
// separate. Limits: 4096 rules, canonical path limits, 1 MiB aggregate scope,
// principal and prefix bytes (including repetitions).
type PathPolicy struct {
	Scope   RepositoryScope
	Version uint64
	Rules   []PathRule
}

type PathDecision struct {
	Allowed       bool
	PolicyVersion uint64
}

var (
	ErrPathPolicy = errors.New("invalid path policy")
	ErrPathDenied = errors.New("resource unavailable")
)

type pathRights struct{ allow, deny uint8 }

// PathPolicyEngine is an immutable local path-policy snapshot coupled to the
// exact repository policy version. Retain it as trusted authority configuration;
// never reconstruct it from request data. Every repository or path ACL edit
// must advance the shared repository version; same-version replacement is not
// a policy update. Repository updates invalidate all old path engines.
// Durable policy publication, sessions, storage and serving adapters are outside
// this evaluator. Decisions authorize only the named version at evaluation and
// are not transferable object grants or authorization to serve cached bytes.
type PathPolicyEngine struct {
	repository *RepositoryPolicyEngine
	scope      RepositoryScope
	version    uint64
	rules      map[PrincipalID]map[string]pathRights
}

func pathSelectorValid(s PathSelector) bool {
	if s.Root {
		return len(s.Path) == 0
	}
	return model.ValidatePath(s.Path) == nil
}

func pathBit(action PathAction) uint8 {
	switch action {
	case PathTraverse:
		return 1
	case PathList:
		return 2
	case PathRead:
		return 4
	case PathWrite:
		return 8
	}
	return 0
}

func pathBits(actions []PathAction) (uint8, bool) {
	if len(actions) > 4 {
		return 0, false
	}
	var bits uint8
	for _, a := range actions {
		b := pathBit(a)
		if b == 0 || bits&b != 0 {
			return 0, false
		}
		bits |= b
	}
	return bits, true
}

func (r pathRights) permits(bits uint8) bool { return r.allow&^r.deny&bits == bits }
func (r pathRights) with(next pathRights) pathRights {
	return pathRights{r.allow | next.allow, r.deny | next.deny}
}

// NewPathPolicy copies all mutable inputs. Missing/unresolved configuration is
// never interpreted as a wildcard grant. Multiple rules at one selector combine
// with deny precedence, independent of input order.
func NewPathPolicy(p PathPolicy, repository *RepositoryPolicyEngine) (*PathPolicyEngine, error) {
	if repository == nil || !repositoryScopeValid(p.Scope) || len(p.Rules) > 4096 {
		return nil, ErrPathPolicy
	}
	e := &PathPolicyEngine{repository, p.Scope, p.Version, make(map[PrincipalID]map[string]pathRights)}
	bytes := len(p.Scope.TenantID) + len(p.Scope.RepositoryID)
	for _, rule := range p.Rules {
		if !repositoryPrincipalValid(rule.Principal) || !pathSelectorValid(rule.Selector) {
			return nil, ErrPathPolicy
		}
		bytes += len(rule.Principal.Issuer) + len(rule.Principal.Subject) + len(rule.Selector.Path)
		a, okA := pathBits(rule.Allow)
		d, okD := pathBits(rule.Deny)
		if bytes > 1<<20 || !okA || !okD {
			return nil, ErrPathPolicy
		}
		if e.rules[rule.Principal] == nil {
			e.rules[rule.Principal] = make(map[string]pathRights)
		}
		// Only validated explicit ROOT can produce the internal empty key.
		key := string(rule.Selector.Path)
		e.rules[rule.Principal][key] = e.rules[rule.Principal][key].with(pathRights{a, d})
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	if repository.current == nil || repository.current.scope != p.Scope || repository.current.version != p.Version {
		return nil, ErrPathPolicy
	}
	return e, nil
}

// pathAllowed checks prefixes only at byte 0x2f boundaries, accumulating every
// applicable deny. No storage/existence lookup, filesystem or normalization is
// involved. Map lookups walk at most the canonical number of path components.
func (e *PathPolicyEngine) pathAllowed(principal PrincipalID, selection PathSelector, action PathAction) bool {
	rules := e.rules[principal]
	rights := rules[""]
	if !selection.Root {
		if !rights.permits(pathBit(PathTraverse)) {
			return false
		}
		path := string(selection.Path)
		for i := 0; i < len(path); i++ {
			if path[i] == '/' {
				rights = rights.with(rules[path[:i]])
				if !rights.permits(pathBit(PathTraverse)) {
					return false
				}
			}
		}
		rights = rights.with(rules[path])
	}
	bits := pathBit(action)
	if action == PathList {
		// A directory hidden by traversal policy cannot expose child names.
		bits |= pathBit(PathTraverse)
	}
	return rights.permits(bits)
}

// evaluate holds one repository head across all endpoint checks. Identity is a
// trusted IdentityResolver output, as required by RepositoryPolicyEngine.
func (e *PathPolicyEngine) evaluate(ctx context.Context, identity Identity, scope RepositoryScope, version uint64, action PathAction, selections ...PathSelector) (PathDecision, error) {
	if e == nil || e.repository == nil || scope != e.scope || version != e.version || pathBit(action) == 0 {
		return PathDecision{}, ErrPathDenied
	}
	for _, s := range selections {
		if !pathSelectorValid(s) || (s.Root && (action == PathRead || action == PathWrite)) {
			return PathDecision{}, ErrPathDenied
		}
	}
	r := e.repository
	r.mu.RLock()
	defer r.mu.RUnlock()
	capability := RepositoryRead
	if action == PathWrite {
		capability = RepositoryWrite
	}
	s := r.current
	if s == nil || s.scope != scope || s.version != version || !r.repositoryIdentity(ctx, identity) || repositoryEffective(s, identity.Principal)&repositoryBit(capability) == 0 {
		return PathDecision{}, ErrPathDenied
	}
	allowed := true
	for _, selection := range selections {
		if !e.pathAllowed(identity.Principal, selection, action) {
			allowed = false
		}
	}
	if !allowed || !r.repositoryIdentity(ctx, identity) {
		return PathDecision{}, ErrPathDenied
	}
	return PathDecision{true, version}, nil
}

// Evaluate requires repository read for traverse/list/read, or repository write
// for mutations, plus traversal of ROOT and each ancestor and the target right.
// Listing also requires target traversal; ROOT supports list/traverse only.
// All denials return identical zero data and error, without hidden path bytes,
// existence, counts or denial reasons. Serving adapters must use that same public
// shape for missing resources and must authorize before any lookup or mutation.
func (e *PathPolicyEngine) Evaluate(ctx context.Context, identity Identity, scope RepositoryScope, version uint64, selection PathSelector, action PathAction) (PathDecision, error) {
	return e.evaluate(ctx, identity, scope, version, action, selection)
}

// EvaluateRename authorizes source removal and destination creation separately
// before returning any allow result. It performs no mutation or existence probe.
// An authority adapter must bind the ensuing atomic mutation to this version;
// this decision is not a durable lease and cannot bypass subsequent revocation.
func (e *PathPolicyEngine) EvaluateRename(ctx context.Context, identity Identity, scope RepositoryScope, version uint64, source, destination PathSelector) (PathDecision, error) {
	return e.evaluate(ctx, identity, scope, version, PathWrite, source, destination)
}
