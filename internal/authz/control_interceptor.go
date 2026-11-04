package authz

import "context"

// SourcePathAccess is one trusted handler's resolved input or output path check.
// It is not a wire request, revision proof, object grant, or existence assertion.
type SourcePathAccess struct {
	Selection PathSelector
	Action    PathAction
}

// SourceAccess is a bounded set of required rights compiled by trusted service
// composition, never accepted as the caller's description of its own rights.
// The service must enumerate every disclosed/modified input and output path,
// including both rename sides and merge conflicts. Metadata and history flags
// describe all disclosed fields/edges, not caller preferences. Empty path sets
// are rejected; pathless ref/history operations require separate authorization.
// Inputs must not be mutated concurrently with evaluation.
type SourceAccess struct {
	Paths        []SourcePathAccess
	ReadMetadata bool
	ReadHistory  bool
}

const (
	MaxSourceAccessPaths = 4096
	MaxSourceAccessBytes = 1 << 20
)

// EvaluateSourceAccess atomically checks a mixed read/write batch against one
// current repository-policy head. This is an internal authorization primitive,
// NOT a gRPC interceptor or an implementation of a source endpoint. Authentic
// identity/session/view binding, exact revision and alias resolution, complete
// path discovery and response projection remain trusted adapter obligations.
// A successful decision is neither a lease nor permission to reuse the result
// after policy changes: reauthorize before emission and bind mutations to the
// exact policy at commit. This method performs no storage or existence lookups
// and returns the same zero result and error for all unsuccessful checks.
func (e *PathPolicyEngine) EvaluateSourceAccess(ctx context.Context, identity Identity,
	scope RepositoryScope, version uint64, access SourceAccess) (PathDecision, error) {
	deny := func() (PathDecision, error) { return PathDecision{}, ErrPathDenied }
	if ctx == nil || ctx.Err() != nil || e == nil || e.repository == nil ||
		scope != e.scope || version != e.version || len(access.Paths) == 0 ||
		len(access.Paths) > MaxSourceAccessPaths {
		return deny()
	}
	var required uint8
	if access.ReadMetadata {
		required |= repositoryBit(RepositoryMetadataRead) | repositoryBit(RepositoryRead)
	}
	if access.ReadHistory {
		required |= repositoryBit(RepositoryHistoryRead) | repositoryBit(RepositoryRead)
	}
	remaining := MaxSourceAccessBytes
	for _, check := range access.Paths {
		if ctx.Err() != nil || len(check.Selection.Path) > remaining {
			return deny()
		}
		remaining -= len(check.Selection.Path)
		if pathBit(check.Action) == 0 || !pathSelectorValid(check.Selection) ||
			(check.Selection.Root && (check.Action == PathRead || check.Action == PathWrite)) {
			return deny()
		}
		if check.Action == PathWrite {
			required |= repositoryBit(RepositoryWrite)
		} else {
			required |= repositoryBit(RepositoryRead)
		}
	}
	r := e.repository
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := r.current
	if s == nil || s.scope != scope || s.version != version ||
		!r.repositoryIdentity(ctx, identity) ||
		repositoryEffective(s, identity.Principal)&required != required {
		return deny()
	}
	allowed := true
	for _, check := range access.Paths {
		if ctx.Err() != nil {
			return deny()
		}
		if !e.pathAllowed(identity.Principal, check.Selection, check.Action) {
			allowed = false
		}
	}
	if !allowed || !r.repositoryIdentity(ctx, identity) {
		return deny()
	}
	return PathDecision{Allowed: true, PolicyVersion: version}, nil
}
