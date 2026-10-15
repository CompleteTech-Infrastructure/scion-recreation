package authz_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"canopy.local/canopy/internal/authz"
)

const repoAudience = "repository-policy-test"

func repoClock() (time.Time, error) { return time.Unix(150, 0), nil }

// These values model trusted IdentityResolver outputs; resolver signatures have separate tests.
func repoIdentity(issuer, subject string, class authz.PrincipalClass, audience string) authz.Identity {
	return authz.Identity{Principal: authz.PrincipalID{Issuer: issuer, Subject: subject, Class: class}, Audience: audience, ExpiresAt: time.Unix(200, 0)}
}

func repoPrincipal(subject string) authz.PrincipalID {
	return repoIdentity("fixture-issuer", subject, authz.Human, repoAudience).Principal
}

func repoPolicy() authz.RepositoryPolicy {
	return authz.RepositoryPolicy{
		Scope: repoScope(),
		Roles: []authz.RepositoryRole{
			{Name: "writer", Allow: []authz.RepositoryCapability{authz.RepositoryRead, authz.RepositoryWrite}},
			{Name: "reviewer", Allow: []authz.RepositoryCapability{authz.RepositoryRead, authz.RepositoryApprove}},
			{Name: "administrator", Allow: []authz.RepositoryCapability{authz.RepositoryRead, authz.RepositoryAdmin}},
			{Name: "suppressed", Allow: []authz.RepositoryCapability{authz.RepositoryAdmin, authz.RepositoryApprove}, Deny: []authz.RepositoryCapability{authz.RepositoryAdmin, authz.RepositoryApprove}},
			{Name: "deny-writes", Allow: []authz.RepositoryCapability{authz.RepositoryRead, authz.RepositoryWrite}, Deny: []authz.RepositoryCapability{authz.RepositoryWrite}},
		},
		Members: []authz.RepositoryMember{
			{Principal: repoPrincipal("writer"), Active: true, Roles: []string{"writer", "suppressed"}},
			{Principal: repoPrincipal("reviewer"), Active: true, Roles: []string{"reviewer"}},
			{Principal: repoPrincipal("administrator"), Active: true, Roles: []string{"administrator"}},
			{Principal: repoPrincipal("denied-writer"), Active: true, Roles: []string{"deny-writes"}},
			{Principal: repoPrincipal("membership-only"), Active: true},
		},
	}
}

func repoScope() authz.RepositoryScope {
	return authz.RepositoryScope{TenantID: "tenant-a", RepositoryID: "repo-a"}
}

func repoEngine(t *testing.T, p authz.RepositoryPolicy, clock authz.IdentityClock) *authz.RepositoryPolicyEngine {
	t.Helper()
	e, err := authz.NewRepositoryPolicy(p, repoAudience, clock)
	if err != nil {
		t.Fatalf("construct policy: %v", err)
	}
	return e
}

func repoCheck(t *testing.T, e *authz.RepositoryPolicyEngine, ctx context.Context, id authz.Identity, scope authz.RepositoryScope, version uint64, cap authz.RepositoryCapability, want bool) {
	t.Helper()
	got, err := e.Evaluate(ctx, id, scope, version, cap)
	if want && err == nil && got == (authz.RepositoryDecision{Allowed: true, PolicyVersion: version}) {
		return
	}
	if !want && errors.Is(err, authz.ErrRepositoryDenied) && got == (authz.RepositoryDecision{}) {
		return
	}
	t.Fatalf("Evaluate(%q) = %#v, %v; allowed=%t", cap, got, err, want)
}

func TestRepositoryPolicyCapabilitiesDefaultDenyAndDenyWins(t *testing.T) {
	e := repoEngine(t, repoPolicy(), repoClock)
	cases := []struct {
		name, subject string
		cap           authz.RepositoryCapability
		want          bool
	}{
		{"writer_read", "writer", authz.RepositoryRead, true}, {"writer_write", "writer", authz.RepositoryWrite, true},
		{"writer_no_approve", "writer", authz.RepositoryApprove, false}, {"writer_no_admin", "writer", authz.RepositoryAdmin, false},
		{"reviewer_approve", "reviewer", authz.RepositoryApprove, true}, {"reviewer_no_write", "reviewer", authz.RepositoryWrite, false},
		{"admin_policy", "administrator", authz.RepositoryAdmin, true}, {"admin_no_write", "administrator", authz.RepositoryWrite, false},
		{"unlisted_default_deny", "unlisted", authz.RepositoryRead, false}, {"deny_wins", "denied-writer", authz.RepositoryWrite, false},
		{"membership_without_role_default_deny", "membership-only", authz.RepositoryRead, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repoCheck(t, e, context.Background(), repoIdentity("fixture-issuer", tc.subject, authz.Human, repoAudience), repoScope(), 0, tc.cap, tc.want)
		})
	}
	t.Run("empty_members_default_deny", func(t *testing.T) {
		p := repoPolicy()
		p.Members = nil
		e := repoEngine(t, p, repoClock)
		repoCheck(t, e, context.Background(), repoIdentity("fixture-issuer", "writer", authz.Human, repoAudience), repoScope(), 0, authz.RepositoryRead, false)
	})
}

func TestRepositoryPolicyCapabilitiesAreIndependent(t *testing.T) {
	caps := []authz.RepositoryCapability{authz.RepositoryRead, authz.RepositoryWrite, authz.RepositoryApprove, authz.RepositoryAdmin}
	roles := []string{"read-only", "write-only", "approve-only", "admin-only"}
	want := [4][4]bool{{true, false, false, false}, {false, true, false, false}, {false, false, true, false}, {false, false, false, true}}
	p := authz.RepositoryPolicy{Scope: repoScope()}
	for i, role := range roles {
		p.Roles = append(p.Roles, authz.RepositoryRole{Name: role, Allow: []authz.RepositoryCapability{caps[i]}})
		p.Members = append(p.Members, authz.RepositoryMember{Principal: repoPrincipal(role), Active: true, Roles: []string{role}})
	}
	e := repoEngine(t, p, repoClock)
	for i, role := range roles {
		for j, cap := range caps {
			id := repoIdentity("fixture-issuer", role, authz.Human, repoAudience)
			got, err := e.Evaluate(context.Background(), id, repoScope(), 0, cap)
			if want[i][j] {
				if err != nil || got != (authz.RepositoryDecision{Allowed: true}) {
					t.Fatalf("%s on %s = %#v, %v; want allow", cap, role, got, err)
				}
			} else if !errors.Is(err, authz.ErrRepositoryDenied) || got != (authz.RepositoryDecision{}) {
				t.Fatalf("%s on %s = %#v, %v; want deny", cap, role, got, err)
			}
		}
	}
}

func TestRepositoryPolicyRejectsScopeVersionsAndMalformedInputs(t *testing.T) {
	e, id := repoEngine(t, repoPolicy(), repoClock), repoIdentity("fixture-issuer", "writer", authz.Human, repoAudience)
	for _, tc := range []struct {
		name  string
		scope authz.RepositoryScope
		ver   uint64
		cap   authz.RepositoryCapability
	}{
		{"cross_repo", authz.RepositoryScope{TenantID: "tenant-a", RepositoryID: "repo-b"}, 0, authz.RepositoryRead},
		{"cross_tenant", authz.RepositoryScope{TenantID: "tenant-b", RepositoryID: "repo-a"}, 0, authz.RepositoryRead},
		{"wrong_version", repoScope(), 1, authz.RepositoryRead}, {"empty_scope", authz.RepositoryScope{}, 0, authz.RepositoryRead},
		{"unknown_capability", repoScope(), 0, "publish"},
	} {
		t.Run(tc.name, func(t *testing.T) { repoCheck(t, e, context.Background(), id, tc.scope, tc.ver, tc.cap, false) })
	}
	for _, tc := range []struct {
		name string
		bad  func(*authz.RepositoryPolicy)
	}{
		{"invalid_unknown_capability", func(p *authz.RepositoryPolicy) { p.Roles[0].Allow[0] = "publish" }},
		{"invalid_unknown_role", func(p *authz.RepositoryPolicy) { p.Members[0].Roles = []string{"missing"} }},
		{"invalid_bad_principal", func(p *authz.RepositoryPolicy) { p.Members[0].Principal.Class = "node" }},
		{"invalid_oversized_principal", func(p *authz.RepositoryPolicy) { p.Members[0].Principal.Subject = string(make([]byte, 4097)) }},
		{"invalid_oversized_role", func(p *authz.RepositoryPolicy) { p.Roles[0].Name = string(make([]byte, 4097)) }},
		{"invalid_empty_role", func(p *authz.RepositoryPolicy) { p.Roles[0].Name = "" }},
		{"invalid_duplicate_capability", func(p *authz.RepositoryPolicy) {
			p.Roles[0].Allow = []authz.RepositoryCapability{authz.RepositoryRead, authz.RepositoryRead}
		}},
		{"invalid_duplicate_role", func(p *authz.RepositoryPolicy) { p.Roles = append(p.Roles, p.Roles[0]) }},
		{"invalid_duplicate_member", func(p *authz.RepositoryPolicy) { p.Members = append(p.Members, p.Members[0]) }},
		{"invalid_too_many_roles", func(p *authz.RepositoryPolicy) { p.Roles = make([]authz.RepositoryRole, 65) }},
		{"invalid_too_many_members", func(p *authz.RepositoryPolicy) { p.Members = make([]authz.RepositoryMember, 4097) }},
		{"invalid_aggregate_identity_bytes", func(p *authz.RepositoryPolicy) {
			p.Members = make([]authz.RepositoryMember, 300)
			for i := range p.Members {
				p.Members[i] = authz.RepositoryMember{Principal: authz.PrincipalID{Issuer: strings.Repeat("i", 4096), Subject: strconv.Itoa(i), Class: authz.Human}, Active: true, Roles: []string{"writer"}}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := authz.NewRepositoryPolicy(func() authz.RepositoryPolicy { p := repoPolicy(); tc.bad(&p); return p }(), repoAudience, repoClock); !errors.Is(err, authz.ErrRepositoryPolicy) {
				t.Fatalf("constructor error = %v; want ErrRepositoryPolicy", err)
			}
		})
	}
	if _, err := authz.NewRepositoryPolicy(repoPolicy(), repoAudience, nil); !errors.Is(err, authz.ErrRepositoryPolicy) {
		t.Fatalf("nil clock constructor error = %v; want ErrRepositoryPolicy", err)
	}
}

func TestRepositoryPolicyUpdateRequiresAdminAndRemovesMembership(t *testing.T) {
	e, next := repoEngine(t, repoPolicy(), repoClock), repoPolicy()
	next.Version, next.Members[0].Active = 1, false
	writer := repoIdentity("fixture-issuer", "writer", authz.Human, repoAudience)
	admin := repoIdentity("fixture-issuer", "administrator", authz.Human, repoAudience)
	if err := e.Update(context.Background(), writer, repoScope(), 0, next); !errors.Is(err, authz.ErrRepositoryDenied) {
		t.Fatalf("writer update error = %v; want denied", err)
	}
	if err := e.Update(context.Background(), admin, repoScope(), 1, next); !errors.Is(err, authz.ErrRepositoryDenied) {
		t.Fatalf("stale update error = %v; want denied", err)
	}
	bad := next
	bad.Version = 2
	if err := e.Update(context.Background(), admin, repoScope(), 0, bad); !errors.Is(err, authz.ErrRepositoryDenied) {
		t.Fatalf("skipped-version update error = %v; want denied", err)
	}
	wrongScope := repoPolicy()
	wrongScope.Version, wrongScope.Scope.RepositoryID = 1, "repo-b"
	if err := e.Update(context.Background(), admin, repoScope(), 0, wrongScope); !errors.Is(err, authz.ErrRepositoryDenied) {
		t.Fatalf("cross-repository update error = %v; want denied", err)
	}
	malformed := repoPolicy()
	malformed.Version, malformed.Roles[0].Allow[0] = 1, "publish"
	if err := e.Update(context.Background(), admin, repoScope(), 0, malformed); !errors.Is(err, authz.ErrRepositoryDenied) {
		t.Fatalf("malformed update error = %v; want denied", err)
	}
	repoCheck(t, e, context.Background(), writer, repoScope(), 0, authz.RepositoryWrite, true)
	if err := e.Update(context.Background(), admin, repoScope(), 0, next); err != nil {
		t.Fatalf("valid update: %v", err)
	}
	next.Members[0].Active, next.Roles[2].Allow[1] = true, authz.RepositoryWrite // Published policy must not alias caller memory.
	repoCheck(t, e, context.Background(), writer, repoScope(), 1, authz.RepositoryWrite, false)
	repoCheck(t, e, context.Background(), writer, repoScope(), 0, authz.RepositoryWrite, false)
	repoCheck(t, e, context.Background(), admin, repoScope(), 1, authz.RepositoryAdmin, true)
	repoCheck(t, e, context.Background(), admin, repoScope(), 1, authz.RepositoryWrite, false)
}

func TestRepositoryPolicyWriterCannotEscalateThroughUpdates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		attack func(*authz.RepositoryPolicy)
	}{
		{"new_admin_approve_role", func(p *authz.RepositoryPolicy) {
			p.Roles = append(p.Roles, authz.RepositoryRole{Name: "owner", Allow: []authz.RepositoryCapability{authz.RepositoryAdmin, authz.RepositoryApprove}})
			p.Members[0].Roles = append(p.Members[0].Roles, "owner")
		}},
		{"redefine_writer_role", func(p *authz.RepositoryPolicy) {
			p.Roles[0].Allow = append(p.Roles[0].Allow, authz.RepositoryAdmin, authz.RepositoryApprove)
		}},
		{"assign_approval_role", func(p *authz.RepositoryPolicy) { p.Members[0].Roles = append(p.Members[0].Roles, "reviewer") }},
		{"remove_explicit_denies", func(p *authz.RepositoryPolicy) { p.Roles[3].Deny = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, next := repoEngine(t, repoPolicy(), repoClock), repoPolicy()
			next.Version = 1
			tc.attack(&next)
			writer := repoIdentity("fixture-issuer", "writer", authz.Human, repoAudience)
			if err := e.Update(context.Background(), writer, repoScope(), 0, next); !errors.Is(err, authz.ErrRepositoryDenied) {
				t.Fatalf("escalation update error = %v; want denied", err)
			}
			repoCheck(t, e, context.Background(), writer, repoScope(), 0, authz.RepositoryWrite, true)
			repoCheck(t, e, context.Background(), writer, repoScope(), 0, authz.RepositoryAdmin, false)
			repoCheck(t, e, context.Background(), writer, repoScope(), 0, authz.RepositoryApprove, false)
		})
	}
	t.Run("admin_cannot_self_approve", func(t *testing.T) {
		e, next := repoEngine(t, repoPolicy(), repoClock), repoPolicy()
		next.Version = 1
		next.Roles[2].Allow = append(next.Roles[2].Allow, authz.RepositoryApprove)
		admin := repoIdentity("fixture-issuer", "administrator", authz.Human, repoAudience)
		if err := e.Update(context.Background(), admin, repoScope(), 0, next); !errors.Is(err, authz.ErrRepositoryDenied) {
			t.Fatalf("self-approval update error = %v; want denied", err)
		}
		repoCheck(t, e, context.Background(), admin, repoScope(), 0, authz.RepositoryAdmin, true)
		repoCheck(t, e, context.Background(), admin, repoScope(), 0, authz.RepositoryApprove, false)
	})
	t.Run("admin_cannot_remove_approval_deny", func(t *testing.T) {
		p := repoPolicy()
		p.Roles = append(p.Roles, authz.RepositoryRole{Name: "approval-barrier", Allow: []authz.RepositoryCapability{authz.RepositoryApprove}, Deny: []authz.RepositoryCapability{authz.RepositoryApprove}})
		p.Members[2].Roles = append(p.Members[2].Roles, "approval-barrier")
		e, next := repoEngine(t, p, repoClock), p
		next.Version, next.Roles[5].Deny = 1, nil
		admin := repoIdentity("fixture-issuer", "administrator", authz.Human, repoAudience)
		if err := e.Update(context.Background(), admin, repoScope(), 0, next); !errors.Is(err, authz.ErrRepositoryDenied) {
			t.Fatalf("deny-removal update error = %v; want denied", err)
		}
		repoCheck(t, e, context.Background(), admin, repoScope(), 0, authz.RepositoryAdmin, true)
		repoCheck(t, e, context.Background(), admin, repoScope(), 0, authz.RepositoryApprove, false)
	})
}

func TestRepositoryPolicySnapshotDeterminismAndPrincipalTupleIsolation(t *testing.T) {
	p := repoPolicy()
	p.Members = []authz.RepositoryMember{{Principal: authz.PrincipalID{Issuer: "a:b", Subject: "c", Class: authz.Human}, Active: true, Roles: []string{"writer"}}}
	e := repoEngine(t, p, repoClock)
	p.Roles[0].Allow[0], p.Members[0].Active = authz.RepositoryApprove, false
	id := repoIdentity("a:b", "c", authz.Human, repoAudience)
	first, err := e.Evaluate(context.Background(), id, repoScope(), 0, authz.RepositoryRead)
	second, repeatErr := e.Evaluate(context.Background(), id, repoScope(), 0, authz.RepositoryRead)
	if err != nil || repeatErr != nil || first != (authz.RepositoryDecision{Allowed: true}) || second != first {
		t.Fatalf("non-deterministic or aliased evaluation: first=%#v/%v second=%#v/%v", first, err, second, repeatErr)
	}
	repoCheck(t, e, context.Background(), repoIdentity("a", "b:c", authz.Human, repoAudience), repoScope(), 0, authz.RepositoryRead, false)
	repoCheck(t, e, context.Background(), repoIdentity("a:b", "c", authz.BuildJob, repoAudience), repoScope(), 0, authz.RepositoryRead, false)
}

func TestRepositoryPolicyFailsClosedForIdentityContextAndClock(t *testing.T) {
	e := repoEngine(t, repoPolicy(), repoClock)
	writer := repoIdentity("fixture-issuer", "writer", authz.Human, repoAudience)
	for _, tc := range []struct {
		name string
		edit func(*authz.Identity)
	}{
		{"wrong_audience", func(i *authz.Identity) { i.Audience = "other" }},
		{"expired", func(i *authz.Identity) { i.ExpiresAt = time.Unix(150, 0) }},
		{"unknown_class", func(i *authz.Identity) { i.Principal.Class = "node" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := writer
			tc.edit(&id)
			repoCheck(t, e, context.Background(), id, repoScope(), 0, authz.RepositoryRead, false)
		})
	}
	var nilEngine *authz.RepositoryPolicyEngine
	for _, tc := range []struct {
		name string
		e    *authz.RepositoryPolicyEngine
		ctx  context.Context
	}{
		{"nil_engine", nilEngine, context.Background()}, {"zero_engine", &authz.RepositoryPolicyEngine{}, context.Background()}, {"nil_context", e, nil},
	} {
		t.Run(tc.name, func(t *testing.T) { repoCheck(t, tc.e, tc.ctx, writer, repoScope(), 0, authz.RepositoryRead, false) })
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	repoCheck(t, e, canceled, writer, repoScope(), 0, authz.RepositoryRead, false)
	for _, clock := range []authz.IdentityClock{
		func() (time.Time, error) { return time.Time{}, errors.New("clock failure") },
		func() (time.Time, error) { return time.Time{}, nil },
	} {
		repoCheck(t, repoEngine(t, repoPolicy(), clock), context.Background(), writer, repoScope(), 0, authz.RepositoryRead, false)
	}
}

func TestRepositoryPolicyConcurrentExpectedVersionPublishesOnce(t *testing.T) {
	e := repoEngine(t, repoPolicy(), repoClock)
	admin := repoIdentity("fixture-issuer", "administrator", authz.Human, repoAudience)
	a, b := repoPolicy(), repoPolicy()
	a.Version, b.Version, a.Members[1].Active, b.Members[0].Active = 1, 1, false, false
	start, results := make(chan struct{}), make(chan error, 2)
	for _, next := range []authz.RepositoryPolicy{a, b} {
		go func(p authz.RepositoryPolicy) {
			<-start
			results <- e.Update(context.Background(), admin, repoScope(), 0, p)
		}(next)
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, authz.ErrRepositoryDenied) {
			t.Fatalf("losing update error = %v; want denial", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful updates = %d; want one", successes)
	}
	repoCheck(t, e, context.Background(), admin, repoScope(), 1, authz.RepositoryAdmin, true)
}

func TestRepositoryPolicyVersionCannotWrap(t *testing.T) {
	max := ^uint64(0)
	p := repoPolicy()
	p.Version = max
	e := repoEngine(t, p, repoClock)
	next := repoPolicy()
	admin := repoIdentity("fixture-issuer", "administrator", authz.Human, repoAudience)
	if err := e.Update(context.Background(), admin, repoScope(), max, next); !errors.Is(err, authz.ErrRepositoryDenied) {
		t.Fatalf("wrapping update error = %v; want denied", err)
	}
	repoCheck(t, e, context.Background(), admin, repoScope(), max, authz.RepositoryAdmin, true)
}
