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

const repositoryTestAudience = "repository-policy-test"

func repositoryTestClock() (time.Time, error) { return time.Unix(150, 0), nil }

// These values model trusted IdentityResolver outputs; resolver signatures have separate tests.
func repositoryTestIdentity(issuer, subject string, class authz.PrincipalClass, audience string) authz.Identity {
	return authz.Identity{Principal: authz.PrincipalID{Issuer: issuer, Subject: subject, Class: class}, Audience: audience, ExpiresAt: time.Unix(200, 0)}
}

func repositoryTestPrincipal(subject string) authz.PrincipalID {
	return repositoryTestIdentity("fixture-issuer", subject, authz.Human, repositoryTestAudience).Principal
}

func repositoryTestPolicy() authz.RepositoryPolicy {
	return authz.RepositoryPolicy{
		Scope: repositoryTestScope(),
		Roles: []authz.RepositoryRole{
			{Name: "writer", Allow: []authz.RepositoryCapability{authz.RepositoryRead, authz.RepositoryWrite}},
			{Name: "reviewer", Allow: []authz.RepositoryCapability{authz.RepositoryRead, authz.RepositoryApprove}},
			{Name: "administrator", Allow: []authz.RepositoryCapability{authz.RepositoryRead, authz.RepositoryAdmin}},
			{Name: "suppressed", Allow: []authz.RepositoryCapability{authz.RepositoryAdmin, authz.RepositoryApprove}, Deny: []authz.RepositoryCapability{authz.RepositoryAdmin, authz.RepositoryApprove}},
			{Name: "deny-writes", Allow: []authz.RepositoryCapability{authz.RepositoryRead, authz.RepositoryWrite}, Deny: []authz.RepositoryCapability{authz.RepositoryWrite}},
		},
		Members: []authz.RepositoryMember{
			{Principal: repositoryTestPrincipal("writer"), Active: true, Roles: []string{"writer", "suppressed"}},
			{Principal: repositoryTestPrincipal("reviewer"), Active: true, Roles: []string{"reviewer"}},
			{Principal: repositoryTestPrincipal("administrator"), Active: true, Roles: []string{"administrator"}},
			{Principal: repositoryTestPrincipal("denied-writer"), Active: true, Roles: []string{"deny-writes"}},
			{Principal: repositoryTestPrincipal("membership-only"), Active: true},
		},
	}
}

func repositoryTestScope() authz.RepositoryScope {
	return authz.RepositoryScope{TenantID: "tenant-a", RepositoryID: "repo-a"}
}

func repositoryTestEngine(t *testing.T, p authz.RepositoryPolicy, clock authz.IdentityClock) *authz.RepositoryPolicyEngine {
	t.Helper()
	e, err := authz.NewRepositoryPolicy(p, repositoryTestAudience, clock)
	if err != nil {
		t.Fatalf("construct policy: %v", err)
	}
	return e
}

func repositoryTestCheck(t *testing.T, e *authz.RepositoryPolicyEngine, ctx context.Context, id authz.Identity, scope authz.RepositoryScope, version uint64, cap authz.RepositoryCapability, want bool) {
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
	e := repositoryTestEngine(t, repositoryTestPolicy(), repositoryTestClock)
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
			repositoryTestCheck(t, e, context.Background(), repositoryTestIdentity("fixture-issuer", tc.subject, authz.Human, repositoryTestAudience), repositoryTestScope(), 0, tc.cap, tc.want)
		})
	}
	t.Run("empty_members_default_deny", func(t *testing.T) {
		p := repositoryTestPolicy()
		p.Members = nil
		e := repositoryTestEngine(t, p, repositoryTestClock)
		repositoryTestCheck(t, e, context.Background(), repositoryTestIdentity("fixture-issuer", "writer", authz.Human, repositoryTestAudience), repositoryTestScope(), 0, authz.RepositoryRead, false)
	})
}

func TestRepositoryPolicyCapabilitiesAreIndependent(t *testing.T) {
	caps := []authz.RepositoryCapability{authz.RepositoryRead, authz.RepositoryWrite, authz.RepositoryApprove, authz.RepositoryAdmin, authz.RepositoryMetadataRead, authz.RepositoryHistoryRead}
	roles := []string{"read-only", "write-only", "approve-only", "admin-only", "metadata-only", "history-only"}
	p := authz.RepositoryPolicy{Scope: repositoryTestScope()}
	for i, role := range roles {
		p.Roles = append(p.Roles, authz.RepositoryRole{Name: role, Allow: []authz.RepositoryCapability{caps[i]}})
		p.Members = append(p.Members, authz.RepositoryMember{Principal: repositoryTestPrincipal(role), Active: true, Roles: []string{role}})
	}
	e := repositoryTestEngine(t, p, repositoryTestClock)
	for i, role := range roles {
		for j, cap := range caps {
			t.Run(role+"/"+string(cap), func(t *testing.T) {
				id := repositoryTestIdentity("fixture-issuer", role, authz.Human, repositoryTestAudience)
				got, err := e.Evaluate(context.Background(), id, repositoryTestScope(), 0, cap)
				if i == j {
					if err != nil || got != (authz.RepositoryDecision{Allowed: true}) {
						t.Fatalf("%s on %s = %#v, %v; want allow", cap, role, got, err)
					}
				} else if !errors.Is(err, authz.ErrRepositoryDenied) || got != (authz.RepositoryDecision{}) {
					t.Fatalf("%s on %s = %#v, %v; want deny", cap, role, got, err)
				}
			})
		}
	}
}

func TestRepositoryPolicyOrdinaryRolesDenyMetadataAndHistory(t *testing.T) {
	p := repositoryTestPolicy()
	e := repositoryTestEngine(t, p, repositoryTestClock)
	for _, member := range p.Members {
		for _, cap := range []authz.RepositoryCapability{authz.RepositoryMetadataRead, authz.RepositoryHistoryRead} {
			t.Run(member.Principal.Subject+"/"+string(cap), func(t *testing.T) {
				id := repositoryTestIdentity("fixture-issuer", member.Principal.Subject, authz.Human, repositoryTestAudience)
				repositoryTestCheck(t, e, context.Background(), id, p.Scope, 0, cap, false)
			})
		}
	}
}

func TestRepositoryPolicySixCapabilitiesAndDenyUnions(t *testing.T) {
	caps := []authz.RepositoryCapability{authz.RepositoryRead, authz.RepositoryWrite, authz.RepositoryApprove, authz.RepositoryAdmin, authz.RepositoryMetadataRead, authz.RepositoryHistoryRead}
	for _, denied := range append([]authz.RepositoryCapability{""}, caps...) {
		name := string(denied)
		if name == "" {
			name = "all_explicitly_allowed"
		}
		t.Run(name, func(t *testing.T) {
			p := authz.RepositoryPolicy{
				Scope:   repositoryTestScope(),
				Roles:   []authz.RepositoryRole{{Name: "all", Allow: caps}, {Name: "barrier"}},
				Members: []authz.RepositoryMember{{Principal: repositoryTestPrincipal("member"), Active: true, Roles: []string{"all", "barrier"}}},
			}
			if denied != "" {
				p.Roles[1].Deny = []authz.RepositoryCapability{denied}
			}
			e := repositoryTestEngine(t, p, repositoryTestClock)
			id := repositoryTestIdentity("fixture-issuer", "member", authz.Human, repositoryTestAudience)
			for _, cap := range caps {
				t.Run(string(cap), func(t *testing.T) {
					repositoryTestCheck(t, e, context.Background(), id, p.Scope, 0, cap, cap != denied)
				})
			}
			p.Roles[1].Deny = caps // The full six-entry deny list is valid too.
			e = repositoryTestEngine(t, p, repositoryTestClock)
			for _, cap := range caps {
				repositoryTestCheck(t, e, context.Background(), id, p.Scope, 0, cap, false)
			}
		})
	}
}

func TestRepositoryPolicyInvalidCapabilitySetsFailClosed(t *testing.T) {
	caps := []authz.RepositoryCapability{authz.RepositoryRead, authz.RepositoryWrite, authz.RepositoryApprove, authz.RepositoryAdmin, authz.RepositoryMetadataRead, authz.RepositoryHistoryRead}
	sets := []struct {
		name string
		caps []authz.RepositoryCapability
	}{{"over_six", append(append([]authz.RepositoryCapability{}, caps...), authz.RepositoryRead)}}
	for _, cap := range caps {
		sets = append(sets, struct {
			name string
			caps []authz.RepositoryCapability
		}{"duplicate_" + string(cap), []authz.RepositoryCapability{cap, cap}})
	}
	for i, cap := range []authz.RepositoryCapability{"", "publish", "metadata_read", "history-read ", "Metadata-read", authz.RepositoryCapability(strings.Repeat("x", 4097))} {
		sets = append(sets, struct {
			name string
			caps []authz.RepositoryCapability
		}{"unknown_" + strconv.Itoa(i), []authz.RepositoryCapability{cap}})
	}
	for _, field := range []string{"allow", "deny"} {
		for _, tc := range sets {
			t.Run(field+"/"+tc.name, func(t *testing.T) {
				p := repositoryTestPolicy()
				if field == "allow" {
					p.Roles[0].Allow = tc.caps
				} else {
					p.Roles[0].Deny = tc.caps
				}
				if e, err := authz.NewRepositoryPolicy(p, repositoryTestAudience, repositoryTestClock); e != nil || !errors.Is(err, authz.ErrRepositoryPolicy) {
					t.Fatalf("invalid %s constructor = %v, %v", field, e, err)
				}
				e := repositoryTestEngine(t, repositoryTestPolicy(), repositoryTestClock)
				p.Version = 1
				admin := repositoryTestIdentity("fixture-issuer", "administrator", authz.Human, repositoryTestAudience)
				if err := e.Update(context.Background(), admin, p.Scope, 0, p); !errors.Is(err, authz.ErrRepositoryDenied) {
					t.Fatalf("invalid %s update = %v; want denied", field, err)
				}
				repositoryTestCheck(t, e, context.Background(), admin, p.Scope, 0, authz.RepositoryAdmin, true)
			})
		}
	}
	e := repositoryTestEngine(t, repositoryTestPolicy(), repositoryTestClock)
	id := repositoryTestIdentity("fixture-issuer", "administrator", authz.Human, repositoryTestAudience)
	for _, tc := range sets[7:] { // All malformed/unknown strings also fail at evaluation.
		t.Run("evaluate/"+tc.name, func(t *testing.T) {
			repositoryTestCheck(t, e, context.Background(), id, repositoryTestScope(), 0, tc.caps[0], false)
		})
	}
}

func TestRepositoryPolicyRejectsScopeVersionsAndMalformedInputs(t *testing.T) {
	e, id := repositoryTestEngine(t, repositoryTestPolicy(), repositoryTestClock), repositoryTestIdentity("fixture-issuer", "writer", authz.Human, repositoryTestAudience)
	for _, tc := range []struct {
		name  string
		scope authz.RepositoryScope
		ver   uint64
		cap   authz.RepositoryCapability
	}{
		{"cross_repo", authz.RepositoryScope{TenantID: "tenant-a", RepositoryID: "repo-b"}, 0, authz.RepositoryRead},
		{"cross_tenant", authz.RepositoryScope{TenantID: "tenant-b", RepositoryID: "repo-a"}, 0, authz.RepositoryRead},
		{"wrong_version", repositoryTestScope(), 1, authz.RepositoryRead}, {"empty_scope", authz.RepositoryScope{}, 0, authz.RepositoryRead},
		{"unknown_capability", repositoryTestScope(), 0, "publish"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repositoryTestCheck(t, e, context.Background(), id, tc.scope, tc.ver, tc.cap, false)
		})
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
			if _, err := authz.NewRepositoryPolicy(func() authz.RepositoryPolicy { p := repositoryTestPolicy(); tc.bad(&p); return p }(), repositoryTestAudience, repositoryTestClock); !errors.Is(err, authz.ErrRepositoryPolicy) {
				t.Fatalf("constructor error = %v; want ErrRepositoryPolicy", err)
			}
		})
	}
	if _, err := authz.NewRepositoryPolicy(repositoryTestPolicy(), repositoryTestAudience, nil); !errors.Is(err, authz.ErrRepositoryPolicy) {
		t.Fatalf("nil clock constructor error = %v; want ErrRepositoryPolicy", err)
	}
}

func TestRepositoryPolicyUpdateRequiresAdminAndRemovesMembership(t *testing.T) {
	e, next := repositoryTestEngine(t, repositoryTestPolicy(), repositoryTestClock), repositoryTestPolicy()
	next.Version, next.Members[0].Active = 1, false
	writer := repositoryTestIdentity("fixture-issuer", "writer", authz.Human, repositoryTestAudience)
	admin := repositoryTestIdentity("fixture-issuer", "administrator", authz.Human, repositoryTestAudience)
	if err := e.Update(context.Background(), writer, repositoryTestScope(), 0, next); !errors.Is(err, authz.ErrRepositoryDenied) {
		t.Fatalf("writer update error = %v; want denied", err)
	}
	if err := e.Update(context.Background(), admin, repositoryTestScope(), 1, next); !errors.Is(err, authz.ErrRepositoryDenied) {
		t.Fatalf("stale update error = %v; want denied", err)
	}
	bad := next
	bad.Version = 2
	if err := e.Update(context.Background(), admin, repositoryTestScope(), 0, bad); !errors.Is(err, authz.ErrRepositoryDenied) {
		t.Fatalf("skipped-version update error = %v; want denied", err)
	}
	wrongScope := repositoryTestPolicy()
	wrongScope.Version, wrongScope.Scope.RepositoryID = 1, "repo-b"
	if err := e.Update(context.Background(), admin, repositoryTestScope(), 0, wrongScope); !errors.Is(err, authz.ErrRepositoryDenied) {
		t.Fatalf("cross-repository update error = %v; want denied", err)
	}
	malformed := repositoryTestPolicy()
	malformed.Version, malformed.Roles[0].Allow[0] = 1, "publish"
	if err := e.Update(context.Background(), admin, repositoryTestScope(), 0, malformed); !errors.Is(err, authz.ErrRepositoryDenied) {
		t.Fatalf("malformed update error = %v; want denied", err)
	}
	repositoryTestCheck(t, e, context.Background(), writer, repositoryTestScope(), 0, authz.RepositoryWrite, true)
	if err := e.Update(context.Background(), admin, repositoryTestScope(), 0, next); err != nil {
		t.Fatalf("valid update: %v", err)
	}
	next.Members[0].Active, next.Roles[2].Allow[1] = true, authz.RepositoryWrite // Published policy must not alias caller memory.
	repositoryTestCheck(t, e, context.Background(), writer, repositoryTestScope(), 1, authz.RepositoryWrite, false)
	repositoryTestCheck(t, e, context.Background(), writer, repositoryTestScope(), 0, authz.RepositoryWrite, false)
	repositoryTestCheck(t, e, context.Background(), admin, repositoryTestScope(), 1, authz.RepositoryAdmin, true)
	repositoryTestCheck(t, e, context.Background(), admin, repositoryTestScope(), 1, authz.RepositoryWrite, false)
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
			e, next := repositoryTestEngine(t, repositoryTestPolicy(), repositoryTestClock), repositoryTestPolicy()
			next.Version = 1
			tc.attack(&next)
			writer := repositoryTestIdentity("fixture-issuer", "writer", authz.Human, repositoryTestAudience)
			if err := e.Update(context.Background(), writer, repositoryTestScope(), 0, next); !errors.Is(err, authz.ErrRepositoryDenied) {
				t.Fatalf("escalation update error = %v; want denied", err)
			}
			repositoryTestCheck(t, e, context.Background(), writer, repositoryTestScope(), 0, authz.RepositoryWrite, true)
			repositoryTestCheck(t, e, context.Background(), writer, repositoryTestScope(), 0, authz.RepositoryAdmin, false)
			repositoryTestCheck(t, e, context.Background(), writer, repositoryTestScope(), 0, authz.RepositoryApprove, false)
		})
	}
	t.Run("admin_cannot_self_approve", func(t *testing.T) {
		e, next := repositoryTestEngine(t, repositoryTestPolicy(), repositoryTestClock), repositoryTestPolicy()
		next.Version = 1
		next.Roles[2].Allow = append(next.Roles[2].Allow, authz.RepositoryApprove)
		admin := repositoryTestIdentity("fixture-issuer", "administrator", authz.Human, repositoryTestAudience)
		if err := e.Update(context.Background(), admin, repositoryTestScope(), 0, next); !errors.Is(err, authz.ErrRepositoryDenied) {
			t.Fatalf("self-approval update error = %v; want denied", err)
		}
		repositoryTestCheck(t, e, context.Background(), admin, repositoryTestScope(), 0, authz.RepositoryAdmin, true)
		repositoryTestCheck(t, e, context.Background(), admin, repositoryTestScope(), 0, authz.RepositoryApprove, false)
	})
	t.Run("admin_cannot_remove_approval_deny", func(t *testing.T) {
		p := repositoryTestPolicy()
		p.Roles = append(p.Roles, authz.RepositoryRole{Name: "approval-barrier", Allow: []authz.RepositoryCapability{authz.RepositoryApprove}, Deny: []authz.RepositoryCapability{authz.RepositoryApprove}})
		p.Members[2].Roles = append(p.Members[2].Roles, "approval-barrier")
		e, next := repositoryTestEngine(t, p, repositoryTestClock), p
		next.Version, next.Roles[5].Deny = 1, nil
		admin := repositoryTestIdentity("fixture-issuer", "administrator", authz.Human, repositoryTestAudience)
		if err := e.Update(context.Background(), admin, repositoryTestScope(), 0, next); !errors.Is(err, authz.ErrRepositoryDenied) {
			t.Fatalf("deny-removal update error = %v; want denied", err)
		}
		repositoryTestCheck(t, e, context.Background(), admin, repositoryTestScope(), 0, authz.RepositoryAdmin, true)
		repositoryTestCheck(t, e, context.Background(), admin, repositoryTestScope(), 0, authz.RepositoryApprove, false)
	})
}

func TestRepositoryPolicySnapshotDeterminismAndPrincipalTupleIsolation(t *testing.T) {
	p := repositoryTestPolicy()
	p.Members = []authz.RepositoryMember{{Principal: authz.PrincipalID{Issuer: "a:b", Subject: "c", Class: authz.Human}, Active: true, Roles: []string{"writer"}}}
	e := repositoryTestEngine(t, p, repositoryTestClock)
	p.Roles[0].Allow[0], p.Members[0].Active = authz.RepositoryApprove, false
	id := repositoryTestIdentity("a:b", "c", authz.Human, repositoryTestAudience)
	first, err := e.Evaluate(context.Background(), id, repositoryTestScope(), 0, authz.RepositoryRead)
	second, repeatErr := e.Evaluate(context.Background(), id, repositoryTestScope(), 0, authz.RepositoryRead)
	if err != nil || repeatErr != nil || first != (authz.RepositoryDecision{Allowed: true}) || second != first {
		t.Fatalf("non-deterministic or aliased evaluation: first=%#v/%v second=%#v/%v", first, err, second, repeatErr)
	}
	repositoryTestCheck(t, e, context.Background(), repositoryTestIdentity("a", "b:c", authz.Human, repositoryTestAudience), repositoryTestScope(), 0, authz.RepositoryRead, false)
	repositoryTestCheck(t, e, context.Background(), repositoryTestIdentity("a:b", "c", authz.BuildJob, repositoryTestAudience), repositoryTestScope(), 0, authz.RepositoryRead, false)
}

func TestRepositoryPolicyFailsClosedForIdentityContextAndClock(t *testing.T) {
	e := repositoryTestEngine(t, repositoryTestPolicy(), repositoryTestClock)
	writer := repositoryTestIdentity("fixture-issuer", "writer", authz.Human, repositoryTestAudience)
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
			repositoryTestCheck(t, e, context.Background(), id, repositoryTestScope(), 0, authz.RepositoryRead, false)
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
		t.Run(tc.name, func(t *testing.T) {
			repositoryTestCheck(t, tc.e, tc.ctx, writer, repositoryTestScope(), 0, authz.RepositoryRead, false)
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	repositoryTestCheck(t, e, canceled, writer, repositoryTestScope(), 0, authz.RepositoryRead, false)
	for _, clock := range []authz.IdentityClock{
		func() (time.Time, error) { return time.Time{}, errors.New("clock failure") },
		func() (time.Time, error) { return time.Time{}, nil },
	} {
		repositoryTestCheck(t, repositoryTestEngine(t, repositoryTestPolicy(), clock), context.Background(), writer, repositoryTestScope(), 0, authz.RepositoryRead, false)
	}
}

func TestRepositoryPolicyConcurrentExpectedVersionPublishesOnce(t *testing.T) {
	e := repositoryTestEngine(t, repositoryTestPolicy(), repositoryTestClock)
	admin := repositoryTestIdentity("fixture-issuer", "administrator", authz.Human, repositoryTestAudience)
	a, b := repositoryTestPolicy(), repositoryTestPolicy()
	a.Version, b.Version, a.Members[1].Active, b.Members[0].Active = 1, 1, false, false
	start, results := make(chan struct{}), make(chan error, 2)
	for _, next := range []authz.RepositoryPolicy{a, b} {
		go func(p authz.RepositoryPolicy) {
			<-start
			results <- e.Update(context.Background(), admin, repositoryTestScope(), 0, p)
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
	repositoryTestCheck(t, e, context.Background(), admin, repositoryTestScope(), 1, authz.RepositoryAdmin, true)
}

func TestRepositoryPolicyVersionCannotWrap(t *testing.T) {
	max := ^uint64(0)
	p := repositoryTestPolicy()
	p.Version = max
	e := repositoryTestEngine(t, p, repositoryTestClock)
	next := repositoryTestPolicy()
	admin := repositoryTestIdentity("fixture-issuer", "administrator", authz.Human, repositoryTestAudience)
	if err := e.Update(context.Background(), admin, repositoryTestScope(), max, next); !errors.Is(err, authz.ErrRepositoryDenied) {
		t.Fatalf("wrapping update error = %v; want denied", err)
	}
	repositoryTestCheck(t, e, context.Background(), admin, repositoryTestScope(), max, authz.RepositoryAdmin, true)
}
