package authz_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"canopy.local/canopy/internal/authz"
)

var pathActions = []authz.PathAction{authz.PathTraverse, authz.PathList, authz.PathRead, authz.PathWrite}

func pathSelection(raw string) authz.PathSelector { return authz.PathSelector{Path: []byte(raw)} }
func pathIdentity() authz.Identity {
	return repositoryTestIdentity("fixture-issuer", "writer", authz.Human, repositoryTestAudience)
}
func pathRule(selection authz.PathSelector, allow, deny []authz.PathAction) authz.PathRule {
	return authz.PathRule{Principal: pathIdentity().Principal, Selector: selection, Allow: allow, Deny: deny}
}
func pathEngine(t *testing.T, rules ...authz.PathRule) *authz.PathPolicyEngine {
	t.Helper()
	r := repositoryTestEngine(t, repositoryTestPolicy(), repositoryTestClock)
	e, err := authz.NewPathPolicy(authz.PathPolicy{Scope: repositoryTestScope(), Rules: rules}, r)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func pathCheck(t *testing.T, e *authz.PathPolicyEngine, selection authz.PathSelector, action authz.PathAction, want bool) {
	t.Helper()
	d, err := e.Evaluate(context.Background(), pathIdentity(), repositoryTestScope(), 0, selection, action)
	if want {
		if err != nil || d != (authz.PathDecision{Allowed: true}) {
			t.Fatalf("allow: got %#v, %v", d, err)
		}
	} else if err != authz.ErrPathDenied || d != (authz.PathDecision{}) || err.Error() != "resource unavailable" {
		t.Fatalf("uniform denial: got %#v, %v", d, err)
	}
}

func TestPathSelectorsAndInvalidRequests(t *testing.T) {
	e := pathEngine(t, pathRule(authz.PathSelector{Root: true}, pathActions, nil))
	for _, tc := range []struct {
		name string
		s    authz.PathSelector
		a    authz.PathAction
		want bool
	}{
		{"explicit_root_list", authz.PathSelector{Root: true}, authz.PathList, true},
		{"explicit_root_traverse", authz.PathSelector{Root: true}, authz.PathTraverse, true},
		{"root_not_file", authz.PathSelector{Root: true}, authz.PathRead, false},
		{"root_not_mutation", authz.PathSelector{Root: true}, authz.PathWrite, false},
		{"empty_not_root", authz.PathSelector{}, authz.PathList, false},
		{"empty_slice_not_root", pathSelection(""), authz.PathTraverse, false},
		{"root_with_path", authz.PathSelector{Root: true, Path: []byte("a")}, authz.PathList, false},
		{"literal_ROOT_name", pathSelection("ROOT"), authz.PathRead, true},
		{"unknown_action", pathSelection("a"), "approve", false},
	} {
		t.Run(tc.name, func(t *testing.T) { pathCheck(t, e, tc.s, tc.a, tc.want) })
	}
	for _, raw := range []string{"", "/", "/a", "a/", "a//b", ".", "..", "a/./b", "a/../b", "a\x00b", strings.Repeat("x", 65536), strings.Repeat("a/", 1024) + "a"} {
		t.Run(fmt.Sprintf("invalid_%x", []byte(raw[:min(len(raw), 16)])), func(t *testing.T) {
			for _, action := range pathActions {
				pathCheck(t, e, pathSelection(raw), action, false)
			}
		})
	}
}

func TestPathBytePrefixBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, path string
		want               bool
	}{
		{"exact", "a", "a", true}, {"child", "a", "a/x", true}, {"deep_child", "a", "a/b/x", true},
		{"not_raw_prefix", "a", "ab", false}, {"not_raw_prefix_child", "a", "ab/x", false},
		{"shorter_path", "ab", "a", false}, {"nested_exact", "a/b", "a/b", true}, {"nested_boundary", "a/b", "a/bc", false},
		{"non_utf8", "\xff", "\xff/x", true}, {"non_utf8_distinct", "\xff", "\xfe/x", false},
		{"non_utf8_prefix", "\xff", "\xffa", false}, {"nfc_exact", "\xc3\xa9", "\xc3\xa9/x", true},
		{"nfc_not_nfd", "\xc3\xa9", "e\xcc\x81/x", false}, {"nfd_not_nfc", "e\xcc\x81", "\xc3\xa9/x", false},
		{"case_distinct", "a", "A/x", false}, {"backslash_literal", "a\\b", "a\\b/x", true},
		{"backslash_not_separator", "a", "a\\b", false}, {"slash_not_backslash", "a\\b", "a/b/x", false},
		{"percent_literal", "%2e%2e", "%2e%2e/x", true}, {"percent_not_decoded", "a", "%61/x", false},
		{"percent_slash_literal", "a%2fb", "a%2fb/x", true}, {"percent_slash_not_separator", "a", "a%2fb/x", false},
		{"long_component", strings.Repeat("x", 65535), strings.Repeat("x", 65535), true},
		{"max_components", "a", strings.Repeat("a/", 1023) + "a", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := pathEngine(t, pathRule(authz.PathSelector{Root: true}, []authz.PathAction{authz.PathTraverse}, nil), pathRule(pathSelection(tc.prefix), []authz.PathAction{authz.PathRead}, nil))
			pathCheck(t, e, pathSelection(tc.path), authz.PathRead, tc.want)
		})
	}
}

func TestPathRightsAndAncestors(t *testing.T) {
	for _, grant := range pathActions {
		for _, request := range pathActions {
			t.Run(string(grant)+"_request_"+string(request), func(t *testing.T) {
				e := pathEngine(t, pathRule(authz.PathSelector{Root: true}, []authz.PathAction{authz.PathTraverse}, nil), pathRule(pathSelection("a"), []authz.PathAction{grant}, nil))
				pathCheck(t, e, pathSelection("a/b"), request, request == authz.PathTraverse || request == grant)
			})
		}
	}
	for _, action := range pathActions {
		t.Run("default_deny_"+string(action), func(t *testing.T) { pathCheck(t, pathEngine(t), pathSelection("a/b"), action, false) })
		t.Run("missing_root_traverse_"+string(action), func(t *testing.T) {
			e := pathEngine(t, pathRule(pathSelection("a"), pathActions, nil))
			pathCheck(t, e, pathSelection("a/b"), action, false)
		})
		t.Run("hidden_middle_"+string(action), func(t *testing.T) {
			e := pathEngine(t, pathRule(authz.PathSelector{Root: true}, pathActions, nil), pathRule(pathSelection("a/b"), nil, []authz.PathAction{authz.PathTraverse}), pathRule(pathSelection("a/b/c"), pathActions, nil))
			pathCheck(t, e, pathSelection("a/b/c/file"), action, false)
		})
	}
	e := pathEngine(t, pathRule(authz.PathSelector{Root: true}, pathActions, nil), pathRule(pathSelection("a"), nil, []authz.PathAction{authz.PathTraverse}))
	pathCheck(t, e, pathSelection("a"), authz.PathList, false)
	pathCheck(t, e, pathSelection("ab/file"), authz.PathRead, true)
}

func TestPathDenyPrecedence(t *testing.T) {
	selectors := []authz.PathSelector{{Root: true}, pathSelection("a"), pathSelection("a/private"), pathSelection("a/private/docs")}
	for depth, selector := range selectors {
		for _, action := range pathActions {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("depth%d_%s_reverse%t", depth, action, reverse), func(t *testing.T) {
					rules := []authz.PathRule{pathRule(authz.PathSelector{Root: true}, pathActions, nil), pathRule(selector, nil, []authz.PathAction{action}), pathRule(pathSelection("a/private/docs"), pathActions, nil)}
					if reverse {
						rules[0], rules[2] = rules[2], rules[0]
					}
					e := pathEngine(t, rules...)
					pathCheck(t, e, pathSelection("a/private/docs/x"), action, false)
					if action != authz.PathTraverse {
						other := authz.PathRead
						if action == other {
							other = authz.PathWrite
						}
						pathCheck(t, e, pathSelection("a/private/docs/x"), other, true)
					}
				})
			}
		}
	}
}

func TestPathRenameAndHiddenNonDisclosure(t *testing.T) {
	e := pathEngine(t, pathRule(authz.PathSelector{Root: true}, pathActions, nil), pathRule(pathSelection("blocked"), nil, []authz.PathAction{authz.PathWrite}), pathRule(pathSelection("hidden"), nil, []authz.PathAction{authz.PathTraverse}))
	for _, tc := range []struct {
		name, source, destination string
		want                      bool
	}{
		{"allowed_both", "a/file", "b/file", true}, {"same_path", "a/file", "a/file", true},
		{"source_denied", "blocked/file", "a/file", false}, {"destination_denied", "a/file", "blocked/file", false},
		{"source_hidden", "hidden/file", "a/file", false}, {"destination_hidden", "a/file", "hidden/file", false},
		{"both_denied", "blocked/file", "hidden/file", false}, {"prefix_boundary", "blockeda/file", "a/file", true},
		{"invalid_source", "../a", "a/file", false}, {"invalid_destination", "a/file", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Model an adapter that can mutate only after the combined decision.
			mutations := 0
			d, err := e.EvaluateRename(context.Background(), pathIdentity(), repositoryTestScope(), 0, pathSelection(tc.source), pathSelection(tc.destination))
			if err == nil && d.Allowed {
				mutations++
			}
			if tc.want {
				if err != nil || d != (authz.PathDecision{Allowed: true}) || mutations != 1 {
					t.Fatalf("rename allow: %#v %v, mutations=%d", d, err, mutations)
				}
			} else if d != (authz.PathDecision{}) || err != authz.ErrPathDenied || mutations != 0 {
				t.Fatalf("rename denial: %#v %v, mutations=%d", d, err, mutations)
			}
		})
	}
	// Existing/missing child fixtures differ in names and counts. No denied
	// descendant request may reach the fixture, emit a count or change error data.
	for _, action := range pathActions {
		for _, fixture := range []map[string]string{{"hidden/known": "secret"}, {}, {"hidden/other": "x", "hidden/second": "y"}} {
			lookups := 0
			for _, path := range []string{"hidden/known", "hidden/missing", "hidden/deep/file"} {
				d, err := e.Evaluate(context.Background(), pathIdentity(), repositoryTestScope(), 0, pathSelection(path), action)
				public := err
				if err == nil && d.Allowed {
					lookups++
					_ = fixture[path]
					public = nil
				}
				if d != (authz.PathDecision{}) || public != authz.ErrPathDenied || public.Error() != "resource unavailable" || lookups != 0 {
					t.Fatalf("hidden/missing response differs: %#v %v, lookups=%d", d, public, lookups)
				}
			}
		}
	}
}

func TestPathRepositoryIdentityAndFreshness(t *testing.T) {
	for _, tc := range []struct {
		name, subject string
		action        authz.PathAction
		want          bool
	}{
		{"writer", "writer", authz.PathWrite, true}, {"read_only", "reviewer", authz.PathRead, true},
		{"no_repo_write", "reviewer", authz.PathWrite, false}, {"membership_only", "membership-only", authz.PathRead, false},
		{"unknown_member", "unknown", authz.PathRead, false}, {"repo_deny", "denied-writer", authz.PathWrite, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := pathRule(authz.PathSelector{Root: true}, pathActions, nil)
			rule.Principal = repositoryTestPrincipal(tc.subject)
			e := pathEngine(t, rule)
			id := pathIdentity()
			id.Principal = rule.Principal
			d, err := e.Evaluate(context.Background(), id, repositoryTestScope(), 0, pathSelection("a/b"), tc.action)
			if tc.want && (err != nil || !d.Allowed) || !tc.want && (err != authz.ErrPathDenied || d != (authz.PathDecision{})) {
				t.Fatalf("repo/path separation: %#v %v", d, err)
			}
		})
	}
	r := repositoryTestEngine(t, repositoryTestPolicy(), repositoryTestClock)
	e, err := authz.NewPathPolicy(authz.PathPolicy{Scope: repositoryTestScope(), Rules: []authz.PathRule{pathRule(authz.PathSelector{Root: true}, pathActions, nil)}}, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*authz.Identity, *authz.RepositoryScope, *uint64)
	}{
		{"other_principal", func(i *authz.Identity, _ *authz.RepositoryScope, _ *uint64) { i.Principal.Subject = "reviewer" }},
		{"wrong_issuer", func(i *authz.Identity, _ *authz.RepositoryScope, _ *uint64) { i.Principal.Issuer = "other" }},
		{"wrong_class", func(i *authz.Identity, _ *authz.RepositoryScope, _ *uint64) { i.Principal.Class = authz.ServiceAccount }},
		{"wrong_audience", func(i *authz.Identity, _ *authz.RepositoryScope, _ *uint64) { i.Audience = "other" }},
		{"expired", func(i *authz.Identity, _ *authz.RepositoryScope, _ *uint64) { i.ExpiresAt = time.Unix(150, 0) }},
		{"wrong_scope", func(_ *authz.Identity, s *authz.RepositoryScope, _ *uint64) { s.RepositoryID = "other" }},
		{"wrong_tenant", func(_ *authz.Identity, s *authz.RepositoryScope, _ *uint64) { s.TenantID = "other" }},
		{"wrong_version", func(_ *authz.Identity, _ *authz.RepositoryScope, v *uint64) { *v = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, scope, version := pathIdentity(), repositoryTestScope(), uint64(0)
			tc.change(&id, &scope, &version)
			d, err := e.Evaluate(context.Background(), id, scope, version, pathSelection("a"), authz.PathRead)
			if d != (authz.PathDecision{}) || err != authz.ErrPathDenied {
				t.Fatalf("%#v %v", d, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		d, err := e.Evaluate(ctx, pathIdentity(), repositoryTestScope(), 0, pathSelection("a"), authz.PathRead)
		if d != (authz.PathDecision{}) || err != authz.ErrPathDenied {
			t.Fatalf("context: %#v %v", d, err)
		}
	}
	next := repositoryTestPolicy()
	next.Version = 1
	admin := repositoryTestIdentity("fixture-issuer", "administrator", authz.Human, repositoryTestAudience)
	if err := r.Update(context.Background(), admin, repositoryTestScope(), 0, next); err != nil {
		t.Fatal(err)
	}
	pathCheck(t, e, pathSelection("a"), authz.PathRead, false)
	var nilEngine *authz.PathPolicyEngine
	pathCheck(t, nilEngine, pathSelection("a"), authz.PathRead, false)
	pathCheck(t, &authz.PathPolicyEngine{}, pathSelection("a"), authz.PathRead, false)
}

func TestPathWriteOnlyAndUncertainIdentity(t *testing.T) {
	for _, action := range pathActions {
		t.Run("write_only_repository_"+string(action), func(t *testing.T) {
			p := repositoryTestPolicy()
			p.Roles[0].Allow = []authz.RepositoryCapability{authz.RepositoryWrite}
			r := repositoryTestEngine(t, p, repositoryTestClock)
			e, err := authz.NewPathPolicy(authz.PathPolicy{Scope: p.Scope, Rules: []authz.PathRule{pathRule(authz.PathSelector{Root: true}, pathActions, nil)}}, r)
			if err != nil {
				t.Fatal(err)
			}
			pathCheck(t, e, pathSelection("a/b"), action, action == authz.PathWrite)
			d, err := e.EvaluateRename(context.Background(), pathIdentity(), p.Scope, 0, pathSelection("a/b"), pathSelection("c/d"))
			if err != nil || d != (authz.PathDecision{Allowed: true}) {
				t.Fatalf("write-only rename: %#v %v", d, err)
			}
		})
	}
	for _, mode := range []string{"clock_error", "zero_clock", "expires_during_check", "cancel_during_check"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			clock := func() (time.Time, error) {
				calls++
				if mode == "clock_error" {
					return time.Time{}, errors.New("clock failed with private detail")
				}
				if mode == "zero_clock" {
					return time.Time{}, nil
				}
				if mode == "cancel_during_check" && calls == 2 {
					cancel()
				}
				if mode == "expires_during_check" && calls == 2 {
					return time.Unix(200, 0), nil
				}
				return repositoryTestClock()
			}
			r := repositoryTestEngine(t, repositoryTestPolicy(), clock)
			e, err := authz.NewPathPolicy(authz.PathPolicy{Scope: repositoryTestScope(), Rules: []authz.PathRule{pathRule(authz.PathSelector{Root: true}, pathActions, nil)}}, r)
			if err != nil {
				t.Fatal(err)
			}
			d, err := e.EvaluateRename(ctx, pathIdentity(), repositoryTestScope(), 0, pathSelection("a/b"), pathSelection("c/d"))
			if d != (authz.PathDecision{}) || err != authz.ErrPathDenied || err.Error() != "resource unavailable" {
				t.Fatalf("uncertainty exposed: %#v %v", d, err)
			}
		})
	}
}

func TestPathPolicyValidationAndInputOwnership(t *testing.T) {
	r := repositoryTestEngine(t, repositoryTestPolicy(), repositoryTestClock)
	for _, tc := range []struct {
		name string
		bad  func(*authz.PathPolicy)
	}{
		{"invalid_scope", func(p *authz.PathPolicy) { p.Scope = authz.RepositoryScope{} }},
		{"wrong_scope", func(p *authz.PathPolicy) { p.Scope.RepositoryID = "other" }},
		{"wrong_version", func(p *authz.PathPolicy) { p.Version++ }},
		{"empty_prefix", func(p *authz.PathPolicy) { p.Rules[0].Selector = authz.PathSelector{} }},
		{"ambiguous_root", func(p *authz.PathPolicy) { p.Rules[0].Selector = authz.PathSelector{Root: true, Path: []byte("a")} }},
		{"dot_prefix", func(p *authz.PathPolicy) { p.Rules[0].Selector = pathSelection("a/../b") }},
		{"unknown_allow", func(p *authz.PathPolicy) { p.Rules[0].Allow = []authz.PathAction{"admin"} }},
		{"unknown_deny", func(p *authz.PathPolicy) { p.Rules[0].Deny = []authz.PathAction{"unknown"} }},
		{"duplicate_action", func(p *authz.PathPolicy) { p.Rules[0].Allow = []authz.PathAction{authz.PathRead, authz.PathRead} }},
		{"too_many_actions", func(p *authz.PathPolicy) { p.Rules[0].Deny = make([]authz.PathAction, 5) }},
		{"unresolved_principal", func(p *authz.PathPolicy) { p.Rules[0].Principal = authz.PrincipalID{} }},
		{"too_many_rules", func(p *authz.PathPolicy) { p.Rules = make([]authz.PathRule, 4097) }},
		{"aggregate_bytes", func(p *authz.PathPolicy) {
			for i := 0; i < 17; i++ {
				p.Rules = append(p.Rules, pathRule(pathSelection(strings.Repeat("x", 65535)), pathActions, nil))
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := authz.PathPolicy{Scope: repositoryTestScope(), Rules: []authz.PathRule{pathRule(authz.PathSelector{Root: true}, pathActions, nil)}}
			tc.bad(&p)
			if e, err := authz.NewPathPolicy(p, r); e != nil || !errors.Is(err, authz.ErrPathPolicy) {
				t.Fatalf("invalid policy: %v %v", e, err)
			}
		})
	}
	for _, repo := range []*authz.RepositoryPolicyEngine{nil, {}} {
		if e, err := authz.NewPathPolicy(authz.PathPolicy{Scope: repositoryTestScope()}, repo); e != nil || err != authz.ErrPathPolicy {
			t.Fatalf("invalid repo: %v %v", e, err)
		}
	}
	allow := []authz.PathAction{authz.PathRead}
	p := authz.PathPolicy{Scope: repositoryTestScope(), Rules: []authz.PathRule{pathRule(authz.PathSelector{Root: true}, []authz.PathAction{authz.PathTraverse}, nil), pathRule(pathSelection("a"), allow, nil)}}
	e, err := authz.NewPathPolicy(p, r)
	if err != nil {
		t.Fatal(err)
	}
	p.Rules[1].Selector.Path[0] = 'b'
	allow[0] = authz.PathWrite
	p.Rules[1].Principal.Subject = "other"
	pathCheck(t, e, pathSelection("a/file"), authz.PathRead, true)
	pathCheck(t, e, pathSelection("a/file"), authz.PathWrite, false)
	pathCheck(t, e, pathSelection("b/file"), authz.PathRead, false)
}
