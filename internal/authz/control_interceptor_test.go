package authz_test

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"canopy.local/canopy/internal/authz"
)

func sourcePath(path string, action authz.PathAction) authz.SourcePathAccess {
	return authz.SourcePathAccess{Selection: pathSelection(path), Action: action}
}

func sourceCheck(t *testing.T, e *authz.PathPolicyEngine, access authz.SourceAccess, want bool) {
	t.Helper()
	sourceCheckContext(t, e, context.Background(), pathIdentity(), repositoryTestScope(), 0, access, want)
}

func sourceCheckContext(t *testing.T, e *authz.PathPolicyEngine, ctx context.Context,
	id authz.Identity, scope authz.RepositoryScope, version uint64, access authz.SourceAccess, want bool) {
	t.Helper()
	d, err := e.EvaluateSourceAccess(ctx, id, scope, version, access)
	if want {
		if err != nil || d != (authz.PathDecision{Allowed: true, PolicyVersion: version}) {
			t.Fatalf("allow: got %#v, %v", d, err)
		}
	} else if err != authz.ErrPathDenied || d != (authz.PathDecision{}) || err.Error() != "resource unavailable" {
		t.Fatalf("uniform denial: got %#v, %v", d, err)
	}
}

func TestSourceAccessMixedInputsOutputs(t *testing.T) {
	e := pathEngine(t,
		pathRule(authz.PathSelector{Root: true}, pathActions, nil),
		pathRule(pathSelection("secret"), nil, []authz.PathAction{authz.PathRead, authz.PathWrite}))
	for _, denied := range []bool{false, true} {
		path := "public/new"
		if denied {
			path = "secret/new"
		}
		for _, reverse := range []bool{false, true} {
			checks := []authz.SourcePathAccess{sourcePath("public/old", authz.PathRead), sourcePath(path, authz.PathWrite)}
			if reverse {
				checks[0], checks[1] = checks[1], checks[0]
			}
			sourceCheck(t, e, authz.SourceAccess{Paths: checks}, !denied)
		}
	}
	// A denied output cannot be waived because every input was readable.
	sourceCheck(t, e, authz.SourceAccess{Paths: []authz.SourcePathAccess{
		sourcePath("public/in", authz.PathRead), sourcePath("secret/conflict", authz.PathRead)}}, false)
	// Byte paths retain their exact meaning: percent encoding is not decoded.
	sourceCheck(t, e, authz.SourceAccess{Paths: []authz.SourcePathAccess{
		sourcePath("%73ecret/a", authz.PathRead), sourcePath("\xff/a", authz.PathWrite)}}, true)
}

func TestSourceAccessIndependentCapabilities(t *testing.T) {
	for _, metadata := range []bool{false, true} {
		for _, history := range []bool{false, true} {
			p := repositoryTestPolicy()
			if metadata {
				p.Roles[0].Allow = append(p.Roles[0].Allow, authz.RepositoryMetadataRead)
			}
			if history {
				p.Roles[0].Allow = append(p.Roles[0].Allow, authz.RepositoryHistoryRead)
			}
			r := repositoryTestEngine(t, p, repositoryTestClock)
			e, err := authz.NewPathPolicy(authz.PathPolicy{Scope: repositoryTestScope(), Rules: []authz.PathRule{
				pathRule(authz.PathSelector{Root: true}, pathActions, nil)}}, r)
			if err != nil {
				t.Fatal(err)
			}
			access := authz.SourceAccess{Paths: []authz.SourcePathAccess{sourcePath("public/a", authz.PathRead)}}
			access.ReadMetadata = true
			sourceCheck(t, e, access, metadata)
			access.ReadMetadata, access.ReadHistory = false, true
			sourceCheck(t, e, access, history)
			access.ReadMetadata = true
			sourceCheck(t, e, access, metadata && history)
		}
	}
}

func TestSourceAccessBoundsAndInvalidSelections(t *testing.T) {
	e := pathEngine(t, pathRule(authz.PathSelector{Root: true}, pathActions, nil))
	valid := sourcePath("a", authz.PathRead)
	for _, checks := range [][]authz.SourcePathAccess{
		nil, {}, {sourcePath("", authz.PathRead)}, {sourcePath("../a", authz.PathRead)},
		{sourcePath("a", "unknown")},
		{{Selection: authz.PathSelector{Root: true}, Action: authz.PathWrite}},
		{{Selection: authz.PathSelector{Root: true, Path: []byte("a")}, Action: authz.PathList}},
		make([]authz.SourcePathAccess, authz.MaxSourceAccessPaths+1),
	} {
		sourceCheck(t, e, authz.SourceAccess{Paths: checks}, false)
	}
	checks := make([]authz.SourcePathAccess, authz.MaxSourceAccessPaths)
	for i := range checks {
		checks[i] = valid
	}
	sourceCheck(t, e, authz.SourceAccess{Paths: checks}, true)
	for i := range checks {
		checks[i] = sourcePath(strings.Repeat("a", 255)+"/b", authz.PathRead)
	}
	sourceCheck(t, e, authz.SourceAccess{Paths: checks}, false)
	sourceCheck(t, e, authz.SourceAccess{Paths: []authz.SourcePathAccess{
		{Selection: authz.PathSelector{Root: true}, Action: authz.PathList}}}, true)
}

func TestSourceAccessCurrentPolicyAndIdentity(t *testing.T) {
	p := repositoryTestPolicy()
	r := repositoryTestEngine(t, p, repositoryTestClock)
	e, err := authz.NewPathPolicy(authz.PathPolicy{Scope: p.Scope, Rules: []authz.PathRule{
		pathRule(authz.PathSelector{Root: true}, pathActions, nil)}}, r)
	if err != nil {
		t.Fatal(err)
	}
	a := authz.SourceAccess{Paths: []authz.SourcePathAccess{sourcePath("old/revision/path", authz.PathRead)}}
	sourceCheck(t, e, a, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []context.Context{nil, ctx} {
		sourceCheckContext(t, e, c, pathIdentity(), p.Scope, 0, a, false)
	}
	id := pathIdentity()
	id.ExpiresAt = time.Unix(149, 0)
	sourceCheckContext(t, e, context.Background(), id, p.Scope, 0, a, false)
	id = pathIdentity()
	id.Audience = "other"
	sourceCheckContext(t, e, context.Background(), id, p.Scope, 0, a, false)
	sourceCheckContext(t, nil, context.Background(), pathIdentity(), p.Scope, 0, a, false)
	sourceCheckContext(t, e, context.Background(), pathIdentity(), authz.RepositoryScope{"other", "repo-a"}, 0, a, false)
	p.Version = 1
	admin := repositoryTestIdentity("fixture-issuer", "administrator", authz.Human, repositoryTestAudience)
	if err := r.Update(context.Background(), admin, p.Scope, 0, p); err != nil {
		t.Fatal(err)
	}
	// The path spelling is only a label. This tests stale policy rejection,
	// not historical-revision resolution or alternate-alias integration.
	sourceCheck(t, e, a, false)
	sourceCheckContext(t, e, context.Background(), pathIdentity(), p.Scope, 1, a, false)
}

func TestSourceAccessCannotBorrowWriteOrTraversal(t *testing.T) {
	p := repositoryTestPolicy()
	r := repositoryTestEngine(t, p, repositoryTestClock)
	reviewer := repositoryTestIdentity("fixture-issuer", "reviewer", authz.Human, repositoryTestAudience)
	e, err := authz.NewPathPolicy(authz.PathPolicy{Scope: p.Scope, Rules: []authz.PathRule{
		{Principal: reviewer.Principal, Selector: authz.PathSelector{Root: true}, Allow: pathActions},
		pathRule(authz.PathSelector{Root: true}, pathActions, nil),
		pathRule(pathSelection("hidden"), nil, []authz.PathAction{authz.PathTraverse}),
		pathRule(pathSelection("hidden/deep"), pathActions, nil),
	}}, r)
	if err != nil {
		t.Fatal(err)
	}
	a := authz.SourceAccess{Paths: []authz.SourcePathAccess{
		sourcePath("public/a", authz.PathRead), sourcePath("public/b", authz.PathWrite)}}
	sourceCheckContext(t, e, context.Background(), reviewer, p.Scope, 0, a, false)
	a.Paths[1] = sourcePath("hidden/deep/file", authz.PathRead)
	sourceCheck(t, e, a, false)
}

func TestSourceAccessRechecksIdentityBeforeAllow(t *testing.T) {
	calls := 0
	clock := func() (time.Time, error) {
		calls++
		if calls == 1 {
			return time.Unix(150, 0), nil
		}
		return time.Unix(201, 0), nil
	}
	r := repositoryTestEngine(t, repositoryTestPolicy(), clock)
	e, err := authz.NewPathPolicy(authz.PathPolicy{Scope: repositoryTestScope(), Rules: []authz.PathRule{
		pathRule(authz.PathSelector{Root: true}, pathActions, nil)}}, r)
	if err != nil {
		t.Fatal(err)
	}
	sourceCheck(t, e, authz.SourceAccess{Paths: []authz.SourcePathAccess{sourcePath("a", authz.PathRead)}}, false)
	if calls != 2 {
		t.Fatalf("expected identity checks before and after batch; got %d", calls)
	}
}

func TestSourceAccessExactByteBudget(t *testing.T) {
	e := pathEngine(t, pathRule(authz.PathSelector{Root: true}, pathActions, nil))
	checks := make([]authz.SourcePathAccess, authz.MaxSourceAccessPaths)
	for i := range checks {
		checks[i] = sourcePath("a/"+strings.Repeat("b", 254), authz.PathRead)
	}
	// 4096 * 256 bytes exactly consumes the 1 MiB aggregate budget.
	sourceCheck(t, e, authz.SourceAccess{Paths: checks}, true)
	checks[0] = sourcePath("a/"+strings.Repeat("b", 255), authz.PathRead)
	sourceCheck(t, e, authz.SourceAccess{Paths: checks}, false)
}

func TestSourceAccessPrincipalSubstitutionAndExplicitCapabilityDenies(t *testing.T) {
	p := repositoryTestPolicy()
	p.Roles[0].Allow = append(p.Roles[0].Allow, authz.RepositoryMetadataRead, authz.RepositoryHistoryRead)
	p.Roles[0].Deny = []authz.RepositoryCapability{authz.RepositoryMetadataRead, authz.RepositoryHistoryRead}
	r := repositoryTestEngine(t, p, repositoryTestClock)
	e, err := authz.NewPathPolicy(authz.PathPolicy{Scope: p.Scope, Rules: []authz.PathRule{
		pathRule(authz.PathSelector{Root: true}, pathActions, nil)}}, r)
	if err != nil {
		t.Fatal(err)
	}
	a := authz.SourceAccess{Paths: []authz.SourcePathAccess{sourcePath("a", authz.PathRead)}}
	sourceCheck(t, e, a, true)
	for _, field := range []string{"issuer", "subject", "class"} {
		id := pathIdentity()
		switch field {
		case "issuer":
			id.Principal.Issuer = "different-issuer"
		case "subject":
			id.Principal.Subject = "different-subject"
		case "class":
			id.Principal.Class = authz.ServiceAccount
		}
		sourceCheckContext(t, e, context.Background(), id, p.Scope, 0, a, false)
	}
	a.ReadMetadata = true
	sourceCheck(t, e, a, false)
	a.ReadMetadata, a.ReadHistory = false, true
	sourceCheck(t, e, a, false)
}

// sourceCancelContext deterministically cancels on an Err check during the
// mixed-path loop, after initial validation and both entry identity checks.
// It wraps a real cancellation context; no goroutine timing is required.
type sourceCancelContext struct {
	context.Context
	cancel context.CancelFunc
	calls  int
}

func (c *sourceCancelContext) Err() error {
	c.calls++
	if c.calls == 8 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestSourceAccessMidBatchCancellation(t *testing.T) {
	e := pathEngine(t, pathRule(authz.PathSelector{Root: true}, pathActions, nil))
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &sourceCancelContext{Context: base, cancel: cancel}
	a := authz.SourceAccess{Paths: []authz.SourcePathAccess{
		sourcePath("a", authz.PathRead), sourcePath("b", authz.PathWrite), sourcePath("c", authz.PathRead)}}
	sourceCheckContext(t, e, ctx, pathIdentity(), repositoryTestScope(), 0, a, false)
	if ctx.calls != 8 || base.Err() != context.Canceled {
		t.Fatalf("expected cancellation during the second path check; calls=%d", ctx.calls)
	}
}

func TestSourceAccessConcurrentPolicyUpdate(t *testing.T) {
	entered, updateChecked, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	clock := func() (time.Time, error) {
		switch calls.Add(1) {
		case 1:
			close(entered)
			<-release // evaluator holds the current repository head's read lock
		case 2:
			close(updateChecked) // Update authorized against that same old head
		}
		return repositoryTestClock()
	}
	p := repositoryTestPolicy()
	r := repositoryTestEngine(t, p, clock)
	e, err := authz.NewPathPolicy(authz.PathPolicy{Scope: p.Scope, Rules: []authz.PathRule{
		pathRule(authz.PathSelector{Root: true}, pathActions, nil)}}, r)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		decision authz.PathDecision
		err      error
	}
	evaluated := make(chan result, 1)
	go func() {
		d, err := e.EvaluateSourceAccess(context.Background(), pathIdentity(), p.Scope, 0,
			authz.SourceAccess{Paths: []authz.SourcePathAccess{sourcePath("a", authz.PathRead), sourcePath("b", authz.PathWrite)}})
		evaluated <- result{d, err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("evaluation never entered identity check")
	}
	updated := make(chan error, 1)
	p.Version = 1
	admin := repositoryTestIdentity("fixture-issuer", "administrator", authz.Human, repositoryTestAudience)
	go func() { updated <- r.Update(context.Background(), admin, p.Scope, 0, p) }()
	select {
	case <-updateChecked:
	case <-time.After(5 * time.Second):
		t.Fatal("update never checked old head")
	}
	select {
	case err := <-updated:
		t.Fatalf("update completed while evaluation held the policy snapshot: %v", err)
	default:
	}
	unblock()
	select {
	case got := <-evaluated:
		if got.err != nil || got.decision != (authz.PathDecision{Allowed: true}) {
			t.Fatalf("old-head batch result: %#v, %v", got.decision, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("evaluation did not finish")
	}
	select {
	case err := <-updated:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("policy update did not finish")
	}
	// The completed batch is not a lease: the old engine cannot authorize again.
	sourceCheck(t, e, authz.SourceAccess{Paths: []authz.SourcePathAccess{sourcePath("a", authz.PathRead)}}, false)
}
