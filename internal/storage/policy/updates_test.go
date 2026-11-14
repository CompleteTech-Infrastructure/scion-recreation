package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"canopy.local/canopy/internal/authz"
	"canopy.local/canopy/internal/storage/metadata"
	"github.com/jackc/pgx/v5"
)

func nextFixturePolicy(t *testing.T, p authz.PolicySnapshot) authz.PolicySnapshot {
	t.Helper()
	b, e := authz.EncodePolicySnapshot(p)
	if e != nil {
		t.Fatal(e)
	}
	n, e := authz.DecodePolicySnapshot(b)
	if e != nil {
		t.Fatal(e)
	}
	n.Repository.Version++
	n.Paths.Version = n.Repository.Version
	return n
}
func fixtureHead(t *testing.T, f *managementFixture, p authz.PolicySnapshot) HeadExpectation {
	t.Helper()
	b, e := authz.EncodePolicySnapshot(p)
	if e != nil {
		t.Fatal(e)
	}
	return HeadExpectation{Tenant: f.tenant, Repository: f.repo, Version: p.Repository.Version, Digest: sha256.Sum256(b)}
}

func TestPolicyCASCurrentAuthorizationReplayAndOwnedBytes(t *testing.T) {
	f := managementSetup(t)
	admin, writer, s, a, _ := f.bootstrap(t)
	enrollFixture(t, a, admin, writer, 2)
	ctx := context.Background()
	old := f.policy(admin, writer)
	expected := fixtureHead(t, f, old)
	next := nextFixturePolicy(t, old)
	next.Paths.Rules = []authz.PathRule{{Principal: writer.Session.Claims.Principal, Selector: authz.PathSelector{Path: []byte{0xff, '/', 'x'}}, Allow: []authz.PathAction{authz.PathRead, authz.PathTraverse}}}
	before := policyCounts(t, f)
	if got, e := a.CompareAndSwapPolicy(ctx, writer, expected, next, fixtureRequest(10)); got != (Receipt{}) || e == nil {
		t.Fatal("writer changed policy", got, e)
	}
	if got, e := a.GetPolicy(ctx, writer, expected); got.Repository.Scope != (authz.RepositoryScope{}) || e == nil {
		t.Fatal("writer read policy", e)
	}
	if after := policyCounts(t, f); after != before {
		t.Fatal("denied policy operation changed rows", before, after)
	}
	r, e := a.CompareAndSwapPolicy(ctx, admin, expected, next, fixtureRequest(10))
	if e != nil || r.Operation != 5 || r.PolicyVersion != 1 || r.PolicyDigest != fixtureHead(t, f, next).Digest || r.TargetSession != ([32]byte{}) || r.TargetCredentialHash != ([32]byte{}) {
		t.Fatal("CAS", r, e)
	}
	assertReceiptAudit(t, f, admin, r)
	if again, e := a.CompareAndSwapPolicy(ctx, admin, expected, next, fixtureRequest(10)); e != nil || again != r {
		t.Fatal("exact retry after changed head", again, e)
	}
	changed := nextFixturePolicy(t, old)
	if got, e := a.CompareAndSwapPolicy(ctx, admin, expected, changed, fixtureRequest(10)); got != (Receipt{}) || !errors.Is(e, metadata.ErrConflict) {
		t.Fatal("changed immutable intent replay", got, e)
	}
	if got, e := a.CompareAndSwapPolicy(ctx, admin, expected, next, fixtureRequest(11)); got != (Receipt{}) || !errors.Is(e, metadata.ErrConflict) {
		t.Fatal("stale head overwrite", got, e)
	}
	current := fixtureHead(t, f, next)
	returned, e := a.GetPolicy(ctx, admin, current)
	if e != nil || !bytes.Equal(returned.Paths.Rules[0].Selector.Path, []byte{0xff, '/', 'x'}) {
		t.Fatal("byte policy read", e)
	}
	returned.Paths.Rules[0].Selector.Path[0] = 0x61
	returned.Repository.Roles[0].Name = "mutated caller result"
	again, e := a.GetPolicy(ctx, admin, current)
	if e != nil || !bytes.Equal(again.Paths.Rules[0].Selector.Path, []byte{0xff, '/', 'x'}) {
		t.Fatal("policy alias escaped", e)
	}
	if got, e := a.GetAdminResult(ctx, admin, AdminResultQuery{Operation: 5, RequestID: fixtureRequest(10)}); e != nil || got != r {
		t.Fatal("current admin result", got, e)
	}
	if got, e := a.GetAdminResult(ctx, writer, AdminResultQuery{Operation: 5, RequestID: fixtureRequest(10)}); got != (Receipt{}) || e == nil {
		t.Fatal("writer recovered result", got, e)
	}
	for _, q := range []AdminResultQuery{{}, {Operation: 6, RequestID: fixtureRequest(10)}, {Operation: 5}} {
		if got, e := a.GetAdminResult(ctx, admin, q); got != (Receipt{}) || e == nil {
			t.Fatal("invalid result query", got, e)
		}
	}
	// Closing/reopening all serving/admin handles retains actual database state.
	_ = a.Close()
	_ = s.Close()
	a, e = OpenAdmin(ctx, f.config(f.roles.Admin))
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	if got, e := a.GetAdminResult(ctx, admin, AdminResultQuery{Operation: 5, RequestID: fixtureRequest(10)}); e != nil || got != r {
		t.Fatal("application reopen lost result", got, e)
	}
	replacement := f.credentials("admin", 8)
	enrollFixture(t, a, admin, replacement, 12)
	if got, e := a.GetAdminResult(ctx, replacement, AdminResultQuery{Operation: 5, RequestID: fixtureRequest(10)}); e != nil || got != r {
		t.Fatal("same principal fresh session recovery", got, e)
	}
	if _, e := a.RevokeSession(ctx, replacement, SessionRevocation{SessionID: admin.Session.Claims.Session, RequestID: fixtureRequest(13)}); e != nil {
		t.Fatal(e)
	}
	if got, e := a.GetAdminResult(ctx, admin, AdminResultQuery{Operation: 5, RequestID: fixtureRequest(10)}); got != (Receipt{}) || e == nil {
		t.Fatal("revoked actor recovered historical result", got, e)
	}
}

func TestPolicyCASRejectsSelfEscalationAndMalformedSuccessors(t *testing.T) {
	f := managementSetup(t)
	admin, writer, _, a, _ := f.bootstrap(t)
	ctx := context.Background()
	p := f.policy(admin, writer)
	expected := fixtureHead(t, f, p)
	for name, edit := range map[string]func(*authz.PolicySnapshot){
		"approve": func(n *authz.PolicySnapshot) {
			n.Repository.Roles[0].Allow = append(n.Repository.Roles[0].Allow, authz.RepositoryApprove)
		},
		"same-version-path":       func(n *authz.PolicySnapshot) { n.Repository.Version = 0; n.Paths.Version = 0 },
		"skip-version":            func(n *authz.PolicySnapshot) { n.Repository.Version = 2; n.Paths.Version = 2 },
		"mismatched-path-version": func(n *authz.PolicySnapshot) { n.Paths.Version = 0 },
		"wrong-tenant": func(n *authz.PolicySnapshot) {
			n.Repository.Scope.TenantID = "other"
			n.Paths.Scope = n.Repository.Scope
		},
	} {
		t.Run(name, func(t *testing.T) {
			n := nextFixturePolicy(t, p)
			edit(&n)
			before := policyCounts(t, f)
			if got, e := a.CompareAndSwapPolicy(ctx, admin, expected, n, fixtureRequest(20)); got != (Receipt{}) || e == nil {
				t.Fatal("invalid successor accepted", got, e)
			}
			if after := policyCounts(t, f); after != before {
				t.Fatal("rejected successor changed rows", before, after)
			}
		})
	}
	wrong := expected
	wrong.Digest[0] ^= 1
	if got, e := a.CompareAndSwapPolicy(ctx, admin, wrong, nextFixturePolicy(t, p), fixtureRequest(21)); got != (Receipt{}) || !errors.Is(e, metadata.ErrConflict) {
		t.Fatal("wrong expected digest", got, e)
	}
	wrapped := expected
	wrapped.Version = ^uint64(0)
	if got, e := a.CompareAndSwapPolicy(ctx, admin, wrapped, p, fixtureRequest(22)); got != (Receipt{}) || e == nil {
		t.Fatal("version wrap request", got, e)
	}
	// Introduce an explicit approval deny without increasing effective rights.
	denied := nextFixturePolicy(t, p)
	denied.Repository.Roles[0].Allow = append(denied.Repository.Roles[0].Allow, authz.RepositoryApprove)
	denied.Repository.Roles[0].Deny = []authz.RepositoryCapability{authz.RepositoryApprove}
	if _, e := a.CompareAndSwapPolicy(ctx, admin, expected, denied, fixtureRequest(23)); e != nil {
		t.Fatal("non-escalating deny introduction", e)
	}
	removed := nextFixturePolicy(t, denied)
	removed.Repository.Roles[0].Deny = nil
	if got, e := a.CompareAndSwapPolicy(ctx, admin, fixtureHead(t, f, denied), removed, fixtureRequest(24)); got != (Receipt{}) || !errors.Is(e, metadata.ErrPermissionDenied) {
		t.Fatal("deny removal escalated approval", got, e)
	}
	// The SQL uint64 successor must reject the actual all-ff boundary.
	var value []byte
	if e := f.db.QueryRow(ctx, "SELECT scion_policy.next_version($1)", versionBytes(^uint64(0))).Scan(&value); e == nil {
		t.Fatal("SQL version wrapped", value)
	}
	if e := f.db.QueryRow(ctx, "SELECT scion_policy.next_version($1)", versionBytes(1<<63-1)).Scan(&value); e != nil || !bytes.Equal(value, versionBytes(1<<63)) {
		t.Fatal("unsigned signed-boundary successor", value, e)
	}
}

func TestPolicyCASConcurrentExactlyOneAndAuditRollback(t *testing.T) {
	f := managementSetup(t)
	admin, writer, _, a, _ := f.bootstrap(t)
	ctx := context.Background()
	p := f.policy(admin, writer)
	expected := fixtureHead(t, f, p)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := byte(30); i < 32; i++ {
		wg.Add(1)
		go func(id byte) {
			defer wg.Done()
			<-start
			_, e := a.CompareAndSwapPolicy(ctx, admin, expected, nextFixturePolicy(t, p), fixtureRequest(id))
			results <- e
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if errors.Is(e, metadata.ErrConflict) {
			conflicts++
		} else {
			t.Fatal("unexpected concurrent result", e)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatal("CAS winners", success, conflicts)
	}
	current := nextFixturePolicy(t, p)
	expected = fixtureHead(t, f, current)
	before := policyCounts(t, f)
	lock, e := f.db.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Rollback(context.Background())
	if _, e = lock.Exec(ctx, "LOCK TABLE scion_policy.audit IN ACCESS EXCLUSIVE MODE"); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		got, e := a.CompareAndSwapPolicy(ctx, admin, expected, nextFixturePolicy(t, current), fixtureRequest(32))
		if got != (Receipt{}) {
			e = fmt.Errorf("failed audit returned success receipt")
		}
		done <- e
	}()
	waitPolicyLock(t, f, f.roles.Admin, "record_admin_result", done)
	if e = <-done; e == nil {
		t.Fatal("blocked audit CAS succeeded")
	}
	if e = lock.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	if after := policyCounts(t, f); after != before {
		t.Fatal("audit failure partially published policy", before, after)
	}
	if _, e = a.GetPolicy(ctx, admin, expected); e != nil {
		t.Fatal("audit failure moved head", e)
	}
}

func TestPolicySharedHeadGuardFencesCASAndPolicyLoss(t *testing.T) {
	f := managementSetup(t)
	admin, writer, s, a, _ := f.bootstrap(t)
	ctx := context.Background()
	p := f.policy(admin, writer)
	entered, release, done := make(chan struct{}, 1), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- s.runTx(ctx, func(work context.Context, tx pgx.Tx) error {
			if _, _, e := loadHead(work, tx, admin.Session.Claims); e != nil {
				return e
			}
			entered <- struct{}{}
			<-release
			return nil
		})
	}()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	select {
	case <-entered:
	case e := <-done:
		t.Fatal(e)
	case <-time.After(4 * time.Second):
		t.Fatal("guard not acquired")
	}
	n := nextFixturePolicy(t, p)
	// An administrator may remove its own administration, but never add it.
	n.Repository.Roles[0].Allow = nil
	updated := make(chan error, 1)
	go func() {
		_, e := a.CompareAndSwapPolicy(ctx, admin, fixtureHead(t, f, p), n, fixtureRequest(40))
		updated <- e
	}()
	waitPolicyLock(t, f, f.roles.Admin, "lock_head_exclusive", updated)
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := <-updated; e != nil {
		t.Fatal("update after shared guard", e)
	}
	if got, e := a.GetPolicy(ctx, admin, fixtureHead(t, f, n)); got.Repository.Scope != (authz.RepositoryScope{}) || e == nil {
		t.Fatal("removed admin read current policy", e)
	}
	if got, e := a.GetAdminResult(ctx, admin, AdminResultQuery{Operation: 5, RequestID: fixtureRequest(40)}); got != (Receipt{}) || e == nil {
		t.Fatal("historical allow bypassed current policy", got, e)
	}
}

func TestPolicyCASLostCommitAcknowledgementRecoversDurableResult(t *testing.T) {
	f := managementSetup(t)
	admin, writer, _, a, _ := f.bootstrap(t)
	ctx := context.Background()
	p := f.policy(admin, writer)
	n := nextFixturePolicy(t, p)
	ack := make(chan struct{}, 1)
	original := a.store.config.DialFunc
	// This is a transport fault against a REAL backend. Suppress only a real
	// CommandComplete COMMIT response, after PostgreSQL committed the transaction.
	a.store.config.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		server, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		client, proxy := net.Pipe()
		go func() { defer server.Close(); defer proxy.Close(); _, _ = io.Copy(server, proxy) }()
		go func() {
			defer server.Close()
			defer proxy.Close()
			for {
				var header [5]byte
				if _, err := io.ReadFull(server, header[:]); err != nil {
					return
				}
				size := binary.BigEndian.Uint32(header[1:])
				if size < 4 || size > 4<<20 {
					return
				}
				body := make([]byte, int(size)-4)
				if _, err := io.ReadFull(server, body); err != nil {
					return
				}
				if header[0] == 'C' && string(body) == "COMMIT\x00" {
					ack <- struct{}{}
					return
				}
				if _, err := proxy.Write(header[:]); err != nil {
					return
				}
				if _, err := proxy.Write(body); err != nil {
					return
				}
			}
		}()
		return client, nil
	}
	r, e := a.CompareAndSwapPolicy(ctx, admin, fixtureHead(t, f, p), n, fixtureRequest(50))
	a.store.config.DialFunc = original
	if r != (Receipt{}) || !errors.Is(e, metadata.ErrOutcomeUnknown) {
		t.Fatal("lost COMMIT acknowledgment claimed known result", r, e)
	}
	select {
	case <-ack:
	default:
		t.Fatal("fault never intercepted actual COMMIT acknowledgment")
	}
	if _, e := a.GetPolicy(ctx, admin, fixtureHead(t, f, n)); e != nil {
		t.Fatal("acknowledged-on-server policy was not durable", e)
	}
	recovered, e := a.GetAdminResult(ctx, admin, AdminResultQuery{Operation: 5, RequestID: fixtureRequest(50)})
	if e != nil || recovered.PolicyVersion != 1 || recovered.PolicyDigest != fixtureHead(t, f, n).Digest {
		t.Fatal("cannot recover actual committed result", recovered, e)
	}
	if replay, e := a.CompareAndSwapPolicy(ctx, admin, fixtureHead(t, f, p), n, fixtureRequest(50)); e != nil || replay != recovered {
		t.Fatal("exact uncertain retry did not resolve actual commit", replay, e)
	}
}

func TestPolicyWaitedHeadUsesFreshImmutableBody(t *testing.T) {
	f := managementSetup(t)
	admin, writer, _, a, _ := f.bootstrap(t)
	ctx := context.Background()
	p := f.policy(admin, writer)
	n := nextFixturePolicy(t, p)
	old, next := fixtureHead(t, f, p), fixtureHead(t, f, n)
	lock, e := f.db.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Rollback(context.Background())
	if _, e = lock.Exec(ctx, "LOCK TABLE scion_policy.audit IN ACCESS EXCLUSIVE MODE"); e != nil {
		t.Fatal(e)
	}
	winner, loser, reader := make(chan error, 1), make(chan error, 1), make(chan error, 1)
	go func() { _, e := a.CompareAndSwapPolicy(ctx, admin, old, n, fixtureRequest(60)); winner <- e }()
	// Winner owns an uncommitted successor head and is paused at its audit.
	waitPolicyLock(t, f, f.roles.Admin, "record_admin_result", winner)
	go func() { _, e := a.CompareAndSwapPolicy(ctx, admin, old, n, fixtureRequest(61)); loser <- e }()
	waitPolicyLock(t, f, f.roles.Admin, "lock_head_exclusive", loser)
	go func() { _, e := a.GetPolicy(ctx, admin, next); reader <- e }()
	waitPolicyLock(t, f, f.roles.Admin, "lock_head_shared", reader)
	if e = lock.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-winner; e != nil {
		t.Fatal("paused winning CAS", e)
	}
	if e = <-loser; !errors.Is(e, metadata.ErrConflict) {
		t.Fatal("waited exclusive head did not observe current successor", e)
	}
	if e = <-reader; e != nil {
		t.Fatal("waited shared head did not observe matching current body", e)
	}
}
