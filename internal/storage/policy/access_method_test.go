package policy

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"

	"canopy.local/canopy/internal/storage/metadata"
)

// DDL here changes only each disposable fixture database, never the shared
// server configuration or another database's builtin catalog.
func TestPolicyAccessMethodDrift(t *testing.T) {
	for name, ddl := range map[string]string{
		"table-method":             "CREATE ACCESS METHOD policy_fixture_heap TYPE TABLE HANDLER pg_catalog.heap_tableam_handler; ALTER TABLE scion_policy.session_state SET ACCESS METHOD policy_fixture_heap",
		"table-handler-name":       "ALTER FUNCTION pg_catalog.heap_tableam_handler(internal) RENAME TO fixture_heap_handler",
		"index-handler-name":       "ALTER FUNCTION pg_catalog.bthandler(internal) RENAME TO fixture_btree_handler",
		"table-handler-owner":      "ALTER FUNCTION pg_catalog.heap_tableam_handler(internal) OWNER TO %OWNER%",
		"index-handler-acl":        "REVOKE EXECUTE ON FUNCTION pg_catalog.bthandler(internal) FROM PUBLIC",
		"table-handler-security":   "ALTER FUNCTION pg_catalog.heap_tableam_handler(internal) SECURITY DEFINER",
		"handler-oversized-config": "ALTER FUNCTION pg_catalog.bthandler(internal) SET fixture.large = " + quoteFixture(strings.Repeat("x", 2<<20)),
	} {
		t.Run(name, func(t *testing.T) {
			f := managementSetup(t)
			actor, _, s, a, b := f.bootstrap(t)
			ctx := context.Background()
			if _, err := s.Authenticate(ctx, actor.Identity, actor.Session); err != nil {
				t.Fatal("healthy binding", err)
			}
			before := policyCounts(t, f)
			if name == "table-handler-owner" {
				ddl = "ALTER FUNCTION pg_catalog.heap_tableam_handler(internal) OWNER TO " + pgx.Identifier{f.roles.Owner}.Sanitize()
			}
			if _, err := f.db.Exec(ctx, ddl); err != nil {
				t.Fatal("fixture drift DDL", err)
			}
			if name == "table-method" {
				var method string
				if err := f.db.QueryRow(ctx, "SELECT a.amname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_am a ON a.oid=c.relam WHERE c.oid='scion_policy.session_state'::regclass").Scan(&method); err != nil || method != "policy_fixture_heap" {
					t.Fatal("method change not applied", method, err)
				}
			}
			mustDenyAuthentication(t, s, actor)
			if r, err := a.Enroll(ctx, actor, Enrollment{Target: f.credentials("after-drift", 240), RequestID: fixtureRequest(240)}); r != (Receipt{}) || !errors.Is(err, metadata.ErrFailedPrecondition) {
				t.Fatal("existing admin accepted drift", r, err)
			}
			if r, err := b.Bootstrap(ctx, BootstrapRequest{Target: actor, Policy: f.policy(actor, f.credentials("writer", 2)), RequestID: fixtureRequest(1)}); r != (Receipt{}) || !errors.Is(err, metadata.ErrFailedPrecondition) {
				t.Fatal("existing bootstrap returned retained result after drift", r, err)
			}
			if got, err := Open(ctx, f.config(f.roles.Serving)); got != nil || !errors.Is(err, metadata.ErrFailedPrecondition) {
				t.Fatal("fresh serving accepted drift", got, err)
			}
			if got, err := OpenAdmin(ctx, f.config(f.roles.Admin)); got != nil || !errors.Is(err, metadata.ErrFailedPrecondition) {
				t.Fatal("fresh admin accepted drift", got, err)
			}
			if got, err := OpenBootstrap(ctx, f.config(f.roles.Bootstrap)); got != nil || !errors.Is(err, metadata.ErrFailedPrecondition) {
				t.Fatal("fresh bootstrap accepted drift", got, err)
			}
			if after := policyCounts(t, f); after != before {
				t.Fatal("drift admission changed application state", before, after)
			}
		})
	}
}

func TestPolicyAccessMethodProvisionRejectsCustomDefault(t *testing.T) {
	f := managementSetup(t)
	ctx := context.Background()
	if _, err := f.db.Exec(ctx, "DROP SCHEMA scion_policy CASCADE; CREATE ACCESS METHOD policy_fixture_heap TYPE TABLE HANDLER pg_catalog.heap_tableam_handler"); err != nil {
		t.Fatal(err)
	}
	// The new offline install must not bless a custom method selected by a DSN.
	binding, err := Provision(ctx, ProvisionConfig{DSN: f.dsn("complete") + " default_table_access_method=policy_fixture_heap", Roles: f.roles})
	if binding != (DatabaseBinding{}) || !errors.Is(err, metadata.ErrFailedPrecondition) {
		t.Fatal("custom default method provisioned", binding, err)
	}
	var exists bool
	if err = f.db.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_catalog.pg_namespace WHERE nspname='scion_policy')").Scan(&exists); err != nil || exists {
		t.Fatal("failed provision left partial installation", exists, err)
	}
	// Safe retry provisions only absent schema, and the returned binding works.
	f.binding, err = Provision(ctx, ProvisionConfig{DSN: f.dsn("complete"), Roles: f.roles})
	if err != nil {
		t.Fatal(err)
	}
	f.bootstrap(t)
}

func TestPolicyAccessMethodProvisionRejectsHandlerDrift(t *testing.T) {
	f := managementSetup(t)
	ctx := context.Background()
	if _, err := f.db.Exec(ctx, "DROP SCHEMA scion_policy CASCADE; ALTER FUNCTION pg_catalog.heap_tableam_handler(internal) SECURITY DEFINER"); err != nil {
		t.Fatal(err)
	}
	binding, err := Provision(ctx, ProvisionConfig{DSN: f.dsn("complete"), Roles: f.roles})
	if binding != (DatabaseBinding{}) || !errors.Is(err, metadata.ErrFailedPrecondition) {
		t.Fatal("untrusted handler provisioned", binding, err)
	}
	var exists bool
	if err = f.db.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_catalog.pg_namespace WHERE nspname='scion_policy')").Scan(&exists); err != nil || exists {
		t.Fatal("failed provision left partial installation", exists, err)
	}
}
