package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func roleConnection(t *testing.T, f *managementFixture, role string) *pgx.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := pgx.Connect(ctx, f.dsn(role))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = c.Close(ctx)
	})
	return c
}
func deniedSQL(t *testing.T, c *pgx.Conn, sql string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := c.Exec(ctx, sql, args...)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "42501" {
		t.Fatalf("expected database privilege denial: %s: %v", sql, err)
	}
}
func TestPolicySchemaActualPrivileges(t *testing.T) {
	f := managementSetup(t)
	ctx := context.Background()
	admin, _, _, _, _ := f.bootstrap(t)
	c := roleConnection(t, f, f.roles.Serving)
	for _, sql := range []string{"INSERT INTO scion_policy.management_capacity VALUES('a',decode(repeat('01',16),'hex'),0,0)", "UPDATE scion_policy.session_state SET revoked=true", "DELETE FROM scion_policy.policy_versions", "TRUNCATE scion_policy.audit", "CREATE SCHEMA forbidden_policy_fixture", "SET ROLE " + pgx.Identifier{f.roles.Owner}.Sanitize(), "SET ROLE " + pgx.Identifier{f.roles.FunctionOwner}.Sanitize(), "SET ROLE " + pgx.Identifier{f.roles.Admin}.Sanitize(), "SET ROLE " + pgx.Identifier{f.roles.Bootstrap}.Sanitize()} {
		deniedSQL(t, c, sql)
	}
	deniedSQL(t, c, "SELECT scion_policy.begin_bootstrap($1,$2)", []byte(admin.Session.Claims.Tenant), f.repo[:])
	deniedSQL(t, c, "SELECT scion_policy.revoke_session($1,$2,$3)", []byte(admin.Session.Claims.Tenant), f.repo[:], admin.Session.Claims.Session[:])
	deniedSQL(t, c, "SELECT * FROM scion_policy.read_admin_result($1,$2,$3,$4::smallint,$5,$6,$7,$8)", []byte(admin.Session.Claims.Tenant), f.repo[:], make([]byte, 32), 1, make([]byte, 32), []byte("identity"), []byte("admin"), []byte("human"))
	tx, err := c.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT FROM scion_policy.lock_credential_shared($1,$2,$3))", []byte(admin.Session.Claims.Tenant), f.repo[:], admin.Session.Claims.CredentialHash[:]).Scan(&found)
	if err != nil || !found {
		t.Fatal("fixed shared lock without direct UPDATE", found, err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"policy_versions", "audit", "admin_results"} {
		if _, err = f.db.Exec(ctx, "DELETE FROM scion_policy."+table); err == nil {
			t.Fatal("immutable delete accepted", table)
		}
	}
	if _, err = Provision(ctx, ProvisionConfig{DSN: f.dsn("complete"), Roles: f.roles}); err == nil {
		t.Fatal("existing installation was adopted")
	}
}
func TestPolicySchemaCatalogDrift(t *testing.T) {
	changes := map[string]func(*testing.T, *managementFixture){
		"rule": func(t *testing.T, f *managementFixture) {
			_, e := f.db.Exec(context.Background(), "CREATE RULE hidden_insert AS ON INSERT TO scion_policy.session_state DO INSTEAD NOTHING")
			if e != nil {
				t.Fatal(e)
			}
		},
		"disabled-trigger": func(t *testing.T, f *managementFixture) {
			_, e := f.db.Exec(context.Background(), "ALTER TABLE scion_policy.policy_versions DISABLE TRIGGER USER")
			if e != nil {
				t.Fatal(e)
			}
		},
		"public-execute": func(t *testing.T, f *managementFixture) {
			_, e := f.db.Exec(context.Background(), "GRANT EXECUTE ON FUNCTION scion_policy.revoke_session(bytea,bytea,bytea) TO PUBLIC")
			if e != nil {
				t.Fatal(e)
			}
		},
		"direct-update": func(t *testing.T, f *managementFixture) {
			_, e := f.db.Exec(context.Background(), "GRANT UPDATE ON scion_policy.session_state TO "+pgx.Identifier{f.roles.Serving}.Sanitize())
			if e != nil {
				t.Fatal(e)
			}
		},
		"role-membership": func(t *testing.T, f *managementFixture) {
			_, e := f.admin.Exec(context.Background(), "GRANT "+pgx.Identifier{f.roles.Owner}.Sanitize()+" TO "+pgx.Identifier{f.roles.Serving}.Sanitize())
			if e != nil {
				t.Fatal(e)
			}
		},
		"role-attribute": func(t *testing.T, f *managementFixture) {
			_, e := f.admin.Exec(context.Background(), "ALTER ROLE "+pgx.Identifier{f.roles.Serving}.Sanitize()+" BYPASSRLS")
			if e != nil {
				t.Fatal(e)
			}
		},
		"function-searchpath": func(t *testing.T, f *managementFixture) {
			_, e := f.db.Exec(context.Background(), "ALTER FUNCTION scion_policy.identity() SET search_path=public,pg_catalog")
			if e != nil {
				t.Fatal(e)
			}
		},
		"inheritance": func(t *testing.T, f *managementFixture) {
			_, e := f.db.Exec(context.Background(), "CREATE TABLE public.external_policy_child() INHERITS(scion_policy.policy_versions)")
			if e != nil {
				t.Fatal(e)
			}
		},
		"oversized-function": func(t *testing.T, f *managementFixture) {
			_, e := f.db.Exec(context.Background(), "CREATE FUNCTION scion_policy.oversized_fixture() RETURNS text LANGUAGE sql AS $fixture$SELECT '"+strings.Repeat("x", 2<<20)+"'::text$fixture$")
			if e != nil {
				t.Fatal(e)
			}
		},
		"oversized-option": func(t *testing.T, f *managementFixture) {
			_, e := f.db.Exec(context.Background(), "ALTER FUNCTION scion_policy.identity() SET fixture.large = "+quoteFixture(strings.Repeat("x", 2<<20)))
			if e != nil {
				t.Fatal(e)
			}
		},
		"excess-objects": func(t *testing.T, f *managementFixture) {
			var b strings.Builder
			for i := 0; i < 1100; i++ {
				fmt.Fprintf(&b, "CREATE FUNCTION scion_policy.x_%d() RETURNS int LANGUAGE sql AS 'SELECT 1';", i)
			}
			if _, e := f.db.Exec(context.Background(), b.String()); e != nil {
				t.Fatal(e)
			}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f := managementSetup(t)
			change(t, f)
			got, e := Open(context.Background(), f.config(f.roles.Serving))
			if e == nil || got != nil {
				t.Fatal("catalog/role drift accepted")
			}
			if strings.Contains(e.Error(), "credential") || strings.Contains(e.Error(), "password=") {
				t.Fatal("unredacted failure", e)
			}
		})
	}
}
func TestPolicySchemaCapacityBound(t *testing.T) {
	f := managementSetup(t)
	admin, _, s, a, _ := f.bootstrap(t)
	ctx := context.Background()
	var before int
	if e := f.db.QueryRow(ctx, "SELECT count(*) FROM scion_policy.session_state").Scan(&before); e != nil {
		t.Fatal(e)
	}
	var rows, size int64
	if e := f.db.QueryRow(ctx, "SELECT rows_used,bytes_used FROM scion_policy.management_capacity").Scan(&rows, &size); e != nil {
		t.Fatal(e)
	}
	target := f.credentials("target", 10)
	for _, limit := range [][2]int64{{65536, size}, {rows, 67108864}} {
		if _, e := f.db.Exec(ctx, "UPDATE scion_policy.management_capacity SET rows_used=$1,bytes_used=$2", limit[0], limit[1]); e != nil {
			t.Fatal(e)
		}
		receipt, e := a.Enroll(ctx, admin, Enrollment{Target: target, RequestID: fixtureRequest(20)})
		if e == nil || receipt != (Receipt{}) {
			t.Fatal("capacity bypass", limit, receipt, e)
		}
		var after int
		if e = f.db.QueryRow(ctx, "SELECT count(*) FROM scion_policy.session_state").Scan(&after); e != nil || after != before {
			t.Fatal("partial quota write", after, e)
		}
		mustDenyAuthentication(t, s, target)
	}

}

func TestPolicyManagementResultExactPrincipalPredicate(t *testing.T) {
	f := managementSetup(t)
	admin, _, _, _, _ := f.bootstrap(t)
	different := f.credentials("different-signed-principal", 80)
	c := roleConnection(t, f, f.roles.Admin)
	index := principalIndex(admin.Session.Claims.Principal)
	request := fixtureRequest(1)
	query := `SELECT count(*) FROM scion_policy.read_admin_result($1,$2,$3,$4::smallint,$5,$6,$7,$8)`
	for _, test := range []struct {
		actor ActorCredentials
		want  int
	}{{admin, 1}, {different, 0}} {
		p := test.actor.Session.Claims.Principal
		var n int
		if e := c.QueryRow(context.Background(), query, []byte(admin.Session.Claims.Tenant), f.repo[:], index[:], 1, request[:], []byte(p.Issuer), []byte(p.Subject), []byte(p.Class)).Scan(&n); e != nil || n != test.want {
			t.Fatal("known digest never substitutes exact tuple", n, e)
		}
	}
	// This is a fixed-SQL collision-defense predicate test under a trusted admin
	// fixture connection, not a claim of endpoint authentication or SHA collision.
}
