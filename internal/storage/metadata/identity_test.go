package metadata

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func identityFixture(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("SCION_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("requires isolated real PostgreSQL admin DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("fixture admin unavailable")
	}
	name := fmt.Sprintf("scion_identity_%d", time.Now().UnixNano())
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		closePostgres(admin)
		t.Fatal(err)
	}
	var c *pgx.Conn
	t.Cleanup(func() {
		if c != nil {
			closePostgres(c)
		}
		// CREATE/DROP DATABASE force checkpoints on real storage; cleanup has a
		// separate finite fixture budget, not the serving-operation deadline.
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if _, e := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); e != nil {
			t.Error(e)
		}
		closePostgres(admin)
	})
	cfg := admin.Config().Copy()
	cfg.Database = name
	cfg.RuntimeParams["statement_timeout"] = "5000"
	cfg.RuntimeParams["lock_timeout"] = "1000"
	cfg.RuntimeParams["transaction_timeout"] = "10000"
	c, err = pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Exec(ctx, postgresDDL); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Exec(ctx, "INSERT INTO scion_metadata.schema_version VALUES(true,1,$1)", postgresDDL); err != nil {
		t.Fatal(err)
	}
	var version string
	if err = c.QueryRow(ctx, "SELECT version()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture=%s backend=%s seed=metadata-v1-fixed-DDL", name, version)
	return c
}

func identityTx(t *testing.T, c *pgx.Conn) pgx.Tx {
	t.Helper()
	tx, err := c.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rollbackPostgres(tx) })
	return tx
}

func TestPostgresDatabaseIdentityReal(t *testing.T) {
	c := identityFixture(t)
	ctx := context.Background()
	tx := identityTx(t, c)
	got, err := VerifyPostgresDatabase(ctx, tx)
	if err != nil || got.Database != c.Config().Database || got.OID == 0 || hex.EncodeToString(got.MetadataFingerprint[:]) != postgresCatalogV1 {
		t.Fatalf("identity=%+v error=%v", got, err)
	}
	var path string
	if err = tx.QueryRow(ctx, "SHOW search_path").Scan(&path); err != nil || path != "pg_catalog, pg_temp" {
		t.Fatalf("hardened search path=%q %v", path, err)
	}
	// Verification owns no commit: caller can continue and roll back its work.
	if _, err = tx.Exec(ctx, "CREATE TEMP TABLE identity_transaction_fixture(v int)"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if value, e := VerifyPostgresDatabase(ctx, tx); value != (PostgresDatabaseIdentity{}) || e != ErrUnavailable {
		t.Fatalf("closed transaction=%+v %v", value, e)
	}
	tx = identityTx(t, c)
	if _, err = tx.Exec(ctx, "CREATE TEMP TABLE pg_class(v int); SET LOCAL search_path=pg_temp,public,pg_catalog"); err != nil {
		t.Fatal(err)
	}
	if value, e := VerifyPostgresDatabase(ctx, tx); e != nil || value != got {
		t.Fatalf("temporary catalog shadow changed result=%+v %v", value, e)
	}
	rollbackPostgres(tx)
	other := identityFixture(t)
	otherID, err := VerifyPostgresDatabase(ctx, identityTx(t, other))
	if err != nil || otherID.Database == got.Database || otherID.OID == got.OID || otherID.MetadataFingerprint != got.MetadataFingerprint {
		t.Fatalf("separate database=%+v %v", otherID, err)
	}
}

func TestPostgresDatabaseIdentityDriftReal(t *testing.T) {
	c := identityFixture(t)
	for name, sql := range map[string]string{
		"marker":      "UPDATE scion_metadata.schema_version SET version=2",
		"definition":  "UPDATE scion_metadata.schema_version SET definition='untrusted'",
		"missing":     "DROP SCHEMA scion_metadata CASCADE",
		"trigger":     "ALTER TABLE scion_metadata.publications DISABLE TRIGGER publication_immutable",
		"rule":        "CREATE RULE discard AS ON INSERT TO scion_metadata.publications DO INSTEAD NOTHING",
		"inheritance": "CREATE TABLE public.shadow() INHERITS(scion_metadata.publications)",
		"oversize function": "CREATE FUNCTION scion_metadata.big() RETURNS text LANGUAGE sql AS " +
			"$fn$ SELECT '" + strings.Repeat("x", 70000) + "'::text $fn$",
		"excess objects": `DO $body$ BEGIN FOR i IN 1..130 LOOP EXECUTE format('CREATE TABLE scion_metadata.extra%s(v int)',i); END LOOP; END $body$`,
	} {
		t.Run(name, func(t *testing.T) {
			tx := identityTx(t, c)
			if _, err := tx.Exec(context.Background(), sql); err != nil {
				t.Fatal(err)
			}
			got, err := VerifyPostgresDatabase(context.Background(), tx)
			if got != (PostgresDatabaseIdentity{}) || err != ErrFailedPrecondition {
				t.Fatalf("drift accepted=%+v error=%v", got, err)
			}
		})
	}
}

func TestPostgresDatabaseIdentityFailureReal(t *testing.T) {
	c := identityFixture(t)
	tx, err := c.BeginTx(context.Background(), pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	if got, e := VerifyPostgresDatabase(context.Background(), tx); got != (PostgresDatabaseIdentity{}) || e != ErrFailedPrecondition {
		t.Fatalf("read-only accepted=%+v %v", got, e)
	}
	rollbackPostgres(tx)
	blocker, err := pgx.ConnectConfig(context.Background(), c.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer closePostgres(blocker)
	locked := identityTx(t, blocker)
	if _, err = locked.Exec(context.Background(), "LOCK TABLE scion_metadata.schema_version IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	tx = identityTx(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if got, e := VerifyPostgresDatabase(ctx, tx); got != (PostgresDatabaseIdentity{}) || !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("blocked cancellation=%+v %v", got, e)
	}
	// Optional real replay fixture, not a mocked pg_is_in_recovery result.
	// Qualification must retain this named subtest and actual standby startup.
	if dsn := os.Getenv("SCION_POSTGRES_STANDBY_TEST_DSN"); dsn != "" {
		t.Run("standby", func(t *testing.T) {
			c, err := pgx.Connect(context.Background(), dsn)
			if err != nil {
				t.Fatal("standby fixture unavailable")
			}
			defer closePostgres(c)
			var recovery bool
			if err = c.QueryRow(context.Background(), "SELECT pg_catalog.pg_is_in_recovery()").Scan(&recovery); err != nil || !recovery {
				t.Fatal("fixture is not a replaying standby", err)
			}
			got, err := VerifyPostgresDatabase(context.Background(), identityTx(t, c))
			if got != (PostgresDatabaseIdentity{}) || err != ErrFailedPrecondition {
				t.Fatalf("standby accepted=%+v %v", got, err)
			}
		})
	}
}

type identityNilTx struct{ pgx.Tx }

func TestPostgresDatabaseIdentityInvalid(t *testing.T) {
	var missing *identityNilTx
	for _, tx := range []pgx.Tx{nil, missing} {
		if got, err := VerifyPostgresDatabase(context.Background(), tx); got != (PostgresDatabaseIdentity{}) || err != ErrFailedPrecondition {
			t.Fatalf("nil transaction=%+v %v", got, err)
		}
	}
	if _, err := VerifyPostgresDatabase(nil, nil); err != ErrFailedPrecondition {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := VerifyPostgresDatabase(ctx, &identityNilTx{}); got != (PostgresDatabaseIdentity{}) || err != context.Canceled {
		t.Fatalf("canceled before transaction access=%+v %v", got, err)
	}
}
