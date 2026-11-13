package metadata

import (
	"bytes"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"os"
	"testing"
	"time"
)

type pgTrust struct {
	deny      bool
	rechecked bool
}

func (a *pgTrust) Authorize(context.Context, Scope, string) error {
	if a.deny {
		return ErrPermissionDenied
	}
	return nil
}
func (a *pgTrust) Recheck(context.Context, pgx.Tx, Scope, string) error {
	a.rechecked = true
	return nil
}
func (*pgTrust) Publication(context.Context, Scope, PublishRequest) (PostgresRetention, error) {
	return nil, ErrFailedPrecondition
}
func (*pgTrust) Derived(context.Context, Scope, DerivedWrite) (PostgresRetention, error) {
	return nil, ErrFailedPrecondition
}
func TestPostgresMissingTrust(t *testing.T) {
	var missing *pgTrust
	good := &pgTrust{}
	for _, deps := range [][2]*pgTrust{{nil, good}, {good, nil}, {missing, missing}} {
		if _, err := OpenPostgres(context.Background(), "password=DO_NOT_LEAK", deps[0], deps[1]); !errors.Is(err, ErrFailedPrecondition) {
			t.Fatal(err)
		}
	}
	if _, err := OpenPostgres(context.Background(), "invalid DO_NOT_LEAK", good, good); err != ErrInvalidArgument {
		t.Fatal(err)
	}
}

// Each invocation creates and drops ONLY its unique disposable database.
// A missing server is a skip, not persistence evidence; qualification must set
// SCION_POSTGRES_TEST_DSN and retain the real server's output/version.
func TestPostgresFoundationReal(t *testing.T) {
	dsn := os.Getenv("SCION_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("requires isolated real PostgreSQL admin DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("admin connect failed")
	}
	defer closePostgres(admin)
	name := "scion_meta_" + time.Now().UTC().Format("20060102150405.000000000")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, e := admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); e != nil {
			t.Error(e)
		}
	}()
	trust := &pgTrust{}
	p, err := OpenPostgres(ctx, dsn, trust, trust)
	if err != nil {
		t.Fatal(err)
	}
	p.config.Database = name // No schema writes occur before this isolated binding.
	defer p.Close()
	t.Log("fixture database", name, "seed: byte keys 00ff and 00fe; schema v1")
	for range 2 {
		if err = p.InitializeSchema(ctx); err != nil {
			t.Fatal(err)
		}
	}
	c, err := p.connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closePostgres(c)
	for setting, want := range map[string]string{"statement_timeout": "5s", "lock_timeout": "1s", "transaction_timeout": "10s", "idle_in_transaction_session_timeout": "5s"} {
		var actual string
		if e := c.QueryRow(ctx, "SHOW "+setting).Scan(&actual); e != nil || actual != want {
			t.Fatalf("setting %s: %s %v", setting, actual, e)
		}
	}
	var version string
	if err = c.QueryRow(ctx, "SELECT version()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Log(version)
	repo := make([]byte, 16)
	id := make([]byte, 35)
	id[1] = 1
	id[2] = 2
	insert := "INSERT INTO scion_metadata.publications VALUES($1,$2,$3,$4)"
	if _, err = c.Exec(ctx, insert, repo, id, []byte{0, 255}, []byte{0, 254}); err != nil {
		t.Fatal(err)
	}
	var got []byte
	if err = c.QueryRow(ctx, "SELECT publication FROM scion_metadata.publications WHERE repository=$1 AND changeset=$2", repo, id).Scan(&got); err != nil || !bytes.Equal(got, []byte{0, 255}) {
		t.Fatal("byte preservation", err)
	}
	other := bytes.Clone(repo)
	other[0] = 1
	if _, err = c.Exec(ctx, insert, other, id, []byte{0, 255}, []byte{0, 254}); err != nil {
		t.Fatal("repository isolation", err)
	}
	tests := []struct {
		name, sql string
		args      []any
	}{
		{"duplicate", insert, []any{repo, id, []byte{1}, []byte{1}}},
		{"invalid repo", insert, []any{[]byte{1}, id, []byte{1}, []byte{1}}},
		{"oversize key", insert, []any{repo, id, make([]byte, 129), []byte{1}}},
		{"immutable update", "UPDATE scion_metadata.publications SET publication=decode('01','hex')", nil},
		{"permanent binding delete", "DELETE FROM scion_metadata.publications", nil},
		{"permanent binding truncate", "TRUNCATE scion_metadata.publications", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, e := c.Exec(ctx, tt.sql, tt.args...); e == nil {
				t.Fatal("constraint accepted invalid state")
			}
		})
	}
	trust.deny = true
	if err = p.withAuthorizedTx(ctx, Scope{}, "read", func(pgx.Tx) error { t.Fatal("unauthorized callback"); return nil }); err != ErrPermissionDenied {
		t.Fatal(err)
	}
	trust.deny = false
	sentinel := errors.New("rollback fixture")
	err = p.withAuthorizedTx(ctx, Scope{}, "write", func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "INSERT INTO scion_metadata.mutations VALUES($1,$2,1,$3,$4,$5)", repo, []byte{255}, []byte{0}, make([]byte, 32), []byte{1}); e != nil {
			t.Fatal(e)
		}
		return sentinel
	})
	if err != sentinel || !trust.rechecked {
		t.Fatal("policy guard/rollback", err)
	}
	var count int
	if err = c.QueryRow(ctx, "SELECT count(*) FROM scion_metadata.mutations").Scan(&count); err != nil || count != 0 {
		t.Fatal("rollback", err, count)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if err = p.InitializeSchema(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation", err)
	}
	if _, err = c.Exec(ctx, "UPDATE scion_metadata.schema_version SET version=2"); err != nil {
		t.Fatal(err)
	}
	if err = p.InitializeSchema(ctx); err != ErrFailedPrecondition {
		t.Fatal("incompatible version", err)
	}
	if err = c.QueryRow(ctx, "SELECT count(*) FROM scion_metadata.publications").Scan(&count); err != nil || count != 2 {
		t.Fatal("schema preserved", err)
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	if err = p.InitializeSchema(ctx); err != ErrUnavailable {
		t.Fatal("closed foundation", err)
	}
	if err = admin.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE datname=$1", name).Scan(&count); err != nil || count != 1 {
		t.Fatal("leaked connection", err, count)
	}
}
