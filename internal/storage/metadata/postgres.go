package metadata

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"reflect"
	"sync/atomic"
	"time"
)

// PostgresAuthorization is supplied by the trusted service composition, never
// the request. Authorize verifies authenticated principal/session, repository,
// operation and current policy before lookup. Recheck holds a policy guard in
// the transaction through commit, preventing revocation races. Hidden and absent
// resources must have the same public error. Implementations must bound work.
type PostgresAuthorization interface {
	Authorize(context.Context, Scope, string) error
	Recheck(context.Context, pgx.Tx, Scope, string) error
}

// PostgresPreflight verifies complete canonical intent/digest, durable blobs,
// final tree validity, or complete TREE-v1 graph/ordered inputs as appropriate.
// It returns a crash-safe durable retention reservation, not a caller assertion.
// Services must provide this dependency; the foundation does not implement it.
type PostgresPreflight interface {
	Publication(context.Context, Scope, PublishRequest) (PostgresRetention, error)
	Derived(context.Context, Scope, DerivedWrite) (PostgresRetention, error)
}

// PostgresRetention binds its durable reservation to the exact metadata row in
// the SAME transaction. Transfer must fail if retention cannot survive commit.
// Release only releases untransferred reservations; after ambiguous commit it
// must resolve durable ownership before releasing, never rely on process memory.
type PostgresRetention interface {
	Transfer(context.Context, pgx.Tx) error
	Release(context.Context) error
}

// Postgres is the schema/connection foundation, not yet a Port implementation.
// Each short operation owns an independent connection; no repository mutex or
// global ingestion sequencer is used. Open/Close own no externally supplied DB.
// DSNs and driver errors are never logged or returned (they can contain secrets).
type Postgres struct {
	config    *pgx.ConnConfig
	auth      PostgresAuthorization
	preflight PostgresPreflight
	closed    atomic.Bool
	slots     chan struct{}
}

func nilDependency(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func postgresError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrUnavailable
}

// OpenPostgres validates dependencies and connectivity without creating schema.
// The returned foundation keeps only a private config; Close is consequently a
// marks it closed (there are no idle sessions). Active operations finish under
// their own deadlines; callers own their cancellation. Later operations fail.
// PostgreSQL 17+ is required for transaction_timeout. Fixed server-side limits
// bound statements (5s), lock waits (1s), idle transactions (5s), total tx (10s).
func OpenPostgres(ctx context.Context, dsn string, auth PostgresAuthorization, preflight PostgresPreflight) (*Postgres, error) {
	if nilDependency(auth) || nilDependency(preflight) {
		return nil, ErrFailedPrecondition
	}
	c, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, ErrInvalidArgument
	}
	c.Tracer = nil
	c.ConnectTimeout = 5 * time.Second
	c.RuntimeParams["statement_timeout"] = "5000"
	c.RuntimeParams["lock_timeout"] = "1000"
	c.RuntimeParams["idle_in_transaction_session_timeout"] = "5000"
	c.RuntimeParams["transaction_timeout"] = "10000"
	c.RuntimeParams["search_path"] = "pg_catalog"
	p := &Postgres{config: c, auth: auth, preflight: preflight, slots: make(chan struct{}, 16)}
	conn, err := p.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer closePostgres(conn)
	var version int
	if err = conn.QueryRow(ctx, "SELECT current_setting('server_version_num')::integer").Scan(&version); err != nil {
		return nil, postgresError(ctx)
	}
	if version < 170000 {
		return nil, ErrFailedPrecondition
	}
	return p, nil
}
func (p *Postgres) Close() error { p.closed.Store(true); return nil }
func closePostgres(c *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = c.Close(ctx)
}
func (p *Postgres) connect(ctx context.Context) (*pgx.Conn, error) {
	if p.closed.Load() {
		return nil, ErrUnavailable
	}
	c, err := pgx.ConnectConfig(ctx, p.config.Copy())
	if err != nil {
		return nil, postgresError(ctx)
	}
	return c, nil
}

// withAuthorizedTx is for bounded future port primitives only. Authorization
// precedes DB access, and policy is rechecked inside the transaction. A commit
// error is ambiguous and never represented as proof of rollback. Returned
// application errors must already be redacted metadata sentinels.
func (p *Postgres) withAuthorizedTx(ctx context.Context, s Scope, op string, fn func(pgx.Tx) error) error {
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		return ErrResourceExhausted
	}
	if err := p.auth.Authorize(ctx, s, op); err != nil {
		return err
	}
	c, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer closePostgres(c)
	tx, err := c.Begin(ctx)
	if err != nil {
		return postgresError(ctx)
	}
	defer tx.Rollback(context.Background())
	if err = p.auth.Recheck(ctx, tx, s, op); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return errors.Join(ErrOutcomeUnknown, postgresError(ctx))
	}
	return nil
}

// InitializeSchema is an explicit administrative action for a dedicated DB.
// It is atomic, repeatable and never upgrades/drops an existing schema. The
// dedicated schema must be administered exclusively by trusted operators.
// Version 1 installs immutable publication/event/mutation identities. Other
// port tables and complete persistence semantics belong to subsequent children.
func (p *Postgres) InitializeSchema(ctx context.Context) error {
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		return ErrResourceExhausted
	}
	c, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer closePostgres(c)
	tx, err := c.Begin(ctx)
	if err != nil {
		return postgresError(ctx)
	}
	defer tx.Rollback(context.Background())
	var exists bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_namespace WHERE nspname='scion_metadata')").Scan(&exists); err != nil {
		return postgresError(ctx)
	}
	if exists {
		var version int
		var definition string
		err = tx.QueryRow(ctx, "SELECT version, definition FROM scion_metadata.schema_version WHERE singleton").Scan(&version, &definition)
		if err != nil || version != 1 || definition != postgresDDL {
			return ErrFailedPrecondition
		}
	} else {
		if _, err = tx.Exec(ctx, postgresDDL); err != nil {
			return postgresError(ctx)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO scion_metadata.schema_version VALUES(true,1,$1)", postgresDDL); err != nil {
			return postgresError(ctx)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return errors.Join(ErrOutcomeUnknown, postgresError(ctx))
	}
	return nil
}

// bytea preserves arbitrary non-UTF8/NUL bytes and avoids collation folding.
// Canonical changeset IDs remain 35 bytes; no TREE page is a canonical kind.
// Immutable bindings cannot be recycled by UPDATE/DELETE/TRUNCATE. This does
// not defend against a privileged schema owner, who can also drop the schema.
const postgresDDL = `CREATE SCHEMA scion_metadata;
CREATE TABLE scion_metadata.schema_version (
 singleton boolean PRIMARY KEY CHECK(singleton), version integer NOT NULL, definition text NOT NULL);
CREATE FUNCTION scion_metadata.immutable() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN RAISE EXCEPTION 'immutable metadata' USING ERRCODE='23514'; END $$;
CREATE TABLE scion_metadata.publications (
 repository bytea NOT NULL CHECK(octet_length(repository)=16), changeset bytea NOT NULL CHECK(octet_length(changeset)=35 AND substring(changeset from 1 for 3)=decode('000102','hex')), publication bytea NOT NULL CHECK(octet_length(publication) BETWEEN 1 AND 128), event bytea NOT NULL CHECK(octet_length(event) BETWEEN 1 AND 128), PRIMARY KEY(repository,changeset), UNIQUE(repository,publication), UNIQUE(repository,event), UNIQUE(repository,changeset,publication,event));
CREATE TABLE scion_metadata.mutations (
 repository bytea NOT NULL CHECK(octet_length(repository)=16), principal bytea NOT NULL CHECK(octet_length(principal) BETWEEN 1 AND 1024), operation smallint NOT NULL CHECK(operation IN (1,2)), mutation bytea NOT NULL CHECK(octet_length(mutation) BETWEEN 1 AND 1024), digest bytea NOT NULL CHECK(octet_length(digest)=32), result bytea NOT NULL CHECK(octet_length(result) BETWEEN 1 AND 512), PRIMARY KEY(repository,principal,operation,mutation));
CREATE TRIGGER publication_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON scion_metadata.publications
 FOR EACH STATEMENT EXECUTE FUNCTION scion_metadata.immutable();
CREATE TRIGGER mutation_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON scion_metadata.mutations
 FOR EACH STATEMENT EXECUTE FUNCTION scion_metadata.immutable();`
