package metadata

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
// The returned foundation keeps only a private config. Close
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

// Cleanup never inherits a canceled caller or waits indefinitely for a server.
// pgx closes the connection on rollback failure; the outer bounded Close still
// runs, and the original operation/ambiguous-commit result remains unchanged.
func rollbackPostgres(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func postgresSchemaError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var pgerr *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || errors.As(err, &pgerr) && (pgerr.Code == "42P01" || pgerr.Code == "42703" || pgerr.Code == "42883") {
		return ErrFailedPrecondition
	}
	return ErrUnavailable
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
	defer rollbackPostgres(tx)
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
	defer rollbackPostgres(tx)
	var exists bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_namespace WHERE nspname='scion_metadata')").Scan(&exists); err != nil {
		return postgresError(ctx)
	}
	if exists {
		var version int
		var definition string
		err = tx.QueryRow(ctx, "SELECT version, definition FROM scion_metadata.schema_version WHERE singleton").Scan(&version, &definition)
		if err != nil {
			return postgresSchemaError(ctx, err)
		}
		if version != 1 || definition != postgresDDL {
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
	// Compare the actual catalog, never just a mutable version marker. The fixed
	// v1 fingerprint covers tables, columns, constraints, indexes, trigger enable
	// state and function body. Unknown catalog layouts fail closed, never migrate.
	var catalog string
	if err = tx.QueryRow(ctx, postgresCatalog).Scan(&catalog); err != nil {
		return postgresSchemaError(ctx, err)
	}
	if fmt.Sprintf("%x", sha256.Sum256([]byte(catalog))) != postgresCatalogV1 {
		return ErrFailedPrecondition
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

const postgresCatalogV1 = "c755924db471580f665c6c5ff7779c7544fec03b2bd2d68d94f6443118cad896"
const postgresCatalog = `SELECT coalesce(jsonb_agg(v ORDER BY v::text)::text,'[]') FROM (
 SELECT jsonb_build_array('table',c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity) AS v
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='scion_metadata' AND c.relkind IN ('r','p','v','m','f')
 UNION ALL SELECT jsonb_build_array('column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid))
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
 WHERE n.nspname='scion_metadata' AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT jsonb_build_array('constraint',c.relname,k.conname,k.convalidated,pg_get_constraintdef(k.oid))
 FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='scion_metadata'
 UNION ALL SELECT jsonb_build_array('index',c.relname,i.indisvalid,i.indisready,pg_get_indexdef(i.indexrelid))
 FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='scion_metadata'
 UNION ALL SELECT jsonb_build_array('trigger',c.relname,t.tgenabled,pg_get_triggerdef(t.oid))
 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='scion_metadata' AND NOT t.tgisinternal
 UNION ALL SELECT jsonb_build_array('function',pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='scion_metadata'
) s`
