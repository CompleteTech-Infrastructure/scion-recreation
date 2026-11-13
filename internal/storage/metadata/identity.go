package metadata

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// PostgresDatabaseIdentity observes one logical primary database and the accepted
// metadata-v1 catalog. It is not authentication, an installation identity, a
// lease against later DDL, or proof of physical hardware/WAL continuity.
type PostgresDatabaseIdentity struct {
	Database            string
	OID                 uint32
	MetadataFingerprint [32]byte
}

// VerifyPostgresDatabase verifies the caller-owned transaction without creating
// schemas or changing data. It narrows transaction-local search_path to
// pg_catalog,pg_temp and leaves that setting in place until transaction end.
// The caller owns transaction isolation, lifetime, commit and DDL exclusion.
// Use trusted primary connections; arbitrary caller-created transactions are
// not an authorization boundary. Unknown layouts and oversized catalogs deny.
func VerifyPostgresDatabase(ctx context.Context, tx pgx.Tx) (PostgresDatabaseIdentity, error) {
	var zero PostgresDatabaseIdentity
	if ctx == nil || nilDependency(tx) {
		return zero, ErrFailedPrecondition
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := tx.Exec(ctx, "SET LOCAL search_path = pg_catalog, pg_temp"); err != nil {
		return zero, postgresError(ctx)
	}
	var identity PostgresDatabaseIdentity
	var version int
	var recovery bool
	var readOnly string
	err := tx.QueryRow(ctx, `SELECT pg_catalog.current_database(),
 (SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),
 pg_catalog.current_setting('server_version_num')::integer,
 pg_catalog.pg_is_in_recovery(),pg_catalog.current_setting('transaction_read_only')`).Scan(
		&identity.Database, &identity.OID, &version, &recovery, &readOnly)
	if err != nil {
		return zero, postgresError(ctx)
	}
	if identity.Database == "" || identity.OID == 0 || version < 170000 || recovery || readOnly != "off" {
		return zero, ErrFailedPrecondition
	}
	// Preflight the same catalog population before its JSON aggregation. LIMIT
	// bounds row work even under incompatible DDL; raw definition lengths bound
	// renderer input before pg_get_* can build attacker-sized definitions. Marker,
	// budget and rendering share ONE statement snapshot, including READ COMMITTED.
	var catalog *string
	err = tx.QueryRow(ctx, `WITH marker AS MATERIALIZED (
 SELECT version,definition=$1 AS valid FROM scion_metadata.schema_version WHERE singleton LIMIT 2),
 budget(ok) AS MATERIALIZED (`+postgresIdentityBudget+`),
 actual(catalog) AS MATERIALIZED (SELECT CASE
 WHEN (SELECT count(*)=1 AND bool_and(version=1 AND valid) FROM marker)
 AND (SELECT ok FROM budget) THEN (`+postgresCatalog+`) END)
 SELECT CASE WHEN octet_length(catalog)<=131072 THEN catalog END FROM actual`, postgresDDL).Scan(&catalog)
	if err != nil {
		return zero, postgresSchemaError(ctx, err)
	}
	if catalog == nil {
		return zero, ErrFailedPrecondition
	}
	identity.MetadataFingerprint = sha256.Sum256([]byte(*catalog))
	if fmt.Sprintf("%x", identity.MetadataFingerprint) != postgresCatalogV1 {
		return zero, ErrFailedPrecondition
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	return identity, nil
}

// Names/attribute counts have PostgreSQL's fixed limits. This preflight also
// bounds external inheritance edges and variable-size expressions/function
// bodies, not merely the three expected metadata tables. No new schema format.
const postgresIdentityBudget = `SELECT count(*)<=128 AND coalesce(sum(weight),0)<=65536 FROM (
 SELECT weight FROM (
 SELECT 0::bigint AS weight FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='scion_metadata' AND c.relkind IN ('r','p','v','m','f')
 UNION ALL SELECT coalesce(octet_length(d.adbin::text),0) FROM pg_attribute a
 JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
 WHERE n.nspname='scion_metadata' AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT coalesce(octet_length(k.conbin::text),0) FROM pg_constraint k
 JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='scion_metadata'
 UNION ALL SELECT coalesce(octet_length(i.indexprs::text),0)+coalesce(octet_length(i.indpred::text),0) FROM pg_index i
 JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='scion_metadata'
 UNION ALL SELECT octet_length(t.tgargs)+coalesce(octet_length(t.tgqual::text),0) FROM pg_trigger t
 JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='scion_metadata' AND NOT t.tgisinternal
 UNION ALL SELECT octet_length(r.ev_action::text)+octet_length(r.ev_qual::text) FROM pg_rewrite r
 JOIN pg_class c ON c.oid=r.ev_class JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='scion_metadata'
 UNION ALL SELECT 0 FROM pg_inherits i JOIN pg_class p ON p.oid=i.inhparent JOIN pg_namespace pn ON pn.oid=p.relnamespace
 JOIN pg_class c ON c.oid=i.inhrelid JOIN pg_namespace cn ON cn.oid=c.relnamespace
 WHERE pn.nspname='scion_metadata' OR cn.nspname='scion_metadata'
 UNION ALL SELECT octet_length(p.prosrc)+coalesce(octet_length(p.probin),0)+coalesce(pg_column_size(p.proconfig),0) FROM pg_proc p
 JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='scion_metadata'
 ) entries LIMIT 129
) bounded`
