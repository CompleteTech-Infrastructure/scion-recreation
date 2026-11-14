package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strings"

	"canopy.local/canopy/internal/storage/metadata"
	"github.com/jackc/pgx/v5"
)

func policyFailure(ctx context.Context, fallback error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return fallback
}

func roleList(r RoleNames) []string {
	return []string{r.Owner, r.FunctionOwner, r.Serving, r.Admin, r.Bootstrap}
}
func validRoleNames(r RoleNames) bool {
	seen := map[string]bool{}
	for _, name := range roleList(r) {
		if len(name) == 0 || len(name) > 63 || strings.IndexByte(name, 0) >= 0 || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

// Configured roles are isolated capabilities: no membership edge may allow a
// serving/admin/bootstrap role to assume another role, or another ordinary role
// to assume these roles. Privileged database administrators are outside this
// boundary. Role password values are deliberately neither read nor fingerprinted.
func checkRoles(ctx context.Context, tx pgx.Tx, roles RoleNames, expected string) error {
	if !validRoleNames(roles) {
		return policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	var ok bool
	err := tx.QueryRow(ctx, `WITH r AS MATERIALIZED(SELECT oid,rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconfig,rolconnlimit,rolvaliduntil FROM pg_catalog.pg_roles WHERE rolname=ANY($1::text[]))
SELECT count(*)=5 AND bool_and(NOT rolsuper AND NOT rolinherit AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls AND rolconfig IS NULL AND NOT pg_catalog.has_database_privilege(oid,pg_catalog.current_database(),'CREATE') AND rolcanlogin=(rolname=ANY($2::text[])))
AND NOT EXISTS(SELECT FROM pg_catalog.pg_auth_members m WHERE m.roleid IN(SELECT oid FROM r) OR m.member IN(SELECT oid FROM r))
AND NOT EXISTS(SELECT FROM pg_catalog.pg_default_acl d WHERE d.defaclrole IN(SELECT oid FROM r)) FROM r`, roleList(roles), []string{roles.Serving, roles.Admin, roles.Bootstrap}).Scan(&ok)
	if err != nil {
		return policyFailure(ctx, metadata.ErrUnavailable)
	}
	if !ok {
		return policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	if expected != "" {
		var session, current string
		if err = tx.QueryRow(ctx, "SELECT session_user,current_user").Scan(&session, &current); err != nil {
			return policyFailure(ctx, metadata.ErrUnavailable)
		}
		if session != expected || current != expected || (expected != roles.Serving && expected != roles.Admin && expected != roles.Bootstrap) {
			return policyFailure(ctx, metadata.ErrFailedPrecondition)
		}
	}
	return nil
}

func verifyPolicyCatalog(ctx context.Context, tx pgx.Tx, binding DatabaseBinding, roles RoleNames, role string) error {
	if ctx == nil || tx == nil || binding.Installation == ([32]byte{}) || binding.CatalogFingerprint == ([32]byte{}) {
		return policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	if err := checkRoles(ctx, tx, roles, role); err != nil {
		return err
	}
	var version int
	var install, meta []byte
	var name string
	var oid uint32
	if err := tx.QueryRow(ctx, "SELECT version,installation,database_name,database_oid,metadata_fingerprint FROM scion_policy.identity()").Scan(&version, &install, &name, &oid, &meta); err != nil {
		return policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	if version != 1 || name != binding.Database || oid != binding.DatabaseOID || !bytes.Equal(install, binding.Installation[:]) || !bytes.Equal(meta, binding.MetadataFingerprint[:]) {
		return policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	hash, err := policyCatalogHash(ctx, tx, roles)
	if err != nil {
		return err
	}
	if hash != binding.CatalogFingerprint {
		return policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	return ctx.Err()
}

// Fingerprinting is bounded before aggregation/definition rendering. The one
// statement snapshot binds budget and content under READ COMMITTED. Raw catalog
// expression trees avoid expensive pg_get_functiondef/pg_get_expr rendering.
// Every installed object's identity/owner/ACL/body is pinned, plus all incoming
// inheritance and configured-role/default-privilege state. Data rows and mutable
// vacuum statistics are excluded, so ordinary durable writes do not cause drift.
// Only PostgreSQL builtin heap/btree methods and internal handlers are supported.
// Builtin catalog OIDs below are PostgreSQL 18 identities, not name lookups
// that could resolve to a replacement function or custom access method.
// Adding these identities changes the fingerprint: old bindings fail closed and
// are never repinned or adopted by Open or Provision.
func policyCatalogHash(ctx context.Context, tx pgx.Tx, roles RoleNames) ([32]byte, error) {
	var zero [32]byte
	var result *string
	err := tx.QueryRow(ctx, policyCatalogSQL, roleList(roles)).Scan(&result)
	if err != nil {
		return zero, policyFailure(ctx, metadata.ErrUnavailable)
	}
	if result == nil {
		return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	return sha256.Sum256([]byte(*result)), nil
}

const policyCatalogSQL = `WITH ns AS MATERIALIZED(SELECT oid,nspname,nspowner,nspacl FROM pg_catalog.pg_namespace WHERE nspname='scion_policy'),
roles AS MATERIALIZED(SELECT oid,rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconfig,rolconnlimit,rolvaliduntil FROM pg_catalog.pg_roles WHERE rolname=ANY($1::text[])),
methods AS MATERIALIZED(
 SELECT a.*,p.oid AS handler_oid,
 CASE WHEN pg_column_compression(p.prosrc) IS NOT NULL OR pg_column_size(p.prosrc)>256 THEN false ELSE coalesce((a.oid=2 AND a.amname='heap' AND a.amtype='t' AND p.oid=3 AND p.proname='heap_tableam_handler' AND p.prosrc='heap_tableam_handler' AND p.prorettype=269)
 OR (a.oid=403 AND a.amname='btree' AND a.amtype='i' AND p.oid=330 AND p.proname='bthandler' AND p.prosrc='bthandler' AND p.prorettype=325),false)
 AND p.pronamespace=11 AND p.proowner=10 AND p.prolang=12 AND p.prokind='f' AND NOT p.prosecdef AND NOT p.proretset AND p.pronargs=1 AND p.proargtypes='2281'::oidvector
 AND p.proconfig IS NULL AND p.probin IS NULL AND p.proargdefaults IS NULL AND p.prosqlbody IS NULL
 AND p.proargnames IS NULL AND p.proallargtypes IS NULL AND p.proargmodes IS NULL AND p.protrftypes IS NULL AND p.proacl IS NULL
 AND p.proisstrict AND NOT p.proleakproof AND p.proparallel='s' AND p.provolatile='v' AND p.prosupport=0 AND p.provariadic=0 AND p.pronargdefaults=0 AND p.procost=1 AND p.prorows=0 END AS trusted
 FROM pg_catalog.pg_am a LEFT JOIN pg_catalog.pg_proc p ON p.oid=a.amhandler
 WHERE a.oid IN(SELECT c.relam FROM pg_catalog.pg_class c WHERE c.relnamespace IN(SELECT oid FROM ns) AND c.relam<>0 LIMIT 1025) LIMIT 3),
raw AS MATERIALIZED(
 SELECT weight FROM (
 SELECT CASE WHEN pg_column_compression(nspacl) IS NOT NULL OR coalesce(pg_column_size(nspacl),0)>4096 THEN 1048577 ELSE coalesce(pg_column_size(nspacl),0) END AS weight FROM ns
 UNION ALL SELECT CASE WHEN (c.relkind='r' AND c.relam<>2) OR (c.relkind='i' AND c.relam<>403) THEN 1048577 WHEN pg_column_compression(c.relacl) IS NOT NULL OR pg_column_compression(c.reloptions) IS NOT NULL OR coalesce(pg_column_size(c.relacl),0)>4096 OR coalesce(pg_column_size(c.reloptions),0)>4096 THEN 1048577 ELSE coalesce(pg_column_size(c.relacl),0)+coalesce(pg_column_size(c.reloptions),0)+coalesce(octet_length(c.relpartbound::text),0) END FROM pg_catalog.pg_class c WHERE c.relnamespace IN(SELECT oid FROM ns)
 UNION ALL SELECT CASE WHEN pg_column_compression(a.attacl) IS NOT NULL OR coalesce(pg_column_size(a.attacl),0)>4096 THEN 1048577 ELSE coalesce(pg_column_size(a.attacl),0)+coalesce(octet_length(d.adbin::text),0) END FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE c.relnamespace IN(SELECT oid FROM ns) AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT CASE WHEN pg_column_compression(k.conkey) IS NOT NULL OR pg_column_compression(k.confkey) IS NOT NULL OR pg_column_compression(k.conpfeqop) IS NOT NULL OR pg_column_compression(k.conppeqop) IS NOT NULL OR pg_column_compression(k.conffeqop) IS NOT NULL OR coalesce(pg_column_size(k.conkey),0)+coalesce(pg_column_size(k.confkey),0)+coalesce(pg_column_size(k.conpfeqop),0)+coalesce(pg_column_size(k.conppeqop),0)+coalesce(pg_column_size(k.conffeqop),0)>4096 THEN 1048577 ELSE coalesce(octet_length(k.conbin::text),0)+coalesce(pg_column_size(k.conkey),0)+coalesce(pg_column_size(k.confkey),0)+coalesce(pg_column_size(k.conpfeqop),0)+coalesce(pg_column_size(k.conppeqop),0)+coalesce(pg_column_size(k.conffeqop),0) END FROM pg_catalog.pg_constraint k WHERE k.connamespace IN(SELECT oid FROM ns) OR k.confrelid IN(SELECT oid FROM pg_catalog.pg_class WHERE relnamespace IN(SELECT oid FROM ns))
 UNION ALL SELECT coalesce(octet_length(i.indexprs::text),0)+coalesce(octet_length(i.indpred::text),0) FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indrelid WHERE c.relnamespace IN(SELECT oid FROM ns)
 UNION ALL SELECT octet_length(t.tgargs)+coalesce(octet_length(t.tgqual::text),0) FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace IN(SELECT oid FROM ns)
 UNION ALL SELECT octet_length(r.ev_action::text)+octet_length(r.ev_qual::text) FROM pg_catalog.pg_rewrite r JOIN pg_catalog.pg_class c ON c.oid=r.ev_class WHERE c.relnamespace IN(SELECT oid FROM ns)
 UNION ALL SELECT 0 FROM pg_catalog.pg_inherits i WHERE i.inhparent IN(SELECT oid FROM pg_catalog.pg_class WHERE relnamespace IN(SELECT oid FROM ns)) OR i.inhrelid IN(SELECT oid FROM pg_catalog.pg_class WHERE relnamespace IN(SELECT oid FROM ns))
 UNION ALL SELECT CASE WHEN pg_column_compression(p.proconfig) IS NOT NULL OR pg_column_compression(p.proargnames) IS NOT NULL OR pg_column_compression(p.proallargtypes) IS NOT NULL OR pg_column_compression(p.proargmodes) IS NOT NULL OR pg_column_compression(p.proacl) IS NOT NULL OR coalesce(pg_column_size(p.proconfig),0)>256 OR coalesce(pg_column_size(p.proargnames),0)>4096 OR coalesce(pg_column_size(p.proallargtypes),0)>4096 OR coalesce(pg_column_size(p.proargmodes),0)>4096 OR coalesce(pg_column_size(p.proacl),0)>4096 THEN 1048577 WHEN p.proargdefaults IS NOT NULL OR p.prosqlbody IS NOT NULL OR p.pronargs>32 OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, scion_policy, pg_temp']::text[] THEN 1048577 ELSE octet_length(p.prosrc)+coalesce(octet_length(p.probin),0)+coalesce(pg_column_size(p.proargnames),0)+coalesce(pg_column_size(p.proallargtypes),0)+coalesce(pg_column_size(p.proargmodes),0)+coalesce(pg_column_size(p.proacl),0) END FROM pg_catalog.pg_proc p WHERE p.pronamespace IN(SELECT oid FROM ns)
 UNION ALL SELECT CASE WHEN m.trusted AND pg_column_compression(p.proacl) IS NULL AND coalesce(pg_column_size(p.proacl),0)<=4096 THEN coalesce(pg_column_size(p.proacl),0) ELSE 1048577 END FROM methods m LEFT JOIN pg_catalog.pg_proc p ON p.oid=m.handler_oid
 UNION ALL SELECT 0 FROM roles
 UNION ALL SELECT 0 FROM pg_catalog.pg_auth_members m WHERE m.roleid IN(SELECT oid FROM roles) OR m.member IN(SELECT oid FROM roles)
 UNION ALL SELECT CASE WHEN pg_column_compression(d.defaclacl) IS NOT NULL OR coalesce(pg_column_size(d.defaclacl),0)>4096 THEN 1048577 ELSE coalesce(pg_column_size(d.defaclacl),0) END FROM pg_catalog.pg_default_acl d WHERE d.defaclnamespace IN(SELECT oid FROM ns) OR d.defaclrole IN(SELECT oid FROM roles)
 ) all_entries LIMIT 1025),
raw_budget AS MATERIALIZED(SELECT count(*)<=1024 AND coalesce(sum(weight),0)<=262144 AS ok FROM raw),
entries AS MATERIALIZED(
 SELECT jsonb_build_array('schema',nspname,nspowner,nspacl) AS value FROM ns
 UNION ALL SELECT jsonb_build_array('table',c.oid,c.relname,c.relkind,c.relam,c.relpersistence,c.relowner,c.relacl,c.relrowsecurity,c.relforcerowsecurity,c.reloptions,c.relpartbound::text)
 FROM pg_catalog.pg_class c WHERE c.relnamespace IN(SELECT oid FROM ns)
 UNION ALL SELECT jsonb_build_array('column',a.attrelid,a.attnum,a.attname,a.atttypid,a.atttypmod,a.attnotnull,a.attidentity,a.attgenerated,a.attacl,d.adbin::text)
 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE c.relnamespace IN(SELECT oid FROM ns) AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT jsonb_build_array('constraint',to_jsonb(k)) FROM pg_catalog.pg_constraint k WHERE k.connamespace IN(SELECT oid FROM ns) OR k.confrelid IN(SELECT oid FROM pg_catalog.pg_class WHERE relnamespace IN(SELECT oid FROM ns))
 UNION ALL SELECT jsonb_build_array('index',to_jsonb(i)) FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indrelid WHERE c.relnamespace IN(SELECT oid FROM ns)
 UNION ALL SELECT jsonb_build_array('trigger',to_jsonb(t)) FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace IN(SELECT oid FROM ns)
 UNION ALL SELECT jsonb_build_array('rule',to_jsonb(r)) FROM pg_catalog.pg_rewrite r JOIN pg_catalog.pg_class c ON c.oid=r.ev_class WHERE c.relnamespace IN(SELECT oid FROM ns)
 UNION ALL SELECT jsonb_build_array('inheritance',to_jsonb(i)) FROM pg_catalog.pg_inherits i WHERE i.inhparent IN(SELECT oid FROM pg_catalog.pg_class WHERE relnamespace IN(SELECT oid FROM ns)) OR i.inhrelid IN(SELECT oid FROM pg_catalog.pg_class WHERE relnamespace IN(SELECT oid FROM ns))
 UNION ALL SELECT jsonb_build_array('function',to_jsonb(p)) FROM pg_catalog.pg_proc p WHERE p.pronamespace IN(SELECT oid FROM ns)
 UNION ALL SELECT jsonb_build_array('access_method',m.oid,m.amname,m.amhandler,m.amtype,m.handler_oid,to_jsonb(p)) FROM methods m LEFT JOIN pg_catalog.pg_proc p ON p.oid=m.handler_oid
 UNION ALL SELECT jsonb_build_array('role',r.oid,r.rolname,r.rolsuper,r.rolinherit,r.rolcreaterole,r.rolcreatedb,r.rolcanlogin,r.rolreplication,r.rolbypassrls,r.rolconfig,r.rolconnlimit,extract(epoch FROM r.rolvaliduntil)) FROM roles r
 UNION ALL SELECT jsonb_build_array('membership',to_jsonb(m)) FROM pg_catalog.pg_auth_members m WHERE m.roleid IN(SELECT oid FROM roles) OR m.member IN(SELECT oid FROM roles)
 UNION ALL SELECT jsonb_build_array('default_acl',to_jsonb(d)) FROM pg_catalog.pg_default_acl d WHERE d.defaclnamespace IN(SELECT oid FROM ns) OR d.defaclrole IN(SELECT oid FROM roles)
 LIMIT 1025),
budget AS MATERIALIZED(SELECT count(*)<=1024 AND coalesce(sum(octet_length(value::text)),0)<=1048576 AS ok FROM entries),
catalog AS MATERIALIZED(SELECT CASE WHEN (SELECT ok FROM budget) THEN (SELECT jsonb_agg(value ORDER BY value::text)::text FROM entries) END AS body)
SELECT CASE WHEN (SELECT ok FROM raw_budget) THEN (SELECT body FROM catalog) END`
