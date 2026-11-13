package policy

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"canopy.local/canopy/internal/storage/metadata"
	"github.com/jackc/pgx/v5"
)

// ProvisionConfig is trusted offline installation configuration. All five roles
// must already exist. Provision never creates roles, rotates keys, adopts an
// existing namespace or migrates an installation. Preserve its returned binding
// outside this database; its catalog fingerprint is a deployment trust root.
type ProvisionConfig struct {
	DSN   string
	Roles RoleNames
}

func Provision(ctx context.Context, config ProvisionConfig) (DatabaseBinding, error) {
	var zero DatabaseBinding
	if ctx == nil || !validRoleNames(config.Roles) {
		return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig(config.DSN)
	if err != nil {
		return zero, metadata.ErrInvalidArgument
	}
	cfg.Tracer = nil
	cfg.ConnectTimeout = time.Second
	for k, v := range map[string]string{"search_path": "pg_catalog,pg_temp", "statement_timeout": "2000", "lock_timeout": "1000", "transaction_timeout": "5000", "idle_in_transaction_session_timeout": "5000"} {
		cfg.RuntimeParams[k] = v
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return zero, policyFailure(ctx, metadata.ErrUnavailable)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = conn.Close(cleanup)
	}()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return zero, policyFailure(ctx, metadata.ErrUnavailable)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	id, err := metadata.VerifyPostgresDatabase(ctx, tx)
	if err != nil {
		return zero, err
	}
	if err = checkRoles(ctx, tx, config.Roles, ""); err != nil {
		return zero, err
	}
	var exists bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_catalog.pg_namespace WHERE nspname='scion_policy')").Scan(&exists); err != nil {
		return zero, policyFailure(ctx, metadata.ErrUnavailable)
	}
	if exists {
		return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_catalog.pg_default_acl WHERE defaclrole=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user))").Scan(&exists); err != nil {
		return zero, policyFailure(ctx, metadata.ErrUnavailable)
	}
	if exists {
		return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_catalog.pg_event_trigger WHERE evtenabled<>'D')").Scan(&exists); err != nil {
		return zero, policyFailure(ctx, metadata.ErrUnavailable)
	}
	if exists {
		return zero, metadata.ErrFailedPrecondition
	}
	if _, err = tx.Exec(ctx, policyDDL); err != nil {
		return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	roles := roleList(config.Roles)
	owner, functionOwner := pgx.Identifier{roles[0]}.Sanitize(), pgx.Identifier{roles[1]}.Sanitize()
	if _, err = tx.Exec(ctx, "ALTER SCHEMA scion_policy OWNER TO "+owner); err != nil {
		return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	if _, err = tx.Exec(ctx, "GRANT CREATE ON SCHEMA scion_policy TO "+functionOwner); err != nil {
		return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	for _, table := range policyTables {
		if _, err = tx.Exec(ctx, "ALTER TABLE scion_policy."+pgx.Identifier{table}.Sanitize()+" OWNER TO "+owner); err != nil {
			return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
		}
	}
	// No PUBLIC/default privileges survive on the newly created namespace.
	if _, err = tx.Exec(ctx, "REVOKE ALL ON SCHEMA scion_policy FROM PUBLIC; REVOKE ALL ON ALL TABLES IN SCHEMA scion_policy FROM PUBLIC; REVOKE ALL ON ALL FUNCTIONS IN SCHEMA scion_policy FROM PUBLIC;"); err != nil {
		return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	for _, role := range roles[1:] {
		name := pgx.Identifier{role}.Sanitize()
		if _, err = tx.Exec(ctx, "GRANT USAGE ON SCHEMA scion_policy, scion_metadata TO "+name+"; GRANT SELECT ON scion_metadata.schema_version TO "+name); err != nil {
			return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
		}
	}
	if _, err = tx.Exec(ctx, "GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA scion_policy TO "+functionOwner+"; GRANT UPDATE ON scion_policy.policy_head, scion_policy.credential_state, scion_policy.session_state, scion_policy.management_capacity, scion_policy.bootstrap_capacity TO "+functionOwner); err != nil {
		return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	// Resolve only this fixed function set. Ownership and grants are assigned by
	// exact identity arguments, never by attacker-provided executable SQL.
	rows, err := tx.Query(ctx, "SELECT p.oid::regprocedure::text,p.proname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='scion_policy' ORDER BY p.oid")
	if err != nil {
		return zero, policyFailure(ctx, metadata.ErrUnavailable)
	}
	type function struct{ identity, name string }
	var functions []function
	for rows.Next() {
		var f function
		if err = rows.Scan(&f.identity, &f.name); err != nil {
			rows.Close()
			return zero, policyFailure(ctx, metadata.ErrUnavailable)
		}
		functions = append(functions, f)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return zero, policyFailure(ctx, metadata.ErrUnavailable)
	}
	for _, f := range functions {
		if _, err = tx.Exec(ctx, "ALTER FUNCTION "+f.identity+" OWNER TO "+functionOwner); err != nil {
			return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
		}
		for index, role := range roles[2:] {
			read := f.name == "identity" || f.name == "read_credential" || f.name == "read_session" || f.name == "current_head" || f.name == "lock_head_shared" || f.name == "lock_credential_shared" || f.name == "lock_session_shared"
			management := index == 1 && f.name != "bootstrap_head" && f.name != "immutable" && f.name != "terminal" && f.name != "next_version" && f.name != "charge" && f.name != "begin_bootstrap" && f.name != "resolve_tenant"
			bootstrap := index == 2 && (f.name == "insert_credential_if_absent" || f.name == "insert_session_if_absent" || f.name == "bootstrap_head" || f.name == "record_admin_result" || f.name == "read_admin_result" || f.name == "begin_bootstrap")
			if read || management || bootstrap {
				if _, err = tx.Exec(ctx, "GRANT EXECUTE ON FUNCTION "+f.identity+" TO "+pgx.Identifier{role}.Sanitize()); err != nil {
					return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
				}
			}
		}
	}
	if _, err = tx.Exec(ctx, "REVOKE CREATE ON SCHEMA scion_policy FROM "+functionOwner); err != nil {
		return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	binding := DatabaseBinding{Database: id.Database, DatabaseOID: id.OID, MetadataFingerprint: id.MetadataFingerprint}
	if _, err = rand.Read(binding.Installation[:]); err != nil {
		return zero, policyFailure(ctx, metadata.ErrUnavailable)
	}
	if _, err = tx.Exec(ctx, "INSERT INTO scion_policy.installation VALUES(true,1,$1,$2,$3,$4)", binding.Installation[:], binding.Database, binding.DatabaseOID, binding.MetadataFingerprint[:]); err != nil {
		return zero, policyFailure(ctx, metadata.ErrFailedPrecondition)
	}
	binding.CatalogFingerprint, err = policyCatalogHash(ctx, tx, config.Roles)
	if err != nil {
		return zero, err
	}
	if err = tx.Commit(ctx); err != nil {
		return zero, errors.Join(metadata.ErrOutcomeUnknown, metadata.ErrUnavailable)
	}
	return binding, nil
}

var policyTables = []string{"installation", "policy_versions", "policy_head", "credential_state", "session_state", "admin_results", "audit", "management_capacity", "bootstrap_capacity", "tenant_keys"}

// Quotas use a declared conservative accounting envelope: twice each stored
// payload plus at least1024 bytes per row, including indexes/TOAST headroom.
// This is not a physical PostgreSQL/WAL file-size guarantee. No serving or native
// publication operation updates these management-only counters.
//
// SQL is a private trusted authority surface, not an authentication API.
// Administrative helpers require a separate restricted DB role AND concrete Go
// verification/old-policy evaluation. The caller's transaction must append its
// audit/result before commit. No helper can commit or install a public context.
const policyDDL = `CREATE SCHEMA scion_policy;
CREATE TABLE scion_policy.installation(singleton boolean PRIMARY KEY CHECK(singleton),version integer NOT NULL CHECK(version=1),installation bytea NOT NULL CHECK(octet_length(installation)=32),database_name text NOT NULL,database_oid oid NOT NULL,metadata_fingerprint bytea NOT NULL CHECK(octet_length(metadata_fingerprint)=32));
CREATE TABLE scion_policy.tenant_keys(key bytea PRIMARY KEY CHECK(octet_length(key)=32),raw bytea NOT NULL CHECK(octet_length(raw) BETWEEN 1 AND 4096),CHECK(key=sha256(raw)));
CREATE TABLE scion_policy.management_capacity(tenant bytea NOT NULL CHECK(octet_length(tenant)=32) REFERENCES scion_policy.tenant_keys(key),repo bytea NOT NULL CHECK(octet_length(repo)=16),rows_used bigint NOT NULL CHECK(rows_used BETWEEN 0 AND 65536),bytes_used bigint NOT NULL CHECK(bytes_used BETWEEN 0 AND 67108864),PRIMARY KEY(tenant,repo));
CREATE TABLE scion_policy.bootstrap_capacity(singleton boolean PRIMARY KEY CHECK(singleton),repositories integer NOT NULL CHECK(repositories BETWEEN 0 AND 1024));
INSERT INTO scion_policy.bootstrap_capacity VALUES(true,0);
CREATE TABLE scion_policy.policy_versions(tenant bytea NOT NULL CHECK(octet_length(tenant)=32) REFERENCES scion_policy.tenant_keys(key),repo bytea NOT NULL CHECK(octet_length(repo)=16),version bytea NOT NULL CHECK(octet_length(version)=8),body bytea NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 3145728),digest bytea NOT NULL CHECK(octet_length(digest)=32 AND digest=sha256(body)),PRIMARY KEY(tenant,repo,version),UNIQUE(tenant,repo,version,digest));
CREATE TABLE scion_policy.policy_head(tenant bytea NOT NULL,repo bytea NOT NULL,version bytea NOT NULL,digest bytea NOT NULL,PRIMARY KEY(tenant,repo),FOREIGN KEY(tenant,repo,version,digest) REFERENCES scion_policy.policy_versions(tenant,repo,version,digest));
CREATE TABLE scion_policy.credential_state(tenant bytea NOT NULL CHECK(octet_length(tenant)=32) REFERENCES scion_policy.tenant_keys(key),repo bytea NOT NULL CHECK(octet_length(repo)=16),credential_hash bytea NOT NULL CHECK(octet_length(credential_hash)=32),issuer bytea NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 4096),subject bytea NOT NULL CHECK(octet_length(subject) BETWEEN 1 AND 4096),class bytea NOT NULL CHECK(class IN(convert_to('human','UTF8'),convert_to('build_job','UTF8'),convert_to('model_worker','UTF8'),convert_to('service_account','UTF8'))),not_before bigint NOT NULL CHECK(not_before>0),expires bigint NOT NULL CHECK(expires>not_before AND expires<=253402300799),revoked boolean NOT NULL DEFAULT false,PRIMARY KEY(tenant,repo,credential_hash));
CREATE TABLE scion_policy.session_state(tenant bytea NOT NULL,repo bytea NOT NULL,session_id bytea NOT NULL CHECK(octet_length(session_id)=32),credential_hash bytea NOT NULL,issuer bytea NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 4096),subject bytea NOT NULL CHECK(octet_length(subject) BETWEEN 1 AND 4096),class bytea NOT NULL CHECK(class IN(convert_to('human','UTF8'),convert_to('build_job','UTF8'),convert_to('model_worker','UTF8'),convert_to('service_account','UTF8'))),generation bytea NOT NULL CHECK(octet_length(generation)=8),proof_hash bytea NOT NULL CHECK(octet_length(proof_hash)=32),not_before bigint NOT NULL CHECK(not_before>0),expires bigint NOT NULL CHECK(expires>not_before AND expires<=253402300799 AND expires-not_before<=3600),revoked boolean NOT NULL DEFAULT false,PRIMARY KEY(tenant,repo,session_id),FOREIGN KEY(tenant,repo,credential_hash) REFERENCES scion_policy.credential_state(tenant,repo,credential_hash));
CREATE TABLE scion_policy.admin_results(tenant bytea NOT NULL CHECK(octet_length(tenant)=32) REFERENCES scion_policy.tenant_keys(key),repo bytea NOT NULL CHECK(octet_length(repo)=16),actor bytea NOT NULL CHECK(octet_length(actor)=32),operation smallint NOT NULL CHECK(operation BETWEEN 1 AND 5),request_id bytea NOT NULL CHECK(octet_length(request_id)=32),intent bytea NOT NULL CHECK(octet_length(intent)=32),receipt bytea NOT NULL CHECK(octet_length(receipt) BETWEEN 1 AND 4096),actor_issuer bytea NOT NULL CHECK(octet_length(actor_issuer) BETWEEN 1 AND 4096),actor_subject bytea NOT NULL CHECK(octet_length(actor_subject) BETWEEN 1 AND 4096),actor_class bytea NOT NULL CHECK(actor_class IN(convert_to('human','UTF8'),convert_to('build_job','UTF8'),convert_to('model_worker','UTF8'),convert_to('service_account','UTF8'))),PRIMARY KEY(tenant,repo,actor,operation,request_id));
CREATE TABLE scion_policy.audit(tenant bytea NOT NULL CHECK(octet_length(tenant)=32) REFERENCES scion_policy.tenant_keys(key),repo bytea NOT NULL CHECK(octet_length(repo)=16),audit_id bytea NOT NULL CHECK(octet_length(audit_id)=32),actor bytea NOT NULL CHECK(octet_length(actor)=32),session_id bytea NOT NULL CHECK(octet_length(session_id)=32),proof_hash bytea NOT NULL CHECK(octet_length(proof_hash)=32),operation smallint NOT NULL CHECK(operation BETWEEN 1 AND 5),success boolean NOT NULL,request_id bytea NOT NULL CHECK(octet_length(request_id)=32),intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32),occurred timestamptz NOT NULL DEFAULT clock_timestamp(),old_version bytea CHECK(octet_length(old_version)=8),new_version bytea CHECK(octet_length(new_version)=8),old_hash bytea CHECK(octet_length(old_hash)=32),new_hash bytea CHECK(octet_length(new_hash)=32),actor_issuer bytea NOT NULL CHECK(octet_length(actor_issuer) BETWEEN 1 AND 4096),actor_subject bytea NOT NULL CHECK(octet_length(actor_subject) BETWEEN 1 AND 4096),actor_class bytea NOT NULL CHECK(actor_class IN(convert_to('human','UTF8'),convert_to('build_job','UTF8'),convert_to('model_worker','UTF8'),convert_to('service_account','UTF8'))),PRIMARY KEY(tenant,repo,audit_id),FOREIGN KEY(tenant,repo,actor,operation,request_id) REFERENCES scion_policy.admin_results(tenant,repo,actor,operation,request_id));
CREATE FUNCTION scion_policy.immutable() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ BEGIN RAISE EXCEPTION 'immutable policy record' USING ERRCODE='23514'; END $$;
CREATE FUNCTION scion_policy.terminal() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ BEGIN IF TG_OP<>'UPDATE' OR (to_jsonb(OLD)-'revoked') IS DISTINCT FROM (to_jsonb(NEW)-'revoked') OR (OLD.revoked AND NOT NEW.revoked) THEN RAISE EXCEPTION 'immutable policy identity' USING ERRCODE='23514'; END IF; RETURN NEW; END $$;
CREATE TRIGGER tenants_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON scion_policy.tenant_keys FOR EACH STATEMENT EXECUTE FUNCTION scion_policy.immutable();
CREATE TRIGGER installation_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON scion_policy.installation FOR EACH STATEMENT EXECUTE FUNCTION scion_policy.immutable();
CREATE TRIGGER versions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON scion_policy.policy_versions FOR EACH STATEMENT EXECUTE FUNCTION scion_policy.immutable();
CREATE TRIGGER results_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON scion_policy.admin_results FOR EACH STATEMENT EXECUTE FUNCTION scion_policy.immutable();
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON scion_policy.audit FOR EACH STATEMENT EXECUTE FUNCTION scion_policy.immutable();
CREATE TRIGGER credential_terminal BEFORE UPDATE OR DELETE ON scion_policy.credential_state FOR EACH ROW EXECUTE FUNCTION scion_policy.terminal();
CREATE TRIGGER credential_no_truncate BEFORE TRUNCATE ON scion_policy.credential_state FOR EACH STATEMENT EXECUTE FUNCTION scion_policy.immutable();
CREATE TRIGGER session_terminal BEFORE UPDATE OR DELETE ON scion_policy.session_state FOR EACH ROW EXECUTE FUNCTION scion_policy.terminal();
CREATE TRIGGER session_no_truncate BEFORE TRUNCATE ON scion_policy.session_state FOR EACH STATEMENT EXECUTE FUNCTION scion_policy.immutable();
CREATE FUNCTION scion_policy.resolve_tenant(t bytea) RETURNS bytea LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ DECLARE k bytea; BEGIN IF octet_length(t) NOT BETWEEN 1 AND 4096 THEN RAISE EXCEPTION 'tenant unavailable' USING ERRCODE='23514'; END IF; SELECT x.key INTO k FROM scion_policy.tenant_keys x WHERE x.key=sha256(t) AND x.raw=t; IF NOT FOUND THEN RAISE EXCEPTION 'tenant unavailable' USING ERRCODE='23514'; END IF; RETURN k; END $$;
CREATE FUNCTION scion_policy.charge(t bytea,r bytea,n bigint,b bigint) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ BEGIN IF n<0 OR b<0 OR n>65536 OR b>67108864 THEN RAISE EXCEPTION 'policy capacity' USING ERRCODE='54000'; END IF; b:=2*b+1024*n; IF b>67108864 THEN RAISE EXCEPTION 'policy capacity' USING ERRCODE='54000'; END IF; UPDATE scion_policy.management_capacity SET rows_used=rows_used+n,bytes_used=bytes_used+b WHERE tenant=t AND repo=r AND rows_used<=65536-n AND bytes_used<=67108864-b; IF NOT FOUND THEN RAISE EXCEPTION 'policy capacity' USING ERRCODE='54000'; END IF; END $$;
CREATE FUNCTION scion_policy.begin_bootstrap(t bytea,r bytea) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ DECLARE added bigint; raw_length bigint:=octet_length(t); BEGIN PERFORM 1 FROM scion_policy.bootstrap_capacity WHERE singleton FOR UPDATE; INSERT INTO scion_policy.tenant_keys VALUES(sha256(t),t) ON CONFLICT DO NOTHING; GET DIAGNOSTICS added=ROW_COUNT; t:=scion_policy.resolve_tenant(t); IF NOT EXISTS(SELECT FROM scion_policy.management_capacity WHERE tenant=t AND repo=r) THEN UPDATE scion_policy.bootstrap_capacity SET repositories=repositories+1 WHERE singleton AND repositories<1024; IF NOT FOUND THEN RAISE EXCEPTION 'repository capacity' USING ERRCODE='54000'; END IF; INSERT INTO scion_policy.management_capacity VALUES(t,r,1+added,2*(256+octet_length(t)+octet_length(r)+added*(288+raw_length))+1024*(1+added)); END IF; END $$;
CREATE FUNCTION scion_policy.identity() RETURNS SETOF scion_policy.installation LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ SELECT * FROM scion_policy.installation WHERE singleton $$;
CREATE FUNCTION scion_policy.read_credential(t bytea,r bytea,c bytea) RETURNS TABLE(issuer bytea,subject bytea,class bytea,not_before bigint,expires bigint,revoked boolean) LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ SELECT x.issuer,x.subject,x.class,x.not_before,x.expires,x.revoked FROM scion_policy.credential_state x WHERE x.tenant=scion_policy.resolve_tenant(t) AND x.repo=r AND x.credential_hash=c $$;
CREATE FUNCTION scion_policy.read_session(t bytea,r bytea,s bytea) RETURNS TABLE(credential_hash bytea,issuer bytea,subject bytea,class bytea,generation bytea,proof_hash bytea,not_before bigint,expires bigint,revoked boolean) LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ SELECT x.credential_hash,x.issuer,x.subject,x.class,x.generation,x.proof_hash,x.not_before,x.expires,x.revoked FROM scion_policy.session_state x WHERE x.tenant=scion_policy.resolve_tenant(t) AND x.repo=r AND x.session_id=s $$;
CREATE FUNCTION scion_policy.lock_credential_shared(t bytea,r bytea,c bytea) RETURNS TABLE(issuer bytea,subject bytea,class bytea,not_before bigint,expires bigint,revoked boolean) LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ SELECT x.issuer,x.subject,x.class,x.not_before,x.expires,x.revoked FROM scion_policy.credential_state x WHERE x.tenant=scion_policy.resolve_tenant(t) AND x.repo=r AND x.credential_hash=c FOR SHARE $$;
CREATE FUNCTION scion_policy.lock_session_shared(t bytea,r bytea,s bytea) RETURNS TABLE(credential_hash bytea,issuer bytea,subject bytea,class bytea,generation bytea,proof_hash bytea,not_before bigint,expires bigint,revoked boolean) LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ SELECT x.credential_hash,x.issuer,x.subject,x.class,x.generation,x.proof_hash,x.not_before,x.expires,x.revoked FROM scion_policy.session_state x WHERE x.tenant=scion_policy.resolve_tenant(t) AND x.repo=r AND x.session_id=s FOR SHARE $$;
CREATE FUNCTION scion_policy.lock_credential_exclusive(t bytea,r bytea,c bytea) RETURNS TABLE(issuer bytea,subject bytea,class bytea,not_before bigint,expires bigint,revoked boolean) LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ SELECT x.issuer,x.subject,x.class,x.not_before,x.expires,x.revoked FROM scion_policy.credential_state x WHERE x.tenant=scion_policy.resolve_tenant(t) AND x.repo=r AND x.credential_hash=c FOR UPDATE $$;
CREATE FUNCTION scion_policy.lock_session_exclusive(t bytea,r bytea,s bytea) RETURNS TABLE(credential_hash bytea,issuer bytea,subject bytea,class bytea,generation bytea,proof_hash bytea,not_before bigint,expires bigint,revoked boolean) LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ SELECT x.credential_hash,x.issuer,x.subject,x.class,x.generation,x.proof_hash,x.not_before,x.expires,x.revoked FROM scion_policy.session_state x WHERE x.tenant=scion_policy.resolve_tenant(t) AND x.repo=r AND x.session_id=s FOR UPDATE $$;
CREATE FUNCTION scion_policy.current_head(t bytea,r bytea) RETURNS TABLE(version bytea,digest bytea,body bytea) LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ SELECT x.version,x.digest,v.body FROM scion_policy.policy_head x JOIN scion_policy.policy_versions v USING(tenant,repo,version,digest) WHERE x.tenant=scion_policy.resolve_tenant(t) AND x.repo=r $$;
CREATE FUNCTION scion_policy.lock_head_shared(t bytea,r bytea) RETURNS TABLE(version bytea,digest bytea,body bytea) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ DECLARE k bytea; v bytea; h bytea; BEGIN k:=scion_policy.resolve_tenant(t); SELECT x.version,x.digest INTO v,h FROM scion_policy.policy_head x WHERE x.tenant=k AND x.repo=r FOR SHARE; IF NOT FOUND THEN RETURN; END IF; RETURN QUERY SELECT v,h,p.body FROM scion_policy.policy_versions p WHERE p.tenant=k AND p.repo=r AND p.version=v AND p.digest=h; END $$;
CREATE FUNCTION scion_policy.lock_head_exclusive(t bytea,r bytea) RETURNS TABLE(version bytea,digest bytea,body bytea) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ DECLARE k bytea; v bytea; h bytea; BEGIN k:=scion_policy.resolve_tenant(t); SELECT x.version,x.digest INTO v,h FROM scion_policy.policy_head x WHERE x.tenant=k AND x.repo=r FOR UPDATE; IF NOT FOUND THEN RETURN; END IF; RETURN QUERY SELECT v,h,p.body FROM scion_policy.policy_versions p WHERE p.tenant=k AND p.repo=r AND p.version=v AND p.digest=h; END $$;
CREATE FUNCTION scion_policy.insert_credential_if_absent(t bytea,r bytea,c bytea,i bytea,s bytea,k bytea,n bigint,e bigint) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ BEGIN t:=scion_policy.resolve_tenant(t); PERFORM scion_policy.charge(t,r,0,0); IF NOT EXISTS(SELECT FROM scion_policy.credential_state x WHERE x.tenant=t AND x.repo=r AND x.credential_hash=c) THEN PERFORM scion_policy.charge(t,r,1,256+octet_length(t)+octet_length(r)+octet_length(c)+octet_length(i)+octet_length(s)+octet_length(k)+17); END IF; INSERT INTO scion_policy.credential_state VALUES(t,r,c,i,s,k,n,e,false) ON CONFLICT DO NOTHING; IF NOT EXISTS(SELECT FROM scion_policy.credential_state x WHERE (x.tenant,x.repo,x.credential_hash,x.issuer,x.subject,x.class,x.not_before,x.expires)=(t,r,c,i,s,k,n,e) AND NOT x.revoked) THEN RAISE EXCEPTION 'credential conflict' USING ERRCODE='23514'; END IF; END $$;
CREATE FUNCTION scion_policy.insert_session_if_absent(t bytea,r bytea,s bytea,c bytea,i bytea,u bytea,k bytea,g bytea,p bytea,n bigint,e bigint) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ BEGIN t:=scion_policy.resolve_tenant(t); PERFORM scion_policy.charge(t,r,0,0); IF NOT EXISTS(SELECT FROM scion_policy.session_state x WHERE x.tenant=t AND x.repo=r AND x.session_id=s) THEN PERFORM scion_policy.charge(t,r,1,256+octet_length(t)+octet_length(r)+octet_length(s)+octet_length(c)+octet_length(i)+octet_length(u)+octet_length(k)+octet_length(g)+octet_length(p)+17); END IF; INSERT INTO scion_policy.session_state VALUES(t,r,s,c,i,u,k,g,p,n,e,false) ON CONFLICT DO NOTHING; IF NOT EXISTS(SELECT FROM scion_policy.session_state x WHERE (x.tenant,x.repo,x.session_id,x.credential_hash,x.issuer,x.subject,x.class,x.generation,x.proof_hash,x.not_before,x.expires)=(t,r,s,c,i,u,k,g,p,n,e) AND NOT x.revoked) THEN RAISE EXCEPTION 'session conflict' USING ERRCODE='23514'; END IF; END $$;
CREATE FUNCTION scion_policy.bootstrap_head(t bytea,r bytea,b bytea,d bytea) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ BEGIN t:=scion_policy.resolve_tenant(t); PERFORM scion_policy.charge(t,r,2,512+2*octet_length(t)+2*octet_length(r)+octet_length(b)+2*octet_length(d)+16); INSERT INTO scion_policy.policy_versions VALUES(t,r,decode('0000000000000000','hex'),b,d); INSERT INTO scion_policy.policy_head VALUES(t,r,decode('0000000000000000','hex'),d); END $$;
CREATE FUNCTION scion_policy.next_version(v bytea) RETURNS bytea LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ DECLARE i integer:=7; n integer; BEGIN IF octet_length(v)<>8 THEN RAISE EXCEPTION 'invalid version'; END IF; WHILE i>=0 LOOP n:=get_byte(v,i); IF n<255 THEN RETURN set_byte(v,i,n+1); END IF; v:=set_byte(v,i,0);i:=i-1; END LOOP; RAISE EXCEPTION 'version exhausted' USING ERRCODE='22003'; END $$;
CREATE FUNCTION scion_policy.cas_policy(t bytea,r bytea,v bytea,d bytea,b bytea,h bytea) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ DECLARE n bytea; BEGIN t:=scion_policy.resolve_tenant(t); PERFORM 1 FROM scion_policy.policy_head x WHERE x.tenant=t AND x.repo=r AND x.version=v AND x.digest=d FOR UPDATE; IF NOT FOUND THEN RAISE EXCEPTION 'policy conflict' USING ERRCODE='40001'; END IF; n:=scion_policy.next_version(v); PERFORM scion_policy.charge(t,r,1,256+octet_length(t)+octet_length(r)+octet_length(n)+octet_length(b)+octet_length(h)); INSERT INTO scion_policy.policy_versions VALUES(t,r,n,b,h); UPDATE scion_policy.policy_head SET version=n,digest=h WHERE tenant=t AND repo=r; END $$;
CREATE FUNCTION scion_policy.revoke_credential(t bytea,r bytea,c bytea) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ BEGIN t:=scion_policy.resolve_tenant(t); UPDATE scion_policy.credential_state SET revoked=true WHERE tenant=t AND repo=r AND credential_hash=c; IF NOT FOUND THEN RAISE EXCEPTION 'credential absent' USING ERRCODE='23514'; END IF; END $$;
CREATE FUNCTION scion_policy.revoke_session(t bytea,r bytea,s bytea) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ BEGIN t:=scion_policy.resolve_tenant(t); UPDATE scion_policy.session_state SET revoked=true WHERE tenant=t AND repo=r AND session_id=s; IF NOT FOUND THEN RAISE EXCEPTION 'session absent' USING ERRCODE='23514'; END IF; END $$;
CREATE FUNCTION scion_policy.record_admin_result(t bytea,r bytea,a bytea,o smallint,q bytea,d bytea,v bytea,j bytea,s bytea,p bytea,ok boolean,ov bytea,nv bytea,oh bytea,nh bytea,ai bytea,au bytea,ak bytea) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ BEGIN t:=scion_policy.resolve_tenant(t); PERFORM scion_policy.charge(t,r,2,512+2*octet_length(t)+2*octet_length(r)+2*octet_length(a)+octet_length(q)+octet_length(d)+octet_length(v)+octet_length(j)+octet_length(s)+octet_length(p)+coalesce(octet_length(ov),0)+coalesce(octet_length(nv),0)+coalesce(octet_length(oh),0)+coalesce(octet_length(nh),0)+2*octet_length(ai)+2*octet_length(au)+2*octet_length(ak)+64+16); INSERT INTO scion_policy.admin_results VALUES(t,r,a,o,q,d,v,ai,au,ak); INSERT INTO scion_policy.audit(tenant,repo,audit_id,actor,session_id,proof_hash,operation,success,request_id,intent_digest,old_version,new_version,old_hash,new_hash,actor_issuer,actor_subject,actor_class) VALUES(t,r,j,a,s,p,o,ok,q,d,ov,nv,oh,nh,ai,au,ak); END $$;
CREATE FUNCTION scion_policy.read_admin_result(t bytea,r bytea,a bytea,o smallint,q bytea,ai bytea,au bytea,ak bytea) RETURNS TABLE(intent bytea,receipt bytea) LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,scion_policy,pg_temp AS $$ SELECT x.intent,x.receipt FROM scion_policy.admin_results x WHERE x.tenant=scion_policy.resolve_tenant(t) AND x.repo=r AND x.actor=a AND x.operation=o AND x.request_id=q AND x.actor_issuer=ai AND x.actor_subject=au AND x.actor_class=ak $$;`
