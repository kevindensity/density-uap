-- pg_fence 0.1: Consequence Fence Protocol (CFP/1) reference implementation.
\echo Use "CREATE EXTENSION pg_fence" to load this file. \quit

create function ed25519_verify(pk bytea, msg bytea, sig bytea) returns boolean
  as 'MODULE_PATHNAME', 'fence_ed25519_verify' language c strict immutable parallel safe;

create table config (
  id int primary key default 1 check (id = 1),
  audience text not null,
  ledger_mode text not null check (ledger_mode in ('durable', 'local')),
  min_quorum int not null default 2 check (min_quorum >= 1)
);
create table protected (tbl regclass primary key, pk_col name not null);
create table receipts (
  receipt_id bigserial primary key,
  grant_id uuid not null,
  tbl regclass not null,
  pk text not null,
  op text not null,
  prestate text not null,
  poststate text not null,
  history_head text not null,
  authority_epoch bigint not null,
  committed_at timestamptz not null default now()
);
create index on receipts (tbl, pk, receipt_id);

-- Length-prefixed field encoding: 8-byte big-endian length, then UTF-8 bytes.
create function lp(t text) returns bytea language sql immutable as $$
  select int8send(octet_length(convert_to(coalesce(t, ''), 'UTF8'))) || convert_to(coalesce(t, ''), 'UTF8') $$;

-- CFP/1 signing input: domain tag, then the grant's fields in a fixed order.
create function signing_input(g jsonb) returns bytea language sql immutable as $$
  select convert_to('CFP-SIGNING-INPUT/1', 'UTF8')
      || fence.lp(g->>'v') || fence.lp(g->>'grant_id') || fence.lp(g->>'audience')
      || fence.lp(g#>>'{effect,kind}') || fence.lp(g#>>'{effect,table}') || fence.lp(g#>>'{effect,pk}')
      || fence.lp(g#>>'{prestate,digest}') || fence.lp(g#>>'{history,head}')
      || fence.lp(g->>'authority_epoch') || fence.lp(g->>'intent')
      || fence.lp(g->>'not_before') || fence.lp(g->>'not_after') || fence.lp(g#>>'{quorum,t}') $$;

create function digest_json(j json) returns text language sql immutable as $$
  select encode(sha256(convert_to(j::text, 'UTF8')), 'hex') $$;

-- Prestate digest of a protected row, as a client computes it before requesting a grant.
create function row_digest(tbl regclass, pk text) returns text language plpgsql stable as $$
declare col name; j json;
begin
  select pk_col into col from fence.protected where protected.tbl = row_digest.tbl;
  if col is null then raise exception 'CFP_NOT_PROTECTED'; end if;
  execute format('select row_to_json(t) from %s t where %I::text = $1', tbl, col) into j using pk;
  return coalesce(fence.digest_json(j), 'absent');
end $$;

create function history_head(tbl regclass, pk text) returns text language sql stable as $$
  select coalesce((select poststate from fence.receipts r where r.tbl = history_head.tbl and r.pk = history_head.pk
                   order by receipt_id desc limit 1), 'genesis') $$;

-- Admit a grant for the current transaction. Raises a CFP_* error on any failure.
create function "begin"(g jsonb) returns text language plpgsql as $$
declare
  cfg fence.config; epoch bigint; s jsonb; iss record; verified text[] := '{}'; msg bytea;
begin
  select * into cfg from fence.config;
  if g->>'v' is distinct from 'cfp/1' then raise exception 'CFP_VERSION'; end if;
  if g->>'audience' is distinct from cfg.audience then raise exception 'CFP_WRONG_AUDIENCE'; end if;
  if now() < (g->>'not_before')::timestamptz or now() > (g->>'not_after')::timestamptz then raise exception 'CFP_BUDGET_EXPIRED'; end if;
  if coalesce((g#>>'{quorum,t}')::int, 0) < cfg.min_quorum then raise exception 'CFP_QUORUM_POLICY'; end if;

  -- Linearize against revocation: a shared lock on the epoch row until this transaction ends.
  select authority_epoch into epoch from fence_ledger.state where id = 1 for share;
  if (g->>'authority_epoch')::bigint is distinct from epoch then raise exception 'CFP_STALE_EPOCH'; end if;

  msg := fence.signing_input(g);
  for s in select * from jsonb_array_elements(coalesce(g->'signatures', '[]')) loop
    select * into iss from fence_ledger.issuers where issuer_id = s->>'issuer';
    if found and iss.status = 'active' and iss.root_gen = (s->>'root_gen')::int
       and fence.ed25519_verify(iss.pubkey, msg, decode(s->>'sig', 'hex'))
       and not (iss.issuer_id = any(verified)) then
      verified := verified || iss.issuer_id;
    end if;
  end loop;
  if coalesce(array_length(verified, 1), 0) < (g#>>'{quorum,t}')::int then raise exception 'CFP_QUORUM'; end if;

  -- Single use: consumption lives in the durable ledger and commits with this transaction.
  begin
    insert into fence_ledger.consumed (grant_id, consumed_at) values ((g->>'grant_id')::uuid, now());
  exception when unique_violation then
    raise exception 'CFP_REPLAY';
  end;

  perform set_config('fence.grant', g::text, true);
  perform set_config('fence.used', '0', true);
  return 'CFP_ADMITTED';
end $$;

-- Row guard on every protected table: the effect must match the admitted grant exactly.
create function guard() returns trigger language plpgsql as $$
declare
  g jsonb; col name; pkv text; pre text; post text; head text; op text := lower(TG_OP); tblname text;
begin
  g := nullif(current_setting('fence.grant', true), '')::jsonb;
  if g is null then raise exception 'CFP_NO_GRANT'; end if;
  if current_setting('fence.used', true) = '1' then raise exception 'CFP_GRANT_ALREADY_APPLIED'; end if;
  tblname := format('%I.%I', TG_TABLE_SCHEMA, TG_TABLE_NAME);
  if g#>>'{effect,table}' is distinct from tblname then raise exception 'CFP_EFFECT_MISMATCH'; end if;
  if g#>>'{effect,kind}' is distinct from op then raise exception 'CFP_EFFECT_MISMATCH'; end if;
  select pk_col into col from fence.protected where tbl = TG_RELID::regclass;
  pkv := case when op = 'delete' then to_jsonb(OLD)->>col else to_jsonb(NEW)->>col end;
  if op = 'update' and to_jsonb(OLD)->>col is distinct from pkv then raise exception 'CFP_EFFECT_MISMATCH'; end if;
  if g#>>'{effect,pk}' is distinct from pkv then raise exception 'CFP_EFFECT_MISMATCH'; end if;

  pre := case when op = 'insert' then 'absent' else fence.digest_json(row_to_json(OLD)) end;
  if g#>>'{prestate,digest}' is distinct from pre then raise exception 'CFP_PRESTATE_CHANGED'; end if;
  head := fence.history_head(TG_RELID::regclass, pkv);
  if g#>>'{history,head}' is distinct from head then raise exception 'CFP_HISTORY_MISMATCH'; end if;

  post := case when op = 'delete' then 'deleted' else fence.digest_json(row_to_json(NEW)) end;
  insert into fence.receipts (grant_id, tbl, pk, op, prestate, poststate, history_head, authority_epoch)
  values ((g->>'grant_id')::uuid, TG_RELID::regclass, pkv, op, pre, post, head, (g->>'authority_epoch')::bigint);
  perform set_config('fence.used', '1', true);
  return case when op = 'delete' then OLD else NEW end;
end $$;

-- Protect a table. ENABLE ALWAYS keeps the guard active even under session_replication_role = replica.
create function protect(tbl regclass, pk_col name) returns void language plpgsql as $$
#variable_conflict use_variable
begin
  insert into fence.protected as p values (tbl, pk_col) on conflict on constraint protected_pkey do update set pk_col = excluded.pk_col;
  execute format('drop trigger if exists cfp_guard on %s', tbl);
  execute format('create trigger cfp_guard before insert or update or delete on %s for each row execute function fence.guard()', tbl);
  execute format('alter table %s enable always trigger cfp_guard', tbl);
end $$;

-- Revoke an issuer: signed by a different active issuer and by the recovery root; advances the epoch.
create function revoke_issuer(target text, signer text, signer_sig text, recovery_sig text) returns bigint language plpgsql as $$
declare epoch bigint; msg bytea; s record; rk bytea;
begin
  if signer = target then raise exception 'CFP_SELF_REVOCATION'; end if;
  select authority_epoch into epoch from fence_ledger.state where id = 1 for update;
  msg := convert_to('CFP-REVOKE/1', 'UTF8') || fence.lp(target) || fence.lp((epoch + 1)::text);
  select * into s from fence_ledger.issuers where issuer_id = signer and status = 'active';
  if not found or not fence.ed25519_verify(s.pubkey, msg, decode(signer_sig, 'hex')) then raise exception 'CFP_REVOKE_SIGNER'; end if;
  select pubkey into rk from fence_ledger.recovery where id = 1;
  if not fence.ed25519_verify(rk, msg, decode(recovery_sig, 'hex')) then raise exception 'CFP_REVOKE_RECOVERY'; end if;
  update fence_ledger.issuers set status = 'revoked' where issuer_id = target;
  update fence_ledger.state set authority_epoch = epoch + 1 where id = 1;
  return epoch + 1;
end $$;

-- One-time setup. 'durable' places the ledger in a separate database through postgres_fdw;
-- 'local' keeps it in this database (used only as a negative control).
create function setup(audience text, ledger_mode text, ledger_db text default null, ledger_port int default 5432, ledger_user text default null, ledger_host text default 'localhost')
returns void language plpgsql as $$
begin
  insert into fence.config (audience, ledger_mode) values (audience, ledger_mode);
  execute 'create schema if not exists fence_ledger';
  if ledger_mode = 'durable' then
    execute 'create extension if not exists postgres_fdw';
    execute format('create server fence_ledger_srv foreign data wrapper postgres_fdw options (host %L, dbname %L, port %L)', ledger_host, ledger_db, ledger_port::text);
    execute format('create user mapping for current_user server fence_ledger_srv options (user %L)', coalesce(ledger_user, current_user));
    execute 'import foreign schema public limit to (issuers, recovery, state, consumed) from server fence_ledger_srv into fence_ledger';
  else
    execute 'create table fence_ledger.issuers (issuer_id text primary key, pubkey bytea not null, root_gen int not null, status text not null default ''active'')';
    execute 'create table fence_ledger.recovery (id int primary key default 1, pubkey bytea not null)';
    execute 'create table fence_ledger.state (id int primary key default 1, authority_epoch bigint not null default 1)';
    execute 'create table fence_ledger.consumed (grant_id uuid primary key, consumed_at timestamptz not null default now())';
    execute 'insert into fence_ledger.state default values';
  end if;
end $$;

-- Extension-owned tables are excluded from pg_dump unless registered: without this, a backup
-- silently drops protection, configuration and receipts (found by the restore drill).
select pg_catalog.pg_extension_config_dump('fence.config', '');
select pg_catalog.pg_extension_config_dump('fence.protected', '');
select pg_catalog.pg_extension_config_dump('fence.receipts', '');
select pg_catalog.pg_extension_config_dump('fence.receipts_receipt_id_seq', '');

-- Privilege model (found by the B2 demonstration): applications must never hold privileges on the fence's
-- tables or ledger. Admission and the guard run as SECURITY DEFINER with a pinned search path; applications
-- are granted only EXECUTE on fence.begin and fence.row_digest / fence.history_head.
alter function fence."begin"(jsonb) security definer set search_path = fence, fence_ledger, pg_catalog, public;
alter function fence.guard() security definer set search_path = fence, fence_ledger, pg_catalog, public;
alter function fence.row_digest(regclass, text) security definer set search_path = fence, pg_catalog, public;
alter function fence.history_head(regclass, text) security definer set search_path = fence, pg_catalog, public;
revoke all on all tables in schema fence from public;
revoke execute on all functions in schema fence from public;
grant usage on schema fence to public;
grant execute on function fence."begin"(jsonb), fence.row_digest(regclass, text), fence.history_head(regclass, text) to public;
