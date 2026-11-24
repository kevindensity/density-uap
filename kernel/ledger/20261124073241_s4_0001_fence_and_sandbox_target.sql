-- migration 20261124073241 s4_0001_fence_and_sandbox_target (ledger: mzglmdydfcoljrwleooq)
create extension if not exists pgsodium;
create schema if not exists fence;
revoke all on schema fence from public, anon, authenticated;

create table fence.config (id int primary key default 1 check (id = 1), audience text not null, min_quorum int not null default 2 check (min_quorum >= 1));
create table fence.protected (tbl regclass primary key, pk_col name not null);
create table fence.receipts (receipt_id bigserial primary key, grant_id uuid not null, tbl regclass not null, pk text not null, op text not null,
  prestate text not null, poststate text not null, history_head text not null, authority_epoch bigint not null, committed_at timestamptz not null default now());
create index on fence.receipts (tbl, pk, receipt_id);
create index on fence.receipts (grant_id);
alter table fence.config enable row level security; alter table fence.protected enable row level security; alter table fence.receipts enable row level security;
revoke all on fence.config, fence.protected, fence.receipts from public, anon, authenticated;
insert into fence.config (audience) values ('pg://density-ledger/sandbox');

-- CFP/1 encoding, identical to p0-core's Grant::signing_input
create function fence.lp(t text) returns bytea language sql immutable as $$
  select int8send(octet_length(convert_to(coalesce(t, ''), 'UTF8'))) || convert_to(coalesce(t, ''), 'UTF8') $$;
create function fence.signing_input(g jsonb) returns bytea language sql immutable as $$
  select convert_to('CFP-SIGNING-INPUT/1', 'UTF8')
      || fence.lp(g->>'v') || fence.lp(g->>'grant_id') || fence.lp(g->>'audience')
      || fence.lp(g#>>'{effect,kind}') || fence.lp(g#>>'{effect,table}') || fence.lp(g#>>'{effect,pk}')
      || fence.lp(g#>>'{prestate,digest}') || fence.lp(g#>>'{history,head}')
      || fence.lp(g->>'authority_epoch') || fence.lp(g->>'intent')
      || fence.lp(g->>'not_before') || fence.lp(g->>'not_after') || fence.lp(g#>>'{quorum,t}') $$;
create function fence.digest_json(j json) returns text language sql immutable as $$ select encode(sha256(convert_to(j::text, 'UTF8')), 'hex') $$;

create function fence.row_digest(tbl regclass, pk text) returns text language plpgsql stable security definer set search_path = fence, pg_catalog as $$
declare col name; j json;
begin
  select pk_col into col from fence.protected where protected.tbl = row_digest.tbl;
  if col is null then raise exception 'CFP_NOT_PROTECTED'; end if;
  execute format('select row_to_json(t) from %s t where %I::text = $1', tbl, col) into j using pk;
  return coalesce(fence.digest_json(j), 'absent');
end $$;
create function fence.history_head(tbl regclass, pk text) returns text language sql stable security definer set search_path = fence, pg_catalog as $$
  select coalesce((select poststate from fence.receipts r where r.tbl = history_head.tbl and r.pk = history_head.pk order by receipt_id desc limit 1), 'genesis') $$;

-- Admission: version, audience, window, quorum policy, current epoch (shared lock against revocation), quorum of active
-- enrolled issuers (Ed25519 via pgsodium), then single use: consumption commits with this transaction.
create function fence."begin"(g jsonb) returns text language plpgsql security definer set search_path = fence, ledger, pg_catalog as $$
declare cfg fence.config; epoch bigint; s jsonb; iss record; verified text[] := '{}'; msg bytea;
begin
  select * into cfg from fence.config;
  if g->>'v' is distinct from 'cfp/1' then raise exception 'CFP_VERSION'; end if;
  if g->>'audience' is distinct from cfg.audience then raise exception 'CFP_WRONG_AUDIENCE'; end if;
  if now() < (g->>'not_before')::timestamptz or now() > (g->>'not_after')::timestamptz then raise exception 'CFP_BUDGET_EXPIRED'; end if;
  if coalesce((g#>>'{quorum,t}')::int, 0) < cfg.min_quorum then raise exception 'CFP_QUORUM_POLICY'; end if;
  select authority_epoch into epoch from ledger.state where id = 1 for share;
  if (g->>'authority_epoch')::bigint is distinct from epoch then raise exception 'CFP_STALE_EPOCH'; end if;
  msg := fence.signing_input(g);
  for s in select * from jsonb_array_elements(coalesce(g->'signatures', '[]')) loop
    select * into iss from ledger.issuers where issuer_id = s->>'issuer';
    if found and iss.status = 'active' and iss.root_gen = (s->>'root_gen')::int
       and pgsodium.crypto_sign_verify_detached(decode(s->>'sig', 'hex'), msg, iss.pubkey)
       and not (iss.issuer_id = any (verified)) then verified := verified || iss.issuer_id; end if;
  end loop;
  if coalesce(array_length(verified, 1), 0) < (g#>>'{quorum,t}')::int then raise exception 'CFP_QUORUM'; end if;
  begin
    insert into ledger.consumed (grant_id, consumed_at, consumer) values ((g->>'grant_id')::uuid, now(), cfg.audience);
  exception when unique_violation then raise exception 'CFP_REPLAY'; end;
  perform set_config('fence.grant', g::text, true);
  perform set_config('fence.used', '0', true);
  return 'CFP_ADMITTED';
end $$;

-- Row guard: the effect must match the admitted grant exactly, including the intended result when the grant binds it
-- (intent 'poststate:<sha256>'), so a grant for one outcome cannot write another.
create function fence.guard() returns trigger language plpgsql security definer set search_path = fence, pg_catalog as $$
declare g jsonb; col name; pkv text; pre text; post text; head text; op text := lower(TG_OP); tblname text;
begin
  g := nullif(current_setting('fence.grant', true), '')::jsonb;
  if g is null then raise exception 'CFP_NO_GRANT'; end if;
  if current_setting('fence.used', true) = '1' then raise exception 'CFP_GRANT_ALREADY_APPLIED'; end if;
  tblname := format('%I.%I', TG_TABLE_SCHEMA, TG_TABLE_NAME);
  if g#>>'{effect,table}' is distinct from tblname or g#>>'{effect,kind}' is distinct from op then raise exception 'CFP_EFFECT_MISMATCH'; end if;
  select pk_col into col from fence.protected where tbl = TG_RELID::regclass;
  pkv := case when op = 'delete' then to_jsonb(OLD)->>col else to_jsonb(NEW)->>col end;
  if op = 'update' and to_jsonb(OLD)->>col is distinct from pkv then raise exception 'CFP_EFFECT_MISMATCH'; end if;
  if g#>>'{effect,pk}' is distinct from pkv then raise exception 'CFP_EFFECT_MISMATCH'; end if;
  pre := case when op = 'insert' then 'absent' else fence.digest_json(row_to_json(OLD)) end;
  if g#>>'{prestate,digest}' is distinct from pre then raise exception 'CFP_PRESTATE_CHANGED'; end if;
  head := fence.history_head(TG_RELID::regclass, pkv);
  if g#>>'{history,head}' is distinct from head then raise exception 'CFP_HISTORY_MISMATCH'; end if;
  post := case when op = 'delete' then 'deleted' else fence.digest_json(row_to_json(NEW)) end;
  if g->>'intent' like 'poststate:%' and substring(g->>'intent' from 11) is distinct from post then raise exception 'CFP_OUTCOME_NOT_GRANTED'; end if;
  insert into fence.receipts (grant_id, tbl, pk, op, prestate, poststate, history_head, authority_epoch)
  values ((g->>'grant_id')::uuid, TG_RELID::regclass, pkv, op, pre, post, head, (g->>'authority_epoch')::bigint);
  perform set_config('fence.used', '1', true);
  return case when op = 'delete' then OLD else NEW end;
end $$;

create function fence.protect(tbl regclass, pk_col name) returns void language plpgsql security definer set search_path = fence, pg_catalog as $$
#variable_conflict use_variable
begin
  insert into fence.protected as p values (tbl, pk_col) on conflict on constraint protected_pkey do update set pk_col = excluded.pk_col;
  execute format('drop trigger if exists cfp_guard on %s', tbl);
  execute format('create trigger cfp_guard before insert or update or delete on %s for each row execute function fence.guard()', tbl);
  execute format('alter table %s enable always trigger cfp_guard', tbl);
end $$;

-- the bounded target: a flags table, seeded, then protected
create schema if not exists sandbox;
revoke all on schema sandbox from public, anon, authenticated;
create table sandbox.flags (key text primary key, value text not null);
alter table sandbox.flags enable row level security;
revoke all on sandbox.flags from public, anon, authenticated;
insert into sandbox.flags values ('demo-flag', 'off'), ('demo-limit', '10');
select fence.protect('sandbox.flags', 'key');

revoke execute on all functions in schema fence from public;
