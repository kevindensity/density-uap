-- migration 20261124075637 c1_0001_customer_fence_remote_ledger (customer: khpubdyfjhtdwryucbqn)
create extension if not exists pgsodium;
create extension if not exists postgres_fdw;
create server density_ledger foreign data wrapper postgres_fdw options (host 'aws-0-us-west-1.pooler.supabase.com', port '5432', dbname 'postgres', sslmode 'require');
do $$ begin
  execute format('create user mapping for postgres server density_ledger options (user %L, password %L)', 'fence_customer_sim.mzglmdydfcoljrwleooq',
                 (select decrypted_secret from vault.decrypted_secrets where name = 'fence_ledger_password'));
end $$;
create schema fence_ledger;
revoke all on schema fence_ledger from public, anon, authenticated;
import foreign schema ledger limit to (issuers, state, consumed) from server density_ledger into fence_ledger;

create schema fence;
revoke all on schema fence from public, anon, authenticated;
create table fence.config (id int primary key default 1 check (id = 1), audience text not null, min_quorum int not null default 2 check (min_quorum >= 1));
create table fence.protected (tbl regclass primary key, pk_col name not null);
create table fence.receipts (receipt_id bigserial primary key, grant_id uuid not null, tbl regclass not null, pk text not null, op text not null,
  prestate text not null, poststate text not null, history_head text not null, authority_epoch bigint not null, committed_at timestamptz not null default now());
create index on fence.receipts (tbl, pk, receipt_id); create index on fence.receipts (grant_id);
alter table fence.config enable row level security; alter table fence.protected enable row level security; alter table fence.receipts enable row level security;
revoke all on fence.config, fence.protected, fence.receipts from public, anon, authenticated;
insert into fence.config (audience) values ('pg://density-customer-sim/app');

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

-- admission against the REMOTE durable ledger: issuers and epoch read there, consumption recorded there
create function fence."begin"(g jsonb) returns text language plpgsql security definer set search_path = fence, fence_ledger, pg_catalog as $$
declare cfg fence.config; epoch bigint; s jsonb; iss record; verified text[] := '{}'; msg bytea;
begin
  select * into cfg from fence.config;
  if g->>'v' is distinct from 'cfp/1' then raise exception 'CFP_VERSION'; end if;
  if g->>'audience' is distinct from cfg.audience then raise exception 'CFP_WRONG_AUDIENCE'; end if;
  if now() < (g->>'not_before')::timestamptz or now() > (g->>'not_after')::timestamptz then raise exception 'CFP_BUDGET_EXPIRED'; end if;
  if coalesce((g#>>'{quorum,t}')::int, 0) < cfg.min_quorum then raise exception 'CFP_QUORUM_POLICY'; end if;
  select authority_epoch into epoch from fence_ledger.state where id = 1 for share;
  if (g->>'authority_epoch')::bigint is distinct from epoch then raise exception 'CFP_STALE_EPOCH'; end if;
  msg := fence.signing_input(g);
  for s in select * from jsonb_array_elements(coalesce(g->'signatures', '[]')) loop
    select * into iss from fence_ledger.issuers where issuer_id = s->>'issuer';
    if found and iss.status = 'active' and iss.root_gen = (s->>'root_gen')::int
       and pgsodium.crypto_sign_verify_detached(decode(s->>'sig', 'hex'), msg, iss.pubkey)
       and not (iss.issuer_id = any (verified)) then verified := verified || iss.issuer_id; end if;
  end loop;
  if coalesce(array_length(verified, 1), 0) < (g#>>'{quorum,t}')::int then raise exception 'CFP_QUORUM'; end if;
  begin
    insert into fence_ledger.consumed (grant_id, consumed_at, consumer) values ((g->>'grant_id')::uuid, now(), cfg.audience);
  exception when unique_violation then raise exception 'CFP_REPLAY'; end;
  perform set_config('fence.grant', g::text, true);
  perform set_config('fence.used', '0', true);
  return 'CFP_ADMITTED';
end $$;

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
create view fence.receipts_v as select receipt_id, grant_id, tbl::text as tbl, pk, op, prestate, poststate, history_head, authority_epoch, committed_at from fence.receipts;
revoke all on fence.receipts_v from public, anon, authenticated;

create schema app;
revoke all on schema app from public, anon, authenticated;
create table app.feature_flags (key text primary key, value text not null);
alter table app.feature_flags enable row level security;
revoke all on app.feature_flags from public, anon, authenticated;
insert into app.feature_flags values ('demo-checkout-v2', 'off'), ('demo-rate-limit', '100');
select fence.protect('app.feature_flags', 'key');
revoke execute on all functions in schema fence from public;

select (select count(*) from fence_ledger.issuers) as issuers_seen_remotely, (select authority_epoch from fence_ledger.state where id = 1) as remote_epoch;
