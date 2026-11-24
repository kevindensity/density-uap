-- schema snapshot of postgres, generated from the catalogs (structure only, no data)

-- ===== schema app =====
create schema if not exists app;
create table app.feature_flags (
  key text not null,
  value text not null
);
alter table only app.feature_flags add constraint feature_flags_pkey PRIMARY KEY (key);
alter table app.feature_flags enable row level security;
create policy flags_gateway on app.feature_flags as permissive for all to gatewayd_customer using (true) with check (true);
create policy flags_observer on app.feature_flags as permissive for select to density_observer using (true);
CREATE TRIGGER cfp_guard BEFORE INSERT OR DELETE OR UPDATE ON app.feature_flags FOR EACH ROW EXECUTE FUNCTION fence.guard();
alter table app.feature_flags enable always trigger cfp_guard;
grant SELECT on app.feature_flags to density_observer;
grant SELECT on app.feature_flags to gatewayd_customer;
grant UPDATE on app.feature_flags to gatewayd_customer;

-- ===== schema fence =====
create schema if not exists fence;
create table fence.config (
  id integer not null default 1,
  audience text not null,
  min_quorum integer not null default 2
);
alter table only fence.config add constraint config_pkey PRIMARY KEY (id);
alter table only fence.config add constraint config_id_check CHECK ((id = 1));
alter table only fence.config add constraint config_min_quorum_check CHECK ((min_quorum >= 1));
alter table fence.config enable row level security;
create table fence.protected (
  tbl regclass not null,
  pk_col name not null
);
alter table only fence.protected add constraint protected_pkey PRIMARY KEY (tbl);
alter table fence.protected enable row level security;
create table fence.receipts (
  receipt_id bigint not null default nextval('fence.receipts_receipt_id_seq'::regclass),
  grant_id uuid not null,
  tbl regclass not null,
  pk text not null,
  op text not null,
  prestate text not null,
  poststate text not null,
  history_head text not null,
  authority_epoch bigint not null,
  committed_at timestamp with time zone not null default now()
);
alter table only fence.receipts add constraint receipts_pkey PRIMARY KEY (receipt_id);
CREATE INDEX receipts_grant_id_idx ON fence.receipts USING btree (grant_id);
CREATE INDEX receipts_tbl_pk_receipt_id_idx ON fence.receipts USING btree (tbl, pk, receipt_id);
alter table fence.receipts enable row level security;
create policy receipts_observer on fence.receipts as permissive for select to density_observer using (true);
grant SELECT on fence.receipts to density_observer;
create view fence.receipts_v as
 SELECT receipt_id,
    grant_id,
    (tbl)::text AS tbl,
    pk,
    op,
    prestate,
    poststate,
    history_head,
    authority_epoch,
    committed_at
   FROM fence.receipts;
CREATE OR REPLACE FUNCTION fence.begin(g jsonb)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'fence', 'fence_ledger', 'pg_catalog'
AS $function$
declare cfg fence.config; epoch bigint; s jsonb; iss record; verified text[] := '{}'; msg bytea;
begin
  select * into cfg from fence.config;
  if g->>'v' is distinct from 'cfp/1' then raise exception 'CFP_VERSION'; end if;
  if g->>'audience' is distinct from cfg.audience then raise exception 'CFP_WRONG_AUDIENCE'; end if;
  if now() < (g->>'not_before')::timestamptz or now() > (g->>'not_after')::timestamptz then raise exception 'CFP_BUDGET_EXPIRED'; end if;
  if coalesce((g#>>'{quorum,t}')::int, 0) < cfg.min_quorum then raise exception 'CFP_QUORUM_POLICY'; end if;
  perform 1 from fence_ledger.epoch_lock where id = 1 for share;   -- revocation waits for this effect
  select authority_epoch into epoch from fence_ledger.state where id = 1;
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
end $function$
;
CREATE OR REPLACE FUNCTION fence.digest_json(j json)
 RETURNS text
 LANGUAGE sql
 IMMUTABLE
AS $function$ select encode(sha256(convert_to(j::text, 'UTF8')), 'hex') $function$
;
CREATE OR REPLACE FUNCTION fence.guard()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'fence', 'pg_catalog'
AS $function$
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
end $function$
;
CREATE OR REPLACE FUNCTION fence.history_head(tbl regclass, pk text)
 RETURNS text
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'fence', 'pg_catalog'
AS $function$
  select coalesce((select poststate from fence.receipts r where r.tbl = history_head.tbl and r.pk = history_head.pk order by receipt_id desc limit 1), 'genesis') $function$
;
CREATE OR REPLACE FUNCTION fence.lp(t text)
 RETURNS bytea
 LANGUAGE sql
 IMMUTABLE
AS $function$
  select int8send(octet_length(convert_to(coalesce(t, ''), 'UTF8'))) || convert_to(coalesce(t, ''), 'UTF8') $function$
;
CREATE OR REPLACE FUNCTION fence.protect(tbl regclass, pk_col name)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'fence', 'pg_catalog'
AS $function$
#variable_conflict use_variable
begin
  insert into fence.protected as p values (tbl, pk_col) on conflict on constraint protected_pkey do update set pk_col = excluded.pk_col;
  execute format('drop trigger if exists cfp_guard on %s', tbl);
  execute format('create trigger cfp_guard before insert or update or delete on %s for each row execute function fence.guard()', tbl);
  execute format('alter table %s enable always trigger cfp_guard', tbl);
end $function$
;
CREATE OR REPLACE FUNCTION fence.row_digest(tbl regclass, pk text)
 RETURNS text
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'fence', 'pg_catalog'
AS $function$
declare col name; j json;
begin
  select pk_col into col from fence.protected where protected.tbl = row_digest.tbl;
  if col is null then raise exception 'CFP_NOT_PROTECTED'; end if;
  execute format('select row_to_json(t) from %s t where %I::text = $1', tbl, col) into j using pk;
  return coalesce(fence.digest_json(j), 'absent');
end $function$
;
CREATE OR REPLACE FUNCTION fence.signing_input(g jsonb)
 RETURNS bytea
 LANGUAGE sql
 IMMUTABLE
AS $function$
  select convert_to('CFP-SIGNING-INPUT/1', 'UTF8')
      || fence.lp(g->>'v') || fence.lp(g->>'grant_id') || fence.lp(g->>'audience')
      || fence.lp(g#>>'{effect,kind}') || fence.lp(g#>>'{effect,table}') || fence.lp(g#>>'{effect,pk}')
      || fence.lp(g#>>'{prestate,digest}') || fence.lp(g#>>'{history,head}')
      || fence.lp(g->>'authority_epoch') || fence.lp(g->>'intent')
      || fence.lp(g->>'not_before') || fence.lp(g->>'not_after') || fence.lp(g#>>'{quorum,t}') $function$
;

-- ===== schema fence_ledger =====
create schema if not exists fence_ledger;
create foreign table fence_ledger.consumed (
  grant_id uuid not null,
  consumed_at timestamp with time zone not null,
  consumer text not null
);
create foreign table fence_ledger.epoch_lock (
  id integer not null
);
create foreign table fence_ledger.issuers (
  issuer_id text not null,
  pubkey bytea not null,
  root_gen integer not null,
  status text not null,
  administrator text not null,
  enrolled_at timestamp with time zone not null
);
create foreign table fence_ledger.state (
  id integer not null,
  authority_epoch bigint not null,
  updated_at timestamp with time zone not null
);

-- ===== schema public =====
create schema if not exists public;
