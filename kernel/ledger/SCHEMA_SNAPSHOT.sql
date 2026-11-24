-- schema snapshot of postgres, generated from the catalogs (structure only, no data)

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
create policy receipts_observer on fence.receipts as permissive for select to ledger_fdw using (true);
grant SELECT on fence.receipts to ledger_fdw;
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
 SET search_path TO 'fence', 'ledger', 'pg_catalog'
AS $function$
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

-- ===== schema ledger =====
create schema if not exists ledger;
create table ledger.authority_reductions (
  event_id uuid not null,
  root_seq bigint not null,
  machine text not null,
  stream_id uuid not null,
  subject_type text not null,
  subject_id text not null,
  event_kind text not null,
  revision bigint not null,
  expected_predecessor text,
  payload jsonb not null,
  receipts jsonb not null,
  authority_epoch bigint not null,
  identity_digest text not null,
  event_digest text not null,
  admitted_at timestamp with time zone not null,
  mirrored_at timestamp with time zone not null default clock_timestamp()
);
alter table only ledger.authority_reductions add constraint authority_reductions_pkey PRIMARY KEY (event_id);
CREATE INDEX authority_reductions_stream_id_revision_idx ON ledger.authority_reductions USING btree (stream_id, revision);
alter table ledger.authority_reductions enable row level security;
create policy reductions_gateway on ledger.authority_reductions as permissive for select to gatewayd_ledger using (true);
create policy reductions_root on ledger.authority_reductions as permissive for all to ledger_fdw using (true) with check (true);
CREATE TRIGGER authority_reductions_append_only BEFORE DELETE OR UPDATE ON ledger.authority_reductions FOR EACH ROW EXECUTE FUNCTION ledger.heartbeats_append_only();
grant SELECT on ledger.authority_reductions to gatewayd_ledger;
grant INSERT on ledger.authority_reductions to ledger_fdw;
grant SELECT on ledger.authority_reductions to ledger_fdw;
create table ledger.consumed (
  grant_id uuid not null,
  consumed_at timestamp with time zone not null default now(),
  consumer text not null
);
alter table only ledger.consumed add constraint consumed_pkey PRIMARY KEY (grant_id);
alter table ledger.consumed enable row level security;
create policy consumed_fdw on ledger.consumed as permissive for all to ledger_fdw using (true) with check (true);
create policy customer_fence_consumed on ledger.consumed as permissive for insert to fence_customer_sim with check (true);
CREATE TRIGGER consume_guard BEFORE INSERT ON ledger.consumed FOR EACH ROW EXECUTE FUNCTION ledger.consume_guard();
CREATE TRIGGER consumed_append_only BEFORE DELETE OR UPDATE ON ledger.consumed FOR EACH ROW EXECUTE FUNCTION ledger.append_only();
grant INSERT on ledger.consumed to fence_customer_sim;
grant INSERT on ledger.consumed to ledger_fdw;
grant SELECT on ledger.consumed to ledger_fdw;
create table ledger.effect_grants (
  grant_id uuid not null,
  effect_key text not null,
  retry_allowed boolean not null,
  not_after timestamp with time zone not null,
  registered_at timestamp with time zone not null default clock_timestamp()
);
alter table only ledger.effect_grants add constraint effect_grants_pkey PRIMARY KEY (grant_id);
alter table only ledger.effect_grants add constraint effect_grants_effect_key_fkey FOREIGN KEY (effect_key) REFERENCES ledger.effects(effect_key);
alter table ledger.effect_grants enable row level security;
CREATE TRIGGER effect_grants_append_only BEFORE DELETE OR UPDATE ON ledger.effect_grants FOR EACH ROW EXECUTE FUNCTION ledger.heartbeats_append_only();
create table ledger.effects (
  effect_key text not null,
  audience text not null,
  state text not null,
  current_grant uuid not null,
  updated_at timestamp with time zone not null default now()
);
alter table only ledger.effects add constraint effects_pkey PRIMARY KEY (effect_key);
alter table only ledger.effects add constraint effects_state_check CHECK ((state = ANY (ARRAY['AUTHORIZED'::text, 'RELEASED'::text, 'NOT_APPLIED'::text])));
alter table ledger.effects enable row level security;
create policy effects_read on ledger.effects as permissive for select to ledger_fdw, gatewayd_ledger using (true);
grant SELECT on ledger.effects to gatewayd_ledger;
grant SELECT on ledger.effects to ledger_fdw;
create table ledger.epoch_lock (
  id integer not null
);
alter table only ledger.epoch_lock add constraint epoch_lock_pkey PRIMARY KEY (id);
alter table only ledger.epoch_lock add constraint epoch_lock_id_check CHECK ((id = 1));
alter table ledger.epoch_lock enable row level security;
create policy epoch_lock_fence on ledger.epoch_lock as permissive for all to fence_customer_sim using (true) with check (true);
CREATE TRIGGER epoch_lock_immutable BEFORE INSERT OR DELETE OR UPDATE ON ledger.epoch_lock FOR EACH ROW EXECUTE FUNCTION ledger.epoch_lock_immutable();
grant SELECT on ledger.epoch_lock to fence_customer_sim;
grant UPDATE on ledger.epoch_lock to fence_customer_sim;
create table ledger.heartbeats (
  seq bigint not null default nextval('ledger.heartbeats_seq_seq'::regclass),
  nonce text not null,
  written_at timestamp with time zone not null default clock_timestamp()
);
alter table only ledger.heartbeats add constraint heartbeats_nonce_key UNIQUE (nonce);
alter table only ledger.heartbeats add constraint heartbeats_pkey PRIMARY KEY (seq);
alter table ledger.heartbeats enable row level security;
create policy heartbeats_root on ledger.heartbeats as permissive for all to ledger_fdw using (true) with check (true);
CREATE TRIGGER heartbeats_append_only BEFORE DELETE OR UPDATE ON ledger.heartbeats FOR EACH ROW EXECUTE FUNCTION ledger.heartbeats_append_only();
grant INSERT on ledger.heartbeats to ledger_fdw;
grant SELECT on ledger.heartbeats to ledger_fdw;
create table ledger.id_sequence (
  name text not null,
  last_value bigint not null
);
alter table only ledger.id_sequence add constraint id_sequence_pkey PRIMARY KEY (name);
alter table ledger.id_sequence enable row level security;
create policy id_sequence_fdw on ledger.id_sequence as permissive for all to ledger_fdw using (true) with check (true);
CREATE TRIGGER id_sequence_forward_only BEFORE DELETE OR UPDATE ON ledger.id_sequence FOR EACH ROW EXECUTE FUNCTION ledger.forward_only();
grant INSERT on ledger.id_sequence to ledger_fdw;
grant SELECT on ledger.id_sequence to ledger_fdw;
grant UPDATE on ledger.id_sequence to ledger_fdw;
create table ledger.issuers (
  issuer_id text not null,
  pubkey bytea not null,
  root_gen integer not null,
  status text not null default 'active'::text,
  administrator text not null,
  enrolled_at timestamp with time zone not null default now()
);
alter table only ledger.issuers add constraint issuers_pkey PRIMARY KEY (issuer_id);
alter table only ledger.issuers add constraint issuers_pubkey_check CHECK ((octet_length(pubkey) = 32));
alter table only ledger.issuers add constraint issuers_status_check CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text])));
alter table ledger.issuers enable row level security;
create policy customer_fence_issuers on ledger.issuers as permissive for select to fence_customer_sim using (true);
create policy issuers_fdw on ledger.issuers as permissive for all to ledger_fdw using (true) with check (true);
CREATE TRIGGER issuers_forward_only BEFORE DELETE OR UPDATE ON ledger.issuers FOR EACH ROW EXECUTE FUNCTION ledger.forward_only();
grant SELECT on ledger.issuers to fence_customer_sim;
grant SELECT on ledger.issuers to ledger_fdw;
create table ledger.outcomes (
  grant_id uuid not null,
  outcome text not null,
  detail jsonb,
  decided_by text not null,
  at timestamp with time zone not null default now()
);
alter table only ledger.outcomes add constraint outcomes_pkey PRIMARY KEY (grant_id);
alter table only ledger.outcomes add constraint outcomes_grant_id_fkey FOREIGN KEY (grant_id) REFERENCES ledger.sent(grant_id);
alter table only ledger.outcomes add constraint outcomes_outcome_check CHECK ((outcome = ANY (ARRAY['DONE'::text, 'REFUSED'::text, 'RECOVERY_REQUIRED'::text, 'DID'::text, 'NOT_APPLIED'::text, 'UNKNOWN'::text])));
alter table ledger.outcomes enable row level security;
create policy outcomes_fdw on ledger.outcomes as permissive for all to ledger_fdw using (true) with check (true);
CREATE TRIGGER outcomes_append_only BEFORE DELETE OR UPDATE ON ledger.outcomes FOR EACH ROW EXECUTE FUNCTION ledger.append_only();
grant INSERT on ledger.outcomes to ledger_fdw;
grant SELECT on ledger.outcomes to ledger_fdw;
create table ledger.recovery (
  id integer not null default 1,
  pubkey bytea not null,
  administrator text not null
);
alter table only ledger.recovery add constraint recovery_pkey PRIMARY KEY (id);
alter table only ledger.recovery add constraint recovery_id_check CHECK ((id = 1));
alter table only ledger.recovery add constraint recovery_pubkey_check CHECK ((octet_length(pubkey) = 32));
alter table ledger.recovery enable row level security;
create policy recovery_fdw on ledger.recovery as permissive for all to ledger_fdw using (true) with check (true);
grant SELECT on ledger.recovery to ledger_fdw;
create table ledger.revocations (
  id bigint not null,
  target_issuer text not null,
  new_epoch bigint not null,
  signer text not null,
  signer_sig text not null,
  recovery_sig text not null,
  at timestamp with time zone not null default now()
);
alter table only ledger.revocations add constraint revocations_pkey PRIMARY KEY (id);
alter table only ledger.revocations add constraint revocations_target_issuer_fkey FOREIGN KEY (target_issuer) REFERENCES ledger.issuers(issuer_id);
alter table ledger.revocations enable row level security;
create policy revocations_fdw on ledger.revocations as permissive for all to ledger_fdw using (true) with check (true);
CREATE TRIGGER revocations_append_only BEFORE DELETE OR UPDATE ON ledger.revocations FOR EACH ROW EXECUTE FUNCTION ledger.append_only();
grant INSERT on ledger.revocations to ledger_fdw;
grant SELECT on ledger.revocations to ledger_fdw;
create table ledger.revoked_grants (
  grant_id uuid not null,
  reason text not null,
  revoked_at timestamp with time zone not null default clock_timestamp()
);
alter table only ledger.revoked_grants add constraint revoked_grants_pkey PRIMARY KEY (grant_id);
alter table ledger.revoked_grants enable row level security;
create policy revoked_read on ledger.revoked_grants as permissive for select to ledger_fdw, gatewayd_ledger using (true);
CREATE TRIGGER revoked_grants_append_only BEFORE DELETE OR UPDATE ON ledger.revoked_grants FOR EACH ROW EXECUTE FUNCTION ledger.heartbeats_append_only();
grant SELECT on ledger.revoked_grants to gatewayd_ledger;
grant SELECT on ledger.revoked_grants to ledger_fdw;
create table ledger.sent (
  grant_id uuid not null,
  plan_digest text not null,
  emitter text not null,
  target text not null,
  request jsonb not null,
  sent_at timestamp with time zone not null default now()
);
alter table only ledger.sent add constraint sent_pkey PRIMARY KEY (grant_id);
alter table ledger.sent enable row level security;
create policy sent_fdw on ledger.sent as permissive for all to ledger_fdw using (true) with check (true);
create policy sent_gateway on ledger.sent as permissive for all to gatewayd_ledger using (true) with check (true);
CREATE TRIGGER sent_append_only BEFORE DELETE OR UPDATE ON ledger.sent FOR EACH ROW EXECUTE FUNCTION ledger.append_only();
grant INSERT on ledger.sent to gatewayd_ledger;
grant SELECT on ledger.sent to gatewayd_ledger;
grant INSERT on ledger.sent to ledger_fdw;
grant SELECT on ledger.sent to ledger_fdw;
create table ledger.state (
  id integer not null default 1,
  authority_epoch bigint not null default 1,
  updated_at timestamp with time zone not null default now()
);
alter table only ledger.state add constraint state_pkey PRIMARY KEY (id);
alter table only ledger.state add constraint state_id_check CHECK ((id = 1));
alter table ledger.state enable row level security;
create policy customer_fence_state on ledger.state as permissive for select to fence_customer_sim using (true);
create policy state_fdw on ledger.state as permissive for all to ledger_fdw using (true) with check (true);
create policy state_root_advance on ledger.state as permissive for update to ledger_fdw using (true) with check (true);
CREATE TRIGGER epoch_advance_waits BEFORE UPDATE ON ledger.state FOR EACH ROW EXECUTE FUNCTION ledger.epoch_advance_waits();
CREATE TRIGGER epoch_forward_only BEFORE UPDATE ON ledger.state FOR EACH ROW EXECUTE FUNCTION ledger.epoch_forward_only();
CREATE TRIGGER state_forward_only BEFORE DELETE OR UPDATE ON ledger.state FOR EACH ROW EXECUTE FUNCTION ledger.forward_only();
grant SELECT on ledger.state to fence_customer_sim;
grant SELECT on ledger.state to ledger_fdw;
CREATE OR REPLACE FUNCTION ledger.append_only()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog'
AS $function$
begin raise exception 'LEDGER_APPEND_ONLY: % on %.% is not permitted', tg_op, tg_table_schema, tg_table_name; end $function$
;
CREATE OR REPLACE FUNCTION ledger.consume_guard()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'ledger', 'pg_catalog'
AS $function$
declare eg ledger.effect_grants%rowtype; e ledger.effects%rowtype;
begin
  if exists (select 1 from ledger.consumed c where c.grant_id = new.grant_id) then raise exception using errcode = 'unique_violation', message = 'CFP_REPLAY'; end if;
  if exists (select 1 from ledger.revoked_grants r where r.grant_id = new.grant_id) then raise exception 'CFP_GRANT_REVOKED'; end if;
  select * into eg from ledger.effect_grants where grant_id = new.grant_id;
  if not found then raise exception 'CFP_GRANT_NOT_REGISTERED'; end if;
  select * into e from ledger.effects where effect_key = eg.effect_key for update;
  if e.state <> 'AUTHORIZED' or e.current_grant <> new.grant_id then raise exception 'CFP_GRANT_NOT_CURRENT'; end if;
  update ledger.effects set state = 'RELEASED', updated_at = now() where effect_key = eg.effect_key;
  return new;
end $function$
;
CREATE OR REPLACE FUNCTION ledger.epoch_advance_waits()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'ledger', 'pg_catalog'
AS $function$
begin perform 1 from ledger.epoch_lock where id = 1 for update; return new; end $function$
;
CREATE OR REPLACE FUNCTION ledger.epoch_forward_only()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
begin
  if new.authority_epoch < old.authority_epoch then raise exception 'EPOCH_FORWARD_ONLY'; end if;
  new.updated_at := now(); return new;
end $function$
;
CREATE OR REPLACE FUNCTION ledger.epoch_lock_immutable()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
begin raise exception 'EPOCH_LOCK_ROW_IMMUTABLE'; end $function$
;
CREATE OR REPLACE FUNCTION ledger.forward_only()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog'
AS $function$
begin
  if tg_op = 'DELETE' then raise exception 'LEDGER_FORWARD_ONLY: delete on %.% is not permitted', tg_table_schema, tg_table_name; end if;
  if tg_table_name = 'state' then
    if new.authority_epoch < old.authority_epoch then raise exception 'LEDGER_FORWARD_ONLY: authority epoch cannot move backwards'; end if;
  elsif tg_table_name = 'issuers' then
    if old.status = 'revoked' and new.status <> 'revoked' then raise exception 'LEDGER_FORWARD_ONLY: a revoked issuer cannot be reinstated; enrol a new issuer'; end if;
  elsif tg_table_name = 'id_sequence' then
    if new.last_value < old.last_value then raise exception 'LEDGER_FORWARD_ONLY: identifier sequence cannot move backwards'; end if;
  end if;
  return new;
end $function$
;
CREATE OR REPLACE FUNCTION ledger.heartbeats_append_only()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$ begin raise exception 'HEARTBEATS_APPEND_ONLY'; end $function$
;
CREATE OR REPLACE FUNCTION ledger.policy_reduction(p_policy_stream uuid)
 RETURNS text
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'ledger', 'pg_catalog'
AS $function$
  select r.event_kind || ' at ' || r.admitted_at::text from ledger.authority_reductions r
   where r.stream_id = p_policy_stream and r.event_kind in ('standing_policy:ACTIVE->REVOKED', 'standing_policy:ACTIVE->EXHAUSTED') order by r.root_seq desc limit 1 $function$
;
CREATE OR REPLACE FUNCTION ledger.register_grant(p_effect text, p_grant jsonb, p_retry boolean)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'ledger', 'pg_catalog'
AS $function$
declare e ledger.effects%rowtype; prior ledger.effect_grants%rowtype; gid uuid := (p_grant->>'grant_id')::uuid; na timestamptz := (p_grant->>'not_after')::timestamptz;
begin
  select * into e from ledger.effects where effect_key = p_effect for update;
  if found then
    -- an outstanding grant that expired unused proves the effect did not happen
    if e.state = 'AUTHORIZED' and not exists (select 1 from ledger.consumed c where c.grant_id = e.current_grant)
       and (select g.not_after from ledger.effect_grants g where g.grant_id = e.current_grant) < now() then
      update ledger.effects set state = 'NOT_APPLIED', updated_at = now() where effect_key = p_effect; e.state := 'NOT_APPLIED';
    end if;
    if e.state in ('AUTHORIZED', 'RELEASED') then raise exception 'TransitionForbidden: effect % is %', p_effect, e.state; end if;
    select * into prior from ledger.effect_grants where grant_id = e.current_grant;
    if not prior.retry_allowed then raise exception 'RetryForbidden: the previous grant for % did not allow retry', p_effect; end if;
    update ledger.effects set state = 'AUTHORIZED', current_grant = gid, updated_at = now() where effect_key = p_effect;
  else
    insert into ledger.effects (effect_key, audience, state, current_grant) values (p_effect, p_grant->>'audience', 'AUTHORIZED', gid);
  end if;
  insert into ledger.effect_grants (grant_id, effect_key, retry_allowed, not_after) values (gid, p_effect, p_retry, na);
  return 'REGISTERED';
end $function$
;
CREATE OR REPLACE FUNCTION ledger.revoke_grant(p_grant uuid, p_reason text)
 RETURNS text
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'ledger', 'pg_catalog'
AS $function$
  insert into ledger.revoked_grants (grant_id, reason) values (p_grant, p_reason) on conflict do nothing returning 'REVOKED' $function$
;

-- ===== schema ledger_test =====
create schema if not exists ledger_test;
create table ledger_test.oracle_traces (
  id text not null,
  sha256 text not null,
  oracle_source_sha256 text not null,
  traces jsonb not null,
  loaded_at timestamp with time zone not null default now()
);
alter table only ledger_test.oracle_traces add constraint oracle_traces_pkey PRIMARY KEY (id);
alter table ledger_test.oracle_traces enable row level security;
CREATE OR REPLACE FUNCTION ledger_test.mint_grant(p_key text, p_value text, p_sk1 bytea, p_sk2 bytea, p_register text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'ledger', 'fence', 'sandbox', 'pg_catalog'
AS $function$
declare g jsonb; msg bytea;
begin
  g := jsonb_build_object('v', 'cfp/1', 'grant_id', gen_random_uuid(), 'audience', 'pg://density-ledger/sandbox',
         'effect', jsonb_build_object('kind', 'update', 'table', 'sandbox.flags', 'pk', p_key),
         'prestate', jsonb_build_object('digest', fence.row_digest('sandbox.flags', p_key), 'scheme', 'row-json-sha256/1'),
         'history', jsonb_build_object('head', fence.history_head('sandbox.flags', p_key)),
         'authority_epoch', (select authority_epoch::text from ledger.state where id = 1),
         'intent', 'poststate:' || (select fence.digest_json(row_to_json(x)) from (select p_key::text as key, p_value::text as value) x),
         'not_before', (now() - interval '5 seconds')::text, 'not_after', (now() + interval '120 seconds')::text, 'quorum', jsonb_build_object('t', 2));
  msg := fence.signing_input(g);
  g := g || jsonb_build_object('signatures', jsonb_build_array(
         jsonb_build_object('issuer', 'conf-a', 'root_gen', 1, 'sig', encode(pgsodium.crypto_sign_detached(msg, p_sk1), 'hex')),
         jsonb_build_object('issuer', 'conf-b', 'root_gen', 1, 'sig', encode(pgsodium.crypto_sign_detached(msg, p_sk2), 'hex'))));
  if p_register is not null then perform ledger.register_grant(p_register, g, false); end if;
  return g;
end $function$
;
CREATE OR REPLACE FUNCTION ledger_test.run_differential(p_id text DEFAULT 'b0-reference-kernel/traces-40-seed-9E3779B97F4A7C15'::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'ledger', 'fence', 'sandbox', 'pg_catalog'
AS $function$
declare traces jsonb; kp1 record; kp2 record; t jsonb; s jsonb; k text; n int; cur jsonb; last_ok jsonb; prev_val text; vc int := 0; live text; exp text; g jsonb; intended text; msg bytea;
  agree int := 0; both_refuse int := 0; live_permits int := 0; live_refuses int := 0; skipped int := 0; permits jsonb := '[]'; refuses jsonb := '[]'; history text; diffs jsonb := '{}'; res jsonb;
begin
  select ot.traces into traces from ledger_test.oracle_traces ot where ot.id = p_id;
  begin
    select * into kp1 from pgsodium.crypto_sign_seed_new_keypair(pgsodium.crypto_sign_new_seed()); select * into kp2 from pgsodium.crypto_sign_seed_new_keypair(pgsodium.crypto_sign_new_seed());
    insert into ledger.issuers (issuer_id, pubkey, root_gen, status, administrator) values
      ('diff-a', kp1.public, 1, 'active', 'differential test (rolled back)'), ('diff-b', kp2.public, 1, 'active', 'differential test (rolled back)');
    for t in select * from jsonb_array_elements(traces) loop
      n := (t->>'trace')::int; k := 'diff-' || n; cur := null; last_ok := null; history := '';
      alter table sandbox.flags disable trigger cfp_guard;
      insert into sandbox.flags (key, value) values (k, 'v0');
      alter table sandbox.flags enable always trigger cfp_guard;
      for s in select * from jsonb_array_elements(t->'steps') loop
        exp := s->>'expect';
        if s->>'op' = 'E' then
          update ledger.state set authority_epoch = authority_epoch + 1 where id = 1; live := 'OK';
        elsif s->>'op' = 'X' then
          if cur is null then live := 'SKIP'; else perform ledger.revoke_grant((cur->>'grant_id')::uuid, 'differential'); live := 'OK'; end if;
        elsif s->>'op' like 'G%' then
          vc := vc + 1; intended := 'v' || vc;
          g := jsonb_build_object('v', 'cfp/1', 'grant_id', gen_random_uuid(), 'audience', 'pg://density-ledger/sandbox',
                 'effect', jsonb_build_object('kind', 'update', 'table', 'sandbox.flags', 'pk', k),
                 'prestate', jsonb_build_object('digest', fence.row_digest('sandbox.flags', k), 'scheme', 'row-json-sha256/1'),
                 'history', jsonb_build_object('head', fence.history_head('sandbox.flags', k)),
                 'authority_epoch', (select authority_epoch::text from ledger.state where id = 1),
                 'intent', 'poststate:' || (select fence.digest_json(row_to_json(x)) from (select k::text as key, intended::text as value) x),
                 'not_before', (now() - interval '5 seconds')::text, 'not_after', (now() + interval '120 seconds')::text, 'quorum', jsonb_build_object('t', 2));
          msg := fence.signing_input(g);
          g := g || jsonb_build_object('signatures', jsonb_build_array(
                 jsonb_build_object('issuer', 'diff-a', 'root_gen', 1, 'sig', encode(pgsodium.crypto_sign_detached(msg, kp1.secret), 'hex')),
                 jsonb_build_object('issuer', 'diff-b', 'root_gen', 1, 'sig', encode(pgsodium.crypto_sign_detached(msg, kp2.secret), 'hex'))));
          begin
            perform ledger.register_grant('diff-effect-' || n, g, s->>'op' = 'G+retry');
            cur := g || jsonb_build_object('intended_value', intended); live := 'OK';
          exception when others then live := split_part(sqlerrm, ':', 1); end;
        elsif s->>'op' = 'R' then
          if cur is null then live := 'TransitionForbidden';
          else
            begin
              perform fence."begin"(cur - 'intended_value');
              select value into prev_val from sandbox.flags where key = k;
              update sandbox.flags set value = cur->>'intended_value' where key = k;
              live := 'OK'; last_ok := cur;
            exception when others then
              live := case split_part(sqlerrm, ' ', 1) when 'CFP_STALE_EPOCH' then 'GrantRevoked' when 'CFP_GRANT_REVOKED' then 'GrantRevoked'
                        when 'CFP_REPLAY' then 'GrantConsumed' when 'CFP_BUDGET_EXPIRED' then 'GrantRevoked'
                        when 'CFP_GRANT_NOT_CURRENT' then 'TransitionForbidden' when 'CFP_GRANT_NOT_REGISTERED' then 'TransitionForbidden'
                        when 'CFP_PRESTATE_CHANGED' then 'TransitionForbidden' when 'CFP_HISTORY_MISMATCH' then 'TransitionForbidden'
                        else 'LIVE:' || split_part(sqlerrm, ' ', 1) end;
            end;
          end if;
        elsif s->>'op' = 'RR' then
          if last_ok is null then live := 'SKIP';
          else
            alter table sandbox.flags disable trigger cfp_guard;
            update sandbox.flags set value = prev_val where key = k;
            alter table sandbox.flags enable always trigger cfp_guard;
            delete from fence.receipts where grant_id = (last_ok->>'grant_id')::uuid;
            begin
              perform fence."begin"(last_ok - 'intended_value'); live := 'OK';
            exception when others then
              live := case split_part(sqlerrm, ' ', 1) when 'CFP_REPLAY' then 'GrantConsumed' when 'CFP_STALE_EPOCH' then 'GrantRevoked'
                        when 'CFP_GRANT_REVOKED' then 'GrantRevoked' else 'LIVE:' || split_part(sqlerrm, ' ', 1) end;
            end;
          end if;
        end if;
        history := history || (s->>'op') || ' ';
        if exp = 'SKIP' or live = 'SKIP' then skipped := skipped + 1;
        elsif exp = live then agree := agree + 1;
        elsif live = 'OK' then live_permits := live_permits + 1; permits := permits || jsonb_build_object('trace', n, 'ops', trim(history), 'oracle', exp);
        elsif exp = 'OK' then live_refuses := live_refuses + 1; refuses := refuses || jsonb_build_object('trace', n, 'ops', trim(history), 'live', live);
        else both_refuse := both_refuse + 1; diffs := diffs || jsonb_build_object(exp || '/' || live, coalesce((diffs->>(exp || '/' || live))::int, 0) + 1);
        end if;
      end loop;
    end loop;
    res := jsonb_build_object('trace_set', p_id, 'compared', agree + both_refuse + live_permits + live_refuses, 'agree', agree, 'both_refuse_different_reason', both_refuse,
      'refusal_pairs', diffs, 'live_permits_oracle_forbids', live_permits, 'live_refuses_oracle_permits', live_refuses, 'skipped', skipped,
      'permit_cases', permits, 'refuse_cases', refuses);
    raise exception 'DIFF_RESULT:%', res::text;
  exception when others then
    if sqlerrm like 'DIFF_RESULT:%' then return substring(sqlerrm from 13)::jsonb; end if;
    return jsonb_build_object('harness_error', sqlerrm);
  end;
end $function$
;
CREATE OR REPLACE FUNCTION ledger_test.run_fence_conformance()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'ledger', 'fence', 'sandbox', 'pg_catalog'
AS $function$
declare kp1 record; kp2 record; g jsonb; old_g jsonb; out jsonb := '{}'; res jsonb;
  -- one probe: admit g, write p_value to p_key; return 'ADMITTED' or the refusal code. The probe itself always rolls back.
begin
  out := jsonb_build_object('live_guard_mode', (select t.tgenabled::text from pg_trigger t where t.tgname = 'cfp_guard' and t.tgrelid = 'sandbox.flags'::regclass));
  begin
    select * into kp1 from pgsodium.crypto_sign_seed_new_keypair(pgsodium.crypto_sign_new_seed()); select * into kp2 from pgsodium.crypto_sign_seed_new_keypair(pgsodium.crypto_sign_new_seed());
    insert into ledger.issuers (issuer_id, pubkey, root_gen, status, administrator) values
      ('conf-a', kp1.public, 1, 'active', 'fence conformance (rolled back)'), ('conf-b', kp2.public, 1, 'active', 'fence conformance (rolled back)');
    alter table sandbox.flags disable trigger cfp_guard;
    insert into sandbox.flags values ('conf-x', 'v0'), ('conf-y', 'v0');
    alter table sandbox.flags enable always trigger cfp_guard;

    -- fence checks (each probe in its own sub-transaction, rolled back by raising)
    begin update sandbox.flags set value = 'v1' where key = 'conf-x'; out := out || '{"no_grant":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('no_grant', split_part(sqlerrm, ' ', 1)); end if; end;
    begin set local session_replication_role = replica; update sandbox.flags set value = 'v1' where key = 'conf-x'; out := out || '{"replica_bypass":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('replica_bypass', split_part(sqlerrm, ' ', 1)); end if; end;
    set local session_replication_role = origin;
    g := ledger_test.mint_grant('conf-x', 'v1', kp1.secret, kp2.secret, 'conf-effect-x');
    begin perform fence."begin"(g); update sandbox.flags set value = 'maybe' where key = 'conf-x'; out := out || '{"wrong_outcome":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('wrong_outcome', split_part(sqlerrm, ' ', 1)); end if; end;
    begin perform fence."begin"(jsonb_set(g, '{audience}', '"pg://elsewhere"')); out := out || '{"wrong_audience":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('wrong_audience', split_part(sqlerrm, ' ', 1)); end if; end;
    begin perform fence."begin"(jsonb_set(g, '{effect,pk}', '"conf-y"')); out := out || '{"tampered_row":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('tampered_row', split_part(sqlerrm, ' ', 1)); end if; end;
    begin perform fence."begin"(jsonb_set(g, '{signatures}', g->'signatures'->0 || '[]'::jsonb)); out := out || '{"one_signature":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('one_signature', split_part(sqlerrm, ' ', 1)); end if; end;
    begin perform fence."begin"(jsonb_set(g, '{signatures,1,sig}', to_jsonb(repeat('ab', 64)))); out := out || '{"forged_signature":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('forged_signature', split_part(sqlerrm, ' ', 1)); end if; end;
    begin perform fence."begin"(g); update sandbox.flags set value = 'v1' where key = 'conf-y'; out := out || '{"other_row":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('other_row', split_part(sqlerrm, ' ', 1)); end if; end;
    begin perform fence."begin"(ledger_test.mint_grant('conf-x', 'v1', kp1.secret, kp2.secret, null)); out := out || '{"unregistered":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('unregistered', split_part(sqlerrm, ' ', 1)); end if; end;
    begin perform ledger.revoke_grant((g->>'grant_id')::uuid, 'conformance'); perform fence."begin"(g); out := out || '{"revoked":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('revoked', split_part(sqlerrm, ' ', 1)); end if; end;
    -- the genuine grant, kept (inside this outer rolled-back block)
    perform fence."begin"(g); update sandbox.flags set value = 'v1' where key = 'conf-x';
    out := out || jsonb_build_object('genuine', 'ADMITTED');
    begin perform fence."begin"(g); out := out || '{"replay":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('replay', split_part(sqlerrm, ' ', 1)); end if; end;

    -- K35 target restore: the target forgets the effect (row and receipt), the ledger does not
    begin
      alter table sandbox.flags disable trigger cfp_guard; update sandbox.flags set value = 'v0' where key = 'conf-x'; alter table sandbox.flags enable always trigger cfp_guard;
      delete from fence.receipts where grant_id = (g->>'grant_id')::uuid;
      perform fence."begin"(g); out := out || '{"target_restore_replay":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('target_restore_replay', split_part(sqlerrm, ' ', 1)); end if; end;
    -- K35 ledger restore with the countermeasure: the ledger forgets the consumption, the epoch is advanced
    begin
      alter table sandbox.flags disable trigger cfp_guard; update sandbox.flags set value = 'v0' where key = 'conf-x'; alter table sandbox.flags enable always trigger cfp_guard;
      delete from fence.receipts where grant_id = (g->>'grant_id')::uuid;
      set local session_replication_role = replica;
      delete from ledger.consumed where grant_id = (g->>'grant_id')::uuid;
      update ledger.effects set state = 'AUTHORIZED' where effect_key = 'conf-effect-x';
      set local session_replication_role = origin;
      update ledger.state set authority_epoch = authority_epoch + 1 where id = 1;
      perform fence."begin"(g); out := out || '{"ledger_restore_replay_after_epoch_advance":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('ledger_restore_replay_after_epoch_advance', split_part(sqlerrm, ' ', 1)); end if; end;
    set local session_replication_role = origin;

    -- K51 history-bound: v0 -> v1 -> v0 again; a grant minted at the first v0 sees the same visible state but another history
    alter table sandbox.flags disable trigger cfp_guard;
    insert into sandbox.flags values ('conf-h', 'v0');
    alter table sandbox.flags enable always trigger cfp_guard;
    old_g := ledger_test.mint_grant('conf-h', 'v9', kp1.secret, kp2.secret, 'conf-effect-h-old');
    g := ledger_test.mint_grant('conf-h', 'v1', kp1.secret, kp2.secret, 'conf-effect-h1'); perform fence."begin"(g); update sandbox.flags set value = 'v1' where key = 'conf-h';
    g := ledger_test.mint_grant('conf-h', 'v0', kp1.secret, kp2.secret, 'conf-effect-h2'); perform fence."begin"(g); update sandbox.flags set value = 'v0' where key = 'conf-h';
    out := out || jsonb_build_object('history_same_visible_state', fence.row_digest('sandbox.flags', 'conf-h') = old_g#>>'{prestate,digest}');
    begin perform fence."begin"(old_g); update sandbox.flags set value = 'v9' where key = 'conf-h'; out := out || '{"history_bound":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('history_bound', split_part(sqlerrm, ' ', 1)); end if; end;

    raise exception 'CONF_RESULT:%', out::text;
  exception when others then
    if sqlerrm like 'CONF_RESULT:%' then return substring(sqlerrm from 13)::jsonb; end if;
    return jsonb_build_object('harness_error', sqlerrm, 'partial', out);
  end;
end $function$
;

-- ===== schema public =====
create schema if not exists public;

-- ===== schema sandbox =====
create schema if not exists sandbox;
create table sandbox.flags (
  key text not null,
  value text not null
);
alter table only sandbox.flags add constraint flags_pkey PRIMARY KEY (key);
alter table sandbox.flags enable row level security;
create policy flags_gateway on sandbox.flags as permissive for all to gatewayd_ledger using (true) with check (true);
create policy flags_observer on sandbox.flags as permissive for select to ledger_fdw using (true);
CREATE TRIGGER cfp_guard BEFORE INSERT OR DELETE OR UPDATE ON sandbox.flags FOR EACH ROW EXECUTE FUNCTION fence.guard();
alter table sandbox.flags enable always trigger cfp_guard;
grant SELECT on sandbox.flags to gatewayd_ledger;
grant UPDATE on sandbox.flags to gatewayd_ledger;
grant SELECT on sandbox.flags to ledger_fdw;
