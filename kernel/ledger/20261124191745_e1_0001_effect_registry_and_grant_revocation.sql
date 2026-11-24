-- migration 20261124191745 e1_0001_effect_registry_and_grant_revocation (ledger: mzglmdydfcoljrwleooq)
-- ===== effect registry: a grant is honoured only if registered as the current grant of an effect =====
create table ledger.effects (effect_key text primary key, audience text not null, state text not null check (state in ('AUTHORIZED','RELEASED','NOT_APPLIED')),
  current_grant uuid not null, updated_at timestamptz not null default now());
create table ledger.effect_grants (grant_id uuid primary key, effect_key text not null references ledger.effects(effect_key), retry_allowed boolean not null,
  not_after timestamptz not null, registered_at timestamptz not null default clock_timestamp());
create table ledger.revoked_grants (grant_id uuid primary key, reason text not null, revoked_at timestamptz not null default clock_timestamp());
create trigger revoked_grants_append_only before update or delete on ledger.revoked_grants for each row execute function ledger.heartbeats_append_only();
create trigger effect_grants_append_only before update or delete on ledger.effect_grants for each row execute function ledger.heartbeats_append_only();
alter table ledger.effects enable row level security; alter table ledger.effect_grants enable row level security; alter table ledger.revoked_grants enable row level security;
revoke all on ledger.effects, ledger.effect_grants, ledger.revoked_grants from public, anon, authenticated;

-- registration: the reference kernel's grant rule (K38)
create or replace function ledger.register_grant(p_effect text, p_grant jsonb, p_retry boolean) returns text language plpgsql security definer set search_path = ledger, pg_catalog as $$
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
end $$;

-- per-grant revocation: always allowed, append-only
create or replace function ledger.revoke_grant(p_grant uuid, p_reason text) returns text language sql security definer set search_path = ledger, pg_catalog as $$
  insert into ledger.revoked_grants (grant_id, reason) values (p_grant, p_reason) on conflict do nothing returning 'REVOKED' $$;

-- at consumption, for every fence, local or remote: replay first, then revocation, registration and currency
create or replace function ledger.consume_guard() returns trigger language plpgsql security definer set search_path = ledger, pg_catalog as $$
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
end $$;
create trigger consume_guard before insert on ledger.consumed for each row execute function ledger.consume_guard();

grant execute on function ledger.register_grant(text, jsonb, boolean), ledger.revoke_grant(uuid, text) to gatewayd_ledger;
grant execute on function ledger.revoke_grant(uuid, text) to ledger_fdw;
grant select on ledger.effects, ledger.revoked_grants to ledger_fdw, gatewayd_ledger;
create policy effects_read on ledger.effects for select to ledger_fdw, gatewayd_ledger using (true);
create policy revoked_read on ledger.revoked_grants for select to ledger_fdw, gatewayd_ledger using (true);
