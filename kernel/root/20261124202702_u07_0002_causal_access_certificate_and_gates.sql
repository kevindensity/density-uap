-- migration 20261124202702 u07_0002_causal_access_certificate_and_gates (root: rtkslhpxdcjoeqhucebp)
-- U07 / K58: one causal-access truth per effect target, computed from live kernel and ledger state alone
create or replace function p0.causal_access_certificate(p_at timestamptz default now()) returns jsonb language plpgsql stable security definer set search_path to '' as $f$
declare t record; out jsonb := '[]'; guard text; did int; na int; pol record; reduced text; rung text; why text; order_ text[] := array['OBSERVED','CANDIDATE_CONTROL','GROUNDED_AFFORDANCE','EFFECT_QUALIFIED','AUTHORIZED','ACTIONABLE'];
begin
  for t in select * from p0.effect_targets loop
    guard := null; rung := 'OBSERVED'; why := null;
    begin
      if t.audience = 'pg://density-ledger/sandbox' then
        select x.m into guard from extensions.dblink('uap_ledger', 'select tgenabled::text from pg_trigger where tgname = ''cfp_guard'' and tgrelid = ''sandbox.flags''::regclass') as x(m text);
      else
        select x.m into guard from extensions.dblink('customer_sim', 'select tgenabled::text from pg_trigger where tgname = ''cfp_guard'' and tgrelid = ''app.feature_flags''::regclass') as x(m text);
      end if;
    exception when others then guard := null; end;
    select count(*) filter (where outcome = 'DID'), count(*) filter (where outcome = 'NOT_APPLIED') into did, na from p0.effect_outcomes where target = t.audience;
    select sp.* into pol from p0.standing_policies sp join p0.streams s on s.stream_id = sp.stream_id
     where sp.capability like 'effect:' || t.audience || ':%' and sp.status = 'ACTIVE' order by sp.expires_at desc limit 1;
    reduced := case when pol.stream_id is null then null else (select r.event_kind from p0_ledger.authority_reductions r where r.stream_id = pol.stream_id limit 1) end;
    if guard = 'A' then rung := 'CANDIDATE_CONTROL'; else why := 'no always-firing fence on the target'; end if;
    if rung = 'CANDIDATE_CONTROL' then if did > 0 then rung := 'GROUNDED_AFFORDANCE'; else why := 'no effect observed (DID) yet'; end if; end if;
    if rung = 'GROUNDED_AFFORDANCE' then if na > 0 then rung := 'EFFECT_QUALIFIED'; else why := 'observer has not yet resolved a NOT_APPLIED'; end if; end if;
    if rung = 'EFFECT_QUALIFIED' then
      if pol.stream_id is null then why := 'no active owner standing policy';
      elsif pol.expires_at <= p_at then why := 'owner standing policy expired at ' || pol.expires_at;
      elsif reduced is not null then why := 'owner standing policy reduced: ' || reduced;
      else rung := 'AUTHORIZED'; end if;
    end if;
    if rung = 'AUTHORIZED' then
      if pol.used < pol.max_uses or (select count(*) from p0_ledger.sent s where s.request->>'policy' = pol.stream_id::text) < pol.max_uses then rung := 'ACTIONABLE';
      else why := 'policy uses exhausted'; end if;
    end if;
    out := out || jsonb_build_object('target', t.audience, 'rung', rung, 'stopped_because', why, 'fence', coalesce(guard, 'unreadable'), 'observed_did', did, 'observed_not_applied', na,
      'policy', case when pol.stream_id is null then null else jsonb_build_object('capability', pol.capability, 'expires_at', pol.expires_at) end, 'as_of', p_at);
  end loop;
  return out;
end $f$;
revoke all on function p0.causal_access_certificate(timestamptz) from public, anon, authenticated;
grant execute on function p0.causal_access_certificate(timestamptz) to portd;

-- the Port's owner-level effects view carries the certificate
do $$
declare def text; old text := $a$  return jsonb_build_object('verdict', 'ALLOW', 'effects',$a$;
begin
  def := pg_get_functiondef('public.port_effects(text)'::regprocedure);
  if position(old in def) = 0 then raise exception 'PORT_LAYOUT_CHANGED'; end if;
  execute replace(def, old, $a$  return jsonb_build_object('verdict', 'ALLOW', 'control_surfaces', p0.causal_access_certificate(), 'effects',$a$);
end $$;

create or replace function gates.access_ladder_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare n int; x text; out jsonb; cert jsonb; later jsonb; pid uuid;
begin
  -- every read-ladder port sits exactly at the rung its evidence earns
  select count(*), string_agg(p.id::text, ', ') into n, x from uap.ports p
   where p.ladder_level in ('UNDERSTOOD','QUALIFIED','BRIDGE_AUTHORIZED')
     and p.ladder_level <> greatest_rung(uap.read_qualification(p.id)->>'earned');
  check_name := 'u07.ports_at_earned_read_rung'; passed := n = 0; detail := case when n = 0 then 'every port is at the rung its evidence earns' else n || ' ports off their earned rung' end; return next;
  -- the guard refuses a rung the evidence has not earned
  select p.id into pid from uap.ports p where p.ladder_level = 'UNDERSTOOD' and not (uap.read_qualification(p.id)->>'qualified')::boolean limit 1;
  begin
    perform set_config('p0.admitting', 'on', true);
    update uap.ports set ladder_level = 'QUALIFIED' where id = pid;
    out := '{"unearned":"ALLOWED"}'; raise exception 'U07_RESULT:%', out::text;
  exception when others then
    if sqlerrm like 'U07_RESULT:%' then out := substring(sqlerrm from 12)::jsonb; else out := jsonb_build_object('unearned', split_part(sqlerrm, ':', 1)); end if;
  end;
  check_name := 'u07.guard_refuses_unearned_qualification'; passed := pid is null or out->>'unearned' = 'LADDER_EVIDENCE'; detail := coalesce(out->>'unearned', 'no unqualified port to probe'); return next;
  -- the causal-access certificate is one truth, and it falls when authority lapses
  cert := p0.causal_access_certificate();
  later := p0.causal_access_certificate(now() + interval '30 days');
  select count(*) into n from jsonb_array_elements(cert) c where c->>'rung' = 'ACTIONABLE' and (c->>'fence') <> 'A';
  check_name := 'u07.actionable_only_behind_an_always_firing_fence'; passed := n = 0; detail := n || ' actionable targets without the fence'; return next;
  select count(*) into n from jsonb_array_elements(later) c where c->>'rung' in ('AUTHORIZED','ACTIONABLE') and (c->'policy'->>'expires_at')::timestamptz <= now() + interval '30 days';
  check_name := 'u07.expired_policy_is_not_actionable'; passed := n = 0;
  detail := 'in 30 days: ' || coalesce((select string_agg((c->>'target') || ' ' || (c->>'rung') || coalesce(' (' || (c->>'stopped_because') || ')', ''), '; ') from jsonb_array_elements(later) c), 'no targets'); return next;
end $function$;
create or replace function gates.greatest_rung(p text) returns text language sql immutable as $$ select case when p = 'CONNECTED' then 'UNDERSTOOD' else p end $$;
revoke all on function gates.access_ladder_checks() from public, anon, authenticated;
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.access_ladder_checks()'::regprocedure);
  execute replace(def, 'greatest_rung(', 'gates.greatest_rung(');
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  def := replace(def, $a$'identities', 'external']$a$, $a$'identities', 'access_ladders', 'external']$a$);
  def := replace(def, $a$                                    when 'identities' then 'select * from gates.identity_checks()'$a$,
                      $a$                                    when 'identities' then 'select * from gates.identity_checks()'
                                    when 'access_ladders' then 'select * from gates.access_ladder_checks()'$a$);
  if position('access_ladder_checks' in def) = 0 then raise exception 'SUITE_LAYOUT_CHANGED'; end if;
  execute def;
end $$;
select p0.causal_access_certificate() as certificate;
