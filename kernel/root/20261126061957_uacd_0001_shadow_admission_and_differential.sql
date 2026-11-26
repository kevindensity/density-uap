-- migration 20261126061957 uacd_0001_shadow_admission_and_differential (root: rtkslhpxdcjoeqhucebp)
create table uac.differential_runs (
  run_id uuid primary key default gen_random_uuid(), scope_stream uuid not null, route text not null,
  rust_at timestamptz not null, rust_collector text not null, rust_body jsonb not null,
  oracle_at timestamptz, oracle_digest text, oracle_decision text,
  fields jsonb, agreed int, diverged int, unavailable int, verdict text check (verdict in ('AGREE','DIVERGE','ORACLE_FAILED')),
  recorded_at timestamptz not null default now());
create table uac.differential_reviews (
  run_id uuid not null references uac.differential_runs, field text not null, classification text not null
    check (classification in ('EXPLAINED_ORACLE_DEFECT','EXPLAINED_RUST_DEFECT','EXPLAINED_WORLD_CHANGED','EXPLAINED_UPSTREAM_FLAKY','UNEXPLAINED')),
  reason text not null, reviewed_by text not null default session_user, reviewed_at timestamptz not null default now(), primary key (run_id, field));
create trigger differential_runs_append_only before update or delete on uac.differential_runs for each row execute function p0.event_order_append_only();
create trigger differential_reviews_append_only before update or delete on uac.differential_reviews for each row execute function p0.event_order_append_only();
alter table uac.differential_runs enable row level security; alter table uac.differential_reviews enable row level security;
revoke all on uac.differential_runs, uac.differential_reviews from anon, authenticated;

-- field-by-field comparison: EQUAL, DIFFERS, or UNAVAILABLE (a side did not observe the field; its source says why)
create or replace function uac.compare_domain_bodies(o jsonb, r jsonb) returns jsonb language sql immutable set search_path to '' as $f$
  select jsonb_object_agg(k, case
      when k = 'sources' then (select jsonb_object_agg(s, case when split_part(o->'sources'->>s, ':', 1) = split_part(r->'sources'->>s, ':', 1) then 'EQUAL' else 'DIFFERS' end)
                               from (select jsonb_object_keys(o->'sources') s union select jsonb_object_keys(r->'sources')) x)
      when not (o ? k) or not (r ? k) then to_jsonb('UNAVAILABLE'::text)
      when k = 'ip_owners' then to_jsonb(case when (select bool_and(coalesce(oo->>'lookup', 'ok') <> 'failed' and rr->>'lookup' <> 'failed' and oo - 'lookup' = rr - 'lookup' or coalesce(oo->>'lookup','') = 'failed' or rr->>'lookup' = 'failed')
                                                     from jsonb_array_elements(o->'ip_owners') with ordinality a(oo, i) join jsonb_array_elements(r->'ip_owners') with ordinality b(rr, j) on i = j)
                                                    and jsonb_array_length(o->'ip_owners') = jsonb_array_length(r->'ip_owners') then 'EQUAL' else 'DIFFERS' end)
      when o->k = r->k then to_jsonb('EQUAL'::text) else to_jsonb('DIFFERS'::text) end)
  from (select jsonb_object_keys(o) k union select jsonb_object_keys(r)) ks $f$;

create or replace function uac.submit_shadow_capture(p_admission jsonb) returns jsonb language plpgsql security definer set search_path to '' as $f$
declare errs text[]; sc uac.scopes%rowtype; o jsonb; ob jsonb; cmp jsonb; run uuid; ag int; dv int; un int; rust_at timestamptz := clock_timestamp();
begin
  errs := contracts.check('density:uac.capture_admission/1', p_admission);
  if cardinality(errs) > 0 then return jsonb_build_object('decision', 'REJECT', 'reason', 'ADMISSION_CONTRACT', 'errors', to_jsonb(errs)); end if;
  if p_admission->>'route' <> 'public.domain' then return jsonb_build_object('decision', 'REJECT', 'reason', 'ROUTE_NOT_IN_SHADOW'); end if;
  errs := contracts.check('density:capture.public_domain/2', p_admission->'body');
  if cardinality(errs) > 0 then return jsonb_build_object('decision', 'REJECT', 'reason', 'BODY_CONTRACT', 'errors', to_jsonb(errs)); end if;
  select * into sc from uac.scopes where stream_id = (p_admission->>'scope')::uuid;
  if sc.status is distinct from 'DECLARED' or not ('public.domain' = any (sc.routes)) or lower(sc.locator) <> p_admission->'body'->>'domain' then
    return jsonb_build_object('decision', 'REJECT', 'reason', 'SCOPE_NOT_DECLARED_FOR_ROUTE_AND_SUBJECT'); end if;
  -- the oracle observes the same domain immediately after (seconds apart)
  o := uac.acquire_domain(sc.stream_id);
  select body into ob from uac.capture_bodies where content_digest = o->>'content_digest';
  if ob is null then
    insert into uac.differential_runs (scope_stream, route, rust_at, rust_collector, rust_body, oracle_at, oracle_decision, verdict)
    values (sc.stream_id, 'public.domain', rust_at, session_user, p_admission->'body', clock_timestamp(), o->>'decision', 'ORACLE_FAILED') returning run_id into run;
    return jsonb_build_object('decision', 'RECORDED', 'run', run, 'verdict', 'ORACLE_FAILED');
  end if;
  cmp := uac.compare_domain_bodies(ob, p_admission->'body');
  select count(*) filter (where v = 'EQUAL'), count(*) filter (where v = 'DIFFERS'), count(*) filter (where v = 'UNAVAILABLE') into ag, dv, un
    from (select value #>> '{}' v from jsonb_each(cmp - 'sources') union all select value #>> '{}' from jsonb_each(cmp->'sources')) x;
  insert into uac.differential_runs (scope_stream, route, rust_at, rust_collector, rust_body, oracle_at, oracle_digest, oracle_decision, fields, agreed, diverged, unavailable, verdict)
  values (sc.stream_id, 'public.domain', rust_at, session_user, p_admission->'body', clock_timestamp(), o->>'content_digest', o->>'decision', cmp, ag, dv, un,
          case when dv = 0 then 'AGREE' else 'DIVERGE' end) returning run_id into run;
  return jsonb_build_object('decision', 'RECORDED', 'run', run, 'verdict', case when dv = 0 then 'AGREE' else 'DIVERGE' end, 'agreed', ag, 'diverged', dv, 'unavailable', un, 'fields', cmp);
end $f$;
revoke all on function uac.submit_shadow_capture(jsonb) from public, anon, authenticated;

do $$ begin if not exists (select 1 from pg_roles where rolname = 'uacd_login') then create role uacd_login nologin noinherit; end if; end $$;
grant usage on schema uac to uacd_login;
grant execute on function uac.submit_shadow_capture(jsonb) to uacd_login;
