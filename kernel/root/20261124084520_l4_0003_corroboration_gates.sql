-- migration 20261124084520 l4_0003_corroboration_gates (root: rtkslhpxdcjoeqhucebp)
create or replace function gates.corroboration_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare n int;
begin
  check_name := 'reread.door_guarded'; passed := exists (select 1 from pg_trigger where tgname = 'reread_admit' and tgenabled <> 'D');
  detail := case when passed then 'signature, digest, key-role and route checks enforced' else 'guard missing or disabled' end; return next;
  select count(*) into n from p0.keys k where k.role = 'REREAD' and k.status = 'active'
     and not exists (select 1 from p0.keys o where o.key_id <> k.key_id and o.pubkey = k.pubkey);
  check_name := 'reread.distinct_route_identity'; passed := n >= 1; detail := n || ' active REREAD keys not shared with any other role'; return next;
  select count(*) into n from uap.corroborations c where c.status = 'CORROBORATED' and coalesce(c.route, '') in ('', 'public.domain');
  check_name := 'reread.no_self_corroboration'; passed := n = 0; detail := n || ' corroborations from the original route or no route'; return next;
  select count(*) into n from uac.scopes s where s.kind = 'domain' and s.status = 'DECLARED'
     and not exists (select 1 from uac.reread_captures r where r.scope_stream = s.stream_id and r.observed_at > now() - interval '2 days');
  check_name := 'reread.fresh_for_every_domain'; passed := n = 0; detail := n || ' declared domains without a re-read in the last 2 days'; return next;
end $function$;
revoke all on function gates.corroboration_checks() from public, anon, authenticated;
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  def := replace(def, $a$'loops_staleness', 'orbit', 'external']$a$, $a$'loops_staleness', 'orbit', 'corroboration', 'external']$a$);
  def := replace(def, $a$                                    when 'orbit' then 'select * from gates.orbit_checks()'$a$,
                      $a$                                    when 'orbit' then 'select * from gates.orbit_checks()'
                                    when 'corroboration' then 'select * from gates.corroboration_checks()'$a$);
  if position('corroboration_checks' in def) = 0 then raise exception 'SUITE_LAYOUT_CHANGED'; end if;
  execute def;
end $$;
