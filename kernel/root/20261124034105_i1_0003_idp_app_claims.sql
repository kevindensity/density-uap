-- migration 20261124034105 i1_0003_idp_app_claims (root: rtkslhpxdcjoeqhucebp)
create or replace function uap.discover_idp_claims() returns jsonb language plpgsql security definer set search_path to '' as $function$
declare n int;
begin
  insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin)
  select format('disc:idp %s authorized app "%s"', s.locator, app), 'SPEC', s.stream_id, array[s.stream_id],
         format('people in %s authorized the app "%s" in the last 180 days (Google audit log)', split_part(s.locator, ':', 2), app),
         jsonb_build_object('op', 'contains', 'left', jsonb_build_object('scope', s.stream_id, 'path', 'apps[].app'), 'needle', app,
                            'product', app, 'category', 'authorized app', 'epistemic', 'observed'), 'discovered'
    from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l
    cross join lateral (select distinct a->>'app' as app from jsonb_array_elements(l.body->'apps') a where coalesce(a->>'app', '') <> '') x
   where s.kind = 'idp' and s.status = 'DECLARED'
  on conflict (consequence_key) do nothing;
  get diagnostics n = row_count;
  return jsonb_build_object('idp_claims', n);
end $function$;
do $$ begin
  execute 'grant create on schema uap to uapd'; execute 'alter function uap.discover_idp_claims() owner to uapd'; execute 'revoke create on schema uap from uapd';
end $$;
revoke all on function uap.discover_idp_claims() from public, anon, authenticated;
grant execute on function uap.discover_idp_claims() to p0d, postgres;
-- the daily cycle discovers identity-provider claims too
do $$
declare def text; old text := $a$array['discover_domain', 'discover_capture',$a$;
begin
  def := pg_get_functiondef('uap.daily_cycle()'::regprocedure);
  if position(old in def) = 0 then raise exception 'CYCLE_LAYOUT_CHANGED'; end if;
  def := replace(def, old, $a$array['discover_domain', 'discover_idp', 'discover_capture',$a$);
  def := replace(def, $a$        when 'discover_capture'  then uap.discover_capture_claims()$a$, $a$        when 'discover_idp'      then uap.discover_idp_claims()
        when 'discover_capture'  then uap.discover_capture_claims()$a$);
  execute def;
end $$;
-- and the directory is captured daily with the other sources
select cron.schedule('uac-capture-idp-daily', '35 6 * * *', $$select uac.acquire_google_workspace(stream_id) from uac.scopes where kind = 'idp' and status = 'DECLARED'$$);
