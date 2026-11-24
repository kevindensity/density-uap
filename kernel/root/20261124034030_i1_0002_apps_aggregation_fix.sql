-- migration 20261124034030 i1_0002_apps_aggregation_fix (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text;
  old text := $a$    'apps', coalesce((select jsonb_agg(jsonb_build_object('app', app, 'client', client, 'users', n, 'scopes', sc2) order by app) from (
        select x->>'app' as app, x->>'client' as client, count(distinct x->>'user') as n,
               (select jsonb_agg(distinct s order by s) from jsonb_array_elements(ev) y, jsonb_array_elements_text(coalesce(y->'scopes', '[]')) s where y->>'client' = x->>'client') as sc2
          from jsonb_array_elements(ev) x where x->>'app' is not null group by 1, 2) a), '[]'));$a$;
  new text := $a$    'apps', coalesce((select jsonb_agg(jsonb_build_object('app', a.app, 'client', a.client, 'users', a.n,
          'scopes', (select coalesce(jsonb_agg(distinct s order by s), '[]') from jsonb_array_elements(ev) y, jsonb_array_elements_text(coalesce(y->'scopes', '[]')) s
                      where y->>'client' = a.client)) order by a.app) from (
        select x->>'app' as app, x->>'client' as client, count(distinct x->>'user') as n
          from jsonb_array_elements(ev) x where x->>'app' is not null group by 1, 2) a), '[]'));$a$;
begin
  def := pg_get_functiondef('uac.acquire_google_workspace(uuid)'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, old, new);
end $$;
