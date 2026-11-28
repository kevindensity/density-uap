-- migration onboard_0002_merge_access_across_oauth_clients (root: rtkslhpxdcjoeqhucebp)
-- An app can be authorized under several OAuth clients; the candidate took an arbitrary one ((array_agg(access))[1],
-- unordered) and could report sign-in only for an app that holds data scopes through another client (found by the
-- uapd differential, run 2ab5cadb: Slack). Access now summarizes every client, deterministically.
do $m$
declare def text; nd text;
begin
  def := pg_get_functiondef('uap.corroborate_seed_ports()'::regprocedure);
  nd := replace(def, '(array_agg(access) filter (where access is not null))[1]',
    'case when count(access) = 0 then null else jsonb_build_object(' ||
    '''users'', max((access->>''users'')::int), ''workspace_users'', max((access->>''workspace_users'')::int), ' ||
    '''scope_class'', case when bool_or(access->>''scope_class'' = ''data'') then ''data'' else ''sign-in only'' end, ' ||
    '''scopes'', coalesce((select jsonb_agg(distinct sc order by sc) from jsonb_array_elements(jsonb_agg(access->''scopes'') filter (where access is not null)) aa, ' ||
    'jsonb_array_elements_text(case when jsonb_typeof(aa) = ''array'' then aa else ''[]'' end) sc), ''[]''), ' ||
    '''clients'', count(access)) end');
  if nd = def then raise exception 'anchor not found; nothing changed'; end if;
  nd := replace(nd, 'jsonb_agg(distinct sc order by sc)', 'jsonb_agg(distinct sc collate "C" order by sc collate "C")');
  execute nd;
end $m$;
