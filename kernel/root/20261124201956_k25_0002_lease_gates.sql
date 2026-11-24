-- migration 20261124201956 k25_0002_lease_gates (root: rtkslhpxdcjoeqhucebp)
create or replace function gates.lease_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare offenders text; out jsonb := '{}'; l uuid; cr p0.credentials%rowtype; st record; k text;
begin
  -- static: nothing outside the broker reads or writes the Vault
  select string_agg(n.nspname || '.' || p.proname, ', ') into offenders from pg_proc p join pg_namespace n on n.oid = p.pronamespace
   where p.prokind = 'f' and n.nspname in ('uac', 'uap', 'p0', 'port', 'public', 'gates', 'verify', 'sem', 'uap_test')
     and pg_get_functiondef(p.oid) ~* 'vault\.(decrypted_secrets|secrets|create_secret|update_secret)'
     and p.oid <> 'gates.lease_checks()'::regprocedure;
  check_name := 'k25.no_vault_access_outside_broker'; passed := offenders is null; detail := coalesce('reads the Vault: ' || offenders, 'only the broker touches the Vault'); return next;
  select string_agg(f, ', ') into offenders from unnest(array['uac.acquire_github_tree(uuid)', 'uac.acquire_supabase_catalog(uuid)', 'uap.recheck(text)']) f
   where position('broker.issue_lease' in pg_get_functiondef(f::regprocedure)) = 0;
  check_name := 'k25.collectors_hold_leases_not_credentials'; passed := offenders is null; detail := coalesce('no lease in: ' || offenders, 'GitHub, catalog and recheck collectors lease their credentials'); return next;
  -- behaviour, all rolled back
  begin
    begin perform broker.issue_lease('not_a_credential', 'github.git.tree', null, 'gate'); out := out || '{"unregistered":"ISSUED"}';
    exception when others then out := out || jsonb_build_object('unregistered', split_part(sqlerrm, ':', 1)); end;
    begin perform broker.issue_lease('uac_github_token', 'supabase.sql.catalog', null, 'gate'); out := out || '{"wrong_route":"ISSUED"}';
    exception when others then out := out || jsonb_build_object('wrong_route', split_part(sqlerrm, ':', 1)); end;
    begin perform broker.issue_lease('uac_github_token', 'github.git.tree', null, 'gate', interval '1 day'); out := out || '{"long_lease":"ISSUED"}';
    exception when others then out := out || jsonb_build_object('long_lease', split_part(sqlerrm, ':', 1)); end;
    l := broker.issue_lease('uac_github_token', 'github.git.tree', null, 'gate', interval '5 minutes', 1);
    perform broker.redeem(l);
    begin perform broker.redeem(l); out := out || '{"used_up":"REDEEMED"}';
    exception when others then out := out || jsonb_build_object('used_up', split_part(sqlerrm, ':', 1)); end;
    l := broker.issue_lease('uac_github_token', 'github.git.tree', null, 'gate', interval '5 minutes', 3);
    perform broker.revoke_lease(l);
    begin perform broker.redeem(l); out := out || '{"revoked":"REDEEMED"}';
    exception when others then out := out || jsonb_build_object('revoked', split_part(sqlerrm, ':', 1)); end;
    l := broker.issue_lease('uac_github_token', 'github.git.tree', null, 'gate', interval '1 millisecond', 3);
    perform pg_sleep(0.01);
    begin perform broker.redeem(l); out := out || '{"expired_lease":"REDEEMED"}';
    exception when others then out := out || jsonb_build_object('expired_lease', split_part(sqlerrm, ':', 1)); end;
    -- the credential expires: new leases are refused, and an outstanding lease can no longer be redeemed
    l := broker.issue_lease('uac_github_token', 'github.git.tree', null, 'gate', interval '5 minutes', 3);
    select * into cr from p0.credentials where name = 'uac_github_token';
    select revision, head_digest into st from p0.streams where stream_id = cr.stream_id;
    perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'credential:' || cr.status || '->EXPIRED', 'stream_id', cr.stream_id,
      'subject_type', 'credential', 'subject_id', cr.name, 'payload', jsonb_build_object('name', cr.name), 'authority_epoch', p0.current_epoch(),
      'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
    begin perform broker.issue_lease('uac_github_token', 'github.git.tree', null, 'gate'); out := out || '{"credential_expired_issue":"ISSUED"}';
    exception when others then out := out || jsonb_build_object('credential_expired_issue', split_part(sqlerrm, ':', 1)); end;
    begin perform broker.redeem(l); out := out || '{"credential_expired_redeem":"REDEEMED"}';
    exception when others then out := out || jsonb_build_object('credential_expired_redeem', split_part(sqlerrm, ':', 1)); end;
    raise exception 'K25_RESULT:%', out::text;
  exception when others then
    if sqlerrm not like 'K25_RESULT:%' then raise exception 'HARNESS: lease drill could not run: %', sqlerrm; end if;
    out := substring(sqlerrm from 12)::jsonb;
  end;
  for k in select * from jsonb_object_keys(out) loop
    check_name := 'k25.refuses_' || k; passed := (out->>k) in ('LEASE_REFUSED', 'LEASE_INVALID'); detail := out->>k; return next;
  end loop;
end $function$;
revoke all on function gates.lease_checks() from public, anon, authenticated;
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  def := replace(def, $a$'fence_conformance', 'external']$a$, $a$'fence_conformance', 'leases', 'external']$a$);
  def := replace(def, $a$                                    when 'fence_conformance' then 'select * from gates.fence_conformance_checks()'$a$,
                      $a$                                    when 'fence_conformance' then 'select * from gates.fence_conformance_checks()'
                                    when 'leases' then 'select * from gates.lease_checks()'$a$);
  if position('lease_checks' in def) = 0 then raise exception 'SUITE_LAYOUT_CHANGED'; end if;
  execute def;
end $$;
