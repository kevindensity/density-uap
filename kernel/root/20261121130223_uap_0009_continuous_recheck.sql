-- migration 20261121130223 uap_0009_continuous_recheck (root: rtkslhpxdcjoeqhucebp)
create table uap.rule_checks (
  run_id          uuid not null,
  checked_at      timestamptz not null default now(),
  check_key       text not null,
  counterexamples bigint not null,
  support         bigint not null,
  primary key (run_id, check_key)
);
create table uap.rule_events (
  id          bigserial primary key,
  checked_at  timestamptz not null default now(),
  run_id      uuid not null,
  check_key   text not null,
  kind        text not null check (kind in ('ALERT','DRIFT_NOTICE','VARIATION_CHANGED','CHECK_FAILED')),
  detail      jsonb not null
);

create function uap.recheck_diw() returns jsonb language plpgsql security definer set search_path = '' as $$
declare run uuid := gen_random_uuid(); r record; prev bigint; env_alert boolean; n_alert int := 0; n_drift int := 0; n_var int := 0; n_ok int := 0;
        conn text;
begin
  select decrypted_secret into conn from vault.decrypted_secrets where name = 'diw_verifier_conn';
  begin
    insert into uap.rule_checks(run_id, check_key, counterexamples, support)
      select run, t.check_key, t.counterexamples, t.support
      from extensions.dblink(conn, 'select check_key, counterexamples, support from uap_probe.check_rules()')
           as t(check_key text, counterexamples bigint, support bigint);
  exception when others then
    insert into uap.rule_events(run_id, check_key, kind, detail) values (run, '*', 'CHECK_FAILED', jsonb_build_object('error', sqlerrm));
    return jsonb_build_object('run_id', run, 'status', 'CHECK_FAILED');
  end;

  for r in select * from uap.rule_checks where run_id = run loop
    if r.check_key like 'watch:%' then
      select c.counterexamples into prev from uap.rule_checks c
       where c.check_key = r.check_key and c.run_id <> run order by c.checked_at desc limit 1;
      if prev is not null and prev <> r.counterexamples then
        insert into uap.rule_events(run_id, check_key, kind, detail)
          values (run, r.check_key, 'VARIATION_CHANGED', jsonb_build_object('previous', prev, 'now', r.counterexamples, 'support', r.support));
        n_var := n_var + 1;
      end if;
    elsif r.counterexamples > 0 then
      select coalesce(bool_or(uap.use_permitted(p.id, 'DATA_QUALITY_ALERT')), false) into env_alert
        from uap.projection_standings p where p.spec->>'rule' = r.check_key;
      insert into uap.rule_events(run_id, check_key, kind, detail)
        values (run, r.check_key, case when env_alert then 'ALERT' else 'DRIFT_NOTICE' end,
                jsonb_build_object('counterexamples', r.counterexamples, 'support', r.support));
      update sem.settlements set status = 'UNRESOLVED'
       where consequence_key = r.check_key and status = 'SETTLED_TRUE';
      if env_alert then n_alert := n_alert + 1; else n_drift := n_drift + 1; end if;
    else
      n_ok := n_ok + 1;
    end if;
  end loop;
  return jsonb_build_object('run_id', run, 'rules_holding', n_ok, 'alerts', n_alert, 'drift_notices', n_drift, 'variation_changes', n_var);
end $$;
revoke all on function uap.recheck_diw() from public, anon, authenticated;

select cron.schedule('uap-recheck-diw-daily', '0 6 * * *', $$select uap.recheck_diw()$$);
