-- migration 20261124034203 i1_0004_sweep_retry (root: rtkslhpxdcjoeqhucebp)
-- A sleeping verifier restarts its database connection on wake (about a second); retry the signed sweep twice before giving up.
alter function uap.trigger_verifier_sweep() rename to trigger_verifier_sweep_once;
create or replace function uap.trigger_verifier_sweep() returns jsonb language plpgsql security definer set search_path to '' as $function$
declare res jsonb; k int;
begin
  for k in 1..3 loop
    res := uap.trigger_verifier_sweep_once();
    exit when (res->>'status') = '200' and not (res ? 'error');
    perform pg_sleep(5 * k);
  end loop;
  return res || jsonb_build_object('attempts', k);
end $function$;
revoke all on function uap.trigger_verifier_sweep(), uap.trigger_verifier_sweep_once() from public, anon, authenticated;
