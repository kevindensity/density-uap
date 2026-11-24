-- migration 20261123225742 h1_0001_uap_least_privilege (root: rtkslhpxdcjoeqhucebp)
grant uapd to postgres;

create or replace function p0.current_epoch() returns text language sql stable security definer set search_path to 'p0', 'pg_catalog' as
$$ select authority_epoch::text from p0_ledger.state where id = 1 $$;
revoke all on function p0.current_epoch() from public, anon, authenticated;
grant execute on function p0.current_epoch() to uacd, uapd, verifierd, p0d, gatewayd, portd;

grant execute on function p0.admit_event(jsonb) to uapd;
grant insert on uap.capture_claims to uapd;
create policy uap_capture_claims_uapd_insert on uap.capture_claims for insert to uapd with check (true);
grant temporary on database postgres to uapd;

do $$
declare f text; def text;
  fns text[] := array['uap.latest_capture(uuid)','uap.eval_capture_claim(text)','uap.eval_spec(jsonb)','uap.capture_values(jsonb,text)','uap.capture_paths(jsonb)',
    'uap.discover_capture_claims()','uap.compile_capture_ports()','uap.claim_submission(text)','uap.promote_capture_ports()','uap.capture_claim_drift()',
    'uap.write_capture_standings()','uap.write_capture_bridges()'];
begin
  foreach f in array fns || array['uap.recheck(text)'] loop
    def := pg_get_functiondef(f::regprocedure);
    if position('(select authority_epoch::text from p0_ledger.state where id = 1)' in def) > 0 then
      execute replace(def, '(select authority_epoch::text from p0_ledger.state where id = 1)', 'p0.current_epoch()');
    end if;
  end loop;
  execute 'grant create on schema uap to uapd';
  foreach f in array fns loop execute format('alter function %s owner to uapd', f); end loop;
  execute 'revoke create on schema uap from uapd';
end $$;

grant execute on function uap.compile_capture_ports(), uap.claim_submission(text), uap.promote_capture_ports(), uap.capture_claim_drift(),
  uap.discover_capture_claims(), uap.write_capture_standings(), uap.write_capture_bridges() to p0d, postgres;
grant execute on function uap.claim_submission(text) to verifierd;
grant execute on function uap.eval_spec(jsonb), uap.eval_capture_claim(text), uap.latest_capture(uuid), uap.capture_values(jsonb,text), uap.capture_paths(jsonb) to p0d, verifierd, postgres;
