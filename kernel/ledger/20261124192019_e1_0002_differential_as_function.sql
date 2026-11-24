-- migration 20261124192019 e1_0002_differential_as_function (ledger: mzglmdydfcoljrwleooq)
create schema if not exists ledger_test;
revoke all on schema ledger_test from public, anon, authenticated;
create table ledger_test.oracle_traces (id text primary key, sha256 text not null, oracle_source_sha256 text not null, traces jsonb not null, loaded_at timestamptz not null default now());
alter table ledger_test.oracle_traces enable row level security;
revoke all on ledger_test.oracle_traces from public, anon, authenticated;
insert into ledger_test.oracle_traces (id, sha256, oracle_source_sha256, traces) values ('b0-reference-kernel/traces-40-seed-9E3779B97F4A7C15', '656f4f843a0d22de57ddbe5159830ac9d53e913d4f905655ab2f57ef6bdc1f4b',
  'reference-kernel/src/lib.rs 92920dcad01187e2', '[{"trace":0,"steps":[{"op":"X","expect":"SKIP"},{"op":"G+retry","expect":"OK"},{"op":"E","expect":"OK"},{"op":"G","expect":"TransitionForbidden"},{"op":"G","expect":"TransitionForbidden"},{"op":"RR","expect":"SKIP"},{"op":"R","expect":"GrantRevoked"},{"op":"E","expect":"OK"}]},{"trace":1,"steps":[{"op":"G","expect":"OK"},{"op":"E","expect":"OK"},{"op":"G","expect":"TransitionForbidden"},{"op":"R","expect":"GrantRevoked"},{"op":"RR","expect":"SKIP"},{"op":"RR","expect":"SKIP"}]},{"trace":2,"steps":[{"op":"E","expect":"OK"},{"op":"E","expect":"OK"},{"op":"E","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"E","expect":"OK"},{"op":"E","expect":"OK"}]},{"trace":3,"steps":[{"op":"E","expect":"OK"},{"op":"G","expect":"OK"},{"op":"G+retry","expect":"TransitionForbidden"},{"op":"E","expect":"OK"},{"op":"X","expect":"OK"},{"op":"G","expect":"TransitionForbidden"},{"op":"X","expect":"OK"}]},{"trace":4,"steps":[{"op":"X","expect":"SKIP"},{"op":"G","expect":"OK"},{"op":"E","expect":"OK"},{"op":"G+retry","expect":"TransitionForbidden"},{"op":"RR","expect":"SKIP"},{"op":"E","expect":"OK"}]},{"trace":5,"steps":[{"op":"G","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"X","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"G+retry","expect":"TransitionForbidden"},{"op":"E","expect":"OK"}]},{"trace":6,"steps":[{"op":"R","expect":"TransitionForbidden"},{"op":"E","expect":"OK"},{"op":"R","expect":"TransitionForbidden"},{"op":"E","expect":"OK"},{"op":"E","expect":"OK"},{"op":"R","expect":"TransitionForbidden"},{"op":"RR","expect":"SKIP"},{"op":"RR","expect":"SKIP"}]},{"trace":7,"steps":[{"op":"R","expect":"TransitionForbidden"},{"op":"G+retry","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"X","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"RR","expect":"SKIP"},{"op":"RR","expect":"SKIP"},{"op":"RR","expect":"SKIP"}]},{"trace":8,"steps":[{"op":"G+retry","expect":"OK"},{"op":"X","expect":"OK"},{"op":"R","expect":"GrantRevoked"},{"op":"X","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"RR","expect":"SKIP"},{"op":"E","expect":"OK"},{"op":"X","expect":"OK"}]},{"trace":9,"steps":[{"op":"RR","expect":"SKIP"},{"op":"E","expect":"OK"},{"op":"R","expect":"TransitionForbidden"},{"op":"X","expect":"SKIP"},{"op":"G+retry","expect":"OK"},{"op":"E","expect":"OK"},{"op":"E","expect":"OK"},{"op":"E","expect":"OK"}]},{"trace":10,"steps":[{"op":"RR","expect":"SKIP"},{"op":"G+retry","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"R","expect":"OK"},{"op":"E","expect":"OK"}]},{"trace":11,"steps":[{"op":"E","expect":"OK"},{"op":"G","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"R","expect":"OK"}]},{"trace":12,"steps":[{"op":"R","expect":"TransitionForbidden"},{"op":"RR","expect":"SKIP"},{"op":"X","expect":"SKIP"},{"op":"X","expect":"SKIP"}]},{"trace":13,"steps":[{"op":"G","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"G+retry","expect":"TransitionForbidden"},{"op":"R","expect":"OK"},{"op":"E","expect":"OK"},{"op":"R","expect":"TransitionForbidden"},{"op":"G+retry","expect":"TransitionForbidden"},{"op":"R","expect":"TransitionForbidden"}]},{"trace":14,"steps":[{"op":"G","expect":"OK"},{"op":"E","expect":"OK"},{"op":"G+retry","expect":"TransitionForbidden"},{"op":"E","expect":"OK"},{"op":"E","expect":"OK"}]},{"trace":15,"steps":[{"op":"E","expect":"OK"},{"op":"E","expect":"OK"},{"op":"E","expect":"OK"},{"op":"R","expect":"TransitionForbidden"},{"op":"E","expect":"OK"}]},{"trace":16,"steps":[{"op":"E","expect":"OK"},{"op":"X","expect":"SKIP"},{"op":"G","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"G","expect":"TransitionForbidden"},{"op":"RR","expect":"SKIP"},{"op":"RR","expect":"SKIP"}]},{"trace":17,"steps":[{"op":"RR","expect":"SKIP"},{"op":"E","expect":"OK"},{"op":"E","expect":"OK"},{"op":"X","expect":"SKIP"},{"op":"X","expect":"SKIP"},{"op":"G+retry","expect":"OK"}]},{"trace":18,"steps":[{"op":"E","expect":"OK"},{"op":"E","expect":"OK"},{"op":"X","expect":"SKIP"},{"op":"RR","expect":"SKIP"}]},{"trace":19,"steps":[{"op":"X","expect":"SKIP"},{"op":"G","expect":"OK"},{"op":"E","expect":"OK"},{"op":"G","expect":"TransitionForbidden"},{"op":"E","expect":"OK"},{"op":"R","expect":"GrantRevoked"},{"op":"RR","expect":"SKIP"}]},{"trace":20,"steps":[{"op":"X","expect":"SKIP"},{"op":"G","expect":"OK"},{"op":"X","expect":"OK"},{"op":"X","expect":"OK"}]},{"trace":21,"steps":[{"op":"G","expect":"OK"},{"op":"X","expect":"OK"},{"op":"E","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"G","expect":"TransitionForbidden"}]},{"trace":22,"steps":[{"op":"X","expect":"SKIP"},{"op":"R","expect":"TransitionForbidden"},{"op":"G+retry","expect":"OK"},{"op":"R","expect":"OK"},{"op":"G","expect":"TransitionForbidden"},{"op":"RR","expect":"GrantConsumed"},{"op":"G","expect":"TransitionForbidden"}]},{"trace":23,"steps":[{"op":"X","expect":"SKIP"},{"op":"RR","expect":"SKIP"},{"op":"RR","expect":"SKIP"},{"op":"E","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"R","expect":"TransitionForbidden"},{"op":"X","expect":"SKIP"}]},{"trace":24,"steps":[{"op":"RR","expect":"SKIP"},{"op":"RR","expect":"SKIP"},{"op":"RR","expect":"SKIP"},{"op":"E","expect":"OK"},{"op":"R","expect":"TransitionForbidden"},{"op":"RR","expect":"SKIP"}]},{"trace":25,"steps":[{"op":"X","expect":"SKIP"},{"op":"X","expect":"SKIP"},{"op":"R","expect":"TransitionForbidden"},{"op":"X","expect":"SKIP"},{"op":"R","expect":"TransitionForbidden"},{"op":"X","expect":"SKIP"}]},{"trace":26,"steps":[{"op":"X","expect":"SKIP"},{"op":"G+retry","expect":"OK"},{"op":"R","expect":"OK"},{"op":"R","expect":"TransitionForbidden"},{"op":"G","expect":"TransitionForbidden"}]},{"trace":27,"steps":[{"op":"R","expect":"TransitionForbidden"},{"op":"E","expect":"OK"},{"op":"E","expect":"OK"},{"op":"R","expect":"TransitionForbidden"},{"op":"RR","expect":"SKIP"},{"op":"RR","expect":"SKIP"},{"op":"X","expect":"SKIP"},{"op":"R","expect":"TransitionForbidden"}]},{"trace":28,"steps":[{"op":"R","expect":"TransitionForbidden"},{"op":"G","expect":"OK"},{"op":"G","expect":"TransitionForbidden"},{"op":"R","expect":"OK"},{"op":"X","expect":"OK"},{"op":"E","expect":"OK"},{"op":"R","expect":"TransitionForbidden"}]},{"trace":29,"steps":[{"op":"R","expect":"TransitionForbidden"},{"op":"E","expect":"OK"},{"op":"R","expect":"TransitionForbidden"},{"op":"R","expect":"TransitionForbidden"},{"op":"R","expect":"TransitionForbidden"},{"op":"R","expect":"TransitionForbidden"},{"op":"X","expect":"SKIP"},{"op":"E","expect":"OK"}]},{"trace":30,"steps":[{"op":"RR","expect":"SKIP"},{"op":"G","expect":"OK"},{"op":"X","expect":"OK"},{"op":"X","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"G+retry","expect":"TransitionForbidden"},{"op":"G+retry","expect":"TransitionForbidden"},{"op":"X","expect":"OK"}]},{"trace":31,"steps":[{"op":"RR","expect":"SKIP"},{"op":"G+retry","expect":"OK"},{"op":"E","expect":"OK"},{"op":"G+retry","expect":"TransitionForbidden"},{"op":"R","expect":"GrantRevoked"},{"op":"R","expect":"GrantRevoked"},{"op":"RR","expect":"SKIP"}]},{"trace":32,"steps":[{"op":"R","expect":"TransitionForbidden"},{"op":"R","expect":"TransitionForbidden"},{"op":"R","expect":"TransitionForbidden"},{"op":"G","expect":"OK"}]},{"trace":33,"steps":[{"op":"X","expect":"SKIP"},{"op":"RR","expect":"SKIP"},{"op":"E","expect":"OK"},{"op":"E","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"X","expect":"SKIP"},{"op":"R","expect":"TransitionForbidden"}]},{"trace":34,"steps":[{"op":"RR","expect":"SKIP"},{"op":"X","expect":"SKIP"},{"op":"E","expect":"OK"},{"op":"E","expect":"OK"},{"op":"R","expect":"TransitionForbidden"},{"op":"G+retry","expect":"OK"},{"op":"R","expect":"OK"},{"op":"X","expect":"OK"}]},{"trace":35,"steps":[{"op":"RR","expect":"SKIP"},{"op":"RR","expect":"SKIP"},{"op":"R","expect":"TransitionForbidden"},{"op":"RR","expect":"SKIP"},{"op":"G+retry","expect":"OK"}]},{"trace":36,"steps":[{"op":"X","expect":"SKIP"},{"op":"X","expect":"SKIP"},{"op":"E","expect":"OK"},{"op":"E","expect":"OK"},{"op":"RR","expect":"SKIP"},{"op":"G","expect":"OK"},{"op":"E","expect":"OK"},{"op":"E","expect":"OK"}]},{"trace":37,"steps":[{"op":"RR","expect":"SKIP"},{"op":"R","expect":"TransitionForbidden"},{"op":"X","expect":"SKIP"},{"op":"G","expect":"OK"},{"op":"X","expect":"OK"},{"op":"E","expect":"OK"}]},{"trace":38,"steps":[{"op":"E","expect":"OK"},{"op":"R","expect":"TransitionForbidden"},{"op":"RR","expect":"SKIP"},{"op":"R","expect":"TransitionForbidden"},{"op":"X","expect":"SKIP"},{"op":"G","expect":"OK"},{"op":"G+retry","expect":"TransitionForbidden"},{"op":"E","expect":"OK"}]},{"trace":39,"steps":[{"op":"G+retry","expect":"OK"},{"op":"X","expect":"OK"},{"op":"G+retry","expect":"TransitionForbidden"},{"op":"RR","expect":"SKIP"},{"op":"RR","expect":"SKIP"},{"op":"E","expect":"OK"}]}]'::jsonb);

create or replace function ledger_test.run_differential(p_id text default 'b0-reference-kernel/traces-40-seed-9E3779B97F4A7C15') returns jsonb
language plpgsql security definer set search_path = ledger, fence, sandbox, pg_catalog as $fn$
declare traces jsonb; kp1 record; kp2 record; t jsonb; s jsonb; k text; n int; cur jsonb; last_ok jsonb; prev_val text; vc int := 0; live text; exp text; g jsonb; intended text; msg bytea;
  agree int := 0; both_refuse int := 0; live_permits int := 0; live_refuses int := 0; skipped int := 0; permits jsonb := '[]'; refuses jsonb := '[]'; history text; diffs jsonb := '{}'; res jsonb;
begin
  select ot.traces into traces from ledger_test.oracle_traces ot where ot.id = p_id;
  begin
    select * into kp1 from pgsodium.crypto_sign_seed_new_keypair(pgsodium.crypto_sign_new_seed()); select * into kp2 from pgsodium.crypto_sign_seed_new_keypair(pgsodium.crypto_sign_new_seed());
    insert into ledger.issuers (issuer_id, pubkey, root_gen, status, administrator) values
      ('diff-a', kp1.public, 1, 'active', 'differential test (rolled back)'), ('diff-b', kp2.public, 1, 'active', 'differential test (rolled back)');
    for t in select * from jsonb_array_elements(traces) loop
      n := (t->>'trace')::int; k := 'diff-' || n; cur := null; last_ok := null; history := '';
      alter table sandbox.flags disable trigger cfp_guard;
      insert into sandbox.flags (key, value) values (k, 'v0');
      alter table sandbox.flags enable trigger cfp_guard;
      for s in select * from jsonb_array_elements(t->'steps') loop
        exp := s->>'expect';
        if s->>'op' = 'E' then
          update ledger.state set authority_epoch = authority_epoch + 1 where id = 1; live := 'OK';
        elsif s->>'op' = 'X' then
          if cur is null then live := 'SKIP'; else perform ledger.revoke_grant((cur->>'grant_id')::uuid, 'differential'); live := 'OK'; end if;
        elsif s->>'op' like 'G%' then
          vc := vc + 1; intended := 'v' || vc;
          g := jsonb_build_object('v', 'cfp/1', 'grant_id', gen_random_uuid(), 'audience', 'pg://density-ledger/sandbox',
                 'effect', jsonb_build_object('kind', 'update', 'table', 'sandbox.flags', 'pk', k),
                 'prestate', jsonb_build_object('digest', fence.row_digest('sandbox.flags', k), 'scheme', 'row-json-sha256/1'),
                 'history', jsonb_build_object('head', fence.history_head('sandbox.flags', k)),
                 'authority_epoch', (select authority_epoch::text from ledger.state where id = 1),
                 'intent', 'poststate:' || (select fence.digest_json(row_to_json(x)) from (select k::text as key, intended::text as value) x),
                 'not_before', (now() - interval '5 seconds')::text, 'not_after', (now() + interval '120 seconds')::text, 'quorum', jsonb_build_object('t', 2));
          msg := fence.signing_input(g);
          g := g || jsonb_build_object('signatures', jsonb_build_array(
                 jsonb_build_object('issuer', 'diff-a', 'root_gen', 1, 'sig', encode(pgsodium.crypto_sign_detached(msg, kp1.secret), 'hex')),
                 jsonb_build_object('issuer', 'diff-b', 'root_gen', 1, 'sig', encode(pgsodium.crypto_sign_detached(msg, kp2.secret), 'hex'))));
          begin
            perform ledger.register_grant('diff-effect-' || n, g, s->>'op' = 'G+retry');
            cur := g || jsonb_build_object('intended_value', intended); live := 'OK';
          exception when others then live := split_part(sqlerrm, ':', 1); end;
        elsif s->>'op' = 'R' then
          if cur is null then live := 'TransitionForbidden';
          else
            begin
              perform fence."begin"(cur - 'intended_value');
              select value into prev_val from sandbox.flags where key = k;
              update sandbox.flags set value = cur->>'intended_value' where key = k;
              live := 'OK'; last_ok := cur;
            exception when others then
              live := case split_part(sqlerrm, ' ', 1) when 'CFP_STALE_EPOCH' then 'GrantRevoked' when 'CFP_GRANT_REVOKED' then 'GrantRevoked'
                        when 'CFP_REPLAY' then 'GrantConsumed' when 'CFP_BUDGET_EXPIRED' then 'GrantRevoked'
                        when 'CFP_GRANT_NOT_CURRENT' then 'TransitionForbidden' when 'CFP_GRANT_NOT_REGISTERED' then 'TransitionForbidden'
                        when 'CFP_PRESTATE_CHANGED' then 'TransitionForbidden' when 'CFP_HISTORY_MISMATCH' then 'TransitionForbidden'
                        else 'LIVE:' || split_part(sqlerrm, ' ', 1) end;
            end;
          end if;
        elsif s->>'op' = 'RR' then
          if last_ok is null then live := 'SKIP';
          else
            alter table sandbox.flags disable trigger cfp_guard;
            update sandbox.flags set value = prev_val where key = k;
            alter table sandbox.flags enable trigger cfp_guard;
            delete from fence.receipts where grant_id = (last_ok->>'grant_id')::uuid;
            begin
              perform fence."begin"(last_ok - 'intended_value'); live := 'OK';
            exception when others then
              live := case split_part(sqlerrm, ' ', 1) when 'CFP_REPLAY' then 'GrantConsumed' when 'CFP_STALE_EPOCH' then 'GrantRevoked'
                        when 'CFP_GRANT_REVOKED' then 'GrantRevoked' else 'LIVE:' || split_part(sqlerrm, ' ', 1) end;
            end;
          end if;
        end if;
        history := history || (s->>'op') || ' ';
        if exp = 'SKIP' or live = 'SKIP' then skipped := skipped + 1;
        elsif exp = live then agree := agree + 1;
        elsif live = 'OK' then live_permits := live_permits + 1; permits := permits || jsonb_build_object('trace', n, 'ops', trim(history), 'oracle', exp);
        elsif exp = 'OK' then live_refuses := live_refuses + 1; refuses := refuses || jsonb_build_object('trace', n, 'ops', trim(history), 'live', live);
        else both_refuse := both_refuse + 1; diffs := diffs || jsonb_build_object(exp || '/' || live, coalesce((diffs->>(exp || '/' || live))::int, 0) + 1);
        end if;
      end loop;
    end loop;
    res := jsonb_build_object('trace_set', p_id, 'compared', agree + both_refuse + live_permits + live_refuses, 'agree', agree, 'both_refuse_different_reason', both_refuse,
      'refusal_pairs', diffs, 'live_permits_oracle_forbids', live_permits, 'live_refuses_oracle_permits', live_refuses, 'skipped', skipped,
      'permit_cases', permits, 'refuse_cases', refuses);
    raise exception 'DIFF_RESULT:%', res::text;
  exception when others then
    if sqlerrm like 'DIFF_RESULT:%' then return substring(sqlerrm from 13)::jsonb; end if;
    return jsonb_build_object('harness_error', sqlerrm);
  end;
end $fn$;
revoke all on function ledger_test.run_differential(text) from public, anon, authenticated;
grant usage on schema ledger_test to ledger_fdw;
grant execute on function ledger_test.run_differential(text) to ledger_fdw;
