-- migration 20261124201424 g2_0003_fence_conformance_function (ledger: mzglmdydfcoljrwleooq)
-- a signed CFP grant from the two ephemeral test issuers, for sandbox.flags row p_key -> p_value (optionally registered)
create or replace function ledger_test.mint_grant(p_key text, p_value text, p_sk1 bytea, p_sk2 bytea, p_register text default null) returns jsonb
language plpgsql security definer set search_path = ledger, fence, sandbox, pg_catalog as $fn$
declare g jsonb; msg bytea;
begin
  g := jsonb_build_object('v', 'cfp/1', 'grant_id', gen_random_uuid(), 'audience', 'pg://density-ledger/sandbox',
         'effect', jsonb_build_object('kind', 'update', 'table', 'sandbox.flags', 'pk', p_key),
         'prestate', jsonb_build_object('digest', fence.row_digest('sandbox.flags', p_key), 'scheme', 'row-json-sha256/1'),
         'history', jsonb_build_object('head', fence.history_head('sandbox.flags', p_key)),
         'authority_epoch', (select authority_epoch::text from ledger.state where id = 1),
         'intent', 'poststate:' || (select fence.digest_json(row_to_json(x)) from (select p_key::text as key, p_value::text as value) x),
         'not_before', (now() - interval '5 seconds')::text, 'not_after', (now() + interval '120 seconds')::text, 'quorum', jsonb_build_object('t', 2));
  msg := fence.signing_input(g);
  g := g || jsonb_build_object('signatures', jsonb_build_array(
         jsonb_build_object('issuer', 'conf-a', 'root_gen', 1, 'sig', encode(pgsodium.crypto_sign_detached(msg, p_sk1), 'hex')),
         jsonb_build_object('issuer', 'conf-b', 'root_gen', 1, 'sig', encode(pgsodium.crypto_sign_detached(msg, p_sk2), 'hex'))));
  if p_register is not null then perform ledger.register_grant(p_register, g, false); end if;
  return g;
end $fn$;

create or replace function ledger_test.run_fence_conformance() returns jsonb language plpgsql security definer set search_path = ledger, fence, sandbox, pg_catalog as $fn$
declare kp1 record; kp2 record; g jsonb; old_g jsonb; out jsonb := '{}'; res jsonb;
  -- one probe: admit g, write p_value to p_key; return 'ADMITTED' or the refusal code. The probe itself always rolls back.
begin
  begin
    select * into kp1 from pgsodium.crypto_sign_seed_new_keypair(pgsodium.crypto_sign_new_seed()); select * into kp2 from pgsodium.crypto_sign_seed_new_keypair(pgsodium.crypto_sign_new_seed());
    insert into ledger.issuers (issuer_id, pubkey, root_gen, status, administrator) values
      ('conf-a', kp1.public, 1, 'active', 'fence conformance (rolled back)'), ('conf-b', kp2.public, 1, 'active', 'fence conformance (rolled back)');
    alter table sandbox.flags disable trigger cfp_guard;
    insert into sandbox.flags values ('conf-x', 'v0'), ('conf-y', 'v0');
    alter table sandbox.flags enable trigger cfp_guard;

    -- fence checks (each probe in its own sub-transaction, rolled back by raising)
    begin update sandbox.flags set value = 'v1' where key = 'conf-x'; out := out || '{"no_grant":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('no_grant', split_part(sqlerrm, ' ', 1)); end if; end;
    begin set local session_replication_role = replica; update sandbox.flags set value = 'v1' where key = 'conf-x'; out := out || '{"replica_bypass":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('replica_bypass', split_part(sqlerrm, ' ', 1)); end if; end;
    set local session_replication_role = origin;
    g := ledger_test.mint_grant('conf-x', 'v1', kp1.secret, kp2.secret, 'conf-effect-x');
    begin perform fence."begin"(g); update sandbox.flags set value = 'maybe' where key = 'conf-x'; out := out || '{"wrong_outcome":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('wrong_outcome', split_part(sqlerrm, ' ', 1)); end if; end;
    begin perform fence."begin"(jsonb_set(g, '{audience}', '"pg://elsewhere"')); out := out || '{"wrong_audience":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('wrong_audience', split_part(sqlerrm, ' ', 1)); end if; end;
    begin perform fence."begin"(jsonb_set(g, '{effect,pk}', '"conf-y"')); out := out || '{"tampered_row":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('tampered_row', split_part(sqlerrm, ' ', 1)); end if; end;
    begin perform fence."begin"(jsonb_set(g, '{signatures}', g->'signatures'->0 || '[]'::jsonb)); out := out || '{"one_signature":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('one_signature', split_part(sqlerrm, ' ', 1)); end if; end;
    begin perform fence."begin"(jsonb_set(g, '{signatures,1,sig}', to_jsonb(repeat('ab', 64)))); out := out || '{"forged_signature":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('forged_signature', split_part(sqlerrm, ' ', 1)); end if; end;
    begin perform fence."begin"(g); update sandbox.flags set value = 'v1' where key = 'conf-y'; out := out || '{"other_row":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('other_row', split_part(sqlerrm, ' ', 1)); end if; end;
    begin perform fence."begin"(ledger_test.mint_grant('conf-x', 'v1', kp1.secret, kp2.secret, null)); out := out || '{"unregistered":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('unregistered', split_part(sqlerrm, ' ', 1)); end if; end;
    begin perform ledger.revoke_grant((g->>'grant_id')::uuid, 'conformance'); perform fence."begin"(g); out := out || '{"revoked":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('revoked', split_part(sqlerrm, ' ', 1)); end if; end;
    -- the genuine grant, kept (inside this outer rolled-back block)
    perform fence."begin"(g); update sandbox.flags set value = 'v1' where key = 'conf-x';
    out := out || jsonb_build_object('genuine', 'ADMITTED');
    begin perform fence."begin"(g); out := out || '{"replay":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('replay', split_part(sqlerrm, ' ', 1)); end if; end;

    -- K35 target restore: the target forgets the effect (row and receipt), the ledger does not
    begin
      alter table sandbox.flags disable trigger cfp_guard; update sandbox.flags set value = 'v0' where key = 'conf-x'; alter table sandbox.flags enable trigger cfp_guard;
      delete from fence.receipts where grant_id = (g->>'grant_id')::uuid;
      perform fence."begin"(g); out := out || '{"target_restore_replay":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('target_restore_replay', split_part(sqlerrm, ' ', 1)); end if; end;
    -- K35 ledger restore with the countermeasure: the ledger forgets the consumption, the epoch is advanced
    begin
      alter table sandbox.flags disable trigger cfp_guard; update sandbox.flags set value = 'v0' where key = 'conf-x'; alter table sandbox.flags enable trigger cfp_guard;
      delete from fence.receipts where grant_id = (g->>'grant_id')::uuid;
      set local session_replication_role = replica;
      delete from ledger.consumed where grant_id = (g->>'grant_id')::uuid;
      update ledger.effects set state = 'AUTHORIZED' where effect_key = 'conf-effect-x';
      set local session_replication_role = origin;
      update ledger.state set authority_epoch = authority_epoch + 1 where id = 1;
      perform fence."begin"(g); out := out || '{"ledger_restore_replay_after_epoch_advance":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('ledger_restore_replay_after_epoch_advance', split_part(sqlerrm, ' ', 1)); end if; end;
    set local session_replication_role = origin;

    -- K51 history-bound: v0 -> v1 -> v0 again; a grant minted at the first v0 sees the same visible state but another history
    alter table sandbox.flags disable trigger cfp_guard;
    insert into sandbox.flags values ('conf-h', 'v0');
    alter table sandbox.flags enable trigger cfp_guard;
    old_g := ledger_test.mint_grant('conf-h', 'v9', kp1.secret, kp2.secret, 'conf-effect-h-old');
    g := ledger_test.mint_grant('conf-h', 'v1', kp1.secret, kp2.secret, 'conf-effect-h1'); perform fence."begin"(g); update sandbox.flags set value = 'v1' where key = 'conf-h';
    g := ledger_test.mint_grant('conf-h', 'v0', kp1.secret, kp2.secret, 'conf-effect-h2'); perform fence."begin"(g); update sandbox.flags set value = 'v0' where key = 'conf-h';
    out := out || jsonb_build_object('history_same_visible_state', fence.row_digest('sandbox.flags', 'conf-h') = old_g#>>'{prestate,digest}');
    begin perform fence."begin"(old_g); update sandbox.flags set value = 'v9' where key = 'conf-h'; out := out || '{"history_bound":"ADMITTED"}'; raise exception 'P';
    exception when others then if sqlerrm <> 'P' then out := out || jsonb_build_object('history_bound', split_part(sqlerrm, ' ', 1)); end if; end;

    raise exception 'CONF_RESULT:%', out::text;
  exception when others then
    if sqlerrm like 'CONF_RESULT:%' then return substring(sqlerrm from 13)::jsonb; end if;
    return jsonb_build_object('harness_error', sqlerrm, 'partial', out);
  end;
end $fn$;
revoke all on function ledger_test.run_fence_conformance(), ledger_test.mint_grant(text, text, bytea, bytea, text) from public, anon, authenticated;
grant execute on function ledger_test.run_fence_conformance() to ledger_fdw;
