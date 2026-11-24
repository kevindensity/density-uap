-- migration 20261124073708 s4_0002_gateway_and_observer_access (ledger: mzglmdydfcoljrwleooq)
-- the emitter: may admit grants and write the guarded table, and must record SENT; may not decide outcomes
create role gatewayd_ledger login password '<redacted>' connection limit 5;
comment on role gatewayd_ledger is 'effect gateway (Fly Sprite mcp-density-kernel, user gatewayd): emits granted effects; never decides outcomes';
grant usage on schema fence, sandbox, ledger to gatewayd_ledger;
grant execute on function fence."begin"(jsonb), fence.row_digest(regclass, text), fence.history_head(regclass, text) to gatewayd_ledger;
grant select, update on sandbox.flags to gatewayd_ledger;
create policy flags_gateway on sandbox.flags for all to gatewayd_ledger using (true) with check (true);
grant select, insert on ledger.sent to gatewayd_ledger;
do $$ begin
  if exists (select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'ledger' and c.relname = 'sent' and c.relrowsecurity) then
    execute 'create policy sent_gateway on ledger.sent for all to gatewayd_ledger using (true) with check (true)'; end if;
end $$;

-- the observer (the root's ledger link): reads the target and the fence receipts, and alone records outcomes
grant usage on schema fence, sandbox, ledger to ledger_fdw;
grant select on sandbox.flags, fence.receipts to ledger_fdw;
grant select on ledger.sent, ledger.consumed, ledger.outcomes to ledger_fdw;
grant insert on ledger.outcomes to ledger_fdw;
create policy flags_observer on sandbox.flags for select to ledger_fdw using (true);
create policy receipts_observer on fence.receipts for select to ledger_fdw using (true);

select (select count(*) from information_schema.role_table_grants where grantee = 'gatewayd_ledger' and table_name = 'outcomes') as gateway_outcome_grants,
       has_table_privilege('gatewayd_ledger', 'ledger.consumed', 'INSERT') as gateway_can_consume_directly;
