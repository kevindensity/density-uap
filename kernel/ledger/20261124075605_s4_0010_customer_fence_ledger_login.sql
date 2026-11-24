-- migration 20261124075605 s4_0010_customer_fence_ledger_login (ledger: mzglmdydfcoljrwleooq)
create role fence_customer_sim login password '<redacted>' connection limit 10;
comment on role fence_customer_sim is 'fence of density-customer-sim (khpubdyfjhtdwryucbqn): reads issuers and epoch, records consumed grants; nothing else';
grant usage on schema ledger to fence_customer_sim;
grant select on ledger.issuers, ledger.state to fence_customer_sim;
grant insert on ledger.consumed to fence_customer_sim;
do $$ declare t text; begin
  foreach t in array array['issuers','state','consumed'] loop
    if exists (select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'ledger' and c.relname = t and c.relrowsecurity) then
      execute format('create policy %I on ledger.%I for %s to fence_customer_sim %s', 'customer_fence_' || t, t,
                     case when t = 'consumed' then 'insert' else 'select' end, case when t = 'consumed' then 'with check (true)' else 'using (true)' end);
    end if;
  end loop; end $$;
select has_table_privilege('fence_customer_sim', 'ledger.consumed', 'DELETE') as can_delete_consumed,
       has_table_privilege('fence_customer_sim', 'ledger.sent', 'SELECT') as can_read_sent;
