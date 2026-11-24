-- migration 20261124075901 c1_0003_emitter_and_observer_logins (customer: khpubdyfjhtdwryucbqn)
create role gatewayd_customer login password '<redacted>' connection limit 5;
comment on role gatewayd_customer is 'Density effect gateway: admits grants and writes the fenced table; reads nothing else';
grant usage on schema fence, app to gatewayd_customer;
grant execute on function fence."begin"(jsonb), fence.row_digest(regclass, text), fence.history_head(regclass, text) to gatewayd_customer;
grant select, update on app.feature_flags to gatewayd_customer;
create policy flags_gateway on app.feature_flags for all to gatewayd_customer using (true) with check (true);

create role density_observer login password '<redacted>' connection limit 5;
comment on role density_observer is 'Density root observer: reads the fenced table and fence receipts; writes nothing';
grant usage on schema fence, app to density_observer;
grant select on app.feature_flags, fence.receipts_v to density_observer;
create policy flags_observer on app.feature_flags for select to density_observer using (true);
create policy receipts_observer on fence.receipts for select to density_observer using (true);
grant select on fence.receipts to density_observer;   -- the view runs as its owner; this keeps direct reads explicit too
