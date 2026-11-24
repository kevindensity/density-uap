-- migration 20261121130248 uap_0010_acquisition_requests (root: rtkslhpxdcjoeqhucebp)
create table uap.acquisition_requests (
  id            bigserial primary key,
  port_epoch_id uuid not null references uap.port_epochs(id),
  open_finding  text not null,
  experiment    text not null,
  resolves      text not null,
  cost_class    text not null check (cost_class in ('PASSIVE_READ','LOW','MEDIUM','HIGH','WAIT')),
  touches_target text not null check (touches_target in ('NO','READ_ONLY','TEST_WORKSPACE','PRODUCTION')),
  status        text not null default 'PROPOSED' check (status in ('PROPOSED','APPROVED','RUNNING','DONE','DECLINED')),
  created_at    timestamptz not null default now()
);
insert into uap.acquisition_requests(port_epoch_id, open_finding, experiment, resolves, cost_class, touches_target)
select e.id, v.f, v.x, v.r, v.c, v.t from uap.port_epochs e join core.systems s on s.id = e.system_id,
(values
 ('3 runs stopped after run.accepted',
  'Read lease_expires_at, fence and updated_at for runs with no finished_at (two more columns through the probe, counts only)',
  'Whether these are expired leases nobody reclaimed (a missing reaper) or runs still in flight', 'PASSIVE_READ', 'READ_ONLY'),
 ('16 unbound claims, all EQUATION; no available feature separates them',
  'Expose the binding validator''s per-claim outcome code (one categorical column) to the probe',
  'Minimal distinction for unbound claims: validator refusal reason versus never attempted', 'LOW', 'READ_ONLY'),
 ('All 6 runs through cognitive.route failed',
  'Send 3 requests known to take the cognitive.route path in a test workspace, with inputs that succeed on the direct path',
  'Whether routing itself causes failure or failing requests are what get routed', 'LOW', 'TEST_WORKSPACE'),
 ('expected_information_gain is null in all 17 decisions',
  'Owner check: is the field meant to be populated? If yes, it is a missing write path, not a data pattern',
  'Whether decision scoring follows its stated design (score from gain and cost)', 'LOW', 'NO'),
 ('Field claims standing/state/maturity never varied (1,561 rows)',
  'Process one document through a second extractor version, or one review that promotes a claim',
  'The rules governing claim promotion, currently unobservable', 'MEDIUM', 'TEST_WORKSPACE'),
 ('Decision score<->cost<->gap and run status->failure/fence below 30-row support',
  'Wait for natural growth to 30 rows each; the daily check reports support',
  'Settles or refutes the two near-rules without any intervention', 'WAIT', 'NO'),
 ('cron status never varied (14,937+ runs, all one status)',
  'None proposed: a deliberately failing scheduled job would add risk for little information',
  'Nothing worth the risk; kept as a watch', 'HIGH', 'PRODUCTION')
) v(f, x, r, c, t)
where s.name like 'Density Intelligence Workspace%';
