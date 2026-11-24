-- migration 20261121130648 uap_0011_mechanism_anchors (root: rtkslhpxdcjoeqhucebp)
alter table uap.operator_anchors drop constraint operator_anchors_verdict_check;
alter table uap.operator_anchors add constraint operator_anchors_verdict_check
  check (verdict in ('DESIGN_INVARIANT','NOT_CONFIRMED','REJECTED','MECHANISM_EVIDENCED','MECHANISM_CONTRADICTS_EXACTNESS'));
alter table uap.operator_anchors add column evidence jsonb;

insert into uap.access_roots values ('cred-diw-owner-read','Density owner (session read of catalog)',null) on conflict do nothing;
insert into uap.access_channels(channel_id,root_id) values ('diw.catalog.function_source','cred-diw-owner-read') on conflict do nothing;
select uap.recompute_access();

insert into uap.operator_anchors(port_epoch_id, rule_pattern, verdict, given_by, channel, evidence)
select e.id, v.rule, v.verdict, v.src, 'diw.catalog.function_source', v.ev::jsonb
from uap.port_epochs e join core.systems s on s.id = e.system_id,
(values
 ('fd:dica.extraction_repair_obligations gap_code<->action<->priority (all six)', 'MECHANISM_EVIDENCED', 'public.diw_plan_pdf_repairs',
  '{"mapping":"CASE on gap code: 6 codes -> 6 distinct actions, priorities 100/95/75/60/45/35","observed_codes_in_data":2,"caveat":"other service-role writers could insert directly; no constraint enforces it"}'),
 ('inc:repair_obligation -> coverage_gap (every obligation has its gap)', 'MECHANISM_EVIDENCED', 'public.diw_plan_pdf_repairs',
  '{"basis":"the only database insert path into extraction_repair_obligations selects from extraction_coverage_gaps","primary_keys":"at most one obligation per (job,page,code)"}'),
 ('inc:coverage_gap -> repair_obligation (every gap has an obligation)', 'MECHANISM_CONTRADICTS_EXACTNESS', 'public.diw_plan_pdf_repairs',
  '{"basis":"planning is budgeted (limit 1..100 per call, highest priority first); a gap can exist with no obligation until planning catches up","consistent_with_owner":"NOT_CONFIRMED"}'),
 ('near:dica.field_investigation_decisions score<->estimated_cost<->gap_code', 'MECHANISM_EVIDENCED', 'public.diw_dpcc07_plan_investigations',
  '{"formula":"score = priority / (1 + estimated_cost); cost by action: EQUATION_VERIFY 3, SELECTIVE_OCR 4, LAYOUT_INSPECT 2, else 1"}'),
 ('silent:field_investigation_decisions expected_information_gain always null', 'MECHANISM_EVIDENCED', 'public.diw_dpcc07_plan_investigations',
  '{"basis":"inserted as NULL by design; function reports estimatedInformationGain = NOT_CALIBRATED"}')
) v(rule, verdict, src, ev)
where s.name like 'Density Intelligence Workspace%';

update uap.acquisition_requests set status = 'DONE'
 where open_finding like 'expected_information_gain is null%';
update uap.acquisition_requests set status = 'DONE'
 where open_finding like 'Decision score<->cost<->gap%';
