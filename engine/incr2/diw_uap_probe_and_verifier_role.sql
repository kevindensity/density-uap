create schema if not exists uap_probe;
revoke all on schema uap_probe from public;

create or replace function uap_probe.check_rules()
returns table(check_key text, counterexamples bigint, support bigint)
language sql stable security definer set search_path = '' as $$
  select 'fd:dica.extraction_coverage_gaps job_id->workspace_id', (select count(*) from dica.extraction_coverage_gaps x join dica.extraction_coverage_gaps y on x.job_id=y.job_id and x.workspace_id<>y.workspace_id), (select count(*) from dica.extraction_coverage_gaps)
  union all select 'fd:dica.extraction_page_receipts job_id->workspace_id', (select count(*) from dica.extraction_page_receipts x join dica.extraction_page_receipts y on x.job_id=y.job_id and x.workspace_id<>y.workspace_id), (select count(*) from dica.extraction_page_receipts)
  union all select 'fd:dica.extraction_semantic_candidates job_id->workspace_id', (select count(*) from dica.extraction_semantic_candidates x join dica.extraction_semantic_candidates y on x.job_id=y.job_id and x.workspace_id<>y.workspace_id), (select count(*) from dica.extraction_semantic_candidates)
  union all select 'fd:dica.field_investigations source_job_id->workspace_id', (select count(*) from dica.field_investigations x join dica.field_investigations y on x.source_job_id=y.source_job_id and x.workspace_id<>y.workspace_id), (select count(*) from dica.field_investigations)
  union all select 'fd:dica.extraction_repair_obligations job_id->workspace_id', (select count(*) from dica.extraction_repair_obligations x join dica.extraction_repair_obligations y on x.job_id=y.job_id and x.workspace_id<>y.workspace_id), (select count(*) from dica.extraction_repair_obligations)
  union all select 'fd:dica.extraction_repair_obligations gap_code->action', (select count(*) from dica.extraction_repair_obligations x join dica.extraction_repair_obligations y on x.gap_code=y.gap_code and x.action<>y.action), (select count(*) from dica.extraction_repair_obligations)
  union all select 'fd:dica.extraction_repair_obligations action->gap_code', (select count(*) from dica.extraction_repair_obligations x join dica.extraction_repair_obligations y on x.action=y.action and x.gap_code<>y.gap_code), (select count(*) from dica.extraction_repair_obligations)
  union all select 'fd:dica.extraction_repair_obligations gap_code->priority', (select count(*) from dica.extraction_repair_obligations x join dica.extraction_repair_obligations y on x.gap_code=y.gap_code and x.priority<>y.priority), (select count(*) from dica.extraction_repair_obligations)
  union all select 'fd:dica.extraction_repair_obligations priority->gap_code', (select count(*) from dica.extraction_repair_obligations x join dica.extraction_repair_obligations y on x.priority=y.priority and x.gap_code<>y.gap_code), (select count(*) from dica.extraction_repair_obligations)
  union all select 'fd:dica.extraction_repair_obligations action->priority', (select count(*) from dica.extraction_repair_obligations x join dica.extraction_repair_obligations y on x.action=y.action and x.priority<>y.priority), (select count(*) from dica.extraction_repair_obligations)
  union all select 'fd:dica.extraction_repair_obligations priority->action', (select count(*) from dica.extraction_repair_obligations x join dica.extraction_repair_obligations y on x.priority=y.priority and x.action<>y.action), (select count(*) from dica.extraction_repair_obligations)
  union all select 'inc:coverage_gaps<->repair_obligations one-to-one on (job,page,code)',
     (select count(*) from dica.extraction_coverage_gaps g where not exists (select 1 from dica.extraction_repair_obligations o where o.job_id=g.job_id and o.page_number=g.page_number and o.gap_code=g.code))
   + (select count(*) from dica.extraction_repair_obligations o where not exists (select 1 from dica.extraction_coverage_gaps g where o.job_id=g.job_id and o.page_number=g.page_number and o.gap_code=g.code))
   + (select count(*) - count(distinct (job_id,page_number,code)) from dica.extraction_coverage_gaps)
   + (select count(*) - count(distinct (job_id,page_number,gap_code)) from dica.extraction_repair_obligations),
     (select count(*) from dica.extraction_coverage_gaps)
  union all select 'inc:every source_claim_binding has a field_claim', (select count(*) from dica.source_claim_bindings b where not exists (select 1 from dica.field_claims f where f.claim_id=b.claim_id)), (select count(*) from dica.source_claim_bindings)
  union all select 'inc:field_claims<->field_lineage_events one-to-one',
     (select count(*) from dica.field_claims f where not exists (select 1 from dica.field_lineage_events e where e.claim_id=f.claim_id))
   + (select count(*) - count(distinct claim_id) from dica.field_lineage_events), (select count(*) from dica.field_claims)
  union all select 'eq:binding span and page equal claim span and page', (select count(*) from dica.field_claims f join dica.source_claim_bindings b on b.claim_id=f.claim_id where b.start_cp<>f.span_start_cp or b.end_cp<>f.span_end_cp or b.source_page<>f.source_page), (select count(*) from dica.source_claim_bindings)
  union all select 'inv:field_claims span_end_cp >= span_start_cp', (select count(*) from dica.field_claims where span_end_cp < span_start_cp), (select count(*) from dica.field_claims)
  union all select 'inv:source_claim_bindings end_cp >= start_cp', (select count(*) from dica.source_claim_bindings where end_cp < start_cp), (select count(*) from dica.source_claim_bindings)
  -- variation watch: when these exceed 1 (or 0 for the null-only column), an open finding becomes learnable
  union all select 'watch:distinct cron status', (select count(distinct status) from cron.job_run_details), (select count(*) from cron.job_run_details)
  union all select 'watch:distinct field_claims standing', (select count(distinct standing) from dica.field_claims), (select count(*) from dica.field_claims)
  union all select 'watch:distinct field_claims state', (select count(distinct state) from dica.field_claims), (select count(*) from dica.field_claims)
  union all select 'watch:non-null expected_information_gain', (select count(expected_information_gain) from dica.field_investigation_decisions), (select count(*) from dica.field_investigation_decisions)
  union all select 'watch:unbound field_claims', (select count(*) from dica.field_claims f where not exists (select 1 from dica.source_claim_bindings b where b.claim_id=f.claim_id)), (select count(*) from dica.field_claims)
  union all select 'watch:runs through cognitive.route that did not fail', (select count(distinct r.run_id) from dica.run_events r where r.type='cognitive.route' and not exists (select 1 from dica.run_events f where f.run_id=r.run_id and f.type='run.failed')), (select count(distinct run_id) from dica.run_events where type='cognitive.route')
$$;

revoke all on function uap_probe.check_rules() from public;

do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'uap_verifier') then
    create role uap_verifier login password '<REDACTED: rotate and store only in Density UAP vault>' noinherit nocreatedb nocreaterole connection limit 2;
  end if;
end $$;
alter role uap_verifier set statement_timeout = '30s';
alter role uap_verifier set default_transaction_read_only = on;
grant usage on schema uap_probe to uap_verifier;
grant execute on function uap_probe.check_rules() to uap_verifier;
