select 'dica.extraction_coverage_gaps' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from dica.extraction_coverage_gaps x where x.created_at < '2026-11-21T12:40:06Z') r, unnest(array['workspace_id','job_id','page_number','code','created_at']::text[]) c group by c
union all
select 'dica.extraction_jobs' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from dica.extraction_jobs x where x.created_at < '2026-11-21T12:40:06Z') r, unnest(array['workspace_id','kind','status','next_page','total_pages','fence','attempts','max_pages','consecutive_failures','created_at','updated_at']::text[]) c group by c
union all
select 'dica.extraction_page_receipts' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from dica.extraction_page_receipts x where x.created_at < '2026-11-21T12:40:06Z') r, unnest(array['workspace_id','job_id','page_number','status','parser_version','created_at']::text[]) c group by c
union all
select 'dica.extraction_repair_obligations' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from dica.extraction_repair_obligations x where x.created_at < '2026-11-21T12:40:06Z') r, unnest(array['workspace_id','job_id','page_number','gap_code','action','priority','status','created_at']::text[]) c group by c
union all
select 'dica.extraction_semantic_candidates' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from dica.extraction_semantic_candidates x where x.created_at < '2026-11-21T12:40:06Z') r, unnest(array['workspace_id','job_id','page_number','ordinal','kind','standing','parser_version','created_at']::text[]) c group by c
union all
select 'dica.field_claims' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from dica.field_claims x where x.created_at < '2026-11-21T12:40:06Z') r, unnest(array['workspace_id','source_kind','source_page','source_ordinal','anchor_ambiguous','statement_kind','facet_key','polarity','standing','maturity','state','extractor_version','span_start_cp','span_end_cp','revoked_at','created_at']::text[]) c group by c
union all
select 'dica.field_investigation_decisions' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from dica.field_investigation_decisions x where x.created_at < '2026-11-21T12:40:06Z') r, unnest(array['workspace_id','source_page','gap_code','score','expected_information_gain','estimated_cost','status','standing','created_at']::text[]) c group by c
union all
select 'dica.field_investigations' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from dica.field_investigations x where x.created_at < '2026-11-21T12:40:06Z') r, unnest(array['workspace_id','source_job_id','page_number','gap_code','priority','estimated_cost_class','status','created_at']::text[]) c group by c
union all
select 'dica.field_lineage_events' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from dica.field_lineage_events x where x.created_at < '2026-11-21T12:40:06Z') r, unnest(array['workspace_id','event_kind','created_at']::text[]) c group by c
union all
select 'dica.intelligence_runs' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from dica.intelligence_runs x where x.created_at < '2026-11-21T12:40:06Z') r, unnest(array['workspace_id','status','fence','event_sequence','failure_code','base_revision','created_at','updated_at','finished_at']::text[]) c group by c
union all
select 'dica.jobs' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from dica.jobs x where x.created_at < '2026-11-21T12:40:06Z') r, unnest(array['workspace_id','status','worker_dispatch_attempts','created_at','updated_at']::text[]) c group by c
union all
select 'dica.run_attempts' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from dica.run_attempts x where x.created_at < '2026-11-21T12:40:06Z') r, unnest(array['workspace_id','fence','status','created_at']::text[]) c group by c
union all
select 'dica.run_events' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from dica.run_events x where x.created_at < '2026-11-21T12:40:06Z') r, unnest(array['workspace_id','sequence','type','created_at']::text[]) c group by c
union all
select 'dica.source_claim_bindings' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from dica.source_claim_bindings x where x.created_at < '2026-11-21T12:40:06Z') r, unnest(array['workspace_id','source_page','start_cp','end_cp','validator_version','standing','created_at']::text[]) c group by c
union all
select 'cron.job_run_details' as t, c as col, count(distinct j->>c) as nd, count(*) filter (where j->>c is null) as nulls, count(*) as n from (select to_jsonb(x) j from cron.job_run_details x where x.start_time < '2026-11-21T12:40:06Z') r, unnest(array['jobid','status','start_time','end_time']::text[]) c group by c
order by 1,2;