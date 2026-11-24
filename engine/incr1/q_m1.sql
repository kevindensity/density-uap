select 'dica.extraction_coverage_gaps' t, a, b, count(*) groups, sum(n) n_rows, sum(case when nb>1 then n else 0 end) violating from (
 select p.a, p.b, coalesce(j->>p.a,'<null>') av, count(distinct coalesce(j->>p.b,'<null>')) nb, count(*) n
 from (select to_jsonb(x) j from dica.extraction_coverage_gaps x where x.created_at < '2026-11-21T12:40:06Z') r,
      (select a.c a, b.c b from unnest(array['code','workspace_id','job_id']::text[]) a(c), unnest(array['code','workspace_id','job_id']::text[]) b(c) where a.c<>b.c) p group by 1,2,3) g group by a, b
union all
select 'dica.extraction_page_receipts' t, a, b, count(*) groups, sum(n) n_rows, sum(case when nb>1 then n else 0 end) violating from (
 select p.a, p.b, coalesce(j->>p.a,'<null>') av, count(distinct coalesce(j->>p.b,'<null>')) nb, count(*) n
 from (select to_jsonb(x) j from dica.extraction_page_receipts x where x.created_at < '2026-11-21T12:40:06Z') r,
      (select a.c a, b.c b from unnest(array['status','job_id','workspace_id']::text[]) a(c), unnest(array['status','job_id','workspace_id']::text[]) b(c) where a.c<>b.c) p group by 1,2,3) g group by a, b
union all
select 'dica.extraction_repair_obligations' t, a, b, count(*) groups, sum(n) n_rows, sum(case when nb>1 then n else 0 end) violating from (
 select p.a, p.b, coalesce(j->>p.a,'<null>') av, count(distinct coalesce(j->>p.b,'<null>')) nb, count(*) n
 from (select to_jsonb(x) j from dica.extraction_repair_obligations x where x.created_at < '2026-11-21T12:40:06Z') r,
      (select a.c a, b.c b from unnest(array['action','gap_code','priority','job_id','workspace_id']::text[]) a(c), unnest(array['action','gap_code','priority','job_id','workspace_id']::text[]) b(c) where a.c<>b.c) p group by 1,2,3) g group by a, b
union all
select 'dica.extraction_semantic_candidates' t, a, b, count(*) groups, sum(n) n_rows, sum(case when nb>1 then n else 0 end) violating from (
 select p.a, p.b, coalesce(j->>p.a,'<null>') av, count(distinct coalesce(j->>p.b,'<null>')) nb, count(*) n
 from (select to_jsonb(x) j from dica.extraction_semantic_candidates x where x.created_at < '2026-11-21T12:40:06Z') r,
      (select a.c a, b.c b from unnest(array['kind','ordinal','job_id','workspace_id']::text[]) a(c), unnest(array['kind','ordinal','job_id','workspace_id']::text[]) b(c) where a.c<>b.c) p group by 1,2,3) g group by a, b
union all
select 'dica.field_claims' t, a, b, count(*) groups, sum(n) n_rows, sum(case when nb>1 then n else 0 end) violating from (
 select p.a, p.b, coalesce(j->>p.a,'<null>') av, count(distinct coalesce(j->>p.b,'<null>')) nb, count(*) n
 from (select to_jsonb(x) j from dica.field_claims x where x.created_at < '2026-11-21T12:40:06Z') r,
      (select a.c a, b.c b from unnest(array['statement_kind','source_ordinal','workspace_id']::text[]) a(c), unnest(array['statement_kind','source_ordinal','workspace_id']::text[]) b(c) where a.c<>b.c) p group by 1,2,3) g group by a, b
union all
select 'dica.field_investigations' t, a, b, count(*) groups, sum(n) n_rows, sum(case when nb>1 then n else 0 end) violating from (
 select p.a, p.b, coalesce(j->>p.a,'<null>') av, count(distinct coalesce(j->>p.b,'<null>')) nb, count(*) n
 from (select to_jsonb(x) j from dica.field_investigations x where x.created_at < '2026-11-21T12:40:06Z') r,
      (select a.c a, b.c b from unnest(array['source_job_id','workspace_id']::text[]) a(c), unnest(array['source_job_id','workspace_id']::text[]) b(c) where a.c<>b.c) p group by 1,2,3) g group by a, b
union all
select 'dica.run_events' t, a, b, count(*) groups, sum(n) n_rows, sum(case when nb>1 then n else 0 end) violating from (
 select p.a, p.b, coalesce(j->>p.a,'<null>') av, count(distinct coalesce(j->>p.b,'<null>')) nb, count(*) n
 from (select to_jsonb(x) j from dica.run_events x where x.created_at < '2026-11-21T12:40:06Z') r,
      (select a.c a, b.c b from unnest(array['type','workspace_id']::text[]) a(c), unnest(array['type','workspace_id']::text[]) b(c) where a.c<>b.c) p group by 1,2,3) g group by a, b
union all
select 'dica.intelligence_runs' t, a, b, count(*) groups, sum(n) n_rows, sum(case when nb>1 then n else 0 end) violating from (
 select p.a, p.b, coalesce(j->>p.a,'<null>') av, count(distinct coalesce(j->>p.b,'<null>')) nb, count(*) n
 from (select to_jsonb(x) j from dica.intelligence_runs x where x.created_at < '2026-11-21T12:40:06Z') r,
      (select a.c a, b.c b from unnest(array['status','failure_code','fence','base_revision','workspace_id']::text[]) a(c), unnest(array['status','failure_code','fence','base_revision','workspace_id']::text[]) b(c) where a.c<>b.c) p group by 1,2,3) g group by a, b
union all
select 'dica.jobs' t, a, b, count(*) groups, sum(n) n_rows, sum(case when nb>1 then n else 0 end) violating from (
 select p.a, p.b, coalesce(j->>p.a,'<null>') av, count(distinct coalesce(j->>p.b,'<null>')) nb, count(*) n
 from (select to_jsonb(x) j from dica.jobs x where x.created_at < '2026-11-21T12:40:06Z') r,
      (select a.c a, b.c b from unnest(array['status','worker_dispatch_attempts','workspace_id']::text[]) a(c), unnest(array['status','worker_dispatch_attempts','workspace_id']::text[]) b(c) where a.c<>b.c) p group by 1,2,3) g group by a, b
union all
select 'dica.field_investigation_decisions' t, a, b, count(*) groups, sum(n) n_rows, sum(case when nb>1 then n else 0 end) violating from (
 select p.a, p.b, coalesce(j->>p.a,'<null>') av, count(distinct coalesce(j->>p.b,'<null>')) nb, count(*) n
 from (select to_jsonb(x) j from dica.field_investigation_decisions x where x.created_at < '2026-11-21T12:40:06Z') r,
      (select a.c a, b.c b from unnest(array['score','estimated_cost','gap_code','workspace_id']::text[]) a(c), unnest(array['score','estimated_cost','gap_code','workspace_id']::text[]) b(c) where a.c<>b.c) p group by 1,2,3) g group by a, b
order by 1,2,3;