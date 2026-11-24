-- Generic templates. {T} table, {TS} time column, {CUT} cutoff, {COLS} column array literal.
-- M0 profile
with r as (select to_jsonb(t) j from {T} t where t.{TS} < '{CUT}'),
cols as (select unnest({COLS}::text[]) c)
select c as col, count(distinct j->>c) as n_distinct, count(*) filter (where j->>c is null) as n_null, count(*) as n_rows
from r, cols group by c order by c;
-- M1 functional dependencies (synthesizer)
with r as (select to_jsonb(t) j from {T} t where t.{TS} < '{CUT}'),
cols as (select unnest({COLS}::text[]) c), pairs as (select a.c a, b.c b from cols a, cols b where a.c <> b.c),
g as (select p.a, p.b, coalesce(r.j->>p.a,'<null>') av, count(distinct coalesce(r.j->>p.b,'<null>')) nb, count(*) n from r, pairs p group by 1,2,3)
select a, b, count(*) as groups, sum(n) as rows, sum(case when nb > 1 then n else 0 end) as violating_rows from g group by a, b;
-- M1 verifier (independent formulation): counterexample pairs by self-join
-- select count(*) from {T} x join {T} y on x.{A} is not distinct from y.{A} and x.{B} is distinct from y.{B}
--   where x.{TS} < '{CUT}' and y.{TS} < '{CUT}';
