-- migration 20261126011610 verify_0001_record_sweep_refusals (root: rtkslhpxdcjoeqhucebp)
create table verify.sweep_refusals (id bigserial primary key, refused_at timestamptz not null default clock_timestamp(),
  consequence_key text not null, reason text not null, detail jsonb);
create index on verify.sweep_refusals (consequence_key, refused_at desc);
create trigger sweep_refusals_append_only before update or delete on verify.sweep_refusals for each row execute function p0.event_order_append_only();
alter table verify.sweep_refusals enable row level security;
revoke all on verify.sweep_refusals from anon, authenticated;
do $$
declare def text; old text := $a$  if r.status = 200 and left(ltrim(coalesce(r.content, '')), 1) = '{' then
$a$;
begin
  def := pg_get_functiondef('uap.trigger_verifier_sweep_once()'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, old, old || $a$    -- every refusal is kept with its reason: a refusal is evidence about a claim, not noise
    insert into verify.sweep_refusals (consequence_key, reason, detail)
    select coalesce(x->>'claim', '?'), coalesce(x->>'reason', 'UNSPECIFIED'), x->'detail' from jsonb_array_elements(coalesce(r.content::jsonb->'refused', '[]')) x;
$a$);
end $$;
