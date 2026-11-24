-- migration 20261124202324 k34_0001_formation_gating (root: rtkslhpxdcjoeqhucebp)
create table p0.substrates (tbl text primary key, description text not null);
insert into p0.substrates values
 ('uap.signal_patterns', 'how captured evidence is mapped to products and what each signal determines'),
 ('uap.heuristics', 'every heuristic and the authority it has'),
 ('uac.route_coverage', 'what each capture route covers, per field'),
 ('gates.laws', 'the laws conformance is scored against'),
 ('gates.law_evidence', 'which live checks evidence which law');
alter table p0.substrates enable row level security;
revoke all on p0.substrates from anon, authenticated;

create or replace function p0.substrate_digest(p_tbl text) returns text language plpgsql stable security definer set search_path to '' as $f$
declare d text;
begin
  execute format('select encode(extensions.digest(coalesce(string_agg(t, E''\n'' order by t), ''''), ''sha256''), ''hex'') from (select row_to_json(x)::text as t from %s x) q', p_tbl) into d;
  return d;
end $f$;

create table p0.substrate_state (tbl text primary key references p0.substrates(tbl), digest text not null, basis text not null, last_event uuid not null, updated_at timestamptz not null default now());
create trigger substrate_state_via_admission before insert or update or delete on p0.substrate_state for each row execute function p0.via_admission();
alter table p0.substrate_state enable row level security;
revoke all on p0.substrate_state from anon, authenticated;

create or replace function p0.substrate_guard() returns trigger language plpgsql as $f$
begin
  if coalesce(current_setting('p0.forming', true), '') <> 'on' then
    raise exception 'FORMATION_REQUIRED: % changes only through an owner-adopted formation', tg_table_schema || '.' || tg_table_name;
  end if;
  return case when tg_op = 'DELETE' then old else new end;
end $f$;
do $$ declare t text; begin
  for t in select tbl from p0.substrates loop
    execute format('create trigger substrate_guard before insert or update or delete on %s for each row execute function p0.substrate_guard()', t);
    execute format('alter table %s enable always trigger substrate_guard', t);
  end loop;
end $$;

insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('formation','(none)','BASELINED','p0d','{}','records a substrate''s current contents as the operator-established baseline (once per substrate)',true),
 ('formation','(none)','PROPOSED','p0d','{}','proposes exact row changes against the substrate''s current digest',true),
 ('formation','PROPOSED','ADOPTED','p0d','{OWNER}','the owner adopts the proposal; its changes are applied atomically',true),
 ('formation','PROPOSED','REJECTED','p0d','{}','not adopted; remembered',true);
select p0.generate_contracts();

create or replace function p0.apply_formation(p_stream uuid, p_state text, p_event uuid, p_payload jsonb) returns void language plpgsql security definer set search_path to '' as $f$
declare v_tbl text := p_payload->>'substrate'; ch jsonb; pk text[]; cond text; proposal jsonb;
begin
  if not exists (select 1 from p0.substrates s where s.tbl = v_tbl) then raise exception 'FORMATION_UNKNOWN_SUBSTRATE: %', v_tbl; end if;
  if p_state = 'ADOPTED' then
    select e.payload into proposal from p0.events e where e.stream_id = p_stream and e.event_kind = 'formation:(none)->PROPOSED';
    if coalesce(current_setting('p0.replaying', true), '') <> 'on' and p0.substrate_digest(v_tbl) <> proposal->>'digest_before' then
      raise exception 'FORMATION_STALE: % changed since the proposal', v_tbl; end if;
    pk := array(select a.attname::text from pg_index i join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any (i.indkey) where i.indrelid = v_tbl::regclass and i.indisprimary);
    perform set_config('p0.forming', 'on', true);
    for ch in select * from jsonb_array_elements(proposal->'changes') loop
      if ch->>'op' in ('delete', 'replace') then
        select string_agg(format('%I::text = %L', k, ch->'match'->>k), ' and ') into cond from unnest(pk) k;
        execute format('delete from %s where %s', v_tbl, cond);
      end if;
      if ch->>'op' in ('insert', 'replace') then
        execute format('insert into %s select * from jsonb_populate_record(null::%s, $1)', v_tbl, v_tbl) using ch->'row';
      end if;
    end loop;
    perform set_config('p0.forming', 'off', true);
  end if;
  insert into p0.substrate_state (tbl, digest, basis, last_event) values (v_tbl, p0.substrate_digest(v_tbl), case when p_state = 'ADOPTED' then 'owner-adopted' else 'operator baseline' end, p_event)
  on conflict on constraint substrate_state_pkey do update set digest = excluded.digest, basis = excluded.basis, last_event = excluded.last_event, updated_at = now();
end $f$;
revoke all on function p0.apply_formation(uuid, text, uuid, jsonb), p0.substrate_digest(text) from public, anon, authenticated;

do $$
declare def text; anchor text := E'  elsif machine = ''settlement'' then';
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  execute replace(def, anchor, E'  elsif machine = ''formation'' and to_state in (''BASELINED'', ''ADOPTED'') then\n'
    || E'    perform p0.apply_formation(stream_id, to_state, event_id, payload);\n' || anchor);
end $$;

create or replace function p0.propose_formation(p_substrate text, p_changes jsonb, p_rationale text) returns jsonb language plpgsql security definer set search_path to '' as $f$
declare sid uuid := gen_random_uuid(); r jsonb;
begin
  r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'formation:(none)->PROPOSED', 'stream_id', sid, 'subject_type', 'formation',
    'subject_id', p_substrate, 'payload', jsonb_build_object('substrate', p_substrate, 'changes', p_changes, 'rationale', p_rationale, 'digest_before', p0.substrate_digest(p_substrate)),
    'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
  return r || jsonb_build_object('formation', sid);
end $f$;
revoke all on function p0.propose_formation(text, jsonb, text) from public, anon, authenticated;

do $$ declare t text; begin
  for t in select tbl from p0.substrates loop
    perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'formation:(none)->BASELINED', 'stream_id', gen_random_uuid(),
      'subject_type', 'formation', 'subject_id', t, 'payload', jsonb_build_object('substrate', t, 'digest', p0.substrate_digest(t),
      'note', 'contents as built by the operator before formation gating; not owner-adopted'), 'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
  end loop;
end $$;
select tbl, basis, left(digest, 12) as digest from p0.substrate_state order by 1;
