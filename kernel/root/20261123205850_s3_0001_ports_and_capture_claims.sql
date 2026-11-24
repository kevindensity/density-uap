-- migration 20261123205850 s3_0001_ports_and_capture_claims (root: rtkslhpxdcjoeqhucebp)
-- S3 steps 1-3: ports compiled from captures, capture-backed claims settled by the verifier, claim-relative drift.

insert into verify.keys (key_id, role) values ('verifier-1', 'VERIFIER'), ('uap-compiler', 'SYNTHESIZER') on conflict do nothing;

create table uap.scope_ports (scope_stream uuid primary key references uac.scopes, port_id uuid not null unique references uap.ports);
create trigger scope_ports_via_admission before insert or update or delete on uap.scope_ports for each row execute function p0.via_admission();
alter table uap.scope_ports enable row level security;
revoke all on uap.scope_ports from anon, authenticated;
grant select on uap.scope_ports to uacd, uapd, verifierd, p0d, gatewayd, portd;
create policy uap_scope_ports_read on uap.scope_ports for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);

create table uap.capture_claims (consequence_key text primary key, evaluator text not null, port_scope uuid not null references uac.scopes, scopes uuid[] not null, description text not null);
alter table uap.capture_claims enable row level security;
revoke all on uap.capture_claims from anon, authenticated;
grant select on uap.capture_claims to uacd, uapd, verifierd, p0d, gatewayd, portd;
create policy uap_capture_claims_read on uap.capture_claims for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
insert into p0.table_owners (tbl, owner_role, note) values
 ('uap.scope_ports','p0d','kernel projection: port compiled for a declared scope'),
 ('uap.capture_claims','p0d','registry of capture-backed claims (changed only by migration)');
insert into uap.capture_claims values
 ('xsys:github head of kevindensity/density-lens-production equals the observatory current snapshot commit', 'K1', '5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e903',
  array['5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e901','5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e903']::uuid[], 'cross-system identity between the observatory and the repository it observes'),
 ('xsys:every observatory refresh run published the snapshot it expected', 'K2', '5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e901',
  array['5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e901']::uuid[], 'refresh runs whose expected snapshot is set must publish that snapshot'),
 ('xsys:every observatory snapshot has a publication receipt', 'K3', '5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e901',
  array['5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e901']::uuid[], 'every snapshot row is covered by a publication receipt'),
 ('xsys:every migration applied in the observatory exists on codespace main', 'K4', '5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e902',
  array['5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e901','5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e902']::uuid[], 'each applied migration has its file under supabase/migrations on the default branch');

-- latest capture per scope, and the claim evaluator (the compiler's view; the verifier recomputes independently)
create or replace function uap.latest_capture(p_scope uuid) returns table (digest text, body jsonb) language sql stable security definer set search_path to '' as $$
  select c.content_digest, b.body from uac.captures c join uac.capture_bodies b using (content_digest) where c.scope_stream = p_scope order by c.recorded_at desc limit 1 $$;

create or replace function uap.eval_capture_claim(p_key text) returns jsonb language plpgsql stable security definer set search_path to '' as $function$
declare cl uap.capture_claims%rowtype; obs jsonb; od text; dlp jsonb; dd text; cs jsonb; cd text; v boolean; detail jsonb := '{}'; digests jsonb := '{}'; s uuid;
begin
  select * into cl from uap.capture_claims where consequence_key = p_key;
  if not found then return jsonb_build_object('error', 'UNKNOWN_CLAIM'); end if;
  select l.digest, l.body into od, obs from uap.latest_capture('5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e901') l;
  select l.digest, l.body into cd, cs from uap.latest_capture('5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e902') l;
  select l.digest, l.body into dd, dlp from uap.latest_capture('5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e903') l;
  if cl.evaluator = 'K1' then
    v := (select sn->>'commit_sha' from jsonb_array_elements(obs->'snapshots') sn
           where sn->>'id' = (select r->>'current_snapshot_id' from jsonb_array_elements(obs->'repositories') r where r->>'full_name' = 'kevindensity/density-lens-production'))
         = dlp->>'head';
    detail := jsonb_build_object('github_head', dlp->>'head');
  elsif cl.evaluator = 'K2' then
    detail := jsonb_build_object('mismatched_runs', coalesce((select jsonb_agg(x->>'run_key') from jsonb_array_elements(obs->'refresh_runs') x
              where x->>'expected_snapshot_id' is not null and x->>'expected_snapshot_id' is distinct from x->>'snapshot_id'), '[]'));
    v := jsonb_array_length(detail->'mismatched_runs') = 0;
  elsif cl.evaluator = 'K3' then
    detail := jsonb_build_object('uncovered_snapshots', coalesce((select jsonb_agg(sn->>'id') from jsonb_array_elements(obs->'snapshots') sn
              where not exists (select 1 from jsonb_array_elements(obs->'receipts') r where r->>'snapshot_id' = sn->>'id')), '[]'));
    v := jsonb_array_length(detail->'uncovered_snapshots') = 0;
  elsif cl.evaluator = 'K4' then
    detail := jsonb_build_object('missing_on_main', coalesce((select jsonb_agg((m->>'version') || '_' || (m->>'name') order by m->>'version') from jsonb_array_elements(obs->'migrations') m
              where not (cs->'files') ? ('supabase/migrations/' || (m->>'version') || '_' || (m->>'name') || '.sql')), '[]'));
    v := jsonb_array_length(detail->'missing_on_main') = 0;
  end if;
  foreach s in array cl.scopes loop
    digests := digests || jsonb_build_object(s::text, (select l.digest from uap.latest_capture(s) l));
  end loop;
  return jsonb_build_object('value', v, 'capture_digests', digests, 'detail', detail,
    'live_class_hash', 'captures:' || (select string_agg(k || '=' || (digests->>k), ',' order by k) from jsonb_object_keys(digests) k));
end $function$;

-- port machine
insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('port','(none)','CONNECTED','uapd','{}','a port compiled for a declared scope that has at least one admitted capture',true),
 ('port','CONNECTED','UNDERSTOOD','uapd','{}','uap.guard_ladder requires a settled consequence in the current epoch, itself admitted on a verifier receipt',true);
select p0.generate_contracts();

-- projections: port machine; settlement strengthening writes the bound refinement receipt
do $$
declare def text; anchor text := E'  elsif machine = ''settlement'' then';
  upd text := E'      update sem.settlements set status = to_state::public.evidence_status, updated_at = now() where id = apply_projection.stream_id;';
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  if position(anchor in def) = 0 or position(upd in def) = 0 or position('declare cur text;' in def) = 0 then raise exception 'PROJECTION_LAYOUT_CHANGED'; end if;
  def := replace(def, 'declare cur text;', 'declare cur text; vkey text; rid uuid;');
  def := replace(def, upd,
       E'      if to_state in (''SETTLED_TRUE'', ''SETTLED_FALSE'') then\n'
    || E'        select r->>''key_id'' into vkey from p0.events e, jsonb_array_elements(e.receipts) r where e.event_id = apply_projection.event_id and r->>''role'' = ''VERIFIER'' limit 1;\n'
    || E'        insert into verify.refinement_receipts (id, port_epoch_id, consequence_key, live_class_hash, constant_value, verifier_key_id, synthesizer_key_id, signature_verified, probe_action_ids, issued_at)\n'
    || E'        select gen_random_uuid(), st.port_epoch_id, st.consequence_key, payload->>''live_class_hash'', case when to_state = ''SETTLED_TRUE'' then ''true'' else ''false'' end,\n'
    || E'               vkey, ''uap-compiler'', true, ''{}'', now() from sem.settlements st where st.id = apply_projection.stream_id returning id into rid;\n'
    || E'        update sem.settlements set status = to_state::public.evidence_status, refinement_id = rid, live_class_hash = payload->>''live_class_hash'', updated_at = now() where id = apply_projection.stream_id;\n'
    || E'      else\n'
    || E'        update sem.settlements set status = to_state::public.evidence_status, updated_at = now() where id = apply_projection.stream_id;\n'
    || E'      end if;');
  def := replace(def, anchor, E'  elsif machine = ''port'' then\n'
    || E'    if to_state = ''CONNECTED'' then\n'
    || E'      if not exists (select 1 from uac.captures c where c.scope_stream = (payload->>''scope_stream'')::uuid) then raise exception using errcode = ''P0D01'', message = ''NO_CAPTURE_FOR_SCOPE''; end if;\n'
    || E'      insert into core.systems (id, name) values ((payload->>''system_id'')::uuid, payload->>''system_name'') on conflict (id) do nothing;\n'
    || E'      insert into uap.port_epochs (id, system_id, epoch_no, roots_hash) values ((payload->>''epoch_id'')::uuid, (payload->>''system_id'')::uuid, 1, payload->>''roots_hash'');\n'
    || E'      insert into uap.ports (id, system_id, port_type, ladder_level, current_epoch) values (stream_id, (payload->>''system_id'')::uuid, payload->>''port_type'', ''CONNECTED'', (payload->>''epoch_id'')::uuid);\n'
    || E'      insert into uap.scope_ports (scope_stream, port_id) values ((payload->>''scope_stream'')::uuid, stream_id);\n'
    || E'    else\n'
    || E'      update uap.ports set ladder_level = to_state where id = apply_projection.stream_id;\n'
    || E'    end if;\n'
    || anchor);
  execute def;
end $$;

-- compile ports and pending claims from captures
create or replace function uap.compile_capture_ports() returns jsonb language plpgsql security definer set search_path to '' as $function$
declare sc record; cl record; res jsonb; ep text := (select authority_epoch::text from p0_ledger.state where id = 1); n_ports int := 0; n_claims int := 0; out jsonb := '[]';
begin
  for sc in select s.* from uac.scopes s where s.status = 'DECLARED' and not exists (select 1 from uap.scope_ports p where p.scope_stream = s.stream_id)
            and exists (select 1 from uac.captures c where c.scope_stream = s.stream_id) loop
    res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'port:(none)->CONNECTED', 'stream_id', gen_random_uuid(),
      'subject_type', 'port', 'subject_id', 'port:' || sc.locator,
      'payload', jsonb_build_object('scope_stream', sc.stream_id, 'system_id', gen_random_uuid(), 'system_name', sc.system, 'epoch_id', gen_random_uuid(),
                                    'port_type', 'OBSERVATION', 'roots_hash', (select l.digest from uap.latest_capture(sc.stream_id) l)),
      'authority_epoch', ep, 'expected_revision', '0'));
    out := out || jsonb_build_array(jsonb_build_object('port', sc.locator, 'decision', res->>'decision', 'reason', res->>'reason'));
    if res->>'decision' = 'ACCEPT' then n_ports := n_ports + 1; end if;
  end loop;
  for cl in select c.*, p.current_epoch from uap.capture_claims c join uap.scope_ports sp on sp.scope_stream = c.port_scope join uap.ports p on p.id = sp.port_id
            where not exists (select 1 from sem.settlements s where s.port_epoch_id = p.current_epoch and s.consequence_key = c.consequence_key) loop
    res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'settlement:(none)->UNRESOLVED', 'stream_id', gen_random_uuid(),
      'subject_type', 'settlement', 'subject_id', cl.consequence_key,
      'payload', jsonb_build_object('port_epoch_id', cl.current_epoch, 'consequence_key', cl.consequence_key, 'live_class_hash', 'pending'),
      'authority_epoch', ep, 'expected_revision', '0'));
    out := out || jsonb_build_array(jsonb_build_object('claim', cl.evaluator, 'decision', res->>'decision', 'reason', res->>'reason'));
    if res->>'decision' = 'ACCEPT' then n_claims := n_claims + 1; end if;
  end loop;
  return jsonb_build_object('ports_connected', n_ports, 'claims_created', n_claims, 'detail', out);
end $function$;

-- the strengthening submission the verifier is asked to sign (value and evidence from the compiler's evaluation)
create or replace function uap.claim_submission(p_key text) returns jsonb language plpgsql stable security definer set search_path to '' as $function$
declare st record; ev jsonb := uap.eval_capture_claim(p_key);
begin
  select s.id, s.status::text as status, k.revision, k.head_digest into st from sem.settlements s join p0.streams k on k.stream_id = s.id
   where s.consequence_key = p_key and s.status = 'UNRESOLVED';
  if not found then return jsonb_build_object('error', 'NO_UNRESOLVED_SETTLEMENT'); end if;
  return jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'settlement:UNRESOLVED->' || case when (ev->>'value')::boolean then 'SETTLED_TRUE' else 'SETTLED_FALSE' end,
    'stream_id', st.id, 'subject_type', 'settlement', 'subject_id', p_key,
    'payload', jsonb_build_object('constant_value', ev->'value', 'live_class_hash', ev->>'live_class_hash', 'capture_digests', ev->'capture_digests', 'detail', ev->'detail'),
    'authority_epoch', (select authority_epoch::text from p0_ledger.state where id = 1), 'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest);
end $function$;

-- ladder promotion once a settled consequence exists
create or replace function uap.promote_capture_ports() returns jsonb language plpgsql security definer set search_path to '' as $function$
declare p record; res jsonb; out jsonb := '[]';
begin
  for p in select pt.id, k.revision, k.head_digest, sp.scope_stream from uap.scope_ports sp join uap.ports pt on pt.id = sp.port_id join p0.streams k on k.stream_id = pt.id
           where pt.ladder_level = 'CONNECTED' and exists (select 1 from sem.settlements s where s.port_epoch_id = pt.current_epoch and s.status in ('SETTLED_TRUE','SETTLED_FALSE')) loop
    res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'port:CONNECTED->UNDERSTOOD', 'stream_id', p.id,
      'subject_type', 'port', 'subject_id', 'port:' || (select locator from uac.scopes where stream_id = p.scope_stream), 'payload', '{}'::jsonb,
      'authority_epoch', (select authority_epoch::text from p0_ledger.state where id = 1), 'expected_revision', p.revision::text, 'expected_predecessor', p.head_digest));
    out := out || jsonb_build_array(jsonb_build_object('port', p.id, 'decision', res->>'decision', 'state', res->>'state', 'reason', res->>'reason'));
  end loop;
  return out;
end $function$;

-- claim-relative drift: weaken a settled capture claim only when its value changes
create or replace function uap.capture_claim_drift() returns jsonb language plpgsql security definer set search_path to '' as $function$
declare s record; ev jsonb; res jsonb; n_checked int := 0; n_demoted int := 0;
begin
  for s in select st.id, st.consequence_key, st.status::text as status, k.revision, k.head_digest from sem.settlements st
             join uap.capture_claims c on c.consequence_key = st.consequence_key join p0.streams k on k.stream_id = st.id
            where st.status in ('SETTLED_TRUE','SETTLED_FALSE') loop
    n_checked := n_checked + 1;
    ev := uap.eval_capture_claim(s.consequence_key);
    if (ev->>'value') is null or ((ev->>'value')::boolean <> (s.status = 'SETTLED_TRUE')) then
      res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'settlement:' || s.status || '->UNRESOLVED', 'stream_id', s.id,
        'subject_type', 'settlement', 'subject_id', s.consequence_key,
        'payload', jsonb_build_object('reason', 'CAPTURE_CLAIM_CHANGED', 'now', ev->'value', 'capture_digests', ev->'capture_digests', 'detail', ev->'detail'),
        'authority_epoch', (select authority_epoch::text from p0_ledger.state where id = 1), 'expected_revision', s.revision::text, 'expected_predecessor', s.head_digest));
      if res->>'decision' = 'ACCEPT' then n_demoted := n_demoted + 1; end if;
    end if;
  end loop;
  return jsonb_build_object('checked', n_checked, 'demoted', n_demoted);
end $function$;

revoke all on function uap.latest_capture(uuid), uap.eval_capture_claim(text), uap.compile_capture_ports(), uap.claim_submission(text),
  uap.promote_capture_ports(), uap.capture_claim_drift() from public, anon, authenticated;
grant execute on function uap.compile_capture_ports(), uap.claim_submission(text), uap.promote_capture_ports(), uap.capture_claim_drift() to p0d;
grant execute on function uap.eval_capture_claim(text), uap.latest_capture(uuid) to p0d, verifierd;

select cron.schedule('uap-capture-claim-drift-daily', '40 6 * * *', $$select uap.capture_claim_drift()$$);
