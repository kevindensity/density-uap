-- migration 20261124084351 l4_0002_includes_corroboration_and_honest_web_signal (root: rtkslhpxdcjoeqhucebp)
-- the original collector's web_script_hosts holds hosts from ANY src or href attribute, so it shows a reference, not loaded code
update uap.signal_patterns set basis = 'attribution-ambiguous',
  determines = format('the website''s HTML references %s (in a src or href attribute)', product),
  orbit = jsonb_build_array(format('the website loads %s code', product), format('the website only links to %s', product))
 where path = 'web_script_hosts[]';

-- corroboration covers includes claims too, with the compiler's semantics: every left value appears among the right values
create or replace function uap.corroborate_claims() returns jsonb language plpgsql security definer set search_path to '' as $f$
declare r record; lb jsonb; rb jsonb; lr record; rr2 record; target text; detail jsonb; sid uuid; st record; tally jsonb := '{}'; reread_value boolean;
  ltop text; rtop text; route text; digests text;
begin
  for r in select c.consequence_key, c.spec, c.port_scope, s.id as settlement_id, s.status::text as status
             from uap.capture_claims c join sem.settlements s on s.consequence_key = c.consequence_key join uac.scopes sc on sc.stream_id = c.port_scope
            where sc.kind = 'domain' and c.spec->>'op' in ('contains', 'includes') and s.status::text in ('SETTLED_TRUE', 'SETTLED_FALSE') loop
    lr := null; rr2 := null; reread_value := null; target := 'NOT_REREAD';
    select * into lr from uac.reread_captures x where x.scope_stream = (r.spec->'left'->>'scope')::uuid and x.observed_at > now() - interval '2 days' order by x.observed_at desc limit 1;
    ltop := split_part(split_part(r.spec->'left'->>'path', '[', 1), '.', 1);
    if r.spec->>'op' = 'contains' then
      if lr.content_digest is not null and lr.body ? ltop then
        reread_value := exists (select 1 from uap.capture_values(lr.body, r.spec->'left'->>'path') v where position(lower(r.spec->>'needle') in lower(v)) > 0);
      end if;
      route := lr.route; digests := lr.content_digest;
    else
      select * into rr2 from uac.reread_captures x where x.scope_stream = (r.spec->'right'->>'scope')::uuid and x.observed_at > now() - interval '2 days' order by x.observed_at desc limit 1;
      rtop := split_part(split_part(r.spec->'right'->>'path', '[', 1), '.', 1);
      if lr.content_digest is not null and rr2.content_digest is not null and lr.body ? ltop and rr2.body ? rtop then
        reread_value := not exists (select uap.capture_values(lr.body, r.spec->'left'->>'path') except select uap.capture_values(rr2.body, r.spec->'right'->>'path'));
      end if;
      route := lr.route; digests := concat_ws(',', lr.content_digest, rr2.content_digest);
    end if;
    if reread_value is not null then target := case when reread_value = (r.status = 'SETTLED_TRUE') then 'CORROBORATED' else 'CONTRADICTED' end; end if;
    detail := jsonb_build_object('settled_value', r.status = 'SETTLED_TRUE', 'reread_value', reread_value, 'op', r.spec->>'op',
                                 'fields', jsonb_build_array(r.spec->'left'->>'path', r.spec->'right'->>'path') - 'null');
    sid := md5('corroboration:' || r.settlement_id::text)::uuid;
    select revision, head_digest, state into st from p0.streams where stream_id = sid;
    if st.state is null or st.state <> target then
      perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'corroboration:' || coalesce(st.state, '(none)') || '->' || target,
        'stream_id', sid, 'subject_type', 'corroboration', 'subject_id', r.consequence_key,
        'payload', jsonb_build_object('claim', r.consequence_key, 'settlement_id', r.settlement_id, 'route', route, 'reread_digest', digests, 'detail', detail),
        'authority_epoch', p0.current_epoch(), 'expected_revision', coalesce(st.revision, 0)::text, 'expected_predecessor', st.head_digest));
    end if;
    tally := tally || jsonb_build_object(target, coalesce((tally->>target)::int, 0) + 1);
  end loop;
  return tally;
end $f$;
revoke all on function uap.corroborate_claims() from public, anon, authenticated;
