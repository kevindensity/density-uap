-- migration s5_0001_standing_policy_expiry_and_exhaustion (root: rtkslhpxdcjoeqhucebp)
-- Standing policies could expire or be used up while the kernel's own record still said ACTIVE with used = 0.
-- The gateway refused correctly (it checks expiry and counts SENT in the ledger); the kernel's account did not.
-- 1. ACTIVE->EXPIRED becomes a transition; expiry and exhaustion are authority reductions mirrored to the ledger.
-- 2. Both guards are enforced at admission (they were prose): no early expiry, no exhaustion below the bound.
-- 3. p0.policy_watch() admits them from the always-on root every 5 minutes; uses are counted in the ledger, as the gateway does.
-- 4. The causal-access certificate stops trusting the stale `used` column.
-- 5. The projection can change only through admission, like every other kernel projection.

insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('standing_policy','ACTIVE','EXPIRED','p0d','{}','expires_at has passed (checked against the projection at admission)',true);
select p0.generate_contracts();

create or replace function p0.is_reducing(p_kind text) returns boolean language sql immutable set search_path to '' as $f$
  select p_kind in ('credential:EXPIRING->EXPIRED', 'credential:VALID->EXPIRED', 'node:ADMITTED->RETIRED', 'scope:DECLARED->REVOKED',
                    'secure_boot:ADMITTED->RETIRED', 'secure_boot:PROPOSED->WITHDRAWN', 'standing_policy:ACTIVE->EXHAUSTED', 'standing_policy:ACTIVE->REVOKED',
                    'standing_policy:ACTIVE->EXPIRED', 'ledger_continuity:CONTINUOUS->RESTORE_DETECTED') $f$;

do $m$
declare def text; nd text;
  anchor text := E'      update p0.standing_policies set status = to_state, last_event = event_id, updated_at = now() where standing_policies.stream_id = apply_projection.stream_id;';
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  nd := replace(def, anchor,
       E'      if to_state = ''EXPIRED'' and (select sp.expires_at from p0.standing_policies sp where sp.stream_id = apply_projection.stream_id) > now() then\n'
    || E'        raise exception using errcode = ''P0D01'', message = ''POLICY_NOT_YET_EXPIRED'';\n'
    || E'      end if;\n'
    || E'      if to_state = ''EXHAUSTED'' and (select count(*) from p0_ledger.sent s where s.request->>''policy'' = apply_projection.stream_id::text)\n'
    || E'           < (select sp.max_uses from p0.standing_policies sp where sp.stream_id = apply_projection.stream_id) then\n'
    || E'        raise exception using errcode = ''P0D01'', message = ''POLICY_NOT_EXHAUSTED'';\n'
    || E'      end if;\n'
    || E'      update p0.standing_policies set status = to_state, used = coalesce((payload->>''uses'')::int, standing_policies.used), last_event = event_id, updated_at = now() where standing_policies.stream_id = apply_projection.stream_id;');
  if nd = def then raise exception 'apply_projection anchor not found; nothing changed'; end if;
  execute nd;

  def := pg_get_functiondef('p0.causal_access_certificate(timestamptz)'::regprocedure);
  nd := replace(def, 'if pol.used < pol.max_uses or (select count(*)', 'if (select count(*)');
  if nd = def then raise exception 'causal_access_certificate anchor not found; nothing changed'; end if;
  execute nd;
end $m$;

comment on column p0.standing_policies.used is 'uses recorded at the last reduction event; the live count is SENT in the ledger (p0_ledger.sent), which the gateway and certificate use';

create or replace function p0.policy_watch() returns jsonb language plpgsql security definer set search_path to '' as $f$
declare p p0.standing_policies%rowtype; st record; n bigint; target text; res jsonb; out jsonb := '[]';
begin
  for p in select * from p0.standing_policies where status = 'ACTIVE' order by expires_at loop
    select count(*) into n from p0_ledger.sent s where s.request->>'policy' = p.stream_id::text;
    target := case when p.expires_at <= now() then 'EXPIRED' when n >= p.max_uses then 'EXHAUSTED' end;
    continue when target is null;
    select revision, head_digest, subject_id into st from p0.streams where stream_id = p.stream_id;
    res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'standing_policy:ACTIVE->' || target, 'stream_id', p.stream_id,
      'subject_type', 'standing_policy', 'subject_id', st.subject_id,
      'payload', jsonb_build_object('expires_at', p.expires_at, 'uses', n, 'max_uses', p.max_uses, 'observed_at', now()),
      'references', '[]'::jsonb, 'authority_epoch', p0.current_epoch(), 'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
    out := out || jsonb_build_object('policy', p.stream_id, 'to', target, 'uses', n, 'decision', res->>'decision', 'reason', res->>'reason');
  end loop;
  return out;
end $f$;
revoke all on function p0.policy_watch() from public, anon, authenticated;

create trigger standing_policies_via_admission before insert or update or delete on p0.standing_policies for each row execute function p0.via_admission();

select cron.schedule('p0-policy-watch', '*/5 * * * *', $$select p0.policy_watch()$$);
