-- migration 20261123211657 s3_0005_discovery_filter_and_receipt_table (root: rtkslhpxdcjoeqhucebp)
-- discovery quality rule: shared values cover at least half of the smaller side; never test an array against a single value
do $$
declare def text; old text := 'on (a.scope, a.path) <> (b.scope, b.path) and a.vals && b.vals';
begin
  def := pg_get_functiondef('uap.discover_capture_claims()'::regprocedure);
  if position(old in def) = 0 then raise exception 'DISCOVERY_LAYOUT_CHANGED'; end if;
  execute replace(def, old, old || E'\n       and (select count(*) from unnest(a.vals) x where x = any (b.vals))::numeric / least(cardinality(a.vals), cardinality(b.vals)) >= 0.5\n       and not (cardinality(b.vals) = 1 and cardinality(a.vals) > 1)');
end $$;
delete from uap.capture_claims c where c.origin = 'discovered' and not exists (select 1 from sem.settlements s where s.consequence_key = c.consequence_key);

-- receipts the verifier signs for pending capture claims; it writes them, the kernel admits matching ones
create table verify.kernel_receipts (
  stream_id uuid primary key, consequence_key text not null, event_kind text not null, identity_digest text not null,
  key_id text not null, sig text not null, basis jsonb not null, signed_at timestamptz not null default now(), admitted_event uuid);
alter table verify.kernel_receipts enable row level security;
revoke all on verify.kernel_receipts from anon, authenticated;
grant select on verify.kernel_receipts to uacd, uapd, verifierd, p0d, gatewayd, portd;
grant insert, update on verify.kernel_receipts to verifierd;
create policy verify_kernel_receipts_read on verify.kernel_receipts for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy verify_kernel_receipts_write on verify.kernel_receipts for all to verifierd using (true) with check (true);
insert into p0.table_owners (tbl, owner_role, note) values ('verify.kernel_receipts', 'verifierd', 'verifier-signed receipts awaiting kernel admission');
grant execute on function uap.claim_submission(text) to verifierd;

create or replace function uap.admit_receipted_claims() returns jsonb language plpgsql security definer set search_path to '' as $function$
declare r record; sub jsonb; res jsonb; n int := 0; out jsonb := '[]';
begin
  for r in select * from verify.kernel_receipts where admitted_event is null loop
    sub := uap.claim_submission(r.consequence_key);
    if sub ? 'error' or sub->>'stream_id' <> r.stream_id::text or sub->>'event_kind' <> r.event_kind or p0.event_identity(sub) <> r.identity_digest then
      out := out || jsonb_build_array(jsonb_build_object('claim', r.consequence_key, 'decision', 'SKIPPED', 'reason', 'SUBMISSION_NO_LONGER_MATCHES_RECEIPT'));
      continue;
    end if;
    res := p0.admit_event(sub || jsonb_build_object('receipts', jsonb_build_array(jsonb_build_object('role', 'VERIFIER', 'key_id', r.key_id, 'sig', r.sig))));
    if res->>'decision' = 'ACCEPT' then
      update verify.kernel_receipts set admitted_event = (sub->>'event_id')::uuid where stream_id = r.stream_id; n := n + 1;
    else out := out || jsonb_build_array(jsonb_build_object('claim', r.consequence_key, 'result', res)); end if;
  end loop;
  return jsonb_build_object('admitted', n, 'not_admitted', out);
end $function$;
revoke all on function uap.admit_receipted_claims() from public, anon, authenticated;
grant execute on function uap.admit_receipted_claims() to p0d;

select uap.discover_capture_claims() as rediscovery, (select count(*) from uap.capture_claims where origin = 'discovered') as kept;
