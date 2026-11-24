-- migration 20261124085602 r1_0002_total_event_order (root: rtkslhpxdcjoeqhucebp)
-- Total admission order, kept beside the immutable log (K24): every event gets a global sequence number at admission.
create table p0.event_order (seq bigint primary key, event_id uuid not null unique references p0.events(event_id), ordered_at timestamptz not null default clock_timestamp(),
  basis text not null default 'admission' check (basis in ('admission', 'backfill-insertion-order')));
-- backfill: within one admission timestamp, physical insertion order is the best available evidence of order
insert into p0.event_order (seq, event_id, basis)
select row_number() over (order by e.admitted_at, e.ctid), e.event_id, 'backfill-insertion-order' from p0.events e;
create sequence p0.event_order_seq;
select setval('p0.event_order_seq', (select max(seq) from p0.event_order));
create or replace function p0.order_event() returns trigger language plpgsql security definer set search_path to '' as $f$
begin
  insert into p0.event_order (seq, event_id) values (nextval('p0.event_order_seq'), new.event_id);
  return null;
end $f$;
create trigger events_total_order after insert on p0.events for each row execute function p0.order_event();
create or replace function p0.event_order_append_only() returns trigger language plpgsql as $f$ begin raise exception 'EVENT_ORDER_APPEND_ONLY'; end $f$;
create trigger event_order_append_only before update or delete on p0.event_order for each row execute function p0.event_order_append_only();
alter table p0.event_order enable row level security;
revoke all on p0.event_order from anon, authenticated;
grant select on p0.event_order to p0d, verifierd, portd, uapd;
create policy event_order_read on p0.event_order for select to p0d, verifierd, portd, uapd using (true);
insert into p0.table_owners (tbl, owner_role, note) values ('p0.event_order', 'p0d', 'global admission order of the immutable event log; append-only');
select count(*) as ordered, (select count(*) from p0.events) as events from p0.event_order;
