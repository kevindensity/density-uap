-- migration 20261121124512 uap_0007_operator_anchors (root: rtkslhpxdcjoeqhucebp)
create table uap.operator_anchors (
  id            uuid primary key default gen_random_uuid(),
  port_epoch_id uuid not null references uap.port_epochs(id),
  rule_pattern  text not null,
  verdict       text not null check (verdict in ('DESIGN_INVARIANT','NOT_CONFIRMED','REJECTED')),
  given_by      text not null,
  channel       text not null,
  given_at      timestamptz not null default now()
);
create function uap.forbid_anchor_mutation() returns trigger language plpgsql set search_path = '' as $$
begin raise exception 'APPEND_ONLY: operator anchors are superseded by new rows, never edited'; end $$;
create trigger operator_anchors_immutable before update or delete on uap.operator_anchors
  for each row execute function uap.forbid_anchor_mutation();
