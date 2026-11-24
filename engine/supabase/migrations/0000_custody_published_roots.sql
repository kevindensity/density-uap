-- Append-only publication ledger for custody roots. Rows can be inserted, never updated or deleted.
create schema if not exists custody;
create table custody.published_roots (
  id               bigserial primary key,
  vault_id         text not null,
  seq              integer not null,
  run_id           text not null unique,
  campaign         text not null,
  kind             text not null check (kind in ('ORIGINAL_FREEZE','RECEIVED_ARTIFACT','SUPERSEDES')),
  merkle_root      text not null check (merkle_root ~ '^[0-9a-f]{64}$'),
  manifest_sha256  text not null check (manifest_sha256 ~ '^[0-9a-f]{64}$'),
  entry_hash       text not null unique check (entry_hash ~ '^[0-9a-f]{64}$'),
  prev_entry_hash  text,
  signer_pub       text,
  signature        text,
  published_at     timestamptz not null default now(),
  unique (vault_id, seq)
);

-- The chain must extend the vault's current head: no forks, no gaps.
create function custody.guard_chain() returns trigger language plpgsql as $$
declare last custody.published_roots%rowtype;
begin
  select * into last from custody.published_roots where vault_id = new.vault_id order by seq desc limit 1;
  if found then
    if new.prev_entry_hash is distinct from last.entry_hash or new.seq <> last.seq + 1 then
      raise exception 'CHAIN_FORK: seq % does not extend head %', new.seq, last.seq;
    end if;
  elsif new.prev_entry_hash is not null and new.seq = 0 then
    raise exception 'CHAIN_FORK: genesis entry cannot have a predecessor';
  end if;
  return new;
end $$;
create trigger published_roots_chain before insert on custody.published_roots
  for each row execute function custody.guard_chain();

create function custody.forbid_mutation() returns trigger language plpgsql as $$
begin raise exception 'APPEND_ONLY: published roots cannot be changed or removed'; end $$;
create trigger published_roots_immutable before update or delete on custody.published_roots
  for each row execute function custody.forbid_mutation();

-- Supabase: everyone may read published roots; only the service role inserts.
alter table custody.published_roots enable row level security;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'create policy read_roots on custody.published_roots for select using (true)';
  end if;
end $$;
