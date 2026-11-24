-- The durable ledger: lives in its own database, backed up and restored separately
-- from application databases, and never rolled back with them.
create table issuers  (issuer_id text primary key, pubkey bytea not null, root_gen int not null, status text not null default 'active' check (status in ('active','revoked')));
create table recovery (id int primary key default 1 check (id = 1), pubkey bytea not null);
create table state    (id int primary key default 1 check (id = 1), authority_epoch bigint not null default 1);
create table consumed (grant_id uuid primary key, consumed_at timestamptz not null default now());
insert into state default values;
