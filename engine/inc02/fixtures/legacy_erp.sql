-- Legacy ERP database. The port may read the catalog, read history, and probe inside rolled-back transactions.
create table items (sku text primary key, price numeric not null);
insert into items values ('A100', 12.50), ('B200', 40.00), ('C300', 7.25), ('D400', 99.00);
create table promos (code text primary key, pct numeric not null);
insert into promos values ('NONE', 0), ('SPRING', 0.10), ('CLEAR', 0.40);
create table quote_requests (id serial primary key, sku text not null, qty int not null, promo_code text not null,
                             warehouse text not null, memo text not null, operator text not null);
create view quote_view as
  select r.id,
         round(r.qty * i.price * (1 - p.pct), 2) as line_total,
         round(case r.warehouse when 'W1' then 5 when 'W2' then 9 else 0 end + 0.01 * r.qty * i.price * (1 - p.pct), 2) as shipping,
         (r.qty * i.price * (1 - p.pct)) > 2000 as needs_approval,
         r.memo as memo_out,
         clock_timestamp()::text as computed_at
  from quote_requests r join items i on i.sku = r.sku join promos p on p.code = r.promo_code;
insert into quote_requests (sku, qty, promo_code, warehouse, memo, operator)
  select (array['A100','B200','C300','D400'])[1 + (g % 4)], 1 + (g * 7) % 9, (array['NONE','SPRING','CLEAR'])[1 + (g % 3)],
         (array['W1','W2','W3'])[1 + ((g * 5) % 3)], (array['rush','std','gift'])[1 + (g % 3)], (array['ann','bo','cy','di'])[1 + (g % 4)]
  from generate_series(1, 40) g;
-- Negative references
create view neg_constant as select r.id, 10.0::numeric as line_total, 1.0::numeric as shipping, false as needs_approval from quote_requests r;
create view neg_echo as select r.id, r.sku as sku, r.qty as qty, r.promo_code as promo_code, r.warehouse as warehouse, r.memo as memo, r.operator as operator from quote_requests r;
create view neg_clip as
  select r.id, least(round(r.qty * i.price, 2), 1.0) as line_total, 0.0::numeric as shipping, false as needs_approval
  from quote_requests r join items i on i.sku = r.sku;
