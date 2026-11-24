-- A projection licenses a use only on the port's CURRENT epoch: no standing carries across drift or rotation.
create function uap.grant_permitted(p_port uuid, p_projection uuid, p_use text) returns boolean language sql stable as $$
  select exists (select 1 from uap.ports po join uap.projection_standings ps on ps.port_epoch_id = po.current_epoch
                 where po.id = p_port and ps.id = p_projection) and uap.use_permitted(p_projection, p_use);
$$;
