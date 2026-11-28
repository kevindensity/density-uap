-- u07_0003 (root). Applied 28 Nov 2026, incident D22: uap.promote_read_ladder() was never scheduled, so after any
-- demotion a port never climbed back to the rung its evidence earns. Idempotent, one rung per call; three passes every 15 minutes.
select cron.schedule('uap-read-ladder-promotion', '*/15 * * * *', $$select uap.promote_read_ladder(); select uap.promote_read_ladder(); select uap.promote_read_ladder()$$);
