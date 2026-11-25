# Routes: how UAC connects to a system

A **route** is one way of observing a kind of system (DNS and the web, a Postgres catalog, a Git repository, an
identity provider, HTTP or DNS probes). Everything after observation (claims, blind verification, independent
re-read, settlement, the read ladder and the Port) is shared. Adding a kind of system means adding one route.

## The contract

Every route is registered in `uac.routes` (a guarded substrate: changes need an owner-adopted formation) and must:

| Requirement | Checked by |
| --- | --- |
| Serve only declared, owner-signed scopes | `routes.every_scope_uses_a_registered_route` |
| Declare per-field coverage (what a capture covers, on what basis) | `routes.every_route_declares_coverage` |
| Have an installed collector (`sql:` function) or a committed service | `routes.every_sql_collector_exists`, `routes.every_collector_committed` |
| Never hold a credential: lease it from the broker | `routes.credentialed_collectors_go_through_the_broker`, K25 gates |
| Carry a per-run budget if it probes | `routes.probe_routes_are_budgeted` |
| Observe only: writes go through fenced effects, never a route | `routes.no_write_route_outside_the_effect_chain` |
| State its independent re-read route, or `none` | registry column `reread_route` |

A collector must also: seal each capture with content digests before anything reads it; record per-source status
(`sources`) so coverage can be judged field by field; refuse partial results it cannot certify (for example a
truncated listing) rather than store them as complete; and stay inside its budget.

## Adding a route

1. Copy `_template/` to `routes/<route>/` and fill in `route.json`, `coverage.json` and the collector.
2. Commit it. Collectors are installed from the repository, never written only into a live system.
3. Propose two formations: the route row (`uac.routes`) and its coverage rows (`uac.route_coverage`).
4. The owner adopts both with `owner-tools/`.
5. Declare a scope for a real target (owner-signed), capture once, and run the gate suite. The route counts as
   connected only when every route check passes and its first claims are blind-verified.

## Registered routes

See each `routes/<route>/route.json` (generated from the live registry).
