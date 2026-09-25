# Codestra PostgreSQL Exporter Authority

Principal repository: `appolon1908-hue/Codestra-Postgres-Exporter`

Public DNS identity: none

Private service identity: `postgres-exporter:9187`

## Ownership

This repository owns PostgreSQL Exporter configuration, upstream provenance, least-privilege monitoring connection policy, metric exposure validation and upgrade runbooks.

It does not own PostgreSQL runtime administration, application databases, Prometheus scrape configuration, Grafana dashboards, Alertmanager routing, infrastructure composition, edge routing or secrets.

## Exposure

The exporter has no public hostname and remains **private/internal only**. Its container-local service identity is the only routine monitoring address.

The native exporter port must not be published to a public host interface or exposed through Caddy/Kong for routine use. Prometheus is the approved routine consumer and should scrape through an approved private or network-restricted path.

## Database safety

- Use a dedicated monitoring identity.
- Prefer the built-in `pg_monitor` role plus only explicitly reviewed database CONNECT grants.
- Forbid superuser, database-owner, bypass-RLS, replication administration and application-write privileges.
- Require encrypted database transport where supported.
- Load connection material from runtime secret files; never commit connection strings or passwords.
- Custom queries require explicit review for cost, lock behavior, sensitive columns and metric cardinality.

## Required monitoring coverage

Baseline coverage includes connection count and saturation, transactions and transaction age, locks and blocked queries, deadlocks, database/table/index size, replication health and lag, WAL/checkpoint behavior, cache hit ratio, long-running transactions, vacuum/autovacuum health, dead tuples, reviewed bloat indicators, sequence exhaustion risk, and exporter health through `pg_up`.

## Activation evidence

Deployment remains disabled until all are proven:

1. immutable exporter image digest;
2. approved private observability/database network attachment;
3. runtime secret injection;
4. least-privilege database grants;
5. successful private scrape and `pg_up == 1`;
6. bounded cardinality and query-cost review;
7. Prometheus target remains pending until the evidence is accepted;
8. backup/rollback and source-to-runtime traceability.

## Branch policy

Persistent: `main`, `development`, `test`, `staging`, `production`.

Temporary: `feature/*`, `fix/*`, `upgrade/*`, `security/*`, `docs/*`, `hotfix/*`, optional `release/*`, `rollback/*`.

Promotion: work -> development -> test -> staging -> production -> main. Merge does not deploy.
