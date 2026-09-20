# Codestra PostgreSQL Exporter Authority

Principal repository: `ingtrader21-spec/Codestra-Postgres-Exporter`

Private service identity: `postgres-exporter:9187`

No public service hostname is currently assigned or required.

## Ownership

This repository owns PostgreSQL Exporter configuration, upstream provenance, least-privilege monitoring connection policy, metric exposure validation and upgrade runbooks.

It does not own PostgreSQL runtime administration, application databases, Prometheus scrape configuration, Grafana dashboards, Alertmanager routing, infrastructure composition, edge routing or secrets.

## Exposure

Private/internal only. The native exporter port must not be published to a host public interface or exposed through Caddy/Kong. Prometheus is the approved routine consumer.

## Database safety

- Use a dedicated monitoring identity.
- Prefer the built-in `pg_monitor` role plus only explicitly reviewed database CONNECT grants.
- Forbid superuser, database-owner, replication administration and application-write privileges.
- Require encrypted database transport where supported.
- Load connection material from runtime secret files; never commit connection strings or passwords.
- Custom queries require explicit review for cost, lock behavior, sensitive columns and metric cardinality.

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

Promotion: work -> development -> test -> staging -> production -> main.
