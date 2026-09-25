# Repository profile — Codestra PostgreSQL Exporter

- Principal repository: `appolon1908-hue/Codestra-Postgres-Exporter`
- Component ID: `postgres-exporter`
- Purpose: expose bounded PostgreSQL operational metrics through a dedicated least-privilege monitoring role
- Non-goals: database administration, application queries, business data access, public HTTP/DNS exposure or writes
- Branch path: `feature/* -> development -> test -> staging -> production -> main`
- Configuration authority: `config/`, `deploy/compose.yaml` and `docs/create-monitoring-role.sql`
- Upstream: `prometheus-community/postgres_exporter` v0.20.1, tag commit `867fbcac31cd18c143e244190ea9168cca069827`
- Runtime: `quay.io/prometheuscommunity/postgres-exporter@sha256:ac5ec343104fae0e2d84a27bb8d69b38430a11910c5382cad85d478d2bab713e`
- Artifact model: verified upstream image plus signed Codestra configuration artifact
- Entrypoint: upstream `postgres_exporter`
- Health/readiness: private `/metrics`; `pg_up == 1` is required only against the approved target database
- Dependencies: private database network, private observability network and three runtime secret files
- Consumer: Prometheus over the approved private network
- Exposure: `PRIVATE_INTERNAL_ONLY`; no public hostname, Caddy/Kong route or published host port
- Persistence: none in the exporter; PostgreSQL remains the authority for database state
- Release: exact runtime digest plus deterministic signed configuration artifact
- Rollback: previous pullable image/config digests and checksum after compatibility review

Current verdict: `SOURCE_PREPARED_NOT_DEPLOYED`. Release readiness remains blocked until a protected production merge publishes and verifies the signed artifact and a real previous rollback artifact exists.
