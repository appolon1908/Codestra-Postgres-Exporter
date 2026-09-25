# Codestra PostgreSQL Exporter

Principal source authority for Codestra PostgreSQL Exporter configuration, upstream provenance, least-privilege database monitoring policy, release validation, and runbooks.

## Status

```text
SOURCE_PREPARED_NOT_DEPLOYED
STABLE_GITHUB_REPOSITORY_ID=1350839865
PUBLIC_HOSTNAME=NONE
PRIVATE_SERVICE_IDENTITY=postgres-exporter:9187
EXPOSURE=PRIVATE_INTERNAL_ONLY
```

Deployment is disabled. This repository contains no production credential, database password, private key, certificate, or secret-bearing connection string.

## Authority boundary

This repository owns PostgreSQL Exporter packaging and configuration. It does not own PostgreSQL application schema, database administration, Prometheus scrape policy, Grafana dashboards, Alertmanager routing, infrastructure orchestration, Caddy/Kong publication, or secrets.

Official upstream source is imported from `prometheus-community/postgres_exporter` into `upstream/` by a controlled synchronization workflow and recorded in `CODESTRA_UPSTREAM_LOCK.json`.

The accepted repository-only runtime candidate is upstream `v0.20.1` at tag commit `867fbcac31cd18c143e244190ea9168cca069827`, pinned as `quay.io/prometheuscommunity/postgres-exporter@sha256:ac5ec343104fae0e2d84a27bb8d69b38430a11910c5382cad85d478d2bab713e`. This selection does not activate or deploy it.

The machine-readable authority is [`config/private-service-authority.v1.json`](config/private-service-authority.v1.json).

## Network and exposure

- Internal service identity: `postgres-exporter:9187`
- Metrics path: `/metrics`
- Native port `9187` is private and must never be published to a public host interface.
- The exporter joins only approved observability and database networks.
- Prometheus on an approved private monitoring network is the routine scrape consumer.
- No public Codestra hostname is assigned or required.
- The retired `pgex.codestra.media` name is forbidden and must not appear in active Caddy, Kong, DNS, monitoring, documentation, examples, or deployment source.
- A DNS record, certificate, or historical reference never grants public exposure authority.

## Database access

Use a dedicated application-independent monitoring role with the minimum supported PostgreSQL monitoring privileges. It must not be a superuser, database owner, replication administrator, bypass-RLS role, or application writer.

Connection components are injected from runtime secret files:

- `/run/secrets/postgres_exporter_uri`
- `/run/secrets/postgres_exporter_user`
- `/run/secrets/postgres_exporter_password`

Production values belong in OpenBao or the approved runtime secret mechanism, never Git.

Custom queries require review for cost, lock behavior, sensitive columns, and cardinality. They must never export business-row contents, credentials, customer data, or unbounded identifiers as labels.

## Monitoring target

The Codestra expansion target covers connection saturation, transactions, locks/deadlocks, blocked queries, replication/lag, WAL/checkpoints, cache hit ratio, long-running transactions, database/table/index growth, vacuum/autovacuum health, dead tuples, reviewed bloat indicators, and sequence exhaustion risk. Custom SQL collectors require explicit safety, cost, sensitive-column, and cardinality review.

## Validation

```bash
python scripts/validate_private_service_authority.py
python scripts/validate_repository_readiness.py
python -m unittest discover -s tests -p 'test_*.py'
```

The private-authority validator requires the exact stable repository ID, no public hostname, the private service identity, denied Caddy/Kong/public-port publication, and scans active source for the retired hostname and common public-exposure markers. Repository CI also validates the hardened Compose candidate, external secret references, immutable-image requirement, private network-only exposure, disabled database auto-discovery, bounded collection timeout, least-privilege role template, and activation gates.

## Promotion

```text
feature/* -> development -> test -> staging -> production -> main
```

A merge does not authorize deployment. Activation requires:

1. an immutable image digest with source revision, SBOM, and provenance;
2. approved private observability and database networks;
3. runtime secret-file injection;
4. a dedicated non-superuser monitoring role;
5. successful private scrape and `pg_up == 1`;
6. bounded cardinality and approved query-cost review;
7. backup, rollback, and source-to-runtime evidence;
8. confirmation that port `9187` and the service API remain inaccessible from the public Internet.

`DEPLOYMENT_ENABLED=NO` remains binding until environment promotion gates explicitly authorize activation. No production database, exporter, Prometheus, Caddy, Kong, DNS, secret, or runtime is changed by documenting or validating this authority.
