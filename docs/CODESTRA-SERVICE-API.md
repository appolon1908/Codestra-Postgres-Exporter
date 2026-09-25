# Codestra service API contract: PostgreSQL Exporter

This repository owns the **postgresql-health-capacity-replication-metrics-authority** for the Codestra observability, analytics, telemetry, and secrets suite.

## Communication rule

PostgreSQL Exporter keeps its native API and protocol. The shared Codestra control plane in `appolon1908-hue/Codestra-Telemetry` performs only sanitized health, readiness, contract, topology, and immutable-release read-back. It never proxies SQL queries, native metric bodies, database credentials, dashboard mutations, secret values, or credential issuance.

Public hostname: none
Private service identity: `postgres-exporter:9187`
Native exposure: `internal_private`
Deployment class: `agent`
Contract: `codestra/api/service-contract.v1.json`

## Native operations

| Method | Path | Category | Access | Control-plane rule |
|---|---|---|---|---|
| `GET` | `/metrics` | health | read_only | never proxied by the Codestra control API |
| `GET` | `/metrics` | readiness | read_only | never proxied by the Codestra control API |
| `GET` | `/metrics` | metrics | read_only | never proxied by the Codestra control API |

## Suite integrations

| Peer | Direction | Signal | Protocol | Purpose |
|---|---|---|---|---|
| `prometheus` | outbound | `metrics` | `prometheus-scrape` | publish least-privilege aggregate PostgreSQL metrics over the approved private network |

## Identity and correlation

Every private request should propagate `X-Correlation-ID` and W3C `traceparent` when the native protocol supports them. `request_id`, `trace_id`, and `tenant_id` remain structured, protected, non-indexed fields. Metrics use only the bounded dimensions `codestra_business`, `application`, `service`, `environment`, `server`, `region`, and `deployment`.

Business identity is deployment-controlled. Caller-supplied business identity, cross-business defaults, anonymous management access, insecure TLS verification, inline DSNs, and inline PostgreSQL passwords are prohibited. The exporter database role must remain least privilege and read only. No Caddy route, Kong route, public DNS name, or public host-port publication is authorized.

## Release and runtime boundary

The control plane reads source revision and image digest only from deployment environment variables. A valid release requires a 40-character Git SHA and `sha256:<64 lowercase hex>` image digest. This source change does not connect to PostgreSQL, deploy the exporter, grant database privileges, activate a scrape, expose the exporter, issue credentials, or enable any business mutation.

## Contract authority handoff

- Canonical schema repository: `appolon1908-hue/Codestra-Telemetry`
- Canonical merged Telemetry SHA: `c35d880a730ca5206d445e8a9a688cb465ae2ad4`
- Contract version: `1.0.0`
- Downstream exact head: this PR branch commit; the authoritative literal SHA is the GitHub PR `headRefOid` recorded after this handoff commit.
- Deployment authorization: unauthorized until staging certification and protected production promotion are complete.
