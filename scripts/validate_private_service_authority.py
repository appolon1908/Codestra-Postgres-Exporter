#!/usr/bin/env python3
"""Fail closed if PostgreSQL Exporter is assigned a public hostname or route."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[1]
POLICY = ROOT / "config" / "private-service-authority.v1.json"
RUNTIME = ROOT / "config" / "codestra" / "runtime.v1.json"
README = ROOT / "README.md"
FORBIDDEN_HOST = "pgex" + ".codestra.media"
PRIVATE_IDENTITY = "postgres-exporter:9187"
REQUIRED_CONTROLS = [
    "immutable image digest",
    "private monitoring and database network attachment",
    "dedicated non-superuser monitoring role",
    "runtime secret-file injection",
    "approved custom queries only",
    "connection and query timeouts",
    "bounded metric cardinality",
    "successful private Prometheus scrape",
    "source-to-runtime and rollback evidence",
]


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} root must be an object")
    return value


def validate_policy() -> None:
    policy = load_json(POLICY)
    if policy.get("schema_version") != "1.0":
        fail("schema_version must be 1.0")
    if policy.get("status") != "ACTIVE_SOURCE_AUTHORITY":
        fail("private-service authority must be active")
    if policy.get("repository_id") != 1350839865:
        fail("stable repository ID is incorrect")
    if policy.get("repository") != "appolon1908-hue/Codestra-Postgres-Exporter":
        fail("principal repository is incorrect")
    if policy.get("public_hostname") is not None:
        fail("PostgreSQL Exporter may not have a public hostname")
    if policy.get("private_service_identity") != PRIVATE_IDENTITY:
        fail("private service identity must be postgres-exporter:9187")
    if policy.get("exposure") != "PRIVATE_INTERNAL_ONLY":
        fail("exposure must remain private/internal only")
    if policy.get("routine_consumer") != (
        "Prometheus on an approved private monitoring network"
    ):
        fail("routine consumer policy is incorrect")
    if policy.get("forbidden_public_hostname") != FORBIDDEN_HOST:
        fail("retired public hostname must remain explicitly forbidden")
    for gate in (
        "caddy_publication_allowed",
        "kong_publication_allowed",
        "host_public_port_allowed",
    ):
        if policy.get(gate) is not False:
            fail(f"{gate} must be false")
    if policy.get("required_controls") != REQUIRED_CONTROLS:
        fail("required private-service controls are incomplete")


def validate_runtime_network_policy() -> None:
    runtime = load_json(RUNTIME)
    if runtime.get("service") != "postgres-exporter":
        fail("runtime service identity is incorrect")
    if runtime.get("repository") != "appolon1908-hue/Codestra-Postgres-Exporter":
        fail("runtime repository authority is incorrect")
    if runtime.get("internalEndpoint") != f"http://{PRIVATE_IDENTITY}/metrics":
        fail("runtime internal metrics endpoint is incorrect")

    # Listening on all interfaces *inside the isolated container* is valid only
    # while no host port or internet ingress exists. These controls are checked
    # together so an internal process bind is never confused with public exposure.
    if runtime.get("listenAddress") not in {"0.0.0.0:9187", ":9187"}:
        fail("runtime listen address is outside the approved container-local forms")
    if runtime.get("hostPortPublished") is not False:
        fail("PostgreSQL Exporter host port must not be published")
    if runtime.get("publicHostnameAssigned") is not False:
        fail("PostgreSQL Exporter public hostname must remain unassigned")
    if runtime.get("publicNativePortAllowed") is not False:
        fail("PostgreSQL Exporter native port may not be public")

    networks = runtime.get("networks")
    if not isinstance(networks, dict):
        fail("runtime network policy is missing")
    if networks.get("observability") != "codestra-observability":
        fail("approved observability network is missing")
    if networks.get("database") != "codestra-database":
        fail("approved database network is missing")
    if networks.get("internetIngressAllowed") is not False:
        fail("internet ingress must remain disabled")

    activation = runtime.get("activation")
    if not isinstance(activation, dict):
        fail("runtime activation policy is missing")
    if activation.get("deploymentEnabled") is not False:
        fail("deployment must remain disabled in source authority")
    if activation.get("productionApproved") is not False:
        fail("production approval must remain false")


def validate_explicit_deprecation_text() -> None:
    readme = README.read_text(encoding="utf-8")
    required_fragments = (
        "PUBLIC_HOSTNAME=NONE",
        f"PRIVATE_SERVICE_IDENTITY={PRIVATE_IDENTITY}",
        "EXPOSURE=PRIVATE_INTERNAL_ONLY",
        FORBIDDEN_HOST,
        "is forbidden",
        "must never be published to a public host interface",
    )
    for fragment in required_fragments:
        if fragment not in readme:
            fail(f"README private-service authority is incomplete: missing {fragment}")


def validate_active_source() -> None:
    # These files must contain policy literals so they can explicitly prohibit
    # the retired hostname and detect dangerous route/publication patterns.
    allowed_policy_literal_paths = {POLICY.resolve(), README.resolve(), SCRIPT}
    ignored_parts = {".git", "upstream", "__pycache__"}
    ignored_suffixes = {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".woff",
        ".woff2",
        ".zip",
        ".gz",
        ".pyc",
    }
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if ignored_parts.intersection(path.parts):
            continue
        if path.suffix.lower() in ignored_suffixes:
            continue
        if path.resolve() in allowed_policy_literal_paths:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        lowered = text.lower()
        if FORBIDDEN_HOST in lowered:
            fail(
                "retired public hostname remains in active source: "
                f"{path.relative_to(ROOT)}"
            )
        for violation in public_exposure_violations(path, lowered):
            fail(
                "possible public PostgreSQL Exporter exposure "
                f"{violation} in {path.relative_to(ROOT)}"
            )


def public_exposure_violations(path: Path, lowered: str) -> tuple[str, ...]:
    """Return conservative violations only for deployment/edge sources."""

    violations: list[str] = []
    relative_parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    kubernetes_source = bool(
        relative_parts.intersection({"k8s", "kubernetes", "helm", "templates"})
        or re.search(
            r"(?im)^\s*kind\s*:\s*(?:service|deployment|pod|daemonset|statefulset|ingress)\s*$",
            lowered,
        )
    )
    deployment_source = (
        bool(
            relative_parts.intersection(
                {
                    "deploy",
                    "deployment",
                    "manifests",
                    "k8s",
                    "kubernetes",
                    "helm",
                    "templates",
                    "kong",
                    "gateway",
                    "edge",
                }
            )
        )
        or "compose" in name
        or "kong" in name
        or name == "caddyfile"
        or name.endswith(".caddy")
    )
    if not deployment_source:
        return ()

    route_patterns = (
        r"\breverse_proxy\s+[^\n]*postgres[-_]exporter",
        r"\bupstream\s+[^\n{]*postgres[-_]exporter",
        r"\bproxy_pass\s+[^\n;]*postgres[-_]exporter",
    )
    if any(re.search(pattern, lowered) for pattern in route_patterns):
        violations.append("route to the private exporter")

    kong_exporter_service = bool(
        re.search(
            r"(?im)^\s*url\s*:\s*[\"']?https?://postgres[-_]exporter(?::9187)?(?:[/\"'\s]|$)",
            lowered,
        )
        or (
            re.search(r"(?im)^\s*host\s*:\s*[\"']?postgres[-_]exporter[\"']?\s*$", lowered)
            and re.search(r"(?im)^\s*port\s*:\s*9187\s*$", lowered)
        )
    )
    if kong_exporter_service and re.search(r"(?im)^\s*routes\s*:", lowered):
        violations.append("declarative Kong route to the private exporter")

    if kubernetes_source:
        public_service_type = re.search(
            r"(?im)^\s*type\s*:\s*(?:loadbalancer|nodeport)\s*$",
            lowered,
        )
        exporter_service_port = re.search(
            r"(?im)^\s*(?:port|targetport|nodeport)\s*:\s*9187\s*$",
            lowered,
        )
        if public_service_type and exporter_service_port:
            violations.append("public Kubernetes Service for 9187")
        if (
            re.search(r"(?im)^\s*hostnetwork\s*:\s*true\s*$", lowered)
            and re.search(r"(?im)^\s*containerport\s*:\s*9187\s*$", lowered)
        ):
            violations.append("host-networked Kubernetes listener for 9187")
        if (
            re.search(r"(?im)^\s*kind\s*:\s*ingress\s*$", lowered)
            and re.search(
                r"(?im)^\s*(?:name|serviceName)\s*:\s*[\"']?postgres[-_]exporter[\"']?\s*$",
                lowered,
            )
        ):
            violations.append("Kubernetes Ingress route to the private exporter")
    elif path.suffix.lower() in {".yaml", ".yml"} and re.search(
        r"(?ms)^\s*ports\s*:\s*(?:\[[^\]]*9187[^\]]*\]|\n(?:\s+.*\n)*?\s+.*9187)",
        lowered,
    ):
        violations.append("host port publication for 9187")

    if re.search(
        r"(?i)(?:hostport|host_port|published)\s*[:=]\s*[\"']?9187\b",
        lowered,
    ):
        violations.append("published/host port 9187")
    return tuple(violations)


def main() -> None:
    validate_policy()
    validate_runtime_network_policy()
    validate_explicit_deprecation_text()
    validate_active_source()
    print("PostgreSQL Exporter private-service authority: PASS")


if __name__ == "__main__":
    main()
