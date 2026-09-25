#!/usr/bin/env python3
"""Validate PostgreSQL Exporter repository-only release readiness."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
IMAGE = re.compile(r"^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER = re.compile(r"\b(TBD|TODO|UNKNOWN|UNRESOLVED|RECALCULATE|NOT_BUILT|NOT_PUBLISHED)\b")
REQUIRED = (
    "README.md",
    "REPOSITORY_PROFILE.md",
    "SECURITY.md",
    ".github/CODEOWNERS",
    "docs/BACKUP_RESTORE_ROLLBACK.md",
    "docs/UPGRADE.md",
    "codestra/release/runtime-image.lock.json",
    "codestra/release/config-bundle.manifest.json",
    ".github/workflows/release-config-bundle.yml",
    "scripts/build_config_bundle.py",
    "requirements-validation.txt",
)


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def load(relative: str) -> dict:
    try:
        value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        fail(f"cannot load {relative}: {exc}")
    if not isinstance(value, dict):
        fail(f"{relative} must contain an object")
    return value


def validate() -> None:
    missing = [path for path in REQUIRED if not (ROOT / path).is_file()]
    if missing:
        fail(f"missing readiness files: {missing}")
    lock = load("codestra/release/runtime-image.lock.json")
    if lock.get("artifactModel") != "verified-upstream-image-plus-signed-config":
        fail("PostgreSQL Exporter must use release Model B")
    if not IMAGE.fullmatch(str(lock.get("image", ""))):
        fail("runtime image is not an exact sha256 identity")
    if not re.fullmatch(r"[0-9a-f]{40}", str(lock.get("upstreamTagCommit", ""))):
        fail("upstream tag commit is invalid")
    if lock.get("binaryRevisionReadback") != lock.get("upstreamTagCommit"):
        fail("binary revision readback must equal the upstream tag commit")
    if lock.get("productionActivation") is not False:
        fail("runtime lock must not activate production")
    compose = (ROOT / "deploy/compose.yaml").read_text(encoding="utf-8")
    image_lines = re.findall(r"(?m)^\s+image:\s*(\S+)\s*$", compose)
    if image_lines != [lock["image"]]:
        fail("Compose image must exactly match the immutable runtime lock")
    if re.search(r"(?m)^\s+ports\s*:", compose):
        fail("private exporter may not publish a host port")

    runtime = load("config/codestra/runtime.v1.json")
    if runtime.get("publicHostnameAssigned") is not False:
        fail("PostgreSQL Exporter may not have a public hostname")
    if runtime.get("hostPortPublished") is not False:
        fail("PostgreSQL Exporter host port must stay private")
    if runtime.get("activation", {}).get("deploymentEnabled") is not False:
        fail("deployment must remain disabled in source")

    manifest = load("codestra/release/config-bundle.manifest.json")
    if manifest.get("component") != "postgres-exporter":
        fail("configuration manifest component mismatch")
    if manifest.get("productionActivation") is not False:
        fail("configuration bundle may not activate production")
    files = manifest.get("files")
    if not isinstance(files, dict) or len(files) != 6:
        fail("configuration manifest must contain six governed files")
    for relative, expected in files.items():
        path = ROOT / relative
        if not path.is_file() or not SHA256.fullmatch(str(expected)):
            fail(f"invalid manifest entry: {relative}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            fail(f"configuration checksum mismatch: {relative}")

    for path in [ROOT / item for item in REQUIRED]:
        if PLACEHOLDER.search(path.read_text(encoding="utf-8")):
            fail(f"placeholder in readiness source: {path.relative_to(ROOT)}")
    for workflow in (ROOT / ".github/workflows").glob("*.yml"):
        for reference in re.findall(
            r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)",
            workflow.read_text(encoding="utf-8"),
        ):
            if reference.startswith("./"):
                continue
            if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference):
                fail(f"mutable action reference in {workflow.relative_to(ROOT)}: {reference}")
    release_workflow = yaml.safe_load(
        (ROOT / ".github/workflows/release-config-bundle.yml").read_text(
            encoding="utf-8"
        )
    )
    release_job = release_workflow.get("jobs", {}).get("release", {})
    expected_authority = (
        "appolon1908-hue/Codestra-Telemetry/.github/workflows/"
        "reusable-release-config-bundle.yml@"
        "777292781faeca9348d0e2ecdce6ac3f50c91d93"
    )
    if release_job.get("uses") != expected_authority:
        fail("release caller must pin the accepted Telemetry workflow authority")
    if release_job.get("with", {}).get("component_id") != "postgres-exporter":
        fail("release caller component identity mismatch")


def main() -> None:
    validate()
    print("POSTGRES_EXPORTER_REPOSITORY_READINESS_SOURCE=PASS")
    print("PUBLIC_HOSTNAME=NONE")
    print("PRODUCTION_ACTIVATION=NO")


if __name__ == "__main__":
    main()
