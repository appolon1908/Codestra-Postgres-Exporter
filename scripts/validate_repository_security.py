#!/usr/bin/env python3
"""Validate Codestra PostgreSQL Exporter protected source authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SYNC_WORKFLOW_SHA256 = "519ec8297c1755048f4b28ae42406b06167f63e1293187c2d25857adecbbb423"


def logical_shell_lines(source: str) -> tuple[str, ...]:
    result: list[str] = []
    pending = ""
    heredocs: list[str] = []
    for raw in source.splitlines():
        if heredocs:
            if raw.strip() == heredocs[0]:
                heredocs.pop(0)
            continue
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pending += line
        trailing = len(pending) - len(pending.rstrip("\\"))
        if trailing % 2 == 1:
            pending = pending[:-1]
            continue
        result.append(pending)
        for match in re.finditer(
            r"(?<!<)<<-?(?!<)\s*(?:'([^']+)'|\"([^\"]+)\"|([A-Za-z_][A-Za-z0-9_]*))",
            pending,
        ):
            heredocs.append(next(value for value in match.groups() if value))
        pending = ""
    if pending:
        result.append(pending)
    return tuple(result)


def reject_unapproved_pushes(source: str) -> None:
    approved = ["git", "push", "origin", "HEAD:refs/heads/${SYNC_BRANCH}"]
    approved_count = 0
    for line in logical_shell_lines(source):
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars="();&|<>")
            lexer.whitespace_split = True
            lexer.commenters = "#"
            words = list(lexer)
        except ValueError as error:
            raise ValueError("sync_shell_parse_failed") from error
        if words == approved:
            approved_count += 1
            continue
        for word in words:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=(?:git|push)", word):
                raise ValueError("protected_branch_sync_forbidden:dynamic_command")
        segments: list[list[str]] = [[]]
        for word in words:
            if word in {"{", "}"} or (word and set(word) <= set("();&|")):
                segments.append([])
            else:
                segments[-1].append(word)
        if re.match(r"^(?:(?:elif|if|while)\s+)?(?:\(\(|\[\[)", line) is None:
            for segment in segments:
                while segment and (
                    segment[0] in {"!", "do", "elif", "if", "then", "until", "while"}
                    or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", segment[0])
                ):
                    segment = segment[1:]
                if segment and ("$" in segment[0] or "`" in segment[0]):
                    raise ValueError("protected_branch_sync_forbidden:dynamic_command")
        git_push = False
        for index, word in enumerate(words):
            if Path(word).name != "git":
                continue
            command_index = index + 1
            while command_index < len(words) and words[command_index].startswith("-"):
                option = words[command_index]
                if option == "-c":
                    if command_index + 1 >= len(words):
                        raise ValueError("sync_shell_parse_failed")
                    config = words[command_index + 1]
                    if (
                        config.lower().startswith("alias.")
                        or "$" in config
                    ):
                        raise ValueError(
                            "protected_branch_sync_forbidden:dynamic_command"
                        )
                if option.lower().startswith(("-calias.", "--config-env=alias.")):
                    raise ValueError(
                        "protected_branch_sync_forbidden:dynamic_command"
                    )
                command_index += 2 if option in {
                    "-c", "-C", "--git-dir", "--work-tree"
                } else 1
            if (
                command_index < len(words)
                and words[command_index] == "config"
                and any(
                    "alias." in argument.lower()
                    or "$" in argument
                    or "`" in argument
                    for argument in words[command_index + 1 :]
                )
            ):
                raise ValueError("protected_branch_sync_forbidden:dynamic_command")
            if command_index < len(words) and (
                "$" in words[command_index] or "`" in words[command_index]
            ):
                raise ValueError("protected_branch_sync_forbidden:dynamic_command")
            if command_index < len(words) and words[command_index] == "push":
                git_push = True
                break
        nested_push = any(
            re.search(r"\bgit\s+push\b", re.sub(r"\\([^\n])", r"\1", word))
            for word in words
        )
        dynamic_push = any(
            word == "push" and index > 0
            and ("$" in words[index - 1] or "`" in words[index - 1])
            for index, word in enumerate(words)
        )
        if git_push or nested_push or dynamic_push:
            raise ValueError("protected_branch_sync_forbidden:push_not_exact")
    if approved_count != 1:
        raise ValueError("approved_sync_push_count_invalid")


def validate_sync_branch_authority(source: str) -> None:
    expected = 'readonly SYNC_BRANCH="sync/postgres-exporter-upstream-${UPSTREAM_SHA}-${GITHUB_SHA}"'
    lines = logical_shell_lines(source)
    if lines.count(expected) != 1:
        raise ValueError("sync_branch_authority_invalid")
    for line in lines:
        if line == expected:
            continue
        probe = re.sub(r"\\([^\n])", r"\1", line)
        if re.search(r"(?:^|[();&|<>\s])SYNC_BRANCH\s*=", probe):
            raise ValueError("sync_branch_authority_invalid")
        if re.search(
            r"\b(?:unset|read|mapfile|declare|typeset|local|export|readonly|printf)\b"
            r"[^\n]*\bSYNC_BRANCH\b",
            probe,
        ):
            raise ValueError("sync_branch_authority_invalid")


def validate_upstream(
    source: dict, lock: dict, *, allow_exact_pin_bootstrap: bool = False
) -> None:
    expected = {
        "component": "PostgreSQL Exporter",
        "codestra_repository": "appolon1908-hue/Codestra-Postgres-Exporter",
        "upstream_repository": "prometheus-community/postgres_exporter",
        "upstream_clone_url": "https://github.com/prometheus-community/postgres_exporter.git",
        "import_path": "upstream",
        "deployment_enabled": False,
        "secret_material_allowed_in_git": False,
    }
    for key, value in expected.items():
        if source.get(key) != value:
            raise ValueError(f"upstream_authority_drift:{key}")
    ref = source.get("upstream_ref")
    if not isinstance(ref, str) or re.fullmatch(r"[0-9a-f]{40}", ref) is None:
        raise ValueError("upstream_ref_must_be_exact_commit")
    for key in (
        "upstream_clone_url",
        "import_path",
        "deployment_enabled",
        "secret_material_allowed_in_git",
    ):
        if lock.get(key) != expected[key]:
            raise ValueError(f"upstream_lock_drift:{key}")
    locked_ref = lock.get("upstream_ref")
    locked_commit = lock.get("upstream_commit")
    if (
        not isinstance(locked_ref, str)
        or re.fullmatch(r"[0-9a-f]{40}", locked_ref) is None
        or locked_commit != locked_ref
    ):
        raise ValueError("upstream_lock_not_bound_to_exact_ref")
    if locked_ref != ref and not allow_exact_pin_bootstrap:
        raise ValueError("upstream_lock_not_bound_to_exact_ref")


def validate_runtime(runtime: dict) -> None:
    expected = {
        "service": "postgres-exporter",
        "component": "PostgreSQL Exporter",
        "repository": "appolon1908-hue/Codestra-Postgres-Exporter",
        "internalEndpoint": "http://postgres-exporter:9187/metrics",
        "hostPortPublished": False,
        "publicHostnameAssigned": False,
        "publicNativePortAllowed": False,
    }
    for key, value in expected.items():
        if runtime.get(key) != value:
            raise ValueError(f"runtime_authority_drift:{key}")
    if runtime.get("networks") != {
        "observability": "codestra-observability",
        "database": "codestra-database",
        "internetIngressAllowed": False,
    }:
        raise ValueError("runtime_network_boundary_drift")
    credentials = runtime.get("credentials") or {}
    if credentials.get("secretMaterialAllowedInGit") is not False:
        raise ValueError("runtime_secret_boundary_drift")
    database = runtime.get("databasePolicy") or {}
    for key in ("superuserAllowed", "databaseOwnerAllowed", "applicationWriteAllowed"):
        if database.get(key) is not False:
            raise ValueError(f"runtime_database_boundary_drift:{key}")
    if database.get("dedicatedMonitoringIdentityRequired") is not True:
        raise ValueError("runtime_monitoring_identity_not_required")
    prometheus = runtime.get("prometheus") or {}
    if prometheus.get("targetActivation") != "pending":
        raise ValueError("runtime_prometheus_activation_drift")
    activation = runtime.get("activation") or {}
    if activation.get("deploymentEnabled") is not False or activation.get("productionApproved") is not False:
        raise ValueError("runtime_deployment_must_remain_disabled")


def validate_sync(source: str, document: dict) -> None:
    if (document.get("permissions") or {}) != {
        "actions": "write",
        "contents": "write",
        "pull-requests": "write",
    }:
        raise ValueError("sync_permissions_drift")
    validate_sync_branch_authority(source)
    reject_unapproved_pushes(source)
    required = (
        "github.ref == 'refs/heads/main'",
        "[[ \"$UPSTREAM_REF\" =~ ^[0-9a-f]{40}$ ]]",
        "[[ \"$UPSTREAM_SHA\" == \"$UPSTREAM_REF\" ]]",
        'readonly SYNC_BRANCH="sync/postgres-exporter-upstream-${UPSTREAM_SHA}-${GITHUB_SHA}"',
        'git read-tree --prefix=upstream/ "${UPSTREAM_SHA}^{tree}"',
        '[[ "$(git rev-parse "$remote_ref")" == "$REMOTE_SHA" ]]',
        'git rev-parse "${remote_ref}:upstream"',
        'git rev-parse "${remote_ref}:CODESTRA_UPSTREAM_LOCK.json"',
        '[[ "${remote_parent_values[0]}" == "$GITHUB_SHA" ]]',
        'git diff --name-only "${remote_parent_values[0]}" "$remote_ref"',
        'LOCAL_SHA="$REMOTE_SHA"',
        "gh api --method GET",
        '-f base="main"',
        '-f head="${GITHUB_REPOSITORY_OWNER}:${SYNC_BRANCH}"',
        ".head.repo.full_name",
        '[[ "$pr_head_sha" == "$LOCAL_SHA" ]]',
        '[[ "$pr_repository" == "$GITHUB_REPOSITORY" ]]',
        "Multiple open synchronization pull requests found.",
        "gh pr create",
        "--base main",
        'gh workflow run validate.yml --repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"',
        "'synchronized_at': os.environ['UPSTREAM_TIMESTAMP']",
        'export GIT_AUTHOR_DATE="$UPSTREAM_TIMESTAMP"',
        'export GIT_COMMITTER_DATE="$UPSTREAM_TIMESTAMP"',
        "Validate Codestra runtime contract",
        "validate_repository_security.py",
        '[[ "$GITHUB_EVENT_NAME" == push ]]',
        'before="${{ github.event.before }}"',
        '[[ "${changed[0]}" == CODESTRA_UPSTREAM.json ]]',
        "validator_args+=(--allow-exact-pin-bootstrap)",
    )
    for token in required:
        if token not in source:
            raise ValueError(f"reviewed_sync_boundary_missing:{token}")
    if hashlib.sha256(source.encode()).hexdigest() != SYNC_WORKFLOW_SHA256:
        raise ValueError("sync_workflow_digest_mismatch")


def validate_workflow(source: str) -> None:
    required = (
        "pull_request:",
        "workflow_dispatch:",
        "validate-source:",
        "name: validate-source",
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
        "persist-credentials: false",
        "fetch-depth: 0",
        "Bind vendored Git tree to exact official commit",
        "git rev-parse 'HEAD:upstream'",
        '[[ "$vendored_tree" == "$official_tree" ]]',
        'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
        "Classify an exact upstream-pin bootstrap",
        "POSTGRES_EXPORTER_PENDING_SYNC",
        '[[ "${changed[0]}" == CODESTRA_UPSTREAM.json ]]',
        "validator_args+=(--allow-exact-pin-bootstrap)",
        'validation_ref="$locked_upstream_ref"',
        'scripts/reject_repository_secrets.sh .',
        'base_sha="$POSTGRES_EXPORTER_VALIDATION_BASE_SHA"',
    )
    for token in required:
        if token not in source:
            raise ValueError(f"validation_boundary_missing:{token}")
    if re.search(r"uses:\s+actions/(?:checkout|setup-python)@v\d+", source):
        raise ValueError("mutable_action_reference")
    if re.search(r"pull_request:\s*\n\s+paths:", source):
        raise ValueError("pull_request_validation_must_be_unconditional")
    if re.search(r"^\s*git diff --check\s*$", source, re.MULTILINE):
        raise ValueError("whitespace_check_must_use_committed_range")


def validate_secret_scanner(source: str) -> None:
    required = (
        "set -Eeuo pipefail",
        "-type f -o -type l",
        'if [[ -L "$path" ]]',
        "grep -aEiqz",
        "client[_-]?secret",
        "[[:space:]]*[:=]",
        "PRIVATE KEY",
        "Authorization",
        "Bearer",
        "postgres(ql)?://",
        "PGPASSWORD",
        "DATABASE[_-]?PASSWORD",
        "[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]",
        "[?&[:space:]])[Pp][Aa][Ss][Ss]",
        "scan_status=$?",
        "Secret scan failed before completing",
    )
    for token in required:
        if token not in source:
            raise ValueError(f"secret_scanner_boundary_missing:{token}")
    if '-path "$search_root/tests"' in source or "--exclude-dir=tests" in source:
        raise ValueError("repository_tests_must_be_secret_scanned")


def validate_repository(*, allow_exact_pin_bootstrap: bool = False) -> None:
    paths = {
        "source": ROOT / "CODESTRA_UPSTREAM.json",
        "lock": ROOT / "CODESTRA_UPSTREAM_LOCK.json",
        "sync": ROOT / ".github/workflows/upstream-source-sync.yml",
        "validate": ROOT / ".github/workflows/validate.yml",
        "runtime": ROOT / "config/codestra/runtime.v1.json",
        "secret_scanner": ROOT / "scripts/reject_repository_secrets.sh",
    }
    for path in paths.values():
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required_regular_file_missing:{path.relative_to(ROOT)}")
    source = json.loads(paths["source"].read_text())
    lock = json.loads(paths["lock"].read_text())
    runtime = json.loads(paths["runtime"].read_text())
    sync_source = paths["sync"].read_text()
    validate_source = paths["validate"].read_text()
    secret_scanner_source = paths["secret_scanner"].read_text()
    validate_upstream(
        source, lock, allow_exact_pin_bootstrap=allow_exact_pin_bootstrap
    )
    validate_runtime(runtime)
    validate_sync(sync_source, yaml.safe_load(sync_source))
    yaml.safe_load(validate_source)
    validate_workflow(validate_source)
    validate_secret_scanner(secret_scanner_source)
    if (ROOT / "upstream/.git").exists():
        raise ValueError("nested_upstream_git_metadata_forbidden")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-exact-pin-bootstrap", action="store_true")
    arguments = parser.parse_args()
    try:
        validate_repository(
            allow_exact_pin_bootstrap=arguments.allow_exact_pin_bootstrap
        )
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise SystemExit(f"POSTGRES_EXPORTER_SOURCE_SECURITY=FAIL ERROR={error}") from error
    print("POSTGRES_EXPORTER_SOURCE_SECURITY=PASS")
    print("UPSTREAM_COMMIT_PINNED=YES")
    print("RUNTIME_CONTRACT=PASS")
    print("SYNC_THROUGH_REVIEWED_PR=YES")
    print("DEPLOYMENT_ENABLED=NO")
