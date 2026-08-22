#!/usr/bin/env python3
"""Validate ContextDB M0 governance artifacts without mutating the repository."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

try:
    import yaml
    from jsonschema import Draft202012Validator, FormatChecker
    from referencing import Registry, Resource
except ImportError as exc:  # pragma: no cover - exercised by CI bootstrap failures
    raise SystemExit(
        "Missing validator dependency. Install jsonschema==4.26.0 and PyYAML==6.0.3."
    ) from exc


ROOT = (
    Path(sys.argv[1]).resolve()
    if len(sys.argv) > 1
    else Path(__file__).resolve().parents[2]
)
SCHEMA_DIR = ROOT / "assets" / "schemas"

MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_CARGO_METADATA_BYTES = 64 * 1024 * 1024
MAX_DOCUMENT_NODES = 250_000
MAX_DOCUMENT_DEPTH = 64
MAX_SCALAR_UTF8_BYTES = 4 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024

M16_CODEX_SECURITY_ARTIFACTS = {
    "scan_manifest": "proof/M16/codex-security/scan-manifest.json",
    "findings": "proof/M16/codex-security/findings.json",
    "coverage": "proof/M16/codex-security/coverage.json",
}
M16_CODEX_SECURITY_MAX_BYTES = {
    "scan_manifest": 16 * 1024 * 1024,
    "findings": 128 * 1024 * 1024,
    "coverage": 32 * 1024 * 1024,
}

M16_SECURITY_EXCLUDED_TOP_LEVEL = {".git", "proof", "target", "target-review"}
M16_SECURITY_EXCLUDED_DIRECTORY_NAMES = {
    ".cargo-cache",
    ".contextdb",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "venv",
}
M16_SECURITY_EXCLUDED_FILE_SUFFIXES = (".cdx.json", ".pyc", ".pyo")

_CARGO_METADATA_CACHE: dict[tuple[Path, str, str], dict] = {}

M16_PROOF_CONTRACTS = {
    "proof/M16/security-gates.json": {
        "kind": "security_report",
        "schema_id": "https://contextdb.dev/schemas/m16-security-gates/v1.json",
    },
    "proof/M16/BENCH-G.json": {
        "kind": "benchmark_result",
        "schema_id": "https://contextdb.dev/schemas/benchmark-result/v1.json",
    },
    "proof/M16/fault-delete-restore.json": {
        "kind": "test_report",
        "schema_id": "https://contextdb.dev/schemas/m16-fault-delete-restore/v1.json",
    },
    "proof/M16/fuzz-smoke.json": {
        "kind": "test_report",
        "schema_id": "https://contextdb.dev/schemas/m16-fuzz-smoke/v1.json",
    },
    "proof/M16/sbom-index.json": {
        "kind": "artifact_manifest",
        "schema_id": "https://contextdb.dev/schemas/m16-sbom-index/v1.json",
    },
    "proof/M16/process-kill-redb.json": {
        "kind": "test_report",
        "schema_id": "https://contextdb.dev/schemas/m16-process-kill/v1.json",
    },
}

M16_CUSTOM_PROOF_PATHS = tuple(
    path for path in M16_PROOF_CONTRACTS if path != "proof/M16/BENCH-G.json"
)

M16_DELETION_TARGETS = {
    "primary_content",
    "episode",
    "evidence",
    "semantic_memory",
    "summary",
    "embedding",
    "ann_index",
    "lexical_index",
    "cache",
    "checkpoint_or_handoff",
    "provider_copy",
    "export",
    "backup",
}

M16_FAULT_DEPENDENCIES = {
    "proof/M16/BENCH-G.json",
    "proof/M16/fuzz-smoke.json",
    "proof/M16/sbom-index.json",
    "proof/M16/process-kill-redb.json",
}


def _display_path(path: Path, root: Path) -> Path:
    try:
        return path.relative_to(root)
    except ValueError:
        return path


def _read_bounded_bytes(
    path: Path,
    *,
    max_bytes: int,
    label: str,
    root: Path,
) -> bytes:
    try:
        file_stat = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise AssertionError(
            f"Cannot inspect {label} {_display_path(path, root)}: {exc}"
        ) from exc
    assert stat.S_ISREG(file_stat.st_mode), (
        f"{label} is not a regular file: {_display_path(path, root)}"
    )
    assert file_stat.st_size <= max_bytes, (
        f"{label} {_display_path(path, root)} exceeds {max_bytes}-byte limit"
    )
    try:
        with path.open("rb") as handle:
            payload = handle.read(max_bytes + 1)
    except OSError as exc:
        raise AssertionError(
            f"Cannot read {label} {_display_path(path, root)}: {exc}"
        ) from exc
    assert len(payload) <= max_bytes, (
        f"{label} {_display_path(path, root)} exceeds {max_bytes}-byte limit"
    )
    return payload


def _validate_document_shape(
    value: object, *, label: str, require_string_keys: bool = True
) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        assert nodes <= MAX_DOCUMENT_NODES, (
            f"{label} exceeds {MAX_DOCUMENT_NODES}-node limit"
        )
        assert depth <= MAX_DOCUMENT_DEPTH, (
            f"{label} exceeds {MAX_DOCUMENT_DEPTH}-level depth limit"
        )
        if isinstance(current, dict):
            for key, item in current.items():
                if require_string_keys:
                    assert isinstance(key, str), (
                        f"{label} contains a non-string object key"
                    )
                if isinstance(key, str):
                    assert len(key.encode("utf-8")) <= MAX_SCALAR_UTF8_BYTES, (
                        f"{label} contains an oversized object key"
                    )
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str):
            assert len(current.encode("utf-8")) <= MAX_SCALAR_UTF8_BYTES, (
                f"{label} contains a string exceeding {MAX_SCALAR_UTF8_BYTES} bytes"
            )


def _parse_json_bytes(payload: bytes, *, label: str) -> object:
    try:
        text = payload.decode("utf-8")
        document = json.loads(
            text,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite number {value}")
            ),
        )
    except (UnicodeDecodeError, ValueError, RecursionError, MemoryError) as exc:
        raise AssertionError(f"Cannot load JSON {label}: {exc}") from exc
    _validate_document_shape(document, label=f"JSON {label}")
    return document


def load_json(
    path: Path,
    *,
    root: Path | None = None,
    max_bytes: int = MAX_JSON_BYTES,
) -> object:
    repository_root = ROOT if root is None else root
    payload = _read_bounded_bytes(
        path,
        max_bytes=max_bytes,
        label="JSON",
        root=repository_root,
    )
    return _parse_json_bytes(payload, label=str(_display_path(path, repository_root)))


def load_text(
    path: Path,
    *,
    root: Path | None = None,
    max_bytes: int = MAX_TEXT_BYTES,
    label: str = "text file",
) -> str:
    repository_root = ROOT if root is None else root
    payload = _read_bounded_bytes(
        path, max_bytes=max_bytes, label=label, root=repository_root
    )
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AssertionError(
            f"Cannot decode {label} {_display_path(path, repository_root)} as UTF-8: {exc}"
        ) from exc


def load_yaml(path: Path) -> object:
    try:
        document = yaml.safe_load(load_text(path, label="YAML"))
        _validate_document_shape(
            document,
            label=f"YAML {path.relative_to(ROOT)}",
            require_string_keys=False,
        )
        return document
    except yaml.YAMLError as exc:
        raise AssertionError(
            f"Cannot load YAML {path.relative_to(ROOT)}: {exc}"
        ) from exc


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build_registry() -> tuple[dict[str, dict], Registry]:
    schemas: dict[str, dict] = {}
    resources: list[tuple[str, Resource]] = []
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        schema = load_json(path)
        assert isinstance(schema, dict), f"Schema {path.name} must be an object"
        Draft202012Validator.check_schema(schema)
        schema_id = schema.get("$id")
        assert isinstance(schema_id, str) and schema_id, f"Schema {path.name} needs $id"
        assert schema_id not in schemas, f"Duplicate schema $id: {schema_id}"
        schemas[schema_id] = schema
        resources.append((schema_id, Resource.from_contents(schema)))
    assert schemas, "No JSON schemas found"
    return schemas, Registry().with_resources(resources)


def validate_instance(
    instance_path: Path,
    schema_id: str,
    schemas: dict[str, dict],
    registry: Registry,
    *,
    root: Path | None = None,
) -> dict:
    repository_root = ROOT if root is None else root
    instance = load_json(instance_path, root=repository_root)
    assert isinstance(instance, dict), f"{instance_path.name} must be an object"
    assert schema_id in schemas, f"Unregistered schema: {schema_id}"
    validator = Draft202012Validator(
        schemas[schema_id], registry=registry, format_checker=FormatChecker()
    )
    errors = sorted(
        validator.iter_errors(instance), key=lambda error: list(error.absolute_path)
    )
    if errors:
        try:
            display_path = instance_path.relative_to(repository_root)
        except ValueError:
            display_path = instance_path
        rendered = "\n".join(
            f"  {display_path}:{'/'.join(map(str, error.absolute_path)) or '<root>'}: {error.message}"
            for error in errors
        )
        raise AssertionError(f"Schema validation failed:\n{rendered}")
    return instance


def validate_version_manifest(schemas: dict[str, dict], registry: Registry) -> None:
    manifest = validate_instance(
        ROOT / "docs" / "architecture" / "examples" / "version-manifest.json",
        "https://contextdb.dev/schemas/version-manifest/v1.json",
        schemas,
        registry,
    )
    for name, version in manifest["formats"].items():
        assert version["read_min"] <= version["writer"] <= version["read_max"], (
            f"Format {name} writer must be inside reader range"
        )


def validate_benchmark(schemas: dict[str, dict], registry: Registry) -> None:
    candidates = {
        ROOT / "docs" / "benchmarks" / "examples" / "m0-governance-validation.json"
    }
    candidates.update((ROOT / "docs" / "benchmarks" / "results").glob("*.json"))
    proof_root = ROOT / "proof"
    if proof_root.is_dir():
        candidates.update(proof_root.rglob("*.json"))

    validated = 0
    for path in sorted(candidates):
        document = load_json(path)
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != "contextdb.benchmark-result/v1"
        ):
            continue
        result = validate_instance(
            path,
            "https://contextdb.dev/schemas/benchmark-result/v1.json",
            schemas,
            registry,
        )
        validated += 1
        assert parse_time(result["started_at"]) <= parse_time(result["finished_at"]), (
            f"Benchmark {path.relative_to(ROOT)} finished_at precedes started_at"
        )
        for metric in result["metrics"]:
            if "threshold" in metric:
                assert "passed" in metric, (
                    f"Metric {metric['name']} in {path.relative_to(ROOT)} has threshold without pass result"
                )
        for artifact in result["artifacts"]:
            if "examples" in path.relative_to(ROOT).parts:
                continue
            artifact_path = (ROOT / artifact["uri"]).resolve()
            if not artifact_path.is_file():
                artifact_path = (path.parent / artifact["uri"]).resolve()
            try:
                artifact_path.relative_to(ROOT)
            except ValueError as exc:
                raise AssertionError(
                    f"Benchmark artifact escapes repository: {artifact['uri']}"
                ) from exc
            assert artifact_path.is_file(), (
                f"Benchmark artifact is missing: {artifact['uri']}"
            )
            observed = sha256_file(artifact_path)
            assert observed == artifact["sha256"], (
                f"Benchmark artifact hash mismatch: {artifact['uri']}"
            )
        version_artifacts = [
            artifact
            for artifact in result["artifacts"]
            if artifact["kind"] == "version-manifest"
        ]
        if version_artifacts:
            assert len(version_artifacts) == 1, (
                f"Benchmark {path.relative_to(ROOT)} must reference one version manifest"
            )
            assert (
                version_artifacts[0]["sha256"]
                == result["contextdb"]["version_manifest_sha256"]
            ), f"Embedded version-manifest digest mismatch in {path.relative_to(ROOT)}"
    assert validated >= 1, "No benchmark-result documents were validated"


def resolve_repository_path(path: str, *, label: str, root: Path | None = None) -> Path:
    repository_root = ROOT if root is None else root
    assert path and not Path(path).is_absolute(), (
        f"{label} is not repository-relative: {path}"
    )
    assert not re.match(r"^[A-Za-z]:", path), (
        f"{label} is not repository-relative: {path}"
    )
    assert "\\" not in path, f"{label} must use '/' separators: {path}"
    assert ".." not in Path(path).parts, f"{label} contains parent traversal: {path}"
    candidate = (repository_root / path).resolve()
    try:
        candidate.relative_to(repository_root)
    except ValueError as exc:
        raise AssertionError(f"{label} escapes repository: {path}") from exc
    assert candidate.is_file(), f"{label} is missing: {path}"
    return candidate


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(READ_CHUNK_BYTES):
                digest.update(chunk)
    except OSError as exc:
        raise AssertionError(f"Cannot hash file {path}: {exc}") from exc
    return digest.hexdigest()


def validate_hashed_artifact(
    artifact: dict,
    *,
    label: str,
    root: Path,
    expected_path: str | None = None,
) -> Path:
    assert isinstance(artifact, dict), f"{label} must be an object"
    artifact_path = artifact.get("path")
    assert isinstance(artifact_path, str), f"{label} needs a path"
    if expected_path is not None:
        assert artifact_path == expected_path, (
            f"{label} path is {artifact_path}, expected {expected_path}"
        )
    resolved = resolve_repository_path(artifact_path, label=label, root=root)
    observed = sha256_file(resolved)
    assert artifact.get("sha256") == observed, f"{label} hash mismatch: {artifact_path}"
    if "bytes" in artifact:
        assert artifact["bytes"] == resolved.stat().st_size, (
            f"{label} byte count mismatch: {artifact_path}"
        )
    return resolved


def assert_unique_values(values: list[str], *, label: str) -> None:
    assert len(values) == len(set(values)), f"Duplicate {label}"


def checks_passed(checks: list[dict]) -> bool:
    return bool(checks) and all(
        check["status"] == "passed"
        and (check.get("exit_code") is None or check["exit_code"] == 0)
        for check in checks
    )


def trusted_m16_security_inventory(root: Path) -> list[str]:
    repository_root = root.resolve()
    inventory: list[str] = []
    for current, directory_names, file_names in os.walk(repository_root):
        current_path = Path(current)
        relative_directory = current_path.relative_to(repository_root)
        if relative_directory == Path("."):
            directory_names[:] = [
                name
                for name in directory_names
                if name not in M16_SECURITY_EXCLUDED_TOP_LEVEL
                and name not in M16_SECURITY_EXCLUDED_DIRECTORY_NAMES
            ]
        else:
            directory_names[:] = [
                name
                for name in directory_names
                if name not in M16_SECURITY_EXCLUDED_DIRECTORY_NAMES
            ]
        directory_names.sort(key=lambda value: value.encode("utf-8"))
        for file_name in sorted(file_names, key=lambda value: value.encode("utf-8")):
            if file_name.endswith(M16_SECURITY_EXCLUDED_FILE_SUFFIXES):
                continue
            candidate = current_path / file_name
            assert not candidate.is_symlink(), (
                "M16 trusted security inventory does not allow source symlinks: "
                f"{candidate.relative_to(repository_root).as_posix()}"
            )
            assert candidate.is_file(), (
                "M16 trusted security inventory contains a non-file: "
                f"{candidate.relative_to(repository_root).as_posix()}"
            )
            inventory.append(candidate.relative_to(repository_root).as_posix())
    inventory.sort(key=lambda value: value.encode("utf-8"))
    assert inventory, "M16 trusted security source inventory is empty"
    return inventory


def _validate_canonical_codex_security(
    document: dict,
    *,
    root: Path,
) -> tuple[dict, dict, dict]:
    binding = document["codex_security"]
    canonical: dict[str, dict] = {}
    resolved_paths: dict[str, Path] = {}
    for key, expected_path in M16_CODEX_SECURITY_ARTIFACTS.items():
        resolved_paths[key] = validate_hashed_artifact(
            binding[key],
            label=f"M16 canonical Codex Security {key}",
            root=root,
            expected_path=expected_path,
        )
        loaded = load_json(
            resolved_paths[key],
            root=root,
            max_bytes=M16_CODEX_SECURITY_MAX_BYTES[key],
        )
        assert isinstance(loaded, dict), (
            f"M16 canonical Codex Security {key} must be an object"
        )
        canonical[key] = loaded

    manifest = canonical["scan_manifest"]
    findings = canonical["findings"]
    coverage = canonical["coverage"]
    assert manifest.get("schemaVersion") == "1.0", (
        "M16 canonical Codex Security scan manifest has the wrong schemaVersion"
    )
    assert findings.get("schemaVersion") == "1.0", (
        "M16 canonical Codex Security findings have the wrong schemaVersion"
    )
    assert coverage.get("schemaVersion") == "1.0", (
        "M16 canonical Codex Security coverage has the wrong schemaVersion"
    )
    assert manifest.get("documentType") == "codex-security.scan-manifest", (
        "M16 canonical Codex Security scan manifest has the wrong documentType"
    )
    assert findings.get("documentType") == "codex-security.findings", (
        "M16 canonical Codex Security findings have the wrong documentType"
    )
    assert coverage.get("documentType") == "codex-security.coverage", (
        "M16 canonical Codex Security coverage has the wrong documentType"
    )

    scan = manifest.get("scan")
    assert isinstance(scan, dict), "M16 canonical Codex Security manifest lacks scan"
    scan_id = binding["scan_id"]
    assert scan.get("id") == scan_id, "M16 Codex Security scan ID mismatch"
    assert coverage.get("scanId") == scan_id, "M16 Codex Security coverage ID mismatch"
    assert scan.get("status") == "completed" and scan.get("sealedAt"), (
        "M16 canonical Codex Security scan is not sealed and completed"
    )
    producer = scan.get("producer")
    assert (
        isinstance(producer, dict)
        and producer.get("name") == "codex-security-plugin"
        and isinstance(producer.get("version"), str)
        and producer["version"]
    ), "M16 canonical scan lacks Codex Security producer identity"
    assert scan.get("findingsRef") == "findings.json", (
        "M16 Codex Security findings reference is not canonical"
    )
    assert scan.get("coverageRef") == "coverage.json", (
        "M16 Codex Security coverage reference is not canonical"
    )

    target = scan.get("target")
    assert isinstance(target, dict), "M16 Codex Security manifest lacks target"
    assert target.get("kind") in {"git_worktree", "git_diff", "directory_snapshot"}, (
        "M16 canonical Codex Security target is not snapshot-bound"
    )
    assert isinstance(target.get("targetId"), str) and target["targetId"], (
        "M16 canonical Codex Security target lacks targetId"
    )
    assert target.get("snapshotDigest") == binding["snapshot_digest"], (
        "M16 canonical Codex Security target snapshot differs from the receipt binding"
    )

    manifest_artifacts = scan.get("artifacts")
    assert isinstance(manifest_artifacts, list), (
        "M16 Codex Security manifest lacks sealed artifact hashes"
    )
    assert len(manifest_artifacts) == 2 and all(
        isinstance(artifact, dict) for artifact in manifest_artifacts
    ), "M16 Codex Security manifest must contain two artifact records"
    manifest_artifacts_by_path = {
        artifact["path"]: artifact for artifact in manifest_artifacts
    }
    assert set(manifest_artifacts_by_path) == {"findings.json", "coverage.json"}, (
        "M16 Codex Security manifest does not exactly seal findings.json and coverage.json"
    )
    for key, file_name in (
        ("findings", "findings.json"),
        ("coverage", "coverage.json"),
    ):
        assert (
            manifest_artifacts_by_path[file_name].get("sha256")
            == binding[key]["sha256"]
        ), f"M16 Codex Security manifest hash mismatch for {file_name}"
        assert (
            manifest_artifacts_by_path[file_name].get("mediaType") == "application/json"
        ), f"M16 Codex Security manifest media type mismatch for {file_name}"

    canonical_findings = findings.get("findings")
    assert isinstance(canonical_findings, list), (
        "M16 canonical Codex Security findings list is missing"
    )
    allowed_severities = ("critical", "high", "medium", "low", "informational")
    canonical_severities: list[str] = []
    for finding in canonical_findings:
        assert isinstance(finding, dict) and isinstance(
            finding.get("severity"), dict
        ), "M16 canonical Codex Security finding lacks severity"
        severity = finding["severity"].get("level")
        assert severity in allowed_severities, (
            f"M16 canonical Codex Security finding has unknown severity: {severity}"
        )
        canonical_severities.append(severity)
    severity_counts = {
        severity: canonical_severities.count(severity)
        for severity in allowed_severities
    }
    receipt_findings = document["findings"]
    for severity, count in severity_counts.items():
        assert receipt_findings[severity] == count, (
            f"M16 security {severity} finding count differs from canonical findings"
        )
    assert receipt_findings["unresolved_critical"] == severity_counts["critical"], (
        "M16 unresolved critical count differs from canonical findings"
    )
    assert receipt_findings["unresolved_high"] == severity_counts["high"], (
        "M16 unresolved high count differs from canonical findings"
    )

    assert parse_time(document["scan"]["started_at"]) == parse_time(
        scan["startedAt"]
    ), "M16 security scan start differs from the canonical scan"
    assert parse_time(document["scan"]["finished_at"]) == parse_time(
        scan["completedAt"]
    ), "M16 security scan finish differs from the canonical scan"

    if document["status"] == "passed":
        assert coverage.get("completeness") == "complete", (
            "Passed M16 security receipt has incomplete Codex Security coverage"
        )
        assert coverage.get("deferred") == [], (
            "Passed M16 security receipt has deferred Codex Security coverage"
        )
        assert coverage.get("openQuestions", []) == [], (
            "Passed M16 security receipt has unresolved Codex Security questions"
        )
        assert coverage.get("includePaths") == ["."], (
            "Passed M16 security receipt is not repository-scoped"
        )
        assert coverage.get("excludePaths") == [], (
            "Passed M16 security receipt excludes repository paths"
        )
        assert coverage.get("explicitExclusions", []) == [], (
            "Passed M16 security receipt has explicit coverage exclusions"
        )
        surfaces = coverage.get("surfaces", [])
        assert isinstance(surfaces, list) and all(
            isinstance(surface, dict)
            and surface.get("disposition") not in {"deferred", "not_reviewed"}
            for surface in surfaces
        ), "Passed M16 security receipt has an unreviewed coverage surface"
        scope = scan.get("scope")
        assert isinstance(scope, dict), "Passed M16 security scan lacks scope"
        assert scope.get("includePaths") == ["."] and scope.get("excludePaths") == [], (
            "Passed M16 security scan scope is not complete"
        )
        assert scope.get("limitations", []) == [], (
            "Passed M16 security scan declares coverage limitations"
        )
        assert scope.get("artifactsReviewed") == trusted_m16_security_inventory(root), (
            "Passed M16 canonical scan does not bind the exact trusted source inventory"
        )
    return manifest, findings, coverage


def validate_m16_security_receipt(document: dict, *, root: Path) -> str:
    source_manifest = document["source_manifest"]
    source_files = source_manifest["files"]
    source_paths = [artifact["path"] for artifact in source_files]
    assert_unique_values(source_paths, label="M16 security source path")
    trusted_paths = trusted_m16_security_inventory(root)
    assert source_paths == trusted_paths, (
        "M16 security source manifest does not match the exact trusted source inventory; "
        f"missing={sorted(set(trusted_paths) - set(source_paths))}, "
        f"extra={sorted(set(source_paths) - set(trusted_paths))}"
    )
    assert source_manifest["file_count"] == len(source_files), (
        "M16 security source manifest file_count mismatch"
    )
    for artifact in source_files:
        validate_hashed_artifact(artifact, label="M16 security source", root=root)
    canonical_rows = b"".join(
        artifact["path"].encode("utf-8")
        + b"\t"
        + artifact["sha256"].encode("ascii")
        + b"\n"
        for artifact in sorted(
            source_files, key=lambda item: item["path"].encode("utf-8")
        )
    )
    observed_manifest_digest = hashlib.sha256(canonical_rows).hexdigest()
    assert source_manifest["sha256"] == observed_manifest_digest, (
        "M16 security source-manifest digest mismatch"
    )
    assert (
        document["frozen_inputs"]["security_source_manifest_sha256"]
        == observed_manifest_digest
    ), "M16 security frozen source digest differs from its source manifest"

    _validate_canonical_codex_security(document, root=root)

    parse_time(document["scan"]["started_at"])
    parse_time(document["scan"]["finished_at"])
    assert parse_time(document["scan"]["started_at"]) <= parse_time(
        document["scan"]["finished_at"]
    ), "M16 security scan finished before it started"
    findings = document["findings"]
    assert findings["unresolved_high_critical"] == (
        findings["unresolved_critical"] + findings["unresolved_high"]
    ), "M16 unresolved high/critical aggregate is inconsistent"
    gate_ids = [gate["id"] for gate in document["gates"]]
    assert_unique_values(gate_ids, label="M16 security gate ID")
    receipt_artifact_paths = [artifact["path"] for artifact in document["artifacts"]]
    assert_unique_values(receipt_artifact_paths, label="M16 security artifact path")
    assert set(M16_CODEX_SECURITY_ARTIFACTS.values()) <= set(receipt_artifact_paths), (
        "M16 security receipt does not bind every canonical Codex Security artifact"
    )
    for artifact in document["artifacts"]:
        validate_hashed_artifact(artifact, label="M16 security artifact", root=root)
    if document["status"] == "passed":
        assert document["scan"]["completed"], "Passed M16 security scan is incomplete"
        assert document["scan"]["exit_code"] == 0, (
            "Passed M16 security scan has a nonzero exit code"
        )
        assert findings["unresolved_high_critical"] == 0, (
            "Passed M16 security receipt has unresolved high/critical findings"
        )
        assert checks_passed(document["gates"]), (
            "Passed M16 security receipt contains a non-passing gate"
        )
        assert document["supply_chain"] == {
            "cargo_audit_passed": True,
            "cargo_deny_passed": True,
            "passed": True,
        }, "Passed M16 security receipt has incomplete supply-chain gates"
        assert document["unsafe_review"]["passed"], (
            "Passed M16 security receipt has no passing unsafe review"
        )
        assert document["unsafe_review"]["reviewed_files"] == len(source_files), (
            "Passed M16 unsafe review does not cover the trusted source inventory"
        )
    return observed_manifest_digest


def validate_m16_benchmark(document: dict, *, root: Path) -> dict[str, str]:
    assert document["benchmark"]["family"] == "BENCH-G", (
        "proof/M16/BENCH-G.json must be a BENCH-G benchmark"
    )
    assert parse_time(document["started_at"]) <= parse_time(document["finished_at"]), (
        "M16 BENCH-G finished before it started"
    )
    artifact_hashes: dict[str, str] = {}
    version_manifest_artifact: dict | None = None
    for artifact in document["artifacts"]:
        uri = artifact["uri"]
        assert isinstance(uri, str), "M16 BENCH-G artifact URI must be a string"
        resolved = resolve_repository_path(uri, label="M16 BENCH-G artifact", root=root)
        assert uri not in artifact_hashes, f"Duplicate M16 BENCH-G artifact: {uri}"
        observed = sha256_file(resolved)
        assert artifact["sha256"] == observed, (
            f"M16 BENCH-G artifact hash mismatch: {uri}"
        )
        artifact_hashes[uri] = observed
        if artifact["kind"] == "version-manifest":
            assert version_manifest_artifact is None, (
                "M16 BENCH-G must bind exactly one version manifest"
            )
            version_manifest_artifact = artifact
            assert (
                load_json(resolved, root=root)
                == document["contextdb"]["version_manifest"]
            ), "M16 BENCH-G embedded version manifest differs from its artifact"
    assert version_manifest_artifact is not None, (
        "M16 BENCH-G does not bind a version-manifest artifact"
    )
    assert (
        version_manifest_artifact["sha256"]
        == document["contextdb"]["version_manifest_sha256"]
    ), "M16 BENCH-G version-manifest digest mismatch"
    assert {"Cargo.toml", "Cargo.lock"} <= set(artifact_hashes), (
        "M16 BENCH-G must hash-bind Cargo.toml and Cargo.lock"
    )
    threshold_metrics = [
        metric for metric in document["metrics"] if "threshold" in metric
    ]
    if document["status"] == "passed":
        assert threshold_metrics, "Passed M16 BENCH-G has no threshold metrics"
        assert all(metric["passed"] for metric in threshold_metrics), (
            "Passed M16 BENCH-G has a failed threshold"
        )
        quality_gates = document.get("quality_gates", [])
        assert quality_gates and all(gate["passed"] for gate in quality_gates), (
            "Passed M16 BENCH-G has a missing or failed quality gate"
        )
    return artifact_hashes


def validate_m16_fault_receipt(
    document: dict, documents: dict[str, dict], *, root: Path
) -> None:
    durability = document["acknowledged_durability"]
    assert (
        durability["acknowledged_commits_recovered"]
        <= durability["acknowledged_commits"]
    ), "M16 recovered acknowledgements exceed acknowledged commits"

    deletion = document["deletion"]
    assert set(deletion["required_target_classes"]) == M16_DELETION_TARGETS, (
        "M16 deletion target set is incomplete"
    )
    disposition_targets = [entry["target"] for entry in deletion["dispositions"]]
    assert_unique_values(disposition_targets, label="M16 deletion disposition target")
    assert set(disposition_targets) == M16_DELETION_TARGETS, (
        "M16 deletion dispositions do not cover the required target set"
    )
    for disposition in deletion["dispositions"]:
        if "receipt" in disposition:
            validate_hashed_artifact(
                disposition["receipt"],
                label=f"M16 deletion receipt for {disposition['target']}",
                root=root,
            )

    artifact_paths = [artifact["path"] for artifact in document["artifacts"]]
    assert_unique_values(artifact_paths, label="M16 fault receipt artifact")
    assert M16_FAULT_DEPENDENCIES <= set(artifact_paths), (
        "M16 fault receipt does not bind every subordinate M16 proof"
    )
    for artifact in document["artifacts"]:
        validate_hashed_artifact(
            artifact, label="M16 fault receipt artifact", root=root
        )
    for dependency_path in M16_FAULT_DEPENDENCIES:
        assert dependency_path in documents, (
            f"M16 subordinate proof was not schema-validated: {dependency_path}"
        )

    semantic_checks = document["semantic_atomicity"]["checks"]
    backup_checks = document["backup_restore"]["checks"]
    test_runs = document["test_runs"]
    assert_unique_values(
        [check["id"] for check in semantic_checks],
        label="M16 semantic atomicity check ID",
    )
    assert_unique_values(
        [check["id"] for check in backup_checks],
        label="M16 backup/restore check ID",
    )
    assert_unique_values(
        [run["id"] for run in test_runs], label="M16 fault test-run ID"
    )
    for check in [*semantic_checks, *backup_checks]:
        if "artifact" in check:
            validate_hashed_artifact(
                check["artifact"], label=f"M16 check artifact {check['id']}", root=root
            )
    for run in test_runs:
        if "artifact" in run:
            validate_hashed_artifact(
                run["artifact"], label=f"M16 test-run artifact {run['id']}", root=root
            )

    if document["status"] == "passed":
        assert durability["passed"] and durability["acknowledged_loss"] == 0, (
            "Passed M16 fault receipt reports acknowledged loss"
        )
        assert (
            durability["acknowledged_commits_recovered"]
            == durability["acknowledged_commits"]
        ), "Passed M16 fault receipt did not recover every acknowledged commit"
        atomicity = document["semantic_atomicity"]
        assert (
            atomicity["passed"] and atomicity["partial_publications_observed"] == 0
        ), "Passed M16 fault receipt reports a partial semantic publication"
        assert checks_passed(semantic_checks), (
            "Passed M16 fault receipt has a non-passing semantic check"
        )
        assert document["backup_restore"]["passed"] and checks_passed(backup_checks), (
            "Passed M16 fault receipt has a non-passing backup/restore check"
        )
        assert deletion["passed"] and deletion["all_dispositions_verified"], (
            "Passed M16 fault receipt has incomplete deletion verification"
        )
        assert all(
            disposition["verified"]
            and disposition["disposition"] not in {"unverified", "failed"}
            for disposition in deletion["dispositions"]
        ), "Passed M16 fault receipt contains an unverified deletion disposition"
        assert all(
            run["status"] == "passed" and run["exit_code"] == 0 for run in test_runs
        ), "Passed M16 fault receipt contains a failed test run"


def validate_m16_fuzz_receipt(document: dict, *, root: Path) -> None:
    targets = document["targets"]
    target_names = [target["name"] for target in targets]
    assert_unique_values(target_names, label="M16 fuzz target")
    for target in targets:
        validate_hashed_artifact(
            target["source"], label=f"M16 fuzz source {target['name']}", root=root
        )
        if "seed" in target:
            validate_hashed_artifact(
                target["seed"], label=f"M16 fuzz seed {target['name']}", root=root
            )
    summary = document["summary"]
    passed_count = sum(target["status"] == "passed" for target in targets)
    assert summary["total_targets"] == len(targets), "M16 fuzz target total mismatch"
    assert summary["passed_targets"] == passed_count, "M16 fuzz pass total mismatch"
    assert summary["failed_targets"] == len(targets) - passed_count, (
        "M16 fuzz failure total mismatch"
    )
    if document["status"] == "passed":
        assert {"record_envelope", "security_envelope"} <= set(target_names), (
            "Passed M16 fuzz receipt lacks a required parser target"
        )
        assert all(
            target["status"] == "passed"
            and target["crashes"] == 0
            and target["timeouts"] == 0
            and target["out_of_memory"] == 0
            and target["artifact_files"] == 0
            for target in targets
        ), "Passed M16 fuzz receipt reports a failing target or crash artifact"


def _cargo_executable() -> str:
    executable = shutil.which("cargo")
    if executable is not None:
        return executable
    fallback = (
        Path.home() / ".cargo" / "bin" / ("cargo.exe" if os.name == "nt" else "cargo")
    )
    assert fallback.is_file(), (
        "cargo is required for offline M16 SBOM validation but was not found"
    )
    return str(fallback)


def load_cargo_metadata(root: Path) -> dict:
    repository_root = root.resolve()
    cache_key = (
        repository_root,
        sha256_file(repository_root / "Cargo.toml"),
        sha256_file(repository_root / "Cargo.lock"),
    )
    cached = _CARGO_METADATA_CACHE.get(cache_key)
    if cached is not None:
        return cached

    command = [
        _cargo_executable(),
        "metadata",
        "--locked",
        "--offline",
        "--all-features",
        "--format-version",
        "1",
    ]
    environment = os.environ.copy()
    environment["CARGO_NET_OFFLINE"] = "true"
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            result = subprocess.run(
                command,
                cwd=repository_root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                check=False,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AssertionError(
                f"Cannot derive offline Cargo metadata: {exc}"
            ) from exc
        stdout_size = stdout.tell()
        stderr_size = stderr.tell()
        assert stdout_size <= MAX_CARGO_METADATA_BYTES, (
            "Cargo metadata exceeds the bounded output limit"
        )
        assert stderr_size <= MAX_TEXT_BYTES, (
            "Cargo metadata diagnostics exceed the bounded output limit"
        )
        stderr.seek(0)
        diagnostics = (
            stderr.read(MAX_TEXT_BYTES).decode("utf-8", errors="replace").strip()
        )
        assert result.returncode == 0, (
            "Offline `cargo metadata --locked --all-features` failed"
            + (f": {diagnostics}" if diagnostics else "")
        )
        stdout.seek(0)
        metadata = _parse_json_bytes(
            stdout.read(MAX_CARGO_METADATA_BYTES), label="cargo metadata"
        )
    assert isinstance(metadata, dict), "Cargo metadata must be a JSON object"
    assert isinstance(metadata.get("packages"), list), "Cargo metadata lacks packages"
    resolve = metadata.get("resolve")
    assert isinstance(resolve, dict) and isinstance(resolve.get("nodes"), list), (
        "Cargo metadata lacks a resolved dependency graph"
    )
    assert isinstance(metadata.get("workspace_members"), list), (
        "Cargo metadata lacks workspace members"
    )
    _CARGO_METADATA_CACHE[cache_key] = metadata
    return metadata


def _resolved_non_dev_dependencies(node: dict) -> set[str]:
    dependencies: set[str] = set()
    for dependency in node.get("deps", []):
        assert isinstance(dependency, dict), (
            "Cargo metadata dependency must be an object"
        )
        package_id = dependency.get("pkg")
        assert isinstance(package_id, str), "Cargo metadata dependency lacks package ID"
        kinds = dependency.get("dep_kinds", [])
        assert isinstance(kinds, list), "Cargo metadata dependency kinds must be a list"
        if not kinds or any(
            isinstance(kind, dict) and kind.get("kind") != "dev" for kind in kinds
        ):
            dependencies.add(package_id)
    return dependencies


def _cargo_dependency_closure(root_id: str, nodes: dict[str, dict]) -> set[str]:
    closure = {root_id}
    pending = [root_id]
    while pending:
        package_id = pending.pop()
        assert package_id in nodes, (
            f"Cargo metadata dependency graph lacks node {package_id}"
        )
        for dependency_id in _resolved_non_dev_dependencies(nodes[package_id]):
            if dependency_id not in closure:
                closure.add(dependency_id)
                pending.append(dependency_id)
    return closure


def _validate_cyclonedx_semantics(
    sbom: dict,
    *,
    artifact_path: str,
    root_package: dict,
    packages: dict[str, dict],
    nodes: dict[str, dict],
) -> None:
    root_id = root_package["id"]
    metadata = sbom.get("metadata")
    assert isinstance(metadata, dict), (
        f"M16 CycloneDX dependency graph lacks metadata: {artifact_path}"
    )
    root_component = metadata.get("component")
    assert isinstance(root_component, dict), (
        f"M16 CycloneDX dependency graph lacks its root component: {artifact_path}"
    )
    expected_name = root_package["name"]
    expected_version = root_package["version"]
    assert root_component.get("bom-ref") == root_id, (
        f"M16 CycloneDX root reference differs from Cargo metadata: {artifact_path}"
    )
    assert (
        root_component.get("name"),
        root_component.get("version"),
    ) == (expected_name, expected_version), (
        f"M16 CycloneDX root package identity differs from Cargo metadata: {artifact_path}"
    )
    assert str(root_component.get("purl", "")).startswith(
        f"pkg:cargo/{expected_name}@{expected_version}"
    ), f"M16 CycloneDX root purl differs from Cargo metadata: {artifact_path}"

    closure = _cargo_dependency_closure(root_id, nodes)
    expected_component_refs = closure - {root_id}
    components = sbom.get("components")
    assert isinstance(components, list), (
        f"M16 CycloneDX dependency graph components must be an array: {artifact_path}"
    )
    component_by_ref: dict[str, dict] = {}
    for component in components:
        assert isinstance(component, dict), (
            f"M16 CycloneDX dependency graph component must be an object: {artifact_path}"
        )
        component_ref = component.get("bom-ref")
        assert (
            isinstance(component_ref, str) and component_ref not in component_by_ref
        ), (
            f"M16 CycloneDX dependency graph has a missing or duplicate component ref: {artifact_path}"
        )
        component_by_ref[component_ref] = component
    assert set(component_by_ref) == expected_component_refs, (
        f"M16 CycloneDX dependency graph component closure differs from Cargo metadata: {artifact_path}"
    )
    for component_ref, component in component_by_ref.items():
        package = packages[component_ref]
        assert (component.get("name"), component.get("version")) == (
            package["name"],
            package["version"],
        ), (
            f"M16 CycloneDX component identity differs from Cargo metadata: {artifact_path}"
        )
        assert str(component.get("purl", "")).startswith(
            f"pkg:cargo/{package['name']}@{package['version']}"
        ), f"M16 CycloneDX component purl differs from Cargo metadata: {artifact_path}"

    dependencies = sbom.get("dependencies")
    assert isinstance(dependencies, list), (
        f"M16 CycloneDX dependency graph must be an array: {artifact_path}"
    )
    dependencies_by_ref: dict[str, set[str]] = {}
    for dependency in dependencies:
        assert isinstance(dependency, dict), (
            f"M16 CycloneDX dependency graph entry must be an object: {artifact_path}"
        )
        dependency_ref = dependency.get("ref")
        depends_on = dependency.get("dependsOn", [])
        assert (
            isinstance(dependency_ref, str)
            and dependency_ref not in dependencies_by_ref
        ), (
            f"M16 CycloneDX dependency graph has a missing or duplicate ref: {artifact_path}"
        )
        assert isinstance(depends_on, list) and all(
            isinstance(item, str) for item in depends_on
        ), f"M16 CycloneDX dependency graph has invalid dependsOn: {artifact_path}"
        assert len(depends_on) == len(set(depends_on)), (
            f"M16 CycloneDX dependency graph has duplicate edges: {artifact_path}"
        )
        dependencies_by_ref[dependency_ref] = set(depends_on)
    assert set(dependencies_by_ref) == closure, (
        f"M16 CycloneDX dependency graph node closure differs from Cargo metadata: {artifact_path}"
    )
    for package_id in closure:
        expected_dependencies = (
            _resolved_non_dev_dependencies(nodes[package_id]) & closure
        )
        assert dependencies_by_ref[package_id] == expected_dependencies, (
            f"M16 CycloneDX dependency graph edges differ from Cargo metadata: {artifact_path}"
        )


def validate_m16_sbom_receipt(document: dict, *, root: Path) -> None:
    files = document["files"]
    paths = [artifact["path"] for artifact in files]
    assert_unique_values(paths, label="M16 SBOM path")
    component_count = 0
    dependency_count = 0
    for artifact in files:
        assert "bytes" in artifact, f"M16 SBOM entry lacks bytes: {artifact['path']}"
        resolved = validate_hashed_artifact(artifact, label="M16 SBOM", root=root)
        sbom = load_json(resolved, root=root)
        assert isinstance(sbom, dict), f"M16 SBOM is not an object: {artifact['path']}"
        assert sbom.get("bomFormat") == "CycloneDX", (
            f"M16 SBOM is not CycloneDX: {artifact['path']}"
        )
        assert sbom.get("specVersion") == document["cyclonedx_spec"], (
            f"M16 SBOM spec mismatch: {artifact['path']}"
        )
        components = sbom.get("components")
        dependencies = sbom.get("dependencies")
        assert isinstance(components, list), (
            f"M16 SBOM components must be an array: {artifact['path']}"
        )
        assert isinstance(dependencies, list), (
            f"M16 SBOM dependencies must be an array: {artifact['path']}"
        )
        component_count += len(components)
        for dependency in dependencies:
            assert isinstance(dependency, dict), (
                f"M16 SBOM dependency must be an object: {artifact['path']}"
            )
            depends_on = dependency.get("dependsOn", [])
            assert isinstance(depends_on, list), (
                f"M16 SBOM dependsOn must be an array: {artifact['path']}"
            )
            dependency_count += len(depends_on)
    totals = document["totals"]
    assert totals["files"] == len(files), "M16 SBOM file total mismatch"
    assert totals["bytes"] == sum(artifact["bytes"] for artifact in files), (
        "M16 SBOM byte total mismatch"
    )
    assert totals["components"] == component_count, "M16 SBOM component total mismatch"
    assert totals["dependency_edges"] == dependency_count, (
        "M16 SBOM dependency-edge total mismatch"
    )
    if document["status"] == "passed":
        cargo_metadata = load_cargo_metadata(root)
        packages = {package["id"]: package for package in cargo_metadata["packages"]}
        nodes = {node["id"]: node for node in cargo_metadata["resolve"]["nodes"]}
        workspace_members = cargo_metadata["workspace_members"]
        assert len(workspace_members) == len(set(workspace_members)), (
            "Cargo metadata contains duplicate workspace members"
        )
        expected_packages_by_sbom: dict[str, dict] = {}
        for package_id in workspace_members:
            assert package_id in packages, (
                f"Cargo metadata workspace member lacks package: {package_id}"
            )
            package = packages[package_id]
            manifest_path = Path(package["manifest_path"]).resolve()
            try:
                member_directory = manifest_path.parent.relative_to(root.resolve())
            except ValueError as exc:
                raise AssertionError(
                    f"Cargo workspace member escapes repository: {manifest_path}"
                ) from exc
            sbom_path = (member_directory / f"{package['name']}.cdx.json").as_posix()
            assert sbom_path not in expected_packages_by_sbom, (
                f"Cargo metadata maps duplicate workspace SBOM path: {sbom_path}"
            )
            expected_packages_by_sbom[sbom_path] = package
        expected_sboms = set(expected_packages_by_sbom)
        assert set(paths) == expected_sboms, (
            "Passed M16 SBOM index does not exactly cover Cargo workspace members; "
            f"missing={sorted(expected_sboms - set(paths))}, "
            f"extra={sorted(set(paths) - expected_sboms)}"
        )
        for artifact in files:
            sbom = load_json(root / artifact["path"], root=root)
            assert isinstance(sbom, dict)
            _validate_cyclonedx_semantics(
                sbom,
                artifact_path=artifact["path"],
                root_package=expected_packages_by_sbom[artifact["path"]],
                packages=packages,
                nodes=nodes,
            )


def validate_m16_process_kill_receipt(document: dict, *, root: Path) -> None:
    source_paths = [artifact["path"] for artifact in document["source_artifacts"]]
    assert_unique_values(source_paths, label="M16 process-kill source")
    for artifact in document["source_artifacts"]:
        validate_hashed_artifact(artifact, label="M16 process-kill source", root=root)
    cases = document["cases"]
    case_names = [case["name"] for case in cases]
    assert_unique_values(case_names, label="M16 process-kill case")
    summary = document["summary"]
    assert (
        summary["acknowledged_commits_recovered"] <= summary["acknowledged_commits"]
    ), "M16 process-kill recovered acknowledgements exceed commits"
    if document["status"] == "passed":
        assert {
            "kill_with_uncommitted_transaction",
            "kill_after_sync_ack",
        } <= set(case_names), "Passed M16 process-kill receipt lacks a required case"
        assert all(
            case["status"] == "passed"
            and case["child_reached_barrier"]
            and case["child_was_terminated"]
            and case["reopened"]
            for case in cases
        ), "Passed M16 process-kill receipt contains a failed case"
        by_name = {case["name"]: case for case in cases}
        uncommitted = by_name["kill_with_uncommitted_transaction"]
        assert not uncommitted["expected_value_visible"], (
            "Uncommitted process-kill case exposed an unacknowledged value"
        )
        assert (
            uncommitted["head_sequence"] == 0
            and uncommitted["deep_verify_records"] == 0
        ), "Uncommitted process-kill case left durable state"
        acknowledged = by_name["kill_after_sync_ack"]
        assert acknowledged["expected_value_visible"], (
            "Acknowledged process-kill case lost the synchronized value"
        )
        assert (
            acknowledged["head_sequence"] >= 1
            and acknowledged["deep_verify_records"] >= 1
        ), "Acknowledged process-kill case did not recover durable state"
        assert summary["acknowledged_loss"] == 0, (
            "Passed M16 process-kill receipt reports acknowledged loss"
        )
        assert (
            summary["acknowledged_commits_recovered"] == summary["acknowledged_commits"]
        ), "Passed M16 process-kill receipt did not recover every acknowledgement"


def validate_m16_proofs(
    milestone: dict,
    schemas: dict[str, dict],
    registry: Registry,
    *,
    root: Path | None = None,
) -> dict[str, dict]:
    repository_root = ROOT if root is None else root.resolve()
    complete_proof_required = milestone["status"] in {"passed", "waived"}
    declared = milestone["required_proof"]
    declared_paths = [entry["path"] for entry in declared]
    assert_unique_values(declared_paths, label="M16 required-proof path")
    assert set(declared_paths) == set(M16_PROOF_CONTRACTS), (
        "M16 required-proof paths differ from the registered exact contract: "
        f"missing={sorted(set(M16_PROOF_CONTRACTS) - set(declared_paths))}, "
        f"extra={sorted(set(declared_paths) - set(M16_PROOF_CONTRACTS))}"
    )
    for entry in declared:
        expected = M16_PROOF_CONTRACTS[entry["path"]]
        assert entry.get("kind") == expected["kind"], (
            f"M16 proof kind mismatch for {entry['path']}"
        )
        assert entry.get("schema_id") == expected["schema_id"], (
            f"M16 proof schema mapping mismatch for {entry['path']}"
        )
        assert expected["schema_id"] in schemas, (
            f"M16 proof references an unregistered schema: {expected['schema_id']}"
        )

    documents: dict[str, dict] = {}
    missing_paths: list[str] = []
    for path, contract in M16_PROOF_CONTRACTS.items():
        proof_path = (repository_root / path).resolve()
        try:
            proof_path.relative_to(repository_root)
        except ValueError as exc:
            raise AssertionError(f"M16 required proof escapes repository: {path}") from exc
        if not proof_path.is_file():
            missing_paths.append(path)
            continue
        documents[path] = validate_instance(
            proof_path,
            contract["schema_id"],
            schemas,
            registry,
            root=repository_root,
        )
    if complete_proof_required:
        assert not missing_paths, (
            "M16 required proof is missing: " + ", ".join(missing_paths)
        )

    security = documents.get("proof/M16/security-gates.json")
    source_digest = (
        validate_m16_security_receipt(security, root=repository_root)
        if security is not None
        else None
    )
    benchmark = documents.get("proof/M16/BENCH-G.json")
    benchmark_hashes = (
        validate_m16_benchmark(benchmark, root=repository_root)
        if benchmark is not None
        else None
    )

    current_workspace_inputs = {
        "workspace_manifest_sha256": sha256_file(repository_root / "Cargo.toml"),
        "cargo_lock_sha256": sha256_file(repository_root / "Cargo.lock"),
    }
    frozen_source_digests: set[str] = set()
    for path in M16_CUSTOM_PROOF_PATHS:
        document = documents.get(path)
        if document is None:
            continue
        frozen_inputs = document["frozen_inputs"]
        assert all(
            frozen_inputs[key] == value
            for key, value in current_workspace_inputs.items()
        ), f"M16 frozen source/Cargo hash binding mismatch: {path}"
        frozen_source_digests.add(
            frozen_inputs["security_source_manifest_sha256"]
        )
        if source_digest is not None:
            assert (
                frozen_inputs["security_source_manifest_sha256"] == source_digest
            ), f"M16 frozen source/Cargo hash binding mismatch: {path}"
    assert len(frozen_source_digests) <= 1, (
        "M16 present receipts disagree on the security source-manifest digest"
    )

    if benchmark_hashes is not None:
        assert (
            benchmark_hashes["Cargo.toml"]
            == current_workspace_inputs["workspace_manifest_sha256"]
        ), "M16 BENCH-G Cargo.toml binding differs from current source"
        assert (
            benchmark_hashes["Cargo.lock"]
            == current_workspace_inputs["cargo_lock_sha256"]
        ), "M16 BENCH-G Cargo.lock binding differs from current source"
        benchmark_source_digest = benchmark["configuration"]["parameters"].get(
            "security_source_manifest_sha256"
        )
        expected_source_digest = source_digest
        if expected_source_digest is None and frozen_source_digests:
            expected_source_digest = next(iter(frozen_source_digests))
        if expected_source_digest is not None:
            assert benchmark_source_digest == expected_source_digest, (
                "M16 BENCH-G security source-manifest binding differs from "
                "present receipts"
            )

    fuzz = documents.get("proof/M16/fuzz-smoke.json")
    if fuzz is not None:
        validate_m16_fuzz_receipt(fuzz, root=repository_root)
    sbom = documents.get("proof/M16/sbom-index.json")
    if sbom is not None:
        validate_m16_sbom_receipt(sbom, root=repository_root)
    process_kill = documents.get("proof/M16/process-kill-redb.json")
    if process_kill is not None:
        validate_m16_process_kill_receipt(process_kill, root=repository_root)
    fault = documents.get("proof/M16/fault-delete-restore.json")
    if fault is not None:
        validate_m16_fault_receipt(fault, documents, root=repository_root)

    if milestone["status"] == "passed":
        non_passing = {
            path: document["status"]
            for path, document in documents.items()
            if document["status"] != "passed"
        }
        assert not non_passing, (
            f"M16 passed with non-passing receipt statuses: {non_passing}"
        )
    return documents


def validate_quality_privacy_regressions(
    schemas: dict[str, dict], registry: Registry
) -> dict[Path, dict]:
    receipts: dict[Path, dict] = {}
    proof_root = ROOT / "proof"
    if not proof_root.is_dir():
        return receipts
    for path in sorted(proof_root.rglob("*.json")):
        document = load_json(path)
        if (
            not isinstance(document, dict)
            or document.get("schema_version")
            != "contextdb.quality-privacy-regression/v1"
        ):
            continue
        receipt = validate_instance(
            path,
            "https://contextdb.dev/schemas/quality-privacy-regression/v1.json",
            schemas,
            registry,
        )
        parse_time(receipt["generated_at"])
        check_ids = [check["id"] for check in receipt["checks"]]
        assert len(check_ids) == len(set(check_ids)), (
            f"Duplicate regression check ID in {path.relative_to(ROOT)}"
        )
        for check in receipt["checks"]:
            resolve_repository_path(
                check["source"], label=f"Regression source for {check['id']}"
            )
        artifact_paths: set[str] = set()
        for artifact in receipt["artifacts"]:
            assert artifact["path"] not in artifact_paths, (
                f"Duplicate regression artifact {artifact['path']}"
            )
            artifact_paths.add(artifact["path"])
            artifact_path = resolve_repository_path(
                artifact["path"], label="Regression artifact"
            )
            observed = sha256_file(artifact_path)
            assert observed == artifact["sha256"], (
                f"Regression artifact hash mismatch: {artifact['path']}"
            )
        all_checks_pass = all(check["passed"] for check in receipt["checks"])
        if receipt["status"] == "passed":
            assert all_checks_pass, (
                f"Passed regression receipt contains a failed check: {path.relative_to(ROOT)}"
            )
        elif receipt["status"] == "failed":
            assert not all_checks_pass, (
                f"Failed regression receipt has no failed check: {path.relative_to(ROOT)}"
            )
        receipts[path.resolve()] = receipt
    return receipts


def _waiver_adr_field(content: str, label: str, *, adr_name: str) -> str:
    matches = re.findall(
        rf"(?mi)^-\s*{re.escape(label)}:\s*(\S(?:.*\S)?)\s*$",
        content,
    )
    assert len(matches) == 1, (
        f"{adr_name} must contain exactly one structured waiver field '{label}'"
    )
    return matches[0]


def validate_waivers(
    milestones: list[dict],
    *,
    root: Path,
    trusted_on: date | None = None,
) -> None:
    trusted_date = (
        trusted_on if trusted_on is not None else datetime.now(timezone.utc).date()
    )
    by_id = {milestone["id"]: milestone for milestone in milestones}
    for milestone in milestones:
        milestone_id = milestone["id"]
        status = milestone["status"]
        has_waiver = "waiver" in milestone
        if milestone_id == "M19":
            assert status != "waived", "M19 cannot be waived"
        assert has_waiver == (status == "waived"), (
            f"{milestone_id} waiver metadata is allowed only with waived status"
        )
        if status != "waived":
            continue

        assert milestone.get("status_reason", "").strip(), (
            f"{milestone_id} waived without status_reason"
        )
        non_passing_dependencies = [
            dependency
            for dependency in milestone["depends_on"]
            if dependency not in by_id or by_id[dependency]["status"] != "passed"
        ]
        assert not non_passing_dependencies, (
            f"{milestone_id} waived before dependencies passed: "
            f"{non_passing_dependencies}"
        )

        waiver = milestone["waiver"]
        residual_risk = waiver["residual_risk"].strip()
        assert residual_risk, f"{milestone_id} waiver has empty residual risk"
        try:
            expires = date.fromisoformat(waiver["expires"])
        except (TypeError, ValueError) as exc:
            raise AssertionError(
                f"{milestone_id} waiver expiry is not an ISO date"
            ) from exc
        assert expires >= trusted_date, (
            f"{milestone_id} waiver expired on {expires.isoformat()} before trusted date "
            f"{trusted_date.isoformat()}"
        )

        adr_id = waiver["adr"]
        adr_matches = sorted((root / "docs" / "adr").glob(f"{adr_id}-*.md"))
        assert len(adr_matches) == 1, (
            f"{milestone_id} waiver must resolve exactly one ADR for {adr_id}"
        )
        adr_path = adr_matches[0]
        content = load_text(adr_path, root=root, label="waiver ADR")
        assert re.search(r"(?m)^- Status: Accepted\s*$", content), (
            f"{adr_path.name} is not Accepted for {milestone_id} waiver"
        )
        assert (
            _waiver_adr_field(content, "Waived milestone", adr_name=adr_path.name)
            == milestone_id
        ), f"{adr_path.name} waiver milestone does not match {milestone_id}"
        assert (
            _waiver_adr_field(content, "Waiver expires", adr_name=adr_path.name)
            == waiver["expires"]
        ), f"{adr_path.name} waiver expiry differs from the ledger"
        assert (
            _waiver_adr_field(content, "Residual risk", adr_name=adr_path.name)
            == residual_risk
        ), f"{adr_path.name} residual risk differs from the ledger"


def validate_gate_ledger(
    schemas: dict[str, dict],
    registry: Registry,
    regression_receipts: dict[Path, dict],
) -> None:
    ledger = validate_instance(
        ROOT / "docs" / "roadmap" / "gates.json",
        "https://contextdb.dev/schemas/roadmap-gate-ledger/v1.json",
        schemas,
        registry,
    )
    milestones = ledger["milestones"]
    by_id = {milestone["id"]: milestone for milestone in milestones}
    expected = {f"M{index}" for index in range(20)}
    assert set(by_id) == expected, f"Milestone IDs differ: {set(by_id) ^ expected}"
    assert len(by_id) == len(milestones), "Duplicate milestone ID"
    validate_waivers(milestones, root=ROOT)
    validate_m16_proofs(by_id["M16"], schemas, registry)

    exit_ids: set[str] = set()
    for milestone in milestones:
        current = int(milestone["id"][1:])
        for dependency in milestone["depends_on"]:
            assert dependency in by_id, f"Unknown dependency {dependency}"
            assert int(dependency[1:]) < current, (
                f"{milestone['id']} dependency {dependency} must be an earlier milestone"
            )
        for criterion in milestone["exit_criteria"]:
            assert criterion["id"].startswith(f"{milestone['id']}-"), (
                f"Exit {criterion['id']} has wrong milestone prefix"
            )
            assert criterion["id"] not in exit_ids, (
                f"Duplicate exit ID {criterion['id']}"
            )
            exit_ids.add(criterion["id"])
        if milestone["status"] == "passed":
            unpassed = [
                dep
                for dep in milestone["depends_on"]
                if by_id[dep]["status"] != "passed"
            ]
            assert not unpassed, (
                f"{milestone['id']} passed before dependencies {unpassed}"
            )
            missing_proof = [
                proof["path"]
                for proof in milestone["required_proof"]
                if not (ROOT / proof["path"]).is_file()
            ]
            assert not missing_proof, (
                f"{milestone['id']} passed without proof files {missing_proof}"
            )
            required_paths = {proof["path"] for proof in milestone["required_proof"]}
            referenced_paths: set[str] = set()
            for criterion in milestone["exit_criteria"]:
                assert criterion.get("status") == "passed", (
                    f"{milestone['id']} passed while {criterion['id']} is not explicitly passed"
                )
                evidence = criterion.get("evidence", [])
                assert evidence, f"Passed exit {criterion['id']} has no bound evidence"
                for evidence_path in evidence:
                    assert evidence_path in required_paths, (
                        f"Exit {criterion['id']} binds undeclared proof {evidence_path}"
                    )
                    resolve_repository_path(
                        evidence_path, label=f"Evidence for {criterion['id']}"
                    )
                    referenced_paths.add(evidence_path)
            assert referenced_paths == required_paths, (
                f"{milestone['id']} has required proof not bound to an exit: "
                f"{sorted(required_paths - referenced_paths)}"
            )
            for proof in milestone["required_proof"]:
                proof_path = (ROOT / proof["path"]).resolve()
                document = (
                    load_json(proof_path) if proof_path.suffix == ".json" else None
                )
                if (
                    isinstance(document, dict)
                    and document.get("schema_version")
                    == "contextdb.benchmark-result/v1"
                ):
                    assert document.get("status") == "passed", (
                        f"{milestone['id']} passed with non-passing benchmark {proof['path']}"
                    )
                regression = regression_receipts.get(proof_path)
                if regression is not None:
                    assert regression["status"] == "passed", (
                        f"{milestone['id']} passed with non-passing regression receipt {proof['path']}"
                    )
        if milestone["status"] in {"blocked", "failed", "waived"}:
            assert milestone.get("status_reason", "").strip(), (
                f"{milestone['id']} {milestone['status']} without status_reason"
            )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise AssertionError(f"Roadmap dependency cycle at {node}")
        if node in visited:
            return
        visiting.add(node)
        for dependency in by_id[node]["depends_on"]:
            visit(dependency)
        visiting.remove(node)
        visited.add(node)

    for milestone_id in sorted(by_id, key=lambda value: int(value[1:])):
        visit(milestone_id)

    assert by_id["M0"]["depends_on"] == [], "M0 must have no dependency"
    assert by_id["M19"]["depends_on"] == ["M18"], "M19 must depend on M18"
    m19_artifacts = " ".join(by_id["M19"]["artifacts"]).lower()
    for required in ("signed checksums", "sbom", "mcp", "docker", "benchmark"):
        assert required in m19_artifacts, f"M19 artifact list missing {required}"


def validate_labels(schemas: dict[str, dict], registry: Registry) -> None:
    path = ROOT / ".github" / "labels.yml"
    labels = load_yaml(path)
    schema_id = "https://contextdb.dev/schemas/issue-labels/v1.json"
    validator = Draft202012Validator(
        schemas[schema_id], registry=registry, format_checker=FormatChecker()
    )
    errors = sorted(
        validator.iter_errors(labels), key=lambda error: list(error.absolute_path)
    )
    if errors:
        raise AssertionError(
            "Label schema failed: " + "; ".join(error.message for error in errors)
        )
    names = [label["name"] for label in labels["labels"]]
    assert len(names) == len({name.casefold() for name in names}), (
        "Duplicate issue-label name"
    )
    for milestone in range(20):
        assert f"milestone:M{milestone}" in names, (
            f"Missing milestone:M{milestone} label"
        )


def validate_workflows() -> None:
    workflow_dir = ROOT / ".github" / "workflows"
    workflows = sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")])
    assert workflows, "No GitHub workflows found"
    combined = ""
    for path in workflows:
        document = load_yaml(path)
        assert isinstance(document, dict), f"Workflow {path.name} must be a mapping"
        raw = load_text(path, label="workflow")
        assert "permissions:" in raw, f"Workflow {path.name} lacks explicit permissions"
        combined += "\n" + raw
    required_tokens = (
        "ubuntu-24.04",
        "ubuntu-24.04-arm",
        "macos-14",
        "windows-2025",
        "cargo fmt",
        "cargo clippy",
        "cargo test",
        "cargo audit",
        "cargo deny",
        "cargo-fuzz",
        "fuzz run",
    )
    for token in required_tokens:
        assert token in combined, f"CI workflows missing required token: {token}"


def main() -> None:
    schemas, registry = build_registry()
    validate_version_manifest(schemas, registry)
    validate_benchmark(schemas, registry)
    regressions = validate_quality_privacy_regressions(schemas, registry)
    validate_gate_ledger(schemas, registry, regressions)
    validate_labels(schemas, registry)
    validate_workflows()
    print(
        f"governance validation passed: {len(schemas)} schemas, "
        "20 milestones, workflows and labels"
    )


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(f"governance validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
