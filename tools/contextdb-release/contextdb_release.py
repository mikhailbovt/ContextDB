#!/usr/bin/env python3
"""Fail-closed ContextDB release bundle verifier and packaging utilities.

This tool deliberately separates contract/source evidence from a release claim.
Only ``verify-bundle --profile release`` can emit ``release_ready: true`` and it
requires production signatures, complete artifact/platform coverage, and a
passed roadmap proof closure.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
import zipfile
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9-]*$")
MILESTONE_RE = re.compile(r"^M(?:[0-9]|1[0-9])$")
EXIT_RE = re.compile(r"^M(?:[0-9]|1[0-9])-E[0-9]{2}$")

REQUIRED_V1_ROLES = frozenset(
    {
        "server",
        "cli",
        "rust-crates",
        "python-package",
        "go-sdk",
        "typescript-sdk",
        "chat-middleware",
        "mcp-adapter",
        "document-adapter",
        "coding-plugin",
        "docker-image",
        "example-databases",
        "benchmark-suite",
        "benchmark-datasets",
        "full-docs",
        "signed-checksums",
        "sbom",
    }
)
REQUIRED_ALPHA_ROLES = frozenset(
    {
        "server",
        "cli",
        "rust-crates",
        "chat-middleware",
        "document-adapter",
        "example-databases",
        "benchmark-suite",
        "benchmark-datasets",
        "full-docs",
        "signed-checksums",
        "sbom",
    }
)
ROLE_ARTIFACT_KIND = {
    "server": "executable",
    "cli": "executable",
    "rust-crates": "rust-crate",
    "python-package": "python-wheel",
    "go-sdk": "go-module",
    "typescript-sdk": "typescript-package",
    "chat-middleware": "rust-crate",
    "mcp-adapter": "source-package",
    "document-adapter": "source-package",
    "coding-plugin": "source-package",
    "docker-image": "docker-image",
    "example-databases": "example-database",
    "benchmark-suite": "benchmark-suite",
    "benchmark-datasets": "benchmark-dataset",
    "full-docs": "documentation",
    "signed-checksums": "checksum-set",
    "sbom": "sbom",
}
RUNTIME_REQUIRED_ARTIFACT_KINDS = frozenset(
    {
        "executable",
        "rust-crate",
        "python-wheel",
        "go-module",
        "typescript-package",
        "source-package",
        "docker-image",
        "example-database",
        "benchmark-suite",
    }
)
NORMATIVE_SIGNATURE_ROLES = {
    "alpha": frozenset({"artifact-manifest", "checksums"}),
    "beta": frozenset(
        {"artifact-manifest", "checksums", "proof-index", "version-manifest"}
    ),
    "stable": frozenset(
        {"artifact-manifest", "checksums", "proof-index", "version-manifest"}
    ),
}
NORMATIVE_PLATFORMS = {
    "linux-x86-64": ("x86_64-unknown-linux-gnu", "required"),
    "linux-arm64": ("aarch64-unknown-linux-gnu", "required"),
    "macos-arm64": ("aarch64-apple-darwin", "required"),
    "windows-x86-64": ("x86_64-pc-windows-msvc", "best-effort"),
}
RELEASE_TOOL_VERSION = "0.1.0-alpha.4"
SCHEMA_FILES = {
    "contextdb.release-bundle-input/v1": "release-bundle-input.schema.json",
    "contextdb.release-bundle-assembly-receipt/v1": (
        "release-bundle-assembly-receipt.schema.json"
    ),
    "contextdb.release-artifact-manifest/v1": "release-artifact-manifest.schema.json",
    "contextdb.release-package-matrix/v1": "release-package-matrix.schema.json",
    "contextdb.release-proof-index/v1": "release-proof-index.schema.json",
    "contextdb.release-signature-set/v1": "release-signature-set.schema.json",
    "contextdb.version-manifest/v1": "version-manifest.schema.json",
    "contextdb.clean-install-receipt/v1": "clean-install-receipt.schema.json",
    "contextdb.release-publication-receipt/v1": "release-publication-receipt.schema.json",
    "contextdb.release-documentation-matrix/v1": "release-documentation-matrix.schema.json",
    "contextdb.roadmap-gate-ledger/v1": "roadmap-gate-ledger.schema.json",
    "contextdb.release-source-audit/v1": "release-source-audit.schema.json",
    "contextdb.release-readiness-report/v1": "release-readiness-report.schema.json",
    "contextdb.release-verification-report/v1": "release-verification-report.schema.json",
    "contextdb.portable-example-package-receipt/v1": "portable-example-package-receipt.schema.json",
    "contextdb.release-operational-plan/v1": "release-operational-plan.schema.json",
    "contextdb.release-operational-receipt/v1": (
        "release-operational-receipt.schema.json"
    ),
    "contextdb.release-external-receipt-set/v1": (
        "release-external-receipt-set.schema.json"
    ),
    "contextdb.release-external-receipt-intake/v1": (
        "release-external-receipt-intake.schema.json"
    ),
}
_SCHEMA_VALIDATORS: dict[str, Any] = {}
DOCUMENTATION_CATEGORIES = frozenset(
    {
        "architecture",
        "data-model",
        "memory-concepts",
        "conversation-integration",
        "domain-pack-authoring",
        "security",
        "privacy",
        "operations",
        "formats",
        "apis",
        "benchmarks",
        "limitations",
        "migration",
        "examples",
    }
)


class ContractError(ValueError):
    """Raised for an invalid CLI input or unsafe path before reporting starts."""


@dataclass(frozen=True)
class Issue:
    severity: str
    code: str
    message: str
    context: str | None = None


@dataclass(frozen=True)
class Check:
    id: str
    status: str
    detail: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ContractError) as error:
        raise ContractError(f"cannot load JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise ContractError(f"JSON root must be an object: {path}")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.write_text(encoded, encoding="utf-8", newline="\n")


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _write_bytes_atomic(path: Path, value: bytes, mode: int = 0o644) -> None:
    """Write one file without exposing a partial result."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_value = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_value)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _write_json_atomic(path: Path, value: Any) -> None:
    _write_bytes_atomic(path, _canonical_json_bytes(value))


def _set_mtime(path: Path, epoch: int) -> None:
    try:
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    except NotImplementedError:
        # Windows does not expose follow_symlinks for utime. Callers have already
        # rejected links and junctions before this deterministic metadata step.
        os.utime(path, (epoch, epoch))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_json_contract(value: dict[str, Any], label: str) -> None:
    schema_version = require_string(
        value.get("schema_version"), f"{label}.schema_version"
    )
    schema_filename = SCHEMA_FILES.get(schema_version)
    if schema_filename is None:
        raise ContractError(f"{label} uses unsupported schema {schema_version}")
    try:
        from jsonschema import (  # type: ignore[import-untyped]
            Draft202012Validator,
            FormatChecker,
        )
    except ImportError as error:
        raise ContractError(
            "jsonschema is required for release contract validation"
        ) from error
    validator = _SCHEMA_VALIDATORS.get(schema_filename)
    if validator is None:
        schema_path = (
            Path(__file__).resolve().parents[2] / "assets" / "schemas" / schema_filename
        )
        if not schema_path.is_file():
            raise ContractError(f"trusted release schema is unavailable: {schema_path}")
        schema = load_json(schema_path)
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as error:
            raise ContractError(
                f"trusted release schema is invalid: {schema_filename}: {error}"
            ) from error
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        _SCHEMA_VALIDATORS[schema_filename] = validator
    errors = sorted(
        validator.iter_errors(value),
        key=lambda error: tuple(str(part) for part in error.path),
    )
    if errors:
        validation_error = errors[0]
        location = ".".join(str(part) for part in validation_error.absolute_path) or "$"
        raise ContractError(
            f"{label} schema violation at {location}: {validation_error.message}"
        )


def parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ContractError(f"{label} must be an RFC 3339 string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ContractError(f"{label} is not an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise ContractError(f"{label} must include a UTC offset")
    return parsed


def canonical_relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty relative path")
    if "\\" in value or "\x00" in value:
        raise ContractError(f"{label} must use safe forward-slash separators")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ContractError(f"{label} is not a canonical relative path: {value}")
    if pure.as_posix() != value:
        raise ContractError(f"{label} is not normalized: {value}")
    if re.match(r"^[A-Za-z]:", value):
        raise ContractError(f"{label} must not be drive-qualified: {value}")
    windows_reserved = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
    for part in pure.parts:
        if unicodedata.normalize("NFC", part) != part:
            raise ContractError(f"{label} must use NFC-normalized path text: {value}")
        if (
            part.endswith((" ", "."))
            or any(character in '<>:"|?*' or ord(character) < 32 for character in part)
            or part.split(".", 1)[0].upper() in windows_reserved
        ):
            raise ContractError(f"{label} is not portable across target hosts: {value}")
    return pure.as_posix()


def resolve_member(root: Path, value: Any, label: str) -> tuple[str, Path]:
    relative = canonical_relative_path(value, label)
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    resolved_root = root.resolve(strict=True)
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        raise ContractError(f"{label} escapes bundle root: {relative}") from error
    cursor = candidate
    while cursor != root and cursor != cursor.parent:
        if cursor.is_symlink():
            raise ContractError(f"{label} traverses a symbolic link: {relative}")
        cursor = cursor.parent
    return relative, candidate


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def require_array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    return value


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ContractError(f"{label} must be a lowercase SHA-256 digest")
    return value


def require_semver(value: Any, label: str) -> str:
    if not isinstance(value, str) or SEMVER_RE.fullmatch(value) is None:
        raise ContractError(f"{label} must be semantic version text")
    return value


def _compare_semver_precedence(left: str, right: str) -> int:
    """Compare SemVer precedence while deliberately ignoring build metadata."""

    def parse(value: str) -> tuple[tuple[int, int, int], list[str] | None]:
        normalized = require_semver(value, "semantic version").split("+", 1)[0]
        core, separator, prerelease = normalized.partition("-")
        major, minor, patch = (int(part) for part in core.split("."))
        return (major, minor, patch), prerelease.split(".") if separator else None

    left_core, left_pre = parse(left)
    right_core, right_pre = parse(right)
    if left_core != right_core:
        return -1 if left_core < right_core else 1
    if left_pre is None or right_pre is None:
        if left_pre is right_pre:
            return 0
        return 1 if left_pre is None else -1
    for left_id, right_id in zip(left_pre, right_pre, strict=False):
        if left_id == right_id:
            continue
        left_numeric = left_id.isascii() and left_id.isdigit()
        right_numeric = right_id.isascii() and right_id.isdigit()
        if left_numeric and right_numeric:
            return -1 if int(left_id) < int(right_id) else 1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return -1 if left_id < right_id else 1
    if len(left_pre) == len(right_pre):
        return 0
    return -1 if len(left_pre) < len(right_pre) else 1


def require_semver_upgrade(old: str, new: str, label: str) -> None:
    if _compare_semver_precedence(new, old) <= 0:
        raise ContractError(f"{label} requires new version precedence greater than old")


def require_public_https_uri(value: Any, label: str) -> str:
    uri = require_string(value, label)
    try:
        parsed = urlsplit(uri)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as error:
        raise ContractError(f"{label} is not a valid public HTTPS URI") from error
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or hostname is None
        or parsed.fragment
        or parsed.path in {"", "/"}
    ):
        raise ContractError(f"{label} must name a public HTTPS immutable URI")
    normalized_host = hostname.rstrip(".").lower()
    reserved_suffixes = (
        ".invalid",
        ".localhost",
        ".local",
        ".test",
        ".example",
    )
    try:
        address = ip_address(normalized_host)
    except ValueError:
        if (
            normalized_host == "localhost"
            or "." not in normalized_host
            or normalized_host.endswith(reserved_suffixes)
        ):
            raise ContractError(f"{label} must name a public HTTPS immutable URI")
    else:
        if not address.is_global:
            raise ContractError(f"{label} must name a public HTTPS immutable URI")
    return uri


class BundleVerifier:
    def __init__(
        self,
        bundle_root: Path,
        manifest_path: str,
        profile: str,
        trusted_keys: dict[str, Path],
        allow_test_keys: bool,
    ) -> None:
        self.root = bundle_root.resolve(strict=True)
        self.manifest_relative, self.manifest_path = resolve_member(
            self.root, manifest_path, "artifact manifest path"
        )
        self.profile = profile
        self.trusted_keys = trusted_keys
        self.allow_test_keys = allow_test_keys
        self.issues: list[Issue] = []
        self.checks: list[Check] = []
        self.unresolved_gates: set[str] = set()
        self.expected_checksums: dict[str, str] = {}
        self.crypto_verified_roles: set[str] = set()
        self.control_paths: set[str] = set()
        self.path_spellings: dict[str, str] = {}

    def issue(
        self, severity: str, code: str, message: str, context: str | None = None
    ) -> None:
        self.issues.append(Issue(severity, code, message, context))

    def gate_issue(self, code: str, message: str, context: str | None = None) -> None:
        severity = "error" if self.profile == "release" else "warning"
        self.issue(severity, code, message, context)

    def check(self, identifier: str, status: str, detail: str) -> None:
        self.checks.append(Check(identifier, status, detail))

    def register_path(self, relative: str, label: str) -> None:
        folded = relative.casefold()
        prior = self.path_spellings.get(folded)
        if prior is not None and prior != relative:
            self.issue(
                "error",
                "PATH_CASE_COLLISION",
                f"portable bundle paths collide: {prior!r} and {relative!r}",
                label,
            )
        else:
            self.path_spellings[folded] = relative

    def verify_file(
        self,
        reference: dict[str, Any],
        label: str,
        *,
        include_checksum: bool = True,
        size_required: bool = False,
    ) -> tuple[str, Path] | None:
        try:
            relative, path = resolve_member(
                self.root, reference.get("path"), f"{label}.path"
            )
            self.register_path(relative, label)
            expected = require_sha256(reference.get("sha256"), f"{label}.sha256")
            expected_size = reference.get("size_bytes")
            if size_required and not isinstance(expected_size, int):
                raise ContractError(f"{label}.size_bytes must be an integer")
        except ContractError as error:
            self.issue("error", "INVALID_FILE_REFERENCE", str(error), label)
            return None
        if not path.is_file():
            self.issue(
                "error", "MISSING_FILE", f"required file is absent: {relative}", label
            )
            return None
        actual = sha256_file(path)
        if actual != expected:
            self.issue(
                "error",
                "DIGEST_MISMATCH",
                f"{relative}: expected {expected}, observed {actual}",
                label,
            )
        if isinstance(expected_size, int) and path.stat().st_size != expected_size:
            self.issue(
                "error",
                "SIZE_MISMATCH",
                f"{relative}: expected {expected_size}, observed {path.stat().st_size}",
                label,
            )
        if include_checksum:
            prior = self.expected_checksums.get(relative)
            if prior is not None and prior != expected:
                self.issue(
                    "error",
                    "CONFLICTING_DIGEST",
                    f"{relative} is referenced with two SHA-256 digests",
                    label,
                )
            self.expected_checksums[relative] = expected
        return relative, path

    def verify(self) -> dict[str, Any]:
        self.register_path(self.manifest_relative, "artifact manifest path")
        for key_id, key_path in self.trusted_keys.items():
            try:
                resolved_key = key_path.resolve(strict=True)
            except OSError as error:
                self.issue(
                    "error",
                    "TRUSTED_KEY_UNAVAILABLE",
                    f"cannot resolve trusted key: {error}",
                    key_id,
                )
                continue
            try:
                resolved_key.relative_to(self.root)
            except ValueError:
                pass
            else:
                self.issue(
                    "error",
                    "TRUSTED_KEY_INSIDE_BUNDLE",
                    "trusted public keys must be supplied outside the release bundle",
                    key_id,
                )
        try:
            manifest = load_json(self.manifest_path)
            self.expected_checksums[self.manifest_relative] = sha256_file(
                self.manifest_path
            )
            state = self._verify_manifest(manifest)
            if state is not None:
                self._verify_proof_closure(state)
                self._verify_checksums(state)
                self._verify_signatures(state)
                self._verify_bundle_inventory(state)
        except ContractError as error:
            self.issue("error", "INVALID_CONTRACT", str(error))
            state = None

        errors = sum(issue.severity == "error" for issue in self.issues)
        warnings = sum(issue.severity == "warning" for issue in self.issues)
        release_ready = self.profile == "release" and errors == 0
        contract_valid = errors == 0
        outcome = (
            "release_ready"
            if release_ready
            else "contract_valid"
            if contract_valid
            else "failed"
        )
        channel = None if state is None else state["channel"]
        version = None if state is None else state["version"]
        return {
            "schema_version": "contextdb.release-verification-report/v1",
            "verifier_version": RELEASE_TOOL_VERSION,
            "profile": self.profile,
            "release_version": version,
            "release_channel": channel,
            "outcome": outcome,
            "contract_valid": contract_valid,
            "release_ready": release_ready,
            "summary": {"errors": errors, "warnings": warnings},
            "checks": [
                asdict(check) for check in sorted(self.checks, key=lambda item: item.id)
            ],
            "issues": [
                asdict(issue)
                for issue in sorted(
                    self.issues,
                    key=lambda item: (
                        item.severity,
                        item.code,
                        item.context or "",
                        item.message,
                    ),
                )
            ],
            "unresolved_gates": sorted(self.unresolved_gates),
            "evidence_boundary": {
                "contract_profile_is_release_proof": False,
                "release_profile_requires_production_signatures": True,
                "docker_runtime_executed_by_verifier": False,
                "publication_receipts_cryptographically_bound": True,
                "publication_live_retrieval_performed": False,
            },
        }

    def _verify_manifest(self, manifest: dict[str, Any]) -> dict[str, Any] | None:
        validate_json_contract(manifest, "artifact manifest")
        if manifest.get("schema_version") != "contextdb.release-artifact-manifest/v1":
            raise ContractError("unsupported artifact manifest schema_version")
        release = require_object(manifest.get("release"), "release")
        version = require_semver(release.get("version"), "release.version")
        channel = release.get("channel")
        if channel not in {"development", "alpha", "beta", "stable"}:
            raise ContractError("release.channel is invalid")
        parse_timestamp(release.get("created_at"), "release.created_at")
        if self.profile == "release" and channel == "development":
            self.issue(
                "error",
                "DEVELOPMENT_IS_NOT_RELEASE",
                "development bundles cannot be release-ready",
            )

        source = require_object(manifest.get("source"), "source")
        source_commit = require_string(source.get("git_commit"), "source.git_commit")
        if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
            raise ContractError(
                "source.git_commit must be a lowercase 40-character commit"
            )
        if not isinstance(source.get("dirty"), bool):
            raise ContractError("source.dirty must be boolean")
        if source["dirty"]:
            self.gate_issue("DIRTY_SOURCE", "release source is marked dirty")

        version_ref = require_object(
            manifest.get("version_manifest"), "version_manifest"
        )
        matrix_ref = require_object(manifest.get("package_matrix"), "package_matrix")
        proof_ref = require_object(manifest.get("proof_index"), "proof_index")
        version_file = self.verify_file(version_ref, "version_manifest")
        matrix_file = self.verify_file(matrix_ref, "package_matrix")
        proof_file = self.verify_file(proof_ref, "proof_index")
        if version_file is None or matrix_file is None or proof_file is None:
            return None

        version_manifest = load_json(version_file[1])
        matrix = load_json(matrix_file[1])
        proof = load_json(proof_file[1])
        self._verify_version_manifest(version_manifest, version, channel, source_commit)
        packages, platforms = self._verify_matrix(matrix)

        artifacts_raw = require_array(manifest.get("artifacts"), "artifacts")
        artifacts: list[dict[str, Any]] = []
        artifact_ids: set[str] = set()
        artifact_paths: set[str] = set()
        for index, raw in enumerate(artifacts_raw):
            label = f"artifacts[{index}]"
            try:
                artifact = require_object(raw, label)
                artifact_id = require_string(artifact.get("id"), f"{label}.id")
                package_id = require_string(
                    artifact.get("package_id"), f"{label}.package_id"
                )
                if IDENTIFIER_RE.fullmatch(artifact_id) is None:
                    raise ContractError(f"{label}.id is not canonical")
                if artifact_id in artifact_ids:
                    raise ContractError(f"duplicate artifact id: {artifact_id}")
                artifact_ids.add(artifact_id)
                package = packages.get(package_id)
                if package is None:
                    raise ContractError(
                        f"{label} references unknown package {package_id}"
                    )
                file_value = self.verify_file(artifact, label, size_required=True)
                if file_value is None:
                    continue
                relative = file_value[0]
                if relative in artifact_paths:
                    raise ContractError(f"duplicate artifact path: {relative}")
                artifact_paths.add(relative)
                if artifact.get("kind") != package.get("artifact_kind"):
                    raise ContractError(f"{label}.kind does not match package matrix")
                roles = set(require_array(artifact.get("roles"), f"{label}.roles"))
                required_roles = set(
                    require_array(package.get("roles"), f"package {package_id}.roles")
                )
                if not required_roles.issubset(roles):
                    raise ContractError(f"{label}.roles does not cover package roles")
                targets = require_array(artifact.get("targets"), f"{label}.targets")
                if len(targets) != len(set(targets)):
                    raise ContractError(f"{label}.targets contains duplicates")
                coverage = package.get("coverage")
                if coverage == "per-platform" and len(targets) != 1:
                    raise ContractError(
                        f"{label} must contain exactly one target for per-platform packaging"
                    )
                if coverage == "platform-independent" and targets != [
                    "platform-independent"
                ]:
                    raise ContractError(
                        f"{label} must use only the platform-independent target"
                    )
                allowed_targets = set(
                    require_array(
                        package.get("platforms"), f"package {package_id}.platforms"
                    )
                )
                unexpected_targets = sorted(set(targets) - allowed_targets)
                if unexpected_targets:
                    raise ContractError(
                        f"{label}.targets are not declared by package {package_id}: "
                        f"{unexpected_targets}"
                    )
                if artifact.get("version") != version:
                    raise ContractError(f"{label}.version differs from release version")
                if artifact.get("version_manifest_sha256") != version_ref.get("sha256"):
                    raise ContractError(
                        f"{label} is bound to a different version manifest"
                    )
                provenance = require_object(
                    artifact.get("provenance"), f"{label}.provenance"
                )
                if provenance.get("source_commit") != source_commit:
                    raise ContractError(f"{label} provenance source commit mismatch")
                recipe_relative, recipe_path = resolve_member(
                    self.root,
                    provenance.get("build_recipe"),
                    f"{label}.provenance.build_recipe",
                )
                self.register_path(recipe_relative, f"{label}.provenance.build_recipe")
                if not recipe_path.is_file():
                    raise ContractError(
                        f"{label} build recipe is absent: {recipe_relative}"
                    )
                recipe_digest = sha256_file(recipe_path)
                prior_recipe_digest = self.expected_checksums.get(recipe_relative)
                if (
                    prior_recipe_digest is not None
                    and prior_recipe_digest != recipe_digest
                ):
                    raise ContractError(
                        f"{label} build recipe digest conflicts with another reference"
                    )
                self.expected_checksums[recipe_relative] = recipe_digest
                for related_index, related_raw in enumerate(
                    require_array(
                        artifact.get("related_files"), f"{label}.related_files"
                    )
                ):
                    related_label = f"{label}.related_files[{related_index}]"
                    related = require_object(related_raw, related_label)
                    related_file = self.verify_file(
                        related,
                        related_label,
                        size_required=True,
                    )
                    if related_file is not None:
                        self._verify_related_file_contract(
                            artifact, related, related_file[1], related_label
                        )
                related_kinds = {
                    str(value.get("kind"))
                    for value in artifact.get("related_files", [])
                    if isinstance(value, dict)
                }
                if (
                    artifact.get("kind")
                    in {
                        "executable",
                        "rust-crate",
                        "python-wheel",
                        "go-module",
                        "typescript-package",
                        "source-package",
                        "docker-image",
                    }
                    and "sbom" not in related_kinds
                ):
                    self.gate_issue(
                        "ARTIFACT_SBOM_LINK_MISSING",
                        f"{artifact_id} has no artifact-bound SBOM",
                        label,
                    )
                if (
                    channel in {"beta", "stable"}
                    and "provenance-attestation" not in related_kinds
                ):
                    self.gate_issue(
                        "PROVENANCE_ATTESTATION_MISSING",
                        f"{artifact_id} has no detached provenance attestation",
                        label,
                    )
                artifacts.append(artifact)
            except ContractError as error:
                self.issue("error", "INVALID_ARTIFACT", str(error), label)

        self._verify_package_coverage(channel, matrix, packages, platforms, artifacts)
        limitations = require_array(manifest.get("limitations"), "limitations")
        if channel in {"alpha", "beta"} and not limitations:
            self.gate_issue(
                "LIMITATIONS_NOT_DOCUMENTED",
                "pre-v1 releases must state known limitations explicitly",
            )

        checksum = require_object(manifest.get("checksum_file"), "checksum_file")
        if (
            checksum.get("algorithm") != "sha256"
            or checksum.get("format") != "sha256sum-v1"
        ):
            raise ContractError("checksum_file must use canonical sha256sum-v1")
        checksum_relative, checksum_path = resolve_member(
            self.root, checksum.get("path"), "checksum_file.path"
        )
        signature_ref = require_object(manifest.get("signature_set"), "signature_set")
        signature_relative, signature_path = resolve_member(
            self.root, signature_ref.get("path"), "signature_set.path"
        )
        self.control_paths.update({checksum_relative, signature_relative})
        self.register_path(checksum_relative, "checksum_file.path")
        self.register_path(signature_relative, "signature_set.path")
        return {
            "manifest": manifest,
            "version": version,
            "channel": channel,
            "source_commit": source_commit,
            "version_ref": version_ref,
            "version_path": version_file,
            "matrix": matrix,
            "matrix_path": matrix_file,
            "proof": proof,
            "proof_path": proof_file,
            "checksum_relative": checksum_relative,
            "checksum_path": checksum_path,
            "signature_relative": signature_relative,
            "signature_path": signature_path,
        }

    def _verify_related_file_contract(
        self,
        artifact: dict[str, Any],
        related: dict[str, Any],
        path: Path,
        label: str,
    ) -> None:
        kind = related.get("kind")
        try:
            if kind in {
                "sbom",
                "provenance-attestation",
            } and (
                related.get("status") != "passed"
                or related.get("evidence_level") not in {"static", "publication"}
            ):
                raise ContractError(
                    f"{label} must be passed static or publication evidence"
                )
            if kind == "install-receipt":
                self._verify_install_receipt(artifact, related, path, label)
            elif kind == "publication-receipt":
                self._verify_publication_receipt(artifact, related, path, label)
            elif kind == "sbom":
                self._verify_cyclonedx_binding(artifact, path, label)
            elif kind == "provenance-attestation":
                self._verify_slsa_provenance_binding(artifact, path, label)
        except ContractError as error:
            self.issue("error", "RELATED_EVIDENCE_INVALID", str(error), label)

    @staticmethod
    def _artifact_subject(artifact: dict[str, Any]) -> dict[str, str]:
        return {
            "id": require_string(artifact.get("id"), "artifact.id"),
            "path": canonical_relative_path(artifact.get("path"), "artifact.path"),
            "sha256": require_sha256(artifact.get("sha256"), "artifact.sha256"),
            "version": require_semver(artifact.get("version"), "artifact.version"),
        }

    def _verify_install_receipt(
        self,
        artifact: dict[str, Any],
        related: dict[str, Any],
        path: Path,
        label: str,
    ) -> None:
        receipt = load_json(path)
        validate_json_contract(receipt, label)
        if receipt.get("schema_version") != "contextdb.clean-install-receipt/v1":
            raise ContractError(f"{label} has an unsupported install receipt schema")
        if (
            related.get("status") != "passed"
            or related.get("evidence_level") != "runtime"
        ):
            raise ContractError(f"{label} must be passed runtime evidence")
        platform_id = require_string(related.get("platform"), f"{label}.platform")
        if receipt.get("host_target") != platform_id:
            raise ContractError(
                f"{label} host target does not match related-file platform"
            )
        verification = require_object(
            receipt.get("verification"), f"{label}.verification"
        )
        if verification.get("contract_valid") is not True:
            raise ContractError(f"{label} did not verify artifact contract integrity")
        probes = require_array(receipt.get("probes"), f"{label}.probes")
        if (
            receipt.get("isolated_copy") is not True
            or receipt.get("passed") is not True
            or not probes
            or any(
                not isinstance(probe, dict) or probe.get("status") != "passed"
                for probe in probes
            )
        ):
            raise ContractError(f"{label} is not an all-passing isolated install")
        expected_subject = self._artifact_subject(artifact)
        subjects = require_array(
            receipt.get("subject_artifacts"), f"{label}.subject_artifacts"
        )
        if expected_subject not in subjects:
            raise ContractError(
                f"{label} is not bound to artifact {expected_subject['id']}"
            )
        if (
            artifact.get("kind") == "docker-image"
            and receipt.get("docker_runtime_executed") is not True
        ):
            raise ContractError(f"{label} does not contain Docker runtime evidence")

    def _verify_publication_receipt(
        self,
        artifact: dict[str, Any],
        related: dict[str, Any],
        path: Path,
        label: str,
    ) -> None:
        receipt = load_json(path)
        validate_json_contract(receipt, label)
        if receipt.get("schema_version") != "contextdb.release-publication-receipt/v1":
            raise ContractError(
                f"{label} has an unsupported publication receipt schema"
            )
        if (
            related.get("status") != "passed"
            or related.get("evidence_level") != "publication"
        ):
            raise ContractError(f"{label} must be passed publication evidence")
        subject = require_object(receipt.get("artifact"), f"{label}.artifact")
        if subject != self._artifact_subject(artifact):
            raise ContractError(f"{label} artifact binding does not match")
        if (
            receipt.get("status") != "passed"
            or receipt.get("immutable_reference") is not True
        ):
            raise ContractError(f"{label} is not a passed immutable publication")
        if receipt.get("retrieved_sha256") != artifact.get("sha256"):
            raise ContractError(f"{label} retrieved digest does not match artifact")
        _ = require_public_https_uri(
            receipt.get("immutable_uri"), f"{label}.immutable_uri"
        )
        published_at = parse_timestamp(
            receipt.get("published_at"), f"{label}.published_at"
        )
        verified_at = parse_timestamp(
            receipt.get("verified_at"), f"{label}.verified_at"
        )
        if verified_at < published_at:
            raise ContractError(f"{label}.verified_at predates publication")
        receipt_platform = receipt.get("platform")
        related_platform = related.get("platform")
        if receipt_platform is not None and receipt_platform != related_platform:
            raise ContractError(f"{label} platform binding does not match")
        receipt_uri = receipt.get("receipt_uri")
        if receipt_uri is not None:
            _ = require_public_https_uri(receipt_uri, f"{label}.receipt_uri")

    @staticmethod
    def _verify_cyclonedx_binding(
        artifact: dict[str, Any], path: Path, label: str
    ) -> None:
        bom = load_json(path)
        BundleVerifier._verify_cyclonedx_value(artifact, bom, label)

    @staticmethod
    def _verify_cyclonedx_value(
        artifact: dict[str, Any], bom: dict[str, Any], label: str
    ) -> None:
        if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") not in {
            "1.5",
            "1.6",
        }:
            raise ContractError(f"{label} must be CycloneDX JSON 1.5 or 1.6")
        metadata = require_object(bom.get("metadata"), f"{label}.metadata")
        component = require_object(
            metadata.get("component"), f"{label}.metadata.component"
        )
        hashes = require_array(
            component.get("hashes"), f"{label}.metadata.component.hashes"
        )
        expected = require_sha256(artifact.get("sha256"), "artifact.sha256")
        if not any(
            isinstance(value, dict)
            and value.get("alg") == "SHA-256"
            and value.get("content") == expected
            for value in hashes
        ):
            raise ContractError(
                f"{label} root component is not bound to artifact SHA-256"
            )

    @staticmethod
    def _verify_slsa_provenance_binding(
        artifact: dict[str, Any], path: Path, label: str
    ) -> None:
        statement = load_json(path)
        BundleVerifier._verify_slsa_provenance_value(artifact, statement, label)

    @staticmethod
    def _verify_slsa_provenance_value(
        artifact: dict[str, Any], statement: dict[str, Any], label: str
    ) -> None:
        if statement.get("_type") != "https://in-toto.io/Statement/v1":
            raise ContractError(f"{label} must be an in-toto Statement v1")
        if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
            raise ContractError(f"{label} must use SLSA provenance v1")
        expected = BundleVerifier._artifact_subject(artifact)
        subjects = require_array(statement.get("subject"), f"{label}.subject")
        if not any(
            isinstance(subject, dict)
            and subject.get("name") == expected["path"]
            and isinstance(subject.get("digest"), dict)
            and subject["digest"].get("sha256") == expected["sha256"]
            for subject in subjects
        ):
            raise ContractError(
                f"{label} subject does not bind artifact path and digest"
            )
        predicate = require_object(statement.get("predicate"), f"{label}.predicate")
        definition = require_object(
            predicate.get("buildDefinition"), f"{label}.predicate.buildDefinition"
        )
        require_string(definition.get("buildType"), f"{label}.buildType")
        run_details = require_object(
            predicate.get("runDetails"), f"{label}.predicate.runDetails"
        )
        builder = require_object(run_details.get("builder"), f"{label}.builder")
        require_string(builder.get("id"), f"{label}.builder.id")
        source_commit = require_string(
            require_object(artifact.get("provenance"), "artifact.provenance").get(
                "source_commit"
            ),
            "artifact.provenance.source_commit",
        )
        dependencies = require_array(
            definition.get("resolvedDependencies"), f"{label}.resolvedDependencies"
        )
        if not any(
            isinstance(dependency, dict)
            and isinstance(dependency.get("digest"), dict)
            and source_commit in dependency["digest"].values()
            for dependency in dependencies
        ):
            raise ContractError(f"{label} does not bind the source commit")

    def _verify_version_manifest(
        self, value: dict[str, Any], version: str, channel: str, source_commit: str
    ) -> None:
        validate_json_contract(value, "version manifest")
        if value.get("schema_version") != "contextdb.version-manifest/v1":
            self.issue("error", "VERSION_SCHEMA", "unsupported version manifest schema")
        if value.get("product_version") != version:
            self.issue(
                "error",
                "VERSION_MISMATCH",
                "version manifest and release version differ",
            )
        expected_channel = "development" if channel == "development" else channel
        if value.get("release_channel") != expected_channel:
            self.issue(
                "error",
                "CHANNEL_MISMATCH",
                "version manifest and release channel differ",
            )
        source = value.get("source")
        if not isinstance(source, dict) or source.get("git_commit") != source_commit:
            self.issue(
                "error", "SOURCE_MISMATCH", "version manifest source commit differs"
            )
        formats = value.get("formats")
        if not isinstance(formats, dict) or not formats:
            self.issue(
                "error", "FORMAT_VERSIONS_MISSING", "version manifest has no formats"
            )
            return
        for name, format_value in formats.items():
            if not isinstance(format_value, dict):
                self.issue(
                    "error", "FORMAT_VERSION_INVALID", f"format {name} is not an object"
                )
                continue
            writer = format_value.get("writer")
            read_min = format_value.get("read_min")
            read_max = format_value.get("read_max")
            if (
                not isinstance(writer, int)
                or isinstance(writer, bool)
                or writer < 0
                or not isinstance(read_min, int)
                or isinstance(read_min, bool)
                or read_min < 0
                or not isinstance(read_max, int)
                or isinstance(read_max, bool)
                or read_max < 0
            ):
                self.issue(
                    "error",
                    "FORMAT_VERSION_INVALID",
                    f"format {name} has invalid version bounds",
                )
            else:
                if read_min <= writer <= read_max:
                    continue
                self.issue(
                    "error",
                    "FORMAT_WRITER_UNREADABLE",
                    f"format {name}: writer {writer} is outside [{read_min}, {read_max}]",
                )

    def _verify_matrix(
        self, matrix: dict[str, Any]
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        validate_json_contract(matrix, "package matrix")
        if matrix.get("schema_version") != "contextdb.release-package-matrix/v1":
            raise ContractError("unsupported package matrix schema_version")
        platforms: dict[str, dict[str, Any]] = {}
        for index, raw in enumerate(
            require_array(matrix.get("platforms"), "matrix.platforms")
        ):
            platform = require_object(raw, f"matrix.platforms[{index}]")
            identifier = require_string(
                platform.get("id"), f"matrix.platforms[{index}].id"
            )
            if identifier in platforms:
                raise ContractError(f"duplicate platform id {identifier}")
            platforms[identifier] = platform
        for identifier, (rust_target, tier) in NORMATIVE_PLATFORMS.items():
            normative_platform = platforms.get(identifier)
            if normative_platform is None:
                raise ContractError(
                    f"package matrix omits normative platform {identifier}"
                )
            if (
                normative_platform.get("rust_target") != rust_target
                or normative_platform.get("tier") != tier
            ):
                raise ContractError(
                    f"package matrix weakens normative platform {identifier}"
                )
        packages: dict[str, dict[str, Any]] = {}
        for index, raw in enumerate(
            require_array(matrix.get("packages"), "matrix.packages")
        ):
            package = require_object(raw, f"matrix.packages[{index}]")
            identifier = require_string(
                package.get("id"), f"matrix.packages[{index}].id"
            )
            if identifier in packages:
                raise ContractError(f"duplicate package id {identifier}")
            packages[identifier] = package
            artifact_kind = require_string(
                package.get("artifact_kind"), f"package {identifier}.artifact_kind"
            )
            package_roles = require_array(
                package.get("roles"), f"package {identifier}.roles"
            )
            for role in package_roles:
                expected_kind = ROLE_ARTIFACT_KIND.get(str(role))
                if expected_kind is None or artifact_kind != expected_kind:
                    raise ContractError(
                        f"package {identifier} role {role} requires artifact kind "
                        f"{expected_kind}, found {artifact_kind}"
                    )
            for platform in require_array(
                package.get("platforms"), f"package {identifier}.platforms"
            ):
                if platform != "platform-independent" and platform not in platforms:
                    raise ContractError(
                        f"package {identifier} references unknown platform {platform}"
                    )
            for platform in require_array(
                package.get("runtime_platforms"),
                f"package {identifier}.runtime_platforms",
            ):
                if platform not in platforms:
                    raise ContractError(
                        f"package {identifier} references unknown runtime platform {platform}"
                    )
            install_probe = require_object(
                package.get("install_probe"), f"package {identifier}.install_probe"
            )
            runtime_platforms = require_array(
                package.get("runtime_platforms"),
                f"package {identifier}.runtime_platforms",
            )
            if artifact_kind in RUNTIME_REQUIRED_ARTIFACT_KINDS and (
                install_probe.get("runtime_required") is not True
                or not runtime_platforms
            ):
                raise ContractError(
                    f"package {identifier} requires an explicit runtime probe and target set"
                )
        requirements = require_object(
            matrix.get("release_requirements"), "release_requirements"
        )
        for channel in ("alpha", "beta", "stable"):
            seen: set[str] = set()
            for identifier in require_array(
                requirements.get(channel), f"requirements.{channel}"
            ):
                if identifier not in packages:
                    raise ContractError(
                        f"{channel} requires unknown package {identifier}"
                    )
                if identifier in seen:
                    raise ContractError(f"{channel} repeats package {identifier}")
                seen.add(identifier)
        stable_roles = {
            role
            for identifier in requirements["stable"]
            for role in require_array(
                packages[identifier].get("roles"), f"package {identifier}.roles"
            )
        }
        missing_roles = sorted(REQUIRED_V1_ROLES - stable_roles)
        if missing_roles:
            raise ContractError(
                f"stable matrix misses RFC v1 roles: {', '.join(missing_roles)}"
            )
        beta_roles = {
            role
            for identifier in requirements["beta"]
            for role in require_array(
                packages[identifier].get("roles"), f"package {identifier}.roles"
            )
        }
        missing_beta_roles = sorted(REQUIRED_V1_ROLES - beta_roles)
        if missing_beta_roles:
            raise ContractError(
                f"beta matrix misses required roles: {', '.join(missing_beta_roles)}"
            )
        alpha_roles = {
            role
            for identifier in requirements["alpha"]
            for role in require_array(
                packages[identifier].get("roles"), f"package {identifier}.roles"
            )
        }
        missing_alpha_roles = sorted(REQUIRED_ALPHA_ROLES - alpha_roles)
        if missing_alpha_roles:
            raise ContractError(
                f"alpha matrix misses required roles: {', '.join(missing_alpha_roles)}"
            )
        signatures = require_object(
            matrix.get("signature_requirements"), "signature_requirements"
        )
        for channel, normative_roles in NORMATIVE_SIGNATURE_ROLES.items():
            requirement = require_object(
                signatures.get(channel), f"signatures.{channel}"
            )
            declared_roles = set(
                require_array(requirement.get("roles"), f"signatures.{channel}.roles")
            )
            if not normative_roles.issubset(declared_roles):
                raise ContractError(
                    f"{channel} signature policy is weaker than normative"
                )
            if requirement.get("minimum_trust") != "production":
                raise ContractError(f"{channel} signature trust must be production")
        for identifier, package in packages.items():
            roles = set(
                require_array(package.get("roles"), f"package {identifier}.roles")
            )
            if roles & {"server", "cli"}:
                declared_platforms = set(
                    require_array(
                        package.get("platforms"), f"package {identifier}.platforms"
                    )
                )
                if not set(NORMATIVE_PLATFORMS).issubset(declared_platforms):
                    raise ContractError(
                        f"native server/CLI package {identifier} omits a v1 platform"
                    )
                declared_runtime_platforms = set(
                    require_array(
                        package.get("runtime_platforms"),
                        f"package {identifier}.runtime_platforms",
                    )
                )
                if package.get("coverage") != "per-platform" or not set(
                    NORMATIVE_PLATFORMS
                ).issubset(declared_runtime_platforms):
                    raise ContractError(
                        f"native server/CLI package {identifier} must be per-platform "
                        "and expose every required/best-effort runtime result"
                    )
            if "docker-image" in roles:
                linux_targets = {"linux-x86-64", "linux-arm64"}
                declared_platforms = set(
                    require_array(
                        package.get("platforms"), f"package {identifier}.platforms"
                    )
                )
                declared_runtime_platforms = set(
                    require_array(
                        package.get("runtime_platforms"),
                        f"package {identifier}.runtime_platforms",
                    )
                )
                if (
                    package.get("coverage") != "declared-platforms"
                    or not linux_targets.issubset(declared_platforms)
                    or not linux_targets.issubset(declared_runtime_platforms)
                ):
                    raise ContractError(
                        f"Docker package {identifier} must cover Linux x86_64 and arm64 artifacts and runtime receipts"
                    )
        self.check(
            "package-matrix",
            "passed",
            f"{len(packages)} packages and {len(platforms)} platforms",
        )
        return packages, platforms

    def _verify_package_coverage(
        self,
        channel: str,
        matrix: dict[str, Any],
        packages: dict[str, dict[str, Any]],
        platforms: dict[str, dict[str, Any]],
        artifacts: list[dict[str, Any]],
    ) -> None:
        if channel == "development":
            required: list[str] = []
        else:
            required = list(matrix["release_requirements"][channel])
        by_package: dict[str, list[dict[str, Any]]] = {}
        for artifact in artifacts:
            by_package.setdefault(str(artifact["package_id"]), []).append(artifact)
        for package_id in required:
            package = packages[package_id]
            supplied = by_package.get(package_id, [])
            if not supplied:
                self.gate_issue(
                    "MISSING_REQUIRED_PACKAGE",
                    f"{channel} requires package {package_id}",
                    package_id,
                )
                continue
            covered = {
                str(target)
                for artifact in supplied
                for target in artifact.get("targets", [])
            }
            coverage = package.get("coverage")
            expected = list(package.get("platforms", []))
            if coverage == "platform-independent":
                expected = ["platform-independent"]
            for platform_id in expected:
                if platform_id in covered:
                    continue
                tier = "required"
                if platform_id != "platform-independent":
                    tier = str(platforms[platform_id].get("tier"))
                message = f"package {package_id} lacks artifact for {platform_id}"
                if tier == "best-effort":
                    self.issue(
                        "warning", "BEST_EFFORT_ARTIFACT_MISSING", message, package_id
                    )
                else:
                    self.gate_issue("TARGET_ARTIFACT_MISSING", message, package_id)

            probe = require_object(
                package.get("install_probe"), f"package {package_id}.install_probe"
            )
            if probe.get("runtime_required") is True:
                receipts = [
                    related
                    for artifact in supplied
                    for related in artifact.get("related_files", [])
                    if related.get("kind") == "install-receipt"
                    and related.get("status") == "passed"
                    and related.get("evidence_level") == "runtime"
                ]
                receipt_platforms = {
                    str(receipt.get("platform")) for receipt in receipts
                }
                receipt_expected = list(package.get("runtime_platforms", []))
                for platform_id in receipt_expected:
                    if platform_id in receipt_platforms:
                        continue
                    tier = "required"
                    if platform_id != "platform-independent":
                        tier = str(platforms[platform_id].get("tier"))
                    message = f"package {package_id} lacks passing runtime install receipt for {platform_id}"
                    if tier == "best-effort":
                        self.issue(
                            "warning",
                            "BEST_EFFORT_RECEIPT_MISSING",
                            message,
                            package_id,
                        )
                    else:
                        self.gate_issue("INSTALL_RECEIPT_MISSING", message, package_id)
            if channel != "development":
                for artifact in supplied:
                    publications = [
                        related
                        for related in artifact.get("related_files", [])
                        if related.get("kind") == "publication-receipt"
                        and related.get("status") == "passed"
                        and related.get("evidence_level") == "publication"
                    ]
                    if not publications:
                        self.gate_issue(
                            "PUBLICATION_RECEIPT_MISSING",
                            f"artifact {artifact.get('id')} lacks a signed immutable publication receipt",
                            package_id,
                        )
        self.check(
            "artifact-coverage",
            "passed" if not required else "evaluated",
            f"channel={channel}",
        )

    def _verify_checksums(self, state: dict[str, Any]) -> None:
        path: Path = state["checksum_path"]
        relative: str = state["checksum_relative"]
        if not path.is_file():
            self.issue(
                "error", "CHECKSUM_FILE_MISSING", f"checksum file is absent: {relative}"
            )
            return
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeError) as error:
            self.issue("error", "CHECKSUM_FILE_INVALID", str(error), relative)
            return
        if b"\r" in raw or not raw.endswith(b"\n"):
            self.issue(
                "error",
                "CHECKSUM_ENCODING",
                "canonical checksum files require UTF-8, LF separators, and a final LF",
                relative,
            )
        lines = text.splitlines()
        observed: dict[str, str] = {}
        for number, line in enumerate(lines, start=1):
            match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
            if match is None:
                self.issue(
                    "error", "CHECKSUM_LINE_INVALID", f"invalid line {number}", relative
                )
                continue
            digest, value = match.groups()
            try:
                canonical = canonical_relative_path(value, f"{relative}:{number}")
            except ContractError as error:
                self.issue("error", "CHECKSUM_PATH_INVALID", str(error), relative)
                continue
            if canonical in observed:
                self.issue(
                    "error",
                    "CHECKSUM_DUPLICATE",
                    f"duplicate path {canonical}",
                    relative,
                )
            observed[canonical] = digest
        if list(observed) != sorted(observed):
            self.issue(
                "error",
                "CHECKSUM_ORDER",
                "checksum paths are not bytewise sorted",
                relative,
            )
        if observed != dict(sorted(self.expected_checksums.items())):
            missing = sorted(set(self.expected_checksums) - set(observed))
            extra = sorted(set(observed) - set(self.expected_checksums))
            mismatched = sorted(
                key
                for key in set(observed) & set(self.expected_checksums)
                if observed[key] != self.expected_checksums[key]
            )
            self.issue(
                "error",
                "CHECKSUM_SET_MISMATCH",
                f"missing={missing}, extra={extra}, mismatched={mismatched}",
                relative,
            )
        self.check(
            "checksums",
            "passed"
            if observed == dict(sorted(self.expected_checksums.items()))
            else "failed",
            f"{len(observed)} entries",
        )

    def _verify_signatures(self, state: dict[str, Any]) -> None:
        path: Path = state["signature_path"]
        relative: str = state["signature_relative"]
        if not path.is_file():
            self.issue(
                "error", "SIGNATURE_SET_MISSING", f"signature set is absent: {relative}"
            )
            return
        try:
            signature_set = load_json(path)
            validate_json_contract(signature_set, "signature set")
        except ContractError as error:
            self.issue("error", "SIGNATURE_SET_INVALID", str(error), relative)
            return
        if signature_set.get("schema_version") != "contextdb.release-signature-set/v1":
            self.issue(
                "error",
                "SIGNATURE_SCHEMA",
                "unsupported signature set schema",
                relative,
            )
            return
        if signature_set.get("release_version") != state["version"]:
            self.issue(
                "error", "SIGNATURE_VERSION", "signature set version mismatch", relative
            )
        try:
            parse_timestamp(signature_set.get("created_at"), "signature_set.created_at")
        except ContractError as error:
            self.issue("error", "SIGNATURE_TIMESTAMP", str(error), relative)

        role_paths = {
            "artifact-manifest": self.manifest_relative,
            "checksums": state["checksum_relative"],
            "proof-index": state["proof_path"][0],
            "version-manifest": state["version_path"][0],
        }
        seen_roles: set[str] = set()
        for index, raw in enumerate(signature_set.get("signatures", [])):
            label = f"signatures[{index}]"
            try:
                entry = require_object(raw, label)
                role = require_string(entry.get("role"), f"{label}.role")
                if role in seen_roles:
                    raise ContractError(f"duplicate signature role {role}")
                seen_roles.add(role)
                if role not in role_paths:
                    raise ContractError(f"unknown signature role {role}")
                subject_relative, subject_path = resolve_member(
                    self.root, entry.get("subject_path"), f"{label}.subject_path"
                )
                self.register_path(subject_relative, f"{label}.subject_path")
                if subject_relative != role_paths[role]:
                    raise ContractError(f"signature role {role} covers the wrong path")
                expected_subject = require_sha256(
                    entry.get("subject_sha256"), f"{label}.subject_sha256"
                )
                if (
                    not subject_path.is_file()
                    or sha256_file(subject_path) != expected_subject
                ):
                    raise ContractError(f"signature subject digest mismatch for {role}")
                signature_relative, signature_path = resolve_member(
                    self.root, entry.get("signature_path"), f"{label}.signature_path"
                )
                self.register_path(signature_relative, f"{label}.signature_path")
                expected_signature = require_sha256(
                    entry.get("signature_sha256"), f"{label}.signature_sha256"
                )
                if (
                    not signature_path.is_file()
                    or sha256_file(signature_path) != expected_signature
                ):
                    raise ContractError(
                        f"detached signature digest mismatch for {role}"
                    )
                self.control_paths.add(signature_relative)
                if (
                    entry.get("algorithm") != "ed25519"
                    or entry.get("encoding") != "raw"
                ):
                    raise ContractError(
                        "only raw Ed25519 detached signatures are supported"
                    )
                trust = entry.get("trust")
                if trust not in {"test", "production"}:
                    raise ContractError(f"invalid signature trust for {role}")
                if trust == "test" and not self.allow_test_keys:
                    raise ContractError(
                        f"test signature for {role} requires --allow-test-keys"
                    )
                if self.profile == "release" and trust != "production":
                    raise ContractError(
                        f"release profile requires a production signature for {role}"
                    )
                key_id = require_string(entry.get("key_id"), f"{label}.key_id")
                trusted_key = self.trusted_keys.get(key_id)
                if trusted_key is None:
                    raise ContractError(
                        f"no independently trusted public key supplied for {key_id}"
                    )
                self._verify_ed25519(
                    trusted_key,
                    subject_path,
                    signature_path,
                    require_sha256(
                        entry.get("key_fingerprint_sha256"),
                        f"{label}.key_fingerprint_sha256",
                    ),
                )
                self.crypto_verified_roles.add(role)
                self.check(
                    f"signature-{role}", "passed", f"key={key_id}; trust={trust}"
                )
                _ = signature_relative
            except ContractError as error:
                self.issue("error", "SIGNATURE_INVALID", str(error), label)

        signature_requirements = state["matrix"].get("signature_requirements", {})
        channel = state["channel"]
        if channel != "development":
            requirement = signature_requirements.get(channel, {})
            for role in requirement.get("roles", []):
                if role not in seen_roles:
                    self.issue(
                        "error",
                        "SIGNATURE_MISSING",
                        f"required signature role missing: {role}",
                    )

    def _verify_bundle_inventory(self, state: dict[str, Any]) -> None:
        tracked = set(self.expected_checksums) | self.control_paths
        observed: set[str] = set()
        for path in self.root.rglob("*"):
            if path.is_symlink():
                self.issue(
                    "error", "BUNDLE_SYMLINK", f"symbolic link is forbidden: {path}"
                )
                continue
            if path.is_file():
                observed.add(path.relative_to(self.root).as_posix())
        extras = sorted(observed - tracked)
        if extras:
            if self.profile == "release":
                self.issue(
                    "error", "UNTRACKED_BUNDLE_FILES", f"untracked files: {extras}"
                )
            else:
                self.issue(
                    "warning", "UNTRACKED_BUNDLE_FILES", f"untracked files: {extras}"
                )
        self.check(
            "bundle-file-inventory",
            "passed"
            if not extras
            else "failed"
            if self.profile == "release"
            else "warning",
            f"tracked={len(tracked)}; observed={len(observed)}",
        )

    def _verify_ed25519(
        self,
        public_key_path: Path,
        subject_path: Path,
        signature_path: Path,
        fingerprint: str,
    ) -> None:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
        except ImportError as error:
            raise ContractError(
                "cryptography is required for Ed25519 verification; metadata-only verification is forbidden"
            ) from error
        try:
            key = serialization.load_pem_public_key(public_key_path.read_bytes())
        except (OSError, ValueError, TypeError) as error:
            raise ContractError(
                f"cannot load trusted public key {public_key_path}: {error}"
            ) from error
        if not isinstance(key, Ed25519PublicKey):
            raise ContractError(f"trusted key is not Ed25519: {public_key_path}")
        der = key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if sha256_bytes(der) != fingerprint:
            raise ContractError(f"trusted key fingerprint mismatch: {public_key_path}")
        try:
            key.verify(signature_path.read_bytes(), subject_path.read_bytes())
        except Exception as error:  # cryptography exposes backend-specific subclasses
            raise ContractError(
                f"Ed25519 signature verification failed: {error}"
            ) from error

    def _verify_proof_closure(self, state: dict[str, Any]) -> None:
        proof = state["proof"]
        try:
            validate_json_contract(proof, "proof index")
        except ContractError as error:
            self.issue("error", "PROOF_SCHEMA", str(error))
            return
        if proof.get("schema_version") != "contextdb.release-proof-index/v1":
            self.issue("error", "PROOF_SCHEMA", "unsupported proof index schema")
            return
        if proof.get("release_version") != state["version"]:
            self.issue("error", "PROOF_VERSION", "proof index version mismatch")
        if proof.get("release_stage") != state["channel"]:
            self.issue("error", "PROOF_CHANNEL", "proof index release stage mismatch")
        try:
            parse_timestamp(proof.get("generated_at"), "proof_index.generated_at")
            ledger_ref = require_object(proof.get("ledger"), "proof_index.ledger")
        except ContractError as error:
            self.issue("error", "PROOF_INDEX_INVALID", str(error))
            return
        ledger_file = self.verify_file(ledger_ref, "proof_index.ledger")
        if ledger_file is None:
            return
        try:
            ledger = load_json(ledger_file[1])
            validate_json_contract(ledger, "roadmap ledger")
        except ContractError as error:
            self.issue("error", "LEDGER_INVALID", str(error))
            return
        if ledger.get("schema_version") != "contextdb.roadmap-gate-ledger/v1":
            self.issue("error", "LEDGER_SCHEMA", "unsupported roadmap ledger schema")
            return
        if ledger_ref.get("roadmap_revision") != ledger.get("roadmap_revision"):
            self.issue(
                "error", "LEDGER_REVISION", "proof index roadmap revision mismatch"
            )
        try:
            ledger_milestones = self._milestone_map(
                require_array(ledger.get("milestones"), "ledger.milestones"),
                "ledger",
            )
            proof_milestones = self._milestone_map(
                require_array(proof.get("milestones"), "proof_index.milestones"),
                "proof index",
            )
            self._assert_acyclic(ledger_milestones)
        except ContractError as error:
            self.issue("error", "LEDGER_DAG", str(error))
            return

        for gap_index, raw_gap in enumerate(
            require_array(proof.get("known_gaps"), "proof_index.known_gaps")
        ):
            gap = require_object(raw_gap, f"proof_index.known_gaps[{gap_index}]")
            if gap.get("blocking") is True:
                gate_id = require_string(
                    gap.get("gate_id"), f"proof_index.known_gaps[{gap_index}].gate_id"
                )
                self.unresolved_gates.add(gate_id)
                self.gate_issue(
                    "BLOCKING_KNOWN_GAP",
                    require_string(
                        gap.get("reason"),
                        f"proof_index.known_gaps[{gap_index}].reason",
                    ),
                    gate_id,
                )

        for milestone_id, milestone in proof_milestones.items():
            if milestone_id not in ledger_milestones:
                self.issue("error", "UNKNOWN_PROOF_MILESTONE", milestone_id)
                continue
            for index, raw in enumerate(milestone.get("required_proofs", [])):
                if isinstance(raw, dict):
                    self.verify_file(
                        raw, f"proof {milestone_id}.required_proofs[{index}]"
                    )
            for exit_entry in milestone.get("exit_criteria", []):
                if not isinstance(exit_entry, dict):
                    continue
                for index, raw in enumerate(exit_entry.get("evidence", [])):
                    if isinstance(raw, dict):
                        self.verify_file(
                            raw,
                            f"proof {milestone_id}.{exit_entry.get('id')}.evidence[{index}]",
                        )

        channel = state["channel"]
        if channel == "development":
            self.gate_issue(
                "NO_RELEASE_STAGE",
                "development proof does not close a release milestone",
            )
            return
        target = "M18" if channel in {"alpha", "beta"} else "M19"
        closure = self._dependency_closure(ledger_milestones, target)
        dependencies = sorted(closure - {target}, key=self._milestone_number)
        for milestone_id in dependencies:
            self._require_milestone_passed(
                milestone_id,
                ledger_milestones[milestone_id],
                proof_milestones.get(milestone_id),
            )
        if channel == "alpha":
            self._require_exit_passed("M18-E01", proof_milestones.get("M18"))
            self._require_expected_proofs(
                "M18",
                ledger_milestones["M18"],
                proof_milestones.get("M18"),
                allowed_paths={
                    "proof/M18/alpha-release.json",
                    "proof/M18/benchmark-index.json",
                },
            )
        else:
            self._require_milestone_passed(
                target, ledger_milestones[target], proof_milestones.get(target)
            )
        self.check(
            "roadmap-proof-closure",
            "evaluated",
            f"target={target}; dependencies={len(dependencies)}",
        )

    @staticmethod
    def _milestone_map(values: list[Any], label: str) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for index, raw in enumerate(values):
            milestone = require_object(raw, f"{label}.milestones[{index}]")
            identifier = require_string(
                milestone.get("id"), f"{label}.milestones[{index}].id"
            )
            if MILESTONE_RE.fullmatch(identifier) is None:
                raise ContractError(f"{label} has invalid milestone id {identifier}")
            if identifier in result:
                raise ContractError(f"{label} repeats milestone {identifier}")
            exit_ids: set[str] = set()
            for exit_index, raw_exit in enumerate(
                require_array(
                    milestone.get("exit_criteria"),
                    f"{label}.{identifier}.exit_criteria",
                )
            ):
                exit_entry = require_object(
                    raw_exit, f"{label}.{identifier}.exit_criteria[{exit_index}]"
                )
                exit_id = require_string(
                    exit_entry.get("id"),
                    f"{label}.{identifier}.exit_criteria[{exit_index}].id",
                )
                if EXIT_RE.fullmatch(exit_id) is None or not exit_id.startswith(
                    f"{identifier}-"
                ):
                    raise ContractError(f"{label} has invalid exit id {exit_id}")
                if exit_id in exit_ids:
                    raise ContractError(f"{label} repeats exit {exit_id}")
                exit_ids.add(exit_id)
            result[identifier] = milestone
        return result

    def _require_milestone_passed(
        self,
        milestone_id: str,
        ledger_milestone: dict[str, Any],
        proof_milestone: dict[str, Any] | None,
    ) -> None:
        if ledger_milestone.get("status") != "passed":
            self.unresolved_gates.add(milestone_id)
            self.gate_issue(
                "LEDGER_MILESTONE_NOT_PASSED",
                f"{milestone_id} ledger status is {ledger_milestone.get('status')}",
                milestone_id,
            )
        if proof_milestone is None or proof_milestone.get("status") != "passed":
            self.unresolved_gates.add(milestone_id)
            self.gate_issue(
                "PROOF_MILESTONE_NOT_PASSED",
                f"{milestone_id} has no passed proof-index entry",
                milestone_id,
            )
            return
        for exit_value in ledger_milestone.get("exit_criteria", []):
            if isinstance(exit_value, dict):
                self._require_exit_passed(str(exit_value.get("id")), proof_milestone)
        self._require_expected_proofs(
            milestone_id, ledger_milestone, proof_milestone, allowed_paths=None
        )

    def _require_exit_passed(
        self, exit_id: str, proof_milestone: dict[str, Any] | None
    ) -> None:
        entries = (
            [] if proof_milestone is None else proof_milestone.get("exit_criteria", [])
        )
        entry = next(
            (
                value
                for value in entries
                if isinstance(value, dict) and value.get("id") == exit_id
            ),
            None,
        )
        if (
            entry is None
            or entry.get("status") != "passed"
            or not entry.get("evidence")
        ):
            self.unresolved_gates.add(exit_id)
            self.gate_issue(
                "EXIT_GATE_NOT_PROVEN",
                f"{exit_id} lacks passed evidence",
                exit_id,
            )

    def _require_expected_proofs(
        self,
        milestone_id: str,
        ledger_milestone: dict[str, Any],
        proof_milestone: dict[str, Any] | None,
        allowed_paths: set[str] | None,
    ) -> None:
        expected = {
            str(value.get("path"))
            for value in ledger_milestone.get("required_proof", [])
            if isinstance(value, dict)
            and (allowed_paths is None or str(value.get("path")) in allowed_paths)
        }
        supplied = {
            str(value.get("path"))
            for value in (
                []
                if proof_milestone is None
                else proof_milestone.get("required_proofs", [])
            )
            if isinstance(value, dict)
        }
        missing = expected - supplied
        if missing:
            self.unresolved_gates.add(milestone_id)
            self.gate_issue(
                "REQUIRED_PROOF_MISSING",
                f"{milestone_id} proof index misses {sorted(missing)}",
                milestone_id,
            )

    @staticmethod
    def _milestone_number(value: str) -> int:
        return int(value[1:])

    @staticmethod
    def _dependency_closure(
        milestones: dict[str, dict[str, Any]], target: str
    ) -> set[str]:
        if target not in milestones:
            raise ContractError(f"ledger lacks {target}")
        closure: set[str] = set()
        stack = [target]
        while stack:
            current = stack.pop()
            if current in closure:
                continue
            closure.add(current)
            for dependency in milestones[current].get("depends_on", []):
                if dependency not in milestones:
                    raise ContractError(f"{current} depends on unknown {dependency}")
                stack.append(str(dependency))
        return closure

    @staticmethod
    def _assert_acyclic(milestones: dict[str, dict[str, Any]]) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(identifier: str) -> None:
            if identifier in visiting:
                raise ContractError(f"roadmap cycle at {identifier}")
            if identifier in visited:
                return
            if identifier not in milestones:
                raise ContractError(f"unknown milestone {identifier}")
            visiting.add(identifier)
            for dependency in milestones[identifier].get("depends_on", []):
                visit(str(dependency))
            visiting.remove(identifier)
            visited.add(identifier)

        for identifier in milestones:
            visit(identifier)


def parse_trusted_keys(values: Iterable[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        key_id, separator, path_value = value.partition("=")
        if not separator or not key_id or not path_value:
            raise ContractError("--trusted-key must be KEY_ID=PUBLIC_KEY.pem")
        if key_id in result:
            raise ContractError(f"duplicate trusted key id: {key_id}")
        path = Path(path_value).resolve(strict=True)
        if not path.is_file():
            raise ContractError(f"trusted key is not a file: {path}")
        result[key_id] = path
    return result


def _load_yaml_unique(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as error:
        raise ContractError(
            "PyYAML is required for semantic Compose source validation"
        ) from error

    class UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
        pass

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
        loader.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                repeated = key in mapping
            except TypeError as error:
                raise ContractError(
                    "Compose YAML contains an unhashable key"
                ) from error
            if repeated:
                raise ContractError(f"Compose YAML repeats key {key!r}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
    )
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ContractError(f"cannot parse Compose YAML: {error}") from error
    return require_object(value, "Compose document")


def audit_source(repo_root: Path, matrix_path: Path) -> dict[str, Any]:
    root = repo_root.resolve(strict=True)
    matrix_path = matrix_path.resolve(strict=True)
    try:
        matrix_relative = matrix_path.relative_to(root).as_posix()
    except ValueError as error:
        raise ContractError("package matrix must be inside repo-root") from error
    matrix = load_json(matrix_path)
    validate_json_contract(matrix, "package matrix")
    if matrix.get("schema_version") != "contextdb.release-package-matrix/v1":
        raise ContractError("unsupported package matrix schema")
    packages: list[dict[str, Any]] = []
    issues: list[Issue] = []
    documentation_required = False
    rust_registry_required = False
    docker_required = False
    for raw in require_array(matrix.get("packages"), "packages"):
        package = require_object(raw, "package")
        package_id = require_string(package.get("id"), "package.id")
        documentation_required = documentation_required or "full-docs" in package.get(
            "roles", []
        )
        rust_registry_required = rust_registry_required or "rust-crates" in package.get(
            "roles", []
        )
        docker_required = docker_required or "docker-image" in package.get("roles", [])
        present: list[str] = []
        missing: list[str] = []
        for value in require_array(
            package.get("source_paths"), f"{package_id}.source_paths"
        ):
            try:
                relative, path = resolve_member(
                    root, value, f"{package_id}.source_path"
                )
            except ContractError as error:
                issues.append(
                    Issue("error", "UNSAFE_SOURCE_PATH", str(error), package_id)
                )
                continue
            (present if path.exists() else missing).append(relative)
        if missing:
            issues.append(
                Issue(
                    "error",
                    "SOURCE_PATH_MISSING",
                    f"missing source paths: {missing}",
                    package_id,
                )
            )
        state = str(package.get("current_state"))
        issues.append(
            Issue(
                "warning",
                "RUNTIME_OR_PUBLICATION_PROOF_ABSENT",
                f"declared current_state={state}; source audit does not consume artifact receipts",
                package_id,
            )
        )
        packages.append(
            {
                "id": package_id,
                "current_state": state,
                "present_source_paths": present,
                "missing_source_paths": missing,
            }
        )
    rust_manifests = sorted((root / "crates").glob("*/Cargo.toml"))
    rust_manifest_inventory = "".join(
        f"{manifest.relative_to(root).as_posix()}\0{sha256_file(manifest)}\n"
        for manifest in rust_manifests
    )
    if rust_registry_required:
        unpublished_manifests = []
        for manifest in rust_manifests:
            if re.search(
                r"^\s*publish\s*=\s*false\s*$",
                manifest.read_text(encoding="utf-8"),
                re.MULTILINE,
            ):
                unpublished_manifests.append(manifest.parent.name)
        if unpublished_manifests:
            issues.append(
                Issue(
                    "warning",
                    "RUST_PUBLICATION_SET_UNRESOLVED",
                    "the intended public Rust crate subset is not frozen; publish=false is explicitly set on: "
                    + ", ".join(unpublished_manifests),
                    "rust-crates",
                )
            )
    dockerfile = root / "deploy" / "docker" / "Dockerfile"
    if docker_required and not dockerfile.is_file():
        issues.append(
            Issue(
                "error",
                "DOCKERFILE_MISSING",
                "the declared Docker package has no deploy/docker/Dockerfile",
                "docker-image",
            )
        )
    if dockerfile.is_file():
        docker_text = dockerfile.read_text(encoding="utf-8")
        if (
            re.search(r"^USER\s+[^\s]+", docker_text, re.MULTILINE) is None
            or re.search(r"^HEALTHCHECK\s+", docker_text, re.MULTILINE) is None
            or "cargo build --locked" not in docker_text
            or "COPY . ." in docker_text
            or "COPY crates/ crates/" not in docker_text
            or "COPY bindings/ bindings/" not in docker_text
            or "COPY examples/embedded-rust/ examples/embedded-rust/" not in docker_text
            or 'VOLUME ["/var/lib/contextdb", "/var/lib/contextdb-authority"]'
            not in docker_text
        ):
            issues.append(
                Issue(
                    "error",
                    "DOCKER_HARDENING",
                    "Dockerfile needs non-root USER, HEALTHCHECK, locked build, bounded COPY of every workspace member root, and separate data/authority volumes",
                    "docker-image",
                )
            )
        if (
            re.search(r"^FROM\s+[^\s]+@sha256:[0-9a-f]{64}", docker_text, re.MULTILINE)
            is None
        ):
            issues.append(
                Issue(
                    "warning",
                    "DOCKER_BASE_NOT_DIGEST_PINNED",
                    "base-image digests must be frozen for Beta/v1",
                    "docker-image",
                )
            )
        compose_path = root / "deploy" / "docker" / "compose.yaml"
        entrypoint_path = root / "deploy" / "docker" / "entrypoint.sh"
        ignore_path = root / "deploy" / "docker" / "Dockerfile.dockerignore"
        if not all(
            path.is_file() for path in (compose_path, entrypoint_path, ignore_path)
        ):
            issues.append(
                Issue(
                    "error",
                    "DOCKER_SOURCE_INCOMPLETE",
                    "compose, entrypoint, and Dockerfile-specific ignore policy are required",
                    "docker-image",
                )
            )
        else:
            entrypoint_text = entrypoint_path.read_text(encoding="utf-8")
            ignore_text = ignore_path.read_text(encoding="utf-8")
            try:
                compose = _load_yaml_unique(compose_path)
                services = require_object(compose.get("services"), "compose.services")
                service = require_object(
                    services.get("contextdb"), "compose.services.contextdb"
                )
                environment = require_object(
                    service.get("environment"), "compose.contextdb.environment"
                )
                ports = require_array(service.get("ports"), "compose.contextdb.ports")
                volumes = require_array(
                    service.get("volumes"), "compose.contextdb.volumes"
                )

                def mount_for(target: str) -> object | None:
                    for value in volumes:
                        if isinstance(value, dict) and value.get("target") == target:
                            return value
                        if isinstance(value, str):
                            parts = value.split(":")
                            if len(parts) >= 2 and parts[1] == target:
                                return value
                    return None

                secret_mount = next(
                    (
                        value
                        for value in volumes
                        if isinstance(value, dict)
                        and value.get("target") == "/run/contextdb-secrets/token-key"
                    ),
                    None,
                )
                gateway_key_mount = next(
                    (
                        value
                        for value in volumes
                        if isinstance(value, dict)
                        and value.get("target") == "/run/contextdb-secrets/gateway-key"
                    ),
                    None,
                )
                data_mount = mount_for("/var/lib/contextdb")
                authority_mount = mount_for("/var/lib/contextdb-authority")
                data_source = (
                    data_mount.split(":", 1)[0]
                    if isinstance(data_mount, str)
                    else data_mount.get("source")
                    if isinstance(data_mount, dict)
                    else None
                )
                authority_source = (
                    authority_mount.split(":", 1)[0]
                    if isinstance(authority_mount, str)
                    else authority_mount.get("source")
                    if isinstance(authority_mount, dict)
                    else None
                )
                token_key_source = (
                    secret_mount.get("source")
                    if isinstance(secret_mount, dict)
                    else None
                )
                gateway_key_source = (
                    gateway_key_mount.get("source")
                    if isinstance(gateway_key_mount, dict)
                    else None
                )
                compose_hardened = (
                    service.get("read_only") is True
                    and service.get("cap_drop") == ["ALL"]
                    and service.get("security_opt") == ["no-new-privileges:true"]
                    and set(ports) == {"127.0.0.1:7733:7733", "127.0.0.1:7734:7734"}
                    and environment.get("CONTEXTDB_TOKEN_KEY_FILE")
                    == "/run/contextdb-secrets/token-key"
                    and environment.get("CONTEXTDB_STATE_HEAD_FILE")
                    == "/var/lib/contextdb-authority/state-head.json"
                    and str(environment.get("CONTEXTDB_GATEWAY_ID", "")).startswith(
                        "${CONTEXTDB_DOCKER_GATEWAY_ID:?"
                    )
                    and environment.get("CONTEXTDB_GATEWAY_KEY_FILE")
                    == "/run/contextdb-secrets/gateway-key"
                    and data_mount is not None
                    and authority_mount is not None
                    and bool(data_source)
                    and bool(authority_source)
                    and data_source != authority_source
                    and isinstance(secret_mount, dict)
                    and secret_mount.get("type") == "bind"
                    and secret_mount.get("read_only") is True
                    and str(token_key_source or "").startswith(
                        "${CONTEXTDB_DOCKER_TOKEN_KEY_FILE:?"
                    )
                    and isinstance(gateway_key_mount, dict)
                    and gateway_key_mount.get("type") == "bind"
                    and gateway_key_mount.get("read_only") is True
                    and str(gateway_key_source or "").startswith(
                        "${CONTEXTDB_DOCKER_GATEWAY_KEY_FILE:?"
                    )
                    and gateway_key_source
                    not in {token_key_source, data_source, authority_source}
                )
            except (ContractError, OSError, TypeError, ValueError) as error:
                compose_hardened = False
                issues.append(
                    Issue(
                        "error",
                        "COMPOSE_YAML_INVALID",
                        str(error),
                        "docker-image",
                    )
                )
            if not compose_hardened:
                issues.append(
                    Issue(
                        "error",
                        "COMPOSE_HARDENING",
                        "Compose must remain read-only, capability-dropped, loopback-bound, require a gateway identity, use distinct external read-only token/gateway key binds, and mount independent data/state-head volumes",
                        "docker-image",
                    )
                )
            if not all(
                token in entrypoint_text
                for token in (
                    "set exactly one of CONTEXTDB_TOKEN_KEY_HEX or CONTEXTDB_TOKEN_KEY_FILE",
                    "CONTEXTDB_TOKEN_KEY_FILE must be outside the archive directory",
                    "CONTEXTDB_TOKEN_KEY_FILE must be owned by the container user",
                    "CONTEXTDB_STATE_HEAD_FILE is required",
                    "CONTEXTDB_STATE_HEAD_FILE must be outside the archive directory",
                    "state-head authority directory must be owned by the container user",
                    "CONTEXTDB_GATEWAY_ID is required for the network daemon",
                    "set exactly one of CONTEXTDB_GATEWAY_KEY_HEX or CONTEXTDB_GATEWAY_KEY_FILE",
                    "an external gateway attestation key is required",
                    "CONTEXTDB_GATEWAY_KEY_FILE must be outside the archive directory",
                    "CONTEXTDB_GATEWAY_KEY_FILE must be owned by the container user with one link",
                    "CONTEXTDB_GATEWAY_KEY_FILE must be private and at most 66 bytes",
                )
            ):
                issues.append(
                    Issue(
                        "error",
                        "DOCKER_KEY_BOUNDARY",
                        "entrypoint must enforce exact-one external token/gateway keys, a gateway identity, and an independently owned external state-head authority outside the archive directory",
                        "docker-image",
                    )
                )
            if not ignore_text.startswith("**\n") or "!crates/**" not in ignore_text:
                issues.append(
                    Issue(
                        "error",
                        "DOCKER_CONTEXT_POLICY",
                        "Docker context must be deny-by-default and explicitly include workspace crates",
                        "docker-image",
                    )
                )
    documentation_matrix_path = root / "release" / "documentation-matrix.json"
    if documentation_required and not documentation_matrix_path.is_file():
        issues.append(
            Issue(
                "error",
                "DOCUMENTATION_MATRIX_MISSING",
                "release/documentation-matrix.json is required for RFC 31.16",
                "full-docs",
            )
        )
    elif documentation_matrix_path.is_file():
        documentation = load_json(documentation_matrix_path)
        validate_json_contract(documentation, "documentation matrix")
        if (
            documentation.get("schema_version")
            != "contextdb.release-documentation-matrix/v1"
        ):
            issues.append(
                Issue(
                    "error",
                    "DOCUMENTATION_MATRIX_SCHEMA",
                    "unsupported documentation matrix schema",
                    "full-docs",
                )
            )
        categories = require_array(
            documentation.get("categories"), "documentation.categories"
        )
        category_ids = [
            str(value.get("id")) for value in categories if isinstance(value, dict)
        ]
        if len(category_ids) != len(set(category_ids)):
            issues.append(
                Issue(
                    "error",
                    "DOCUMENTATION_CATEGORY_DUPLICATE",
                    "documentation category ids must be unique",
                    "full-docs",
                )
            )
        actual_categories = frozenset(category_ids)
        if actual_categories != DOCUMENTATION_CATEGORIES:
            missing = sorted(DOCUMENTATION_CATEGORIES - actual_categories)
            unexpected = sorted(actual_categories - DOCUMENTATION_CATEGORIES)
            issues.append(
                Issue(
                    "error",
                    "DOCUMENTATION_CATEGORY_SET",
                    f"missing={missing}; unexpected={unexpected}",
                    "full-docs",
                )
            )
        status_counts: dict[str, int] = {}
        for value in categories:
            category = require_object(value, "documentation.category")
            identifier = require_string(category.get("id"), "documentation.category.id")
            status = require_string(
                category.get("status"), f"documentation category {identifier}.status"
            )
            status_counts[status] = status_counts.get(status, 0) + 1
            for raw_path in require_array(
                category.get("paths"), f"documentation category {identifier}.paths"
            ):
                try:
                    relative, path = resolve_member(
                        root, raw_path, f"documentation category {identifier}.path"
                    )
                except ContractError as error:
                    issues.append(
                        Issue(
                            "error",
                            "UNSAFE_DOCUMENTATION_PATH",
                            str(error),
                            identifier,
                        )
                    )
                    continue
                if not path.exists():
                    issues.append(
                        Issue(
                            "error",
                            "DOCUMENTATION_PATH_MISSING",
                            f"missing documentation source path: {relative}",
                            identifier,
                        )
                    )
        summary = require_object(documentation.get("summary"), "documentation.summary")
        expected_summary = {
            "required": len(DOCUMENTATION_CATEGORIES),
            "source_complete": sum(
                status_counts.get(value, 0)
                for value in (
                    "source-complete",
                    "runtime-verified",
                    "publication-verified",
                )
            ),
            "runtime_verified": sum(
                status_counts.get(value, 0)
                for value in ("runtime-verified", "publication-verified")
            ),
            "publication_verified": status_counts.get("publication-verified", 0),
        }
        if summary != expected_summary:
            issues.append(
                Issue(
                    "error",
                    "DOCUMENTATION_SUMMARY_MISMATCH",
                    f"expected {expected_summary}, found {summary}",
                    "full-docs",
                )
            )
    errors = sum(issue.severity == "error" for issue in issues)
    documentation_input = (
        {
            "path": documentation_matrix_path.relative_to(root).as_posix(),
            "sha256": sha256_file(documentation_matrix_path),
        }
        if documentation_matrix_path.is_file()
        else None
    )
    dockerfile_input = (
        {
            "path": dockerfile.relative_to(root).as_posix(),
            "sha256": sha256_file(dockerfile),
        }
        if dockerfile.is_file()
        else None
    )
    docker_source_files = sorted(
        path for path in (root / "deploy" / "docker").glob("*") if path.is_file()
    )
    docker_source_inventory = "".join(
        f"{path.relative_to(root).as_posix()}\0{sha256_file(path)}\n"
        for path in docker_source_files
    )
    return {
        "schema_version": "contextdb.release-source-audit/v1",
        "verifier_version": RELEASE_TOOL_VERSION,
        "inputs": {
            "package_matrix": {
                "path": matrix_relative,
                "sha256": sha256_file(matrix_path),
            },
            "documentation_matrix": documentation_input,
            "dockerfile": dockerfile_input,
            "docker_source": {
                "count": len(docker_source_files),
                "inventory_sha256": sha256_bytes(
                    docker_source_inventory.encode("utf-8")
                ),
            },
            "rust_manifests": {
                "count": len(rust_manifests),
                "inventory_sha256": sha256_bytes(
                    rust_manifest_inventory.encode("utf-8")
                ),
            },
        },
        "outcome": "source_inventory_valid" if errors == 0 else "failed",
        "release_ready": False,
        "package_count": len(packages),
        "packages": packages,
        "issues": [
            asdict(issue)
            for issue in sorted(
                issues, key=lambda item: (item.severity, item.code, item.context or "")
            )
        ],
        "evidence_boundary": {
            "source_presence_is_package_proof": False,
            "static_docker_check_is_runtime_proof": False,
            "publication_checked": False,
        },
    }


def readiness_report(
    repo_root: Path, ledger_path: Path, matrix_path: Path, stage: str
) -> dict[str, Any]:
    root = repo_root.resolve(strict=True)
    ledger_path = ledger_path.resolve(strict=True)
    matrix_path = matrix_path.resolve(strict=True)
    try:
        ledger_relative = ledger_path.relative_to(root).as_posix()
        matrix_relative = matrix_path.relative_to(root).as_posix()
    except ValueError as error:
        raise ContractError("readiness inputs must be inside repo-root") from error
    ledger = load_json(ledger_path)
    matrix = load_json(matrix_path)
    validate_json_contract(ledger, "roadmap ledger")
    validate_json_contract(matrix, "package matrix")
    if ledger.get("schema_version") != "contextdb.roadmap-gate-ledger/v1":
        raise ContractError("unsupported roadmap ledger schema")
    if matrix.get("schema_version") != "contextdb.release-package-matrix/v1":
        raise ContractError("unsupported package matrix schema")
    milestones = BundleVerifier._milestone_map(
        require_array(ledger.get("milestones"), "ledger.milestones"), "ledger"
    )
    BundleVerifier._assert_acyclic(milestones)
    target = "M18" if stage in {"alpha", "beta"} else "M19"
    closure = BundleVerifier._dependency_closure(milestones, target)
    ordered = sorted(closure, key=BundleVerifier._milestone_number)
    unresolved_milestones: list[dict[str, Any]] = []
    unresolved_exits: list[dict[str, Any]] = []
    required_proofs: list[dict[str, Any]] = []
    for milestone_id in ordered:
        milestone = milestones[milestone_id]
        status = str(milestone.get("status"))
        alpha_target = stage == "alpha" and milestone_id == "M18"
        if status != "passed" and not alpha_target:
            unresolved_milestones.append({"id": milestone_id, "status": status})
            for exit_value in milestone.get("exit_criteria", []):
                if isinstance(exit_value, dict):
                    unresolved_exits.append(
                        {
                            "id": str(exit_value.get("id")),
                            "milestone": milestone_id,
                            "text": str(exit_value.get("text")),
                            "status": status,
                        }
                    )
        elif alpha_target:
            exit_value = next(
                (
                    value
                    for value in milestone.get("exit_criteria", [])
                    if isinstance(value, dict) and value.get("id") == "M18-E01"
                ),
                None,
            )
            if status != "passed" and exit_value is not None:
                unresolved_exits.append(
                    {
                        "id": "M18-E01",
                        "milestone": "M18",
                        "text": str(exit_value.get("text")),
                        "status": status,
                    }
                )
        for proof in milestone.get("required_proof", []):
            if not isinstance(proof, dict):
                continue
            if alpha_target and proof.get("path") not in {
                "proof/M18/alpha-release.json",
                "proof/M18/benchmark-index.json",
            }:
                continue
            try:
                relative, path = resolve_member(
                    root, proof.get("path"), "required proof path"
                )
                present = path.is_file()
                digest = sha256_file(path) if present else None
            except ContractError:
                relative = str(proof.get("path"))
                present = False
                digest = None
            required_proofs.append(
                {
                    "milestone": milestone_id,
                    "kind": str(proof.get("kind")),
                    "path": relative,
                    "present": present,
                    "sha256": digest,
                    "presence_is_pass": False,
                }
            )

    packages = {
        str(value.get("id")): value
        for value in require_array(matrix.get("packages"), "matrix.packages")
        if isinstance(value, dict)
    }
    requirements = require_object(
        matrix.get("release_requirements"), "release_requirements"
    )
    required_packages: list[dict[str, Any]] = []
    for package_id in requirements[stage]:
        package = packages.get(str(package_id))
        if package is None:
            raise ContractError(f"{stage} requires unknown package {package_id}")
        missing_source_paths: list[str] = []
        for source_path in package.get("source_paths", []):
            relative, path = resolve_member(
                root, source_path, f"package {package_id}.source_path"
            )
            if not path.exists():
                missing_source_paths.append(relative)
        probe = require_object(
            package.get("install_probe"), f"package {package_id}.install_probe"
        )
        required_packages.append(
            {
                "id": package_id,
                "current_state": package.get("current_state"),
                "missing_source_paths": missing_source_paths,
                "artifact_targets_required": package.get("platforms"),
                "runtime_install_receipts_required": package.get("runtime_platforms")
                if probe.get("runtime_required")
                else [],
                "artifact_manifest_entry_present": False,
                "publication_receipt_present": False,
                "release_requirement_satisfied": False,
            }
        )

    signature_requirement = matrix["signature_requirements"][stage]
    external_requirements = [
        {
            "id": "production-signatures",
            "status": "unproven",
            "detail": (
                f"independently trusted {signature_requirement['minimum_trust']} Ed25519 signatures "
                f"for roles {signature_requirement['roles']}"
            ),
        },
        {
            "id": "artifact-publication",
            "status": "unproven",
            "detail": "registry/release URIs, immutable digests, and publication receipts for every required package",
        },
        {
            "id": "required-platform-runtime",
            "status": "unproven",
            "detail": "clean-install and operational receipts for Linux x86_64, Linux arm64, and macOS arm64; Windows x86_64 remains visible best effort",
        },
        {
            "id": "external-token-key-custody",
            "status": "unproven",
            "detail": "exactly one external token-key source, one distinct external gateway-attestation key bound to a trusted gateway identity, plus an independently protected external state-head authority per database; no key or authority sidecars in archive/package/receipt paths; custodian rollback protection and target-platform runtime receipts remain required",
        },
        {
            "id": "docker-runtime",
            "status": "not-run",
            "detail": "OCI build, multi-arch manifest, persistence/restart, health, SBOM, provenance, and registry pull-by-digest",
        },
        {
            "id": "public-benchmark-evidence",
            "status": "unproven",
            "detail": "versioned public datasets, immutable benchmark results, frozen floors, reference hardware, and reproducible traces",
        },
    ]
    return {
        "schema_version": "contextdb.release-readiness-report/v1",
        "verifier_version": RELEASE_TOOL_VERSION,
        "stage": stage,
        "target_milestone": target,
        "target_exit": "M18-E01" if stage == "alpha" else None,
        "roadmap_revision": ledger.get("roadmap_revision"),
        "inputs": {
            "ledger": {
                "path": ledger_relative,
                "sha256": sha256_file(ledger_path),
            },
            "package_matrix": {
                "path": matrix_relative,
                "sha256": sha256_file(matrix_path),
            },
        },
        "dependency_closure": ordered,
        "unresolved_milestones": unresolved_milestones,
        "unresolved_exit_criteria": unresolved_exits,
        "required_proofs": required_proofs,
        "required_packages": required_packages,
        "external_requirements": external_requirements,
        "summary": {
            "dependency_milestones": len(ordered),
            "unresolved_milestones": len(unresolved_milestones),
            "unresolved_exit_criteria": len(unresolved_exits),
            "required_proofs": len(required_proofs),
            "present_required_proof_files": sum(
                value["present"] for value in required_proofs
            ),
            "required_packages": len(required_packages),
            "packages_satisfying_release_requirement": 0,
        },
        "release_ready": False,
        "evidence_boundary": {
            "ledger_status_is_authoritative": True,
            "proof_file_presence_is_gate_pass": False,
            "source_presence_is_package_install_proof": False,
            "docker_runtime_executed": False,
            "publication_checked": False,
        },
    }


def _decode_json_value_bytes(value: bytes, label: str) -> Any:
    try:
        decoded = value.decode("utf-8")
        parsed = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ContractError, RecursionError) as error:
        raise ContractError(
            f"cannot load {label} as canonical JSON: {error}"
        ) from error
    return parsed


def _decode_json_bytes(value: bytes, label: str) -> dict[str, Any]:
    parsed = _decode_json_value_bytes(value, label)
    if not isinstance(parsed, dict):
        raise ContractError(f"{label} JSON root must be an object")
    return parsed


def _is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if is_junction is not None and is_junction():
        return True
    try:
        attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _reject_link_chain(path: Path, label: str) -> None:
    cursor = path.absolute()
    while True:
        if _is_link_like(cursor):
            raise ContractError(
                f"{label} traverses a symbolic link or junction: {path}"
            )
        if cursor == cursor.parent:
            break
        cursor = cursor.parent


def _read_regular_file(
    path: Path, label: str, *, max_bytes: int | None = None
) -> bytes:
    _reject_link_chain(path, label)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ContractError(f"cannot open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError(f"{label} must be a regular file")
        if max_bytes is not None and before.st_size > max_bytes:
            raise ContractError(
                f"{label} exceeds the {max_bytes}-byte in-memory validation limit"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            value = stream.read()
        after = os.fstat(descriptor)
        snapshot_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        snapshot_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if snapshot_before != snapshot_after or len(value) != after.st_size:
            raise ContractError(f"{label} changed while it was being read")
        return value
    finally:
        os.close(descriptor)


def _digest_regular_file(path: Path, label: str) -> tuple[str, int]:
    """Hash one stable regular-file snapshot without buffering the payload."""
    _reject_link_chain(path, label)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ContractError(f"cannot open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError(f"{label} must be a regular file")
        digest = hashlib.sha256()
        observed_size = 0
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                observed_size += len(block)
                digest.update(block)
        after = os.fstat(descriptor)
        snapshot_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        snapshot_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if snapshot_before != snapshot_after or observed_size != after.st_size:
            raise ContractError(f"{label} changed while it was being hashed")
        return digest.hexdigest(), observed_size
    finally:
        os.close(descriptor)


def _unsafe_release_material(relative: str) -> str | None:
    source_or_document_suffixes = {
        ".c",
        ".cc",
        ".cpp",
        ".go",
        ".h",
        ".hpp",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".md",
        ".proto",
        ".py",
        ".rb",
        ".rs",
        ".swift",
        ".ts",
        ".tsx",
    }
    source_or_document = PurePosixPath(relative).suffix.casefold() in (
        source_or_document_suffixes
    )
    portable_reason = _portable_custody_material(relative)
    if portable_reason is not None and not (
        portable_reason == "state-head authority material" and source_or_document
    ):
        return portable_reason
    pure = PurePosixPath(relative)
    lowered_parts = [part.casefold() for part in pure.parts]
    basename = lowered_parts[-1]
    normalized = basename.replace("_", "-")
    if (
        "token-key" in normalized or normalized.startswith("tokenkey")
    ) and not source_or_document:
        return "token-key sidecar material"
    if basename == ".env" or basename.startswith(".env."):
        return "environment secret sidecar"
    if basename in {".netrc", ".npmrc", ".pypirc"}:
        return "package-registry credential sidecar"
    if basename in {
        "credentials",
        "credentials.json",
        "secrets.json",
        "id-rsa",
        "id-ed25519",
        "signatures.json",
    }:
        return "credential, key, or pre-generated signature material"
    if any(part in {"secret", "secrets", ".secrets"} for part in lowered_parts):
        return "secret directory material"
    if normalized.endswith((".keystore", ".jks", ".kdbx")):
        return "key-store material"
    stem = normalized.split(".", 1)[0]
    if (
        stem
        in {
            "api-key",
            "client-secret",
            "credential",
            "credentials",
            "password",
            "refresh-token",
            "secret",
            "secrets",
            "token",
        }
        and not source_or_document
    ):
        return "credential or secret sidecar material"
    if basename.endswith(".sig"):
        return "pre-generated signature material"
    return None


PRIVATE_PEM_RE = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----[ \t]*\r?\n"
    rb"(.{40,2097152}?)"
    rb"-----END \1-----",
    re.IGNORECASE | re.DOTALL,
)


def _contains_private_pem(value: bytes) -> bool:
    for match in PRIVATE_PEM_RE.finditer(value):
        encoded_lines: list[bytes] = []
        for raw_line in match.group(2).splitlines():
            line = raw_line.strip()
            if not line or b":" in line:
                continue
            if re.fullmatch(rb"[A-Za-z0-9+/=]+", line) is None:
                encoded_lines = []
                break
            encoded_lines.append(line)
        encoded = b"".join(encoded_lines)
        if len(encoded) < 40:
            continue
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) >= 32:
            return True
    return False


def _reject_private_key_bytes(value: bytes, label: str) -> None:
    if _contains_private_pem(value):
        raise ContractError(f"{label} contains private-key material")


def _reject_json_secrets(value: Any, label: str) -> None:
    sensitive_keys = {
        "access_token",
        "api_key",
        "client_secret",
        "credentials",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "token_key",
    }
    safe_markers = {"", "***", "<redacted>", "redacted", "unset"}
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            if {
                "schema_version",
                "authority_binding",
                "active",
                "pending",
                "mac",
            }.issubset(current):
                raise ContractError(f"{label} contains state-head authority JSON")
            for raw_key, child in current.items():
                key = str(raw_key).casefold().replace("-", "_")
                if isinstance(child, str) and _contains_private_pem(
                    child.encode("utf-8")
                ):
                    raise ContractError(
                        f"{label} contains private-key material in JSON field: "
                        f"{raw_key}"
                    )
                if (
                    key in sensitive_keys
                    and child is not None
                    and child is not False
                    and not (
                        isinstance(child, str) and child.casefold() in safe_markers
                    )
                ):
                    raise ContractError(
                        f"{label} contains a non-redacted secret-bearing JSON field: "
                        f"{raw_key}"
                    )
                pending.append(child)
        elif isinstance(current, list):
            pending.extend(current)
        elif isinstance(current, str) and _contains_private_pem(
            current.encode("utf-8")
        ):
            raise ContractError(f"{label} contains private-key material")


def _scan_private_key_stream(stream: Any, label: str) -> None:
    overlap = b""
    scanned = 0
    while True:
        block = stream.read(1024 * 1024)
        if not block:
            return
        scanned += len(block)
        if scanned > 4 * 1024 * 1024 * 1024:
            raise ContractError(f"{label} expanded content exceeds 4 GiB")
        window = overlap + block
        if _contains_private_pem(window):
            raise ContractError(f"{label} contains private-key material")
        overlap = window[-2 * 1024 * 1024 :]


def _scan_archive_member_stream(
    stream: Any, label: str, relative: str, size_bytes: int
) -> None:
    if PurePosixPath(relative).suffix.casefold() == ".json":
        limit = 256 * 1024 * 1024
        if size_bytes > limit:
            raise ContractError(
                f"{label} structured archive member exceeds {limit} bytes"
            )
        value = stream.read(limit + 1)
        if len(value) != size_bytes:
            raise ContractError(f"{label} archive member size changed while scanning")
        parsed = _decode_json_value_bytes(value, label)
        _reject_private_key_bytes(value, label)
        _reject_json_secrets(parsed, label)
        return
    _scan_private_key_stream(stream, label)


def _register_archive_member(
    seen: dict[str, tuple[str, bool]],
    raw_name: str,
    label: str,
    *,
    is_directory: bool,
) -> str | None:
    normalized_name = raw_name.rstrip("/")
    if not normalized_name:
        return None
    relative = canonical_relative_path(normalized_name, label)
    folded = relative.casefold()
    prior = seen.get(folded)
    if prior is not None:
        raise ContractError(
            f"{label} contains duplicate or case-colliding members: "
            f"{prior[0]!r}, {relative!r}"
        )
    for prior_folded, (prior_relative, prior_is_directory) in seen.items():
        if folded.startswith(prior_folded + "/") and not prior_is_directory:
            raise ContractError(
                f"{label} contains a file/member prefix collision: "
                f"{prior_relative!r}, {relative!r}"
            )
        if prior_folded.startswith(folded + "/") and not is_directory:
            raise ContractError(
                f"{label} contains a file/member prefix collision: "
                f"{relative!r}, {prior_relative!r}"
            )
    seen[folded] = (relative, is_directory)
    unsafe = _unsafe_release_material(relative)
    if unsafe is not None:
        raise ContractError(f"{label} contains {unsafe}: {relative}")
    return relative


def _verify_zip_payload(path: Path, label: str) -> None:
    seen: dict[str, tuple[str, bool]] = {}
    try:
        with zipfile.ZipFile(path, "r") as archive:
            entries = archive.infolist()
            if len(entries) > 100_000:
                raise ContractError(f"{label} contains too many ZIP members")
            total_size = sum(info.file_size for info in entries)
            if total_size > 4 * 1024 * 1024 * 1024:
                raise ContractError(f"{label} ZIP expansion exceeds 4 GiB")
            compressed_size = max(1, sum(info.compress_size for info in entries))
            if total_size > compressed_size * 10_000:
                raise ContractError(f"{label} ZIP expansion ratio is unsafe")
            for info in entries:
                relative = _register_archive_member(
                    seen,
                    info.filename,
                    label,
                    is_directory=info.is_dir(),
                )
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(unix_mode):
                    raise ContractError(
                        f"{label} contains a symbolic-link member: {relative}"
                    )
                if info.flag_bits & 0x1:
                    raise ContractError(f"{label} contains an encrypted member")
                if relative is not None and not info.is_dir():
                    with archive.open(info, "r") as stream:
                        _scan_archive_member_stream(
                            stream,
                            f"{label}:{relative}",
                            relative,
                            info.file_size,
                        )
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise ContractError(f"{label} is not a valid ZIP payload: {error}") from error


def _verify_tar_payload(path: Path, label: str) -> None:
    seen: dict[str, tuple[str, bool]] = {}
    try:
        with tarfile.open(path, "r:*") as archive:
            members = archive.getmembers()
            if len(members) > 100_000:
                raise ContractError(f"{label} contains too many TAR members")
            if sum(member.size for member in members) > 4 * 1024 * 1024 * 1024:
                raise ContractError(f"{label} TAR expansion exceeds 4 GiB")
            for member in members:
                relative = _register_archive_member(
                    seen,
                    member.name,
                    label,
                    is_directory=member.isdir(),
                )
                if not (member.isfile() or member.isdir()):
                    raise ContractError(
                        f"{label} contains a link or special TAR member: {relative}"
                    )
                if member.isfile():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ContractError(
                            f"{label} cannot read TAR member: {relative}"
                        )
                    with stream:
                        _scan_archive_member_stream(
                            stream,
                            f"{label}:{relative}",
                            str(relative),
                            member.size,
                        )
    except (OSError, tarfile.TarError) as error:
        raise ContractError(f"{label} is not a valid TAR payload: {error}") from error


def _verify_declared_media_type(
    path: Path,
    media_type: Any,
    label: str,
    *,
    artifact_kind: str | None = None,
    targets: list[str] | None = None,
) -> None:
    media = require_string(media_type, f"{label}.media_type")
    if re.fullmatch(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+", media) is None:
        raise ContractError(f"{label}.media_type is not canonical MIME type text")
    lowered = media.casefold()
    if lowered == "application/json" or lowered.endswith("+json"):
        value = _read_regular_file(path, label, max_bytes=256 * 1024 * 1024)
        parsed = _decode_json_value_bytes(value, label)
        _reject_private_key_bytes(value, label)
        _reject_json_secrets(parsed, label)
    elif lowered.startswith("text/"):
        value = _read_regular_file(path, label, max_bytes=256 * 1024 * 1024)
        if b"\x00" in value:
            raise ContractError(f"{label} declares text media but contains NUL bytes")
        try:
            value.decode("utf-8")
        except UnicodeError as error:
            raise ContractError(
                f"{label} declares text media but is not UTF-8"
            ) from error
        _reject_private_key_bytes(value, label)
    elif lowered in {
        "application/zip",
        "application/x-wheel+zip",
        "application/vnd.contextdb.package+zip",
    } or lowered.endswith("+zip"):
        _verify_zip_payload(path, label)
    elif lowered in {
        "application/x-tar",
        "application/vnd.oci.image.layer.v1.tar",
    }:
        _verify_tar_payload(path, label)
    elif lowered in {
        "application/gzip",
        "application/x-gzip",
        "application/vnd.npm.package+gzip",
        "application/vnd.rust.crate",
    } or lowered.endswith("+gzip"):
        if artifact_kind in {"rust-crate", "typescript-package", "source-package"}:
            _verify_tar_payload(path, label)
        else:
            try:
                with gzip.open(path, "rb") as stream:
                    _scan_private_key_stream(stream, label)
            except (OSError, EOFError) as error:
                raise ContractError(f"{label} is not a valid gzip payload") from error
    elif lowered != "application/octet-stream":
        raise ContractError(
            f"{label}.media_type is unsupported by the offline assembler: {media}"
        )

    if artifact_kind == "python-wheel":
        if path.suffix.casefold() != ".whl":
            raise ContractError(f"{label} Python wheel path must end in .whl")
        _verify_zip_payload(path, label)
    elif artifact_kind == "rust-crate":
        if path.suffix.casefold() != ".crate":
            raise ContractError(f"{label} Rust crate path must end in .crate")
        _verify_tar_payload(path, label)
    elif artifact_kind == "typescript-package":
        if not path.name.casefold().endswith((".tgz", ".tar.gz")):
            raise ContractError(f"{label} TypeScript package must be a .tgz/.tar.gz")
        _verify_tar_payload(path, label)
    elif artifact_kind == "executable":
        target_set = set(targets or [])
        with path.open("rb") as stream:
            magic = stream.read(4)
        if any(value.startswith("windows-") for value in target_set):
            if not magic.startswith(b"MZ"):
                raise ContractError(f"{label} Windows executable lacks PE MZ magic")
        elif any(value.startswith("linux-") for value in target_set):
            if magic != b"\x7fELF":
                raise ContractError(f"{label} Linux executable lacks ELF magic")
        elif any(value.startswith("macos-") for value in target_set) and magic not in {
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
        }:
            raise ContractError(f"{label} macOS executable lacks Mach-O magic")


def _copy_declared_file(
    source_root: Path,
    reference: dict[str, Any],
    destination_root: Path,
    label: str,
    source_epoch: int,
    *,
    artifact_kind: str | None = None,
    targets: list[str] | None = None,
) -> tuple[str, str, int]:
    source_relative = canonical_relative_path(
        reference.get("source_path"), f"{label}.source_path"
    )
    destination_relative = canonical_relative_path(
        reference.get("path"), f"{label}.path"
    )
    unsafe = _unsafe_release_material(destination_relative)
    if unsafe is not None:
        raise ContractError(
            f"{label}.path would stage forbidden {unsafe}: {destination_relative}"
        )
    unsafe_source = _unsafe_release_material(source_relative)
    if unsafe_source is not None:
        raise ContractError(
            f"{label}.source_path names forbidden {unsafe_source}: {source_relative}"
        )
    _, source = resolve_member(source_root, source_relative, f"{label}.source_path")
    if not source.is_file():
        raise ContractError(f"{label} source file is absent: {source_relative}")
    expected_sha = require_sha256(reference.get("sha256"), f"{label}.sha256")
    expected_size = reference.get("size_bytes")
    if (
        not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or expected_size < 0
    ):
        raise ContractError(f"{label}.size_bytes must be a non-negative integer")
    declared_media = require_string(reference.get("media_type"), f"{label}.media_type")
    lowered_media = declared_media.casefold()
    if (
        lowered_media.startswith("text/")
        or lowered_media == "application/json"
        or lowered_media.endswith("+json")
    ) and expected_size > 256 * 1024 * 1024:
        raise ContractError(
            f"{label} exceeds the 268435456-byte structured-media validation limit"
        )

    destination = destination_root.joinpath(*PurePosixPath(destination_relative).parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    _reject_link_chain(source, label)
    descriptor = os.open(source, flags)
    temporary = destination.with_name(f".{destination.name}.copy.tmp")
    digest = hashlib.sha256()
    copied = 0
    private_key_overlap = b""
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError(f"{label} source is not a regular file")
        if temporary.exists():
            temporary.unlink()
        with (
            os.fdopen(descriptor, "rb", closefd=False) as source_stream,
            temporary.open("xb") as destination_stream,
        ):
            for block in iter(lambda: source_stream.read(1024 * 1024), b""):
                digest.update(block)
                copied += len(block)
                private_key_window = private_key_overlap + block
                if _contains_private_pem(private_key_window):
                    raise ContractError(f"{label} contains private-key material")
                private_key_overlap = private_key_window[-2 * 1024 * 1024 :]
                destination_stream.write(block)
            destination_stream.flush()
            os.fsync(destination_stream.fileno())
        after = os.fstat(descriptor)
        snapshot_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        snapshot_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if snapshot_before != snapshot_after:
            raise ContractError(f"{label} source changed while it was copied")
        if copied != expected_size:
            raise ContractError(
                f"{label} size mismatch: expected {expected_size}, observed {copied}"
            )
        observed_sha = digest.hexdigest()
        if observed_sha != expected_sha:
            raise ContractError(
                f"{label} SHA-256 mismatch: expected {expected_sha}, observed {observed_sha}"
            )
        os.chmod(temporary, 0o755 if artifact_kind == "executable" else 0o644)
        _set_mtime(temporary, source_epoch)
        os.replace(temporary, destination)
        _verify_declared_media_type(
            destination,
            declared_media,
            label,
            artifact_kind=artifact_kind,
            targets=targets,
        )
        return destination_relative, observed_sha, copied
    finally:
        os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def _source_epoch(explicit: int | None, created_at: Any) -> int:
    environment = os.environ.get("SOURCE_DATE_EPOCH")
    environment_value: int | None = None
    if environment is not None:
        if re.fullmatch(r"[0-9]+", environment) is None:
            raise ContractError("SOURCE_DATE_EPOCH must be an unsigned integer")
        environment_value = int(environment)
    if (
        explicit is not None
        and environment_value is not None
        and explicit != environment_value
    ):
        raise ContractError("--source-date-epoch conflicts with SOURCE_DATE_EPOCH")
    if explicit is not None:
        epoch = explicit
    elif environment_value is not None:
        epoch = environment_value
    else:
        parsed = parse_timestamp(created_at, "release.created_at")
        if parsed.microsecond:
            raise ContractError(
                "release.created_at must use whole seconds when SOURCE_DATE_EPOCH is absent"
            )
        epoch = int(parsed.timestamp())
    if epoch < 315532800 or epoch > 253402300799:
        raise ContractError(
            "source date epoch must be between 1980-01-01 and 9999-12-31 UTC"
        )
    return epoch


def _canonical_timestamp(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")


def _reserve_bundle_path(registry: dict[str, str], value: Any, label: str) -> str:
    relative = canonical_relative_path(value, label)
    folded = relative.casefold()
    prior = registry.get(folded)
    if prior is not None:
        raise ContractError(
            f"duplicate or case-colliding bundle path: {prior!r}, {relative!r}"
        )
    for prior_folded, prior_value in registry.items():
        if folded.startswith(prior_folded + "/") or prior_folded.startswith(
            folded + "/"
        ):
            raise ContractError(
                f"bundle file/directory prefix collision: {prior_value!r}, {relative!r}"
            )
    registry[folded] = relative
    return relative


def _validate_assembly_bindings(
    input_manifest: dict[str, Any],
    version_manifest: dict[str, Any],
    proof_index: dict[str, Any],
    staged_digests: dict[str, str],
    bundle_root: Path,
) -> None:
    release = require_object(input_manifest.get("release"), "release")
    source = require_object(input_manifest.get("source"), "source")
    version = require_semver(release.get("version"), "release.version")
    channel = require_string(release.get("channel"), "release.channel")
    validate_json_contract(version_manifest, "version manifest")
    if version_manifest.get("product_version") != version:
        raise ContractError("version manifest product_version differs from release")
    if version_manifest.get("release_channel") != channel:
        raise ContractError("version manifest release_channel differs from release")
    version_source = require_object(version_manifest.get("source"), "version source")
    if version_source.get("git_commit") != source.get("git_commit"):
        raise ContractError(
            "version manifest source commit differs from release source"
        )
    if version_source.get("dirty") != source.get("dirty"):
        raise ContractError("version manifest dirty state differs from release source")
    if version_source.get("repository") is not None and version_source.get(
        "repository"
    ) != source.get("repository"):
        raise ContractError("version manifest repository differs from release source")
    for name, raw_format in require_object(
        version_manifest.get("formats"), "version manifest formats"
    ).items():
        format_value = require_object(raw_format, f"version format {name}")
        writer = format_value.get("writer")
        read_min = format_value.get("read_min")
        read_max = format_value.get("read_max")
        if not (
            isinstance(writer, int)
            and not isinstance(writer, bool)
            and isinstance(read_min, int)
            and not isinstance(read_min, bool)
            and isinstance(read_max, int)
            and not isinstance(read_max, bool)
            and read_min <= writer <= read_max
        ):
            raise ContractError(
                f"version format {name} writer is outside its readable range"
            )

    validate_json_contract(proof_index, "proof index")
    if proof_index.get("release_version") != version:
        raise ContractError("proof index release_version differs from release")
    if proof_index.get("release_stage") != channel:
        raise ContractError("proof index release_stage differs from release")
    ledger = require_object(proof_index.get("ledger"), "proof index ledger")
    ledger_path = canonical_relative_path(ledger.get("path"), "proof index ledger.path")
    ledger_digest = require_sha256(ledger.get("sha256"), "proof index ledger.sha256")
    if staged_digests.get(ledger_path) != ledger_digest:
        raise ContractError(
            "proof index ledger is absent or has a different staged digest"
        )
    ledger_value = load_json(bundle_root.joinpath(*PurePosixPath(ledger_path).parts))
    validate_json_contract(ledger_value, "roadmap gate ledger")
    if ledger_value.get("roadmap_revision") != ledger.get("roadmap_revision"):
        raise ContractError("proof index roadmap revision differs from staged ledger")
    ledger_milestone_ids = [
        require_string(value.get("id"), "ledger milestone id")
        for value in require_array(ledger_value.get("milestones"), "ledger milestones")
        if isinstance(value, dict)
    ]
    if len(ledger_milestone_ids) != len(set(ledger_milestone_ids)):
        raise ContractError("roadmap gate ledger repeats milestone IDs")
    ledger_exit_ids = {
        require_string(exit_value.get("id"), "ledger exit ID")
        for milestone in require_array(
            ledger_value.get("milestones"), "ledger milestones"
        )
        for exit_value in require_array(
            require_object(milestone, "ledger milestone").get("exit_criteria"),
            "ledger exit criteria",
        )
        if isinstance(exit_value, dict)
    }
    proof_references: list[dict[str, Any]] = []
    proof_milestone_ids: set[str] = set()
    proof_exit_ids: set[str] = set()
    for milestone in require_array(proof_index.get("milestones"), "proof milestones"):
        milestone_value = require_object(milestone, "proof milestone")
        milestone_id = require_string(milestone_value.get("id"), "proof milestone id")
        if milestone_id in proof_milestone_ids:
            raise ContractError(f"proof index repeats milestone ID {milestone_id}")
        if milestone_id not in ledger_milestone_ids:
            raise ContractError(
                f"proof index milestone {milestone_id} is absent from staged ledger"
            )
        proof_milestone_ids.add(milestone_id)
        proof_references.extend(
            require_object(value, "required proof")
            for value in require_array(
                milestone_value.get("required_proofs"), "required proofs"
            )
        )
        for criterion in require_array(
            milestone_value.get("exit_criteria"), "exit criteria"
        ):
            criterion_value = require_object(criterion, "exit criterion")
            exit_id = require_string(criterion_value.get("id"), "proof exit ID")
            if exit_id in proof_exit_ids:
                raise ContractError(f"proof index repeats exit ID {exit_id}")
            if exit_id not in ledger_exit_ids:
                raise ContractError(
                    f"proof index exit {exit_id} is absent from staged ledger"
                )
            proof_exit_ids.add(exit_id)
            proof_references.extend(
                require_object(value, "exit evidence")
                for value in require_array(
                    criterion_value.get("evidence"), "exit evidence"
                )
            )
    for index, reference in enumerate(proof_references):
        path = canonical_relative_path(
            reference.get("path"), f"proof reference {index}.path"
        )
        digest = require_sha256(
            reference.get("sha256"), f"proof reference {index}.sha256"
        )
        if staged_digests.get(path) != digest:
            raise ContractError(
                f"proof reference is absent or has a different staged digest: {path}"
            )


def _assembly_unresolved_gates(
    input_manifest: dict[str, Any],
    matrix: dict[str, Any],
    packages: dict[str, dict[str, Any]],
) -> list[str]:
    channel = str(input_manifest["release"]["channel"])
    artifacts = require_array(input_manifest.get("artifacts"), "artifacts")
    unresolved = {
        "artifact-evidence-bindings-require-verifier",
        "independent-release-profile-verification",
        "immutable-publication-retrieval-requires-verifier",
        "production-signatures",
        "required-platform-install-receipts-require-verifier",
        "roadmap-proof-closure-requires-verifier",
    }
    if channel == "development":
        unresolved.add("development-channel-is-not-a-release")
        required_packages: set[str] = set()
    else:
        required_packages = set(matrix["release_requirements"][channel])
    if input_manifest["source"]["dirty"] is True:
        unresolved.add("dirty-source")
    if channel in {"alpha", "beta"} and not input_manifest["limitations"]:
        unresolved.add("pre-release-limitations-not-documented")
    artifact_packages = {
        str(require_object(value, "artifact").get("package_id")) for value in artifacts
    }
    if required_packages - artifact_packages:
        unresolved.add("required-package-and-target-coverage")
    for package_id in required_packages & artifact_packages:
        package = packages[package_id]
        expected_targets = set(package["platforms"])
        actual_targets = {
            str(target)
            for artifact in artifacts
            if artifact.get("package_id") == package_id
            for target in artifact.get("targets", [])
        }
        if expected_targets != actual_targets:
            unresolved.add("required-package-and-target-coverage")

    return sorted(unresolved)


def assemble_bundle(
    input_root: Path,
    input_manifest_path: Path,
    matrix_path: Path,
    output_directory: Path,
    source_date_epoch: int | None,
) -> dict[str, Any]:
    _reject_link_chain(input_root, "input root")
    source_root = input_root.resolve(strict=True)
    if not source_root.is_dir():
        raise ContractError("input root must be a directory")
    output_candidate = output_directory.absolute()
    if output_candidate.exists() or _is_link_like(output_candidate):
        raise ContractError(
            f"assembly output must not already exist: {output_candidate}"
        )
    existing_output_ancestor = output_candidate.parent
    while (
        not existing_output_ancestor.exists()
        and not _is_link_like(existing_output_ancestor)
        and existing_output_ancestor != existing_output_ancestor.parent
    ):
        existing_output_ancestor = existing_output_ancestor.parent
    _reject_link_chain(existing_output_ancestor, "assembly output parent")
    output_candidate.parent.mkdir(parents=True, exist_ok=True)
    _reject_link_chain(output_candidate.parent, "assembly output parent")
    output = output_candidate.parent.resolve(strict=True) / output_candidate.name
    try:
        output.relative_to(source_root)
    except ValueError:
        pass
    else:
        raise ContractError("assembly output must be outside input root")
    _reject_link_chain(input_manifest_path, "input manifest")
    _reject_link_chain(matrix_path, "package matrix")
    input_bytes = _read_regular_file(
        input_manifest_path, "input manifest", max_bytes=16 * 1024 * 1024
    )
    matrix_bytes = _read_regular_file(
        matrix_path, "package matrix", max_bytes=16 * 1024 * 1024
    )
    input_manifest = _decode_json_bytes(input_bytes, "input manifest")
    matrix = _decode_json_bytes(matrix_bytes, "package matrix")
    _reject_private_key_bytes(input_bytes, "input manifest")
    _reject_json_secrets(input_manifest, "input manifest")
    _reject_private_key_bytes(matrix_bytes, "package matrix")
    _reject_json_secrets(matrix, "package matrix")
    validate_json_contract(input_manifest, "input manifest")
    validate_json_contract(matrix, "package matrix")
    if input_manifest.get("schema_version") != "contextdb.release-bundle-input/v1":
        raise ContractError("unsupported bundle input manifest schema")
    if matrix.get("schema_version") != "contextdb.release-package-matrix/v1":
        raise ContractError("unsupported package matrix schema")
    semantic_verifier = BundleVerifier(
        source_root, "unused-artifact-manifest.json", "contract", {}, False
    )
    packages, _ = semantic_verifier._verify_matrix(matrix)
    release = require_object(input_manifest.get("release"), "release")
    source_metadata = require_object(input_manifest.get("source"), "source")
    repository_uri = require_string(
        source_metadata.get("repository"), "source.repository"
    )
    try:
        repository = urlsplit(repository_uri)
    except ValueError as error:
        raise ContractError("source.repository is not a valid URI") from error
    if (
        repository.scheme != "https"
        or repository.hostname is None
        or repository.username is not None
        or repository.password is not None
        or repository.query
        or repository.fragment
    ):
        raise ContractError(
            "source.repository must be a credential-free HTTPS repository URI"
        )
    epoch = _source_epoch(source_date_epoch, release.get("created_at"))
    generated_at = _canonical_timestamp(epoch)

    path_registry: dict[str, str] = {}
    source_registry: dict[str, str] = {}
    for control_path in (
        "release/artifact-manifest.json",
        "release/package-matrix.json",
        "release/signatures.json",
        "SHA256SUMS",
    ):
        path_registry[control_path.casefold()] = control_path
    staged_entries: list[tuple[str, dict[str, Any], str | None, list[str] | None]] = []

    def declare(
        reference: dict[str, Any],
        label: str,
        kind: str | None = None,
        targets: list[str] | None = None,
    ) -> None:
        destination = _reserve_bundle_path(
            path_registry, reference.get("path"), f"{label}.path"
        )
        source = canonical_relative_path(
            reference.get("source_path"), f"{label}.source_path"
        )
        source_folded = source.casefold()
        prior_source = source_registry.get(source_folded)
        if prior_source is not None:
            raise ContractError(
                f"duplicate or case-colliding input source path: {prior_source!r}, {source!r}"
            )
        source_registry[source_folded] = source
        staged_entries.append((label, reference, kind, targets))
        _ = destination

    version_ref = require_object(
        input_manifest.get("version_manifest"), "version_manifest"
    )
    proof_ref = require_object(input_manifest.get("proof_index"), "proof_index")
    declare(version_ref, "version_manifest")
    declare(proof_ref, "proof_index")
    if version_ref.get("path") != "release/version.json":
        raise ContractError("version_manifest.path must be release/version.json")
    if proof_ref.get("path") != "release/proof-index.json":
        raise ContractError("proof_index.path must be release/proof-index.json")

    artifact_ids: set[str] = set()
    artifact_target_owners: dict[tuple[str, str], str] = {}
    manifest_artifacts: list[dict[str, Any]] = []
    for index, raw in enumerate(
        require_array(input_manifest.get("artifacts"), "artifacts")
    ):
        artifact = require_object(raw, f"artifacts[{index}]")
        artifact_id = require_string(artifact.get("id"), f"artifacts[{index}].id")
        if artifact_id in artifact_ids:
            raise ContractError(f"duplicate artifact id: {artifact_id}")
        artifact_ids.add(artifact_id)
        package_id = require_string(
            artifact.get("package_id"), f"artifacts[{index}].package_id"
        )
        package = packages.get(package_id)
        if package is None:
            raise ContractError(
                f"artifact {artifact_id} references unknown package {package_id}"
            )
        if artifact.get("kind") != package.get("artifact_kind"):
            raise ContractError(
                f"artifact {artifact_id} kind differs from package matrix"
            )
        if artifact.get("roles") != package.get("roles"):
            raise ContractError(
                f"artifact {artifact_id} roles must exactly match package matrix"
            )
        targets = [
            str(value)
            for value in require_array(
                artifact.get("targets"), f"artifact {artifact_id}.targets"
            )
        ]
        if len(targets) != len(set(targets)):
            raise ContractError(f"artifact {artifact_id} repeats a target")
        allowed_targets = set(package["platforms"])
        if set(targets) - allowed_targets:
            raise ContractError(f"artifact {artifact_id} uses undeclared targets")
        if package["coverage"] == "per-platform" and len(targets) != 1:
            raise ContractError(
                f"artifact {artifact_id} must carry exactly one platform target"
            )
        if package["coverage"] == "platform-independent" and targets != [
            "platform-independent"
        ]:
            raise ContractError(f"artifact {artifact_id} must be platform-independent")
        for target in targets:
            ownership = (package_id, target)
            prior_artifact = artifact_target_owners.get(ownership)
            if prior_artifact is not None:
                raise ContractError(
                    f"artifacts {prior_artifact} and {artifact_id} both claim "
                    f"package target {package_id}/{target}"
                )
            artifact_target_owners[ownership] = artifact_id
        if artifact.get("version") != release.get("version"):
            raise ContractError(f"artifact {artifact_id} version differs from release")
        provenance = require_object(
            artifact.get("provenance"), f"artifact {artifact_id}.provenance"
        )
        if provenance.get("source_commit") != input_manifest["source"]["git_commit"]:
            raise ContractError(
                f"artifact {artifact_id} provenance commit differs from release"
            )
        declare(artifact, f"artifact {artifact_id}", str(artifact["kind"]), targets)
        output_related: list[dict[str, Any]] = []
        evidence_identities: set[tuple[str, str]] = set()
        for related_index, raw_related in enumerate(
            require_array(
                artifact.get("related_files"), f"artifact {artifact_id}.related_files"
            )
        ):
            related = require_object(
                raw_related, f"artifact {artifact_id}.related_files[{related_index}]"
            )
            kind = require_string(related.get("kind"), "related file kind")
            platform = related.get("platform")
            if platform is not None:
                platform_value = require_string(platform, "related file platform")
                allowed_related_platforms = set(package["runtime_platforms"]) | set(
                    targets
                )
                if platform_value not in allowed_related_platforms:
                    raise ContractError(
                        f"related file platform {platform_value} is not declared for "
                        f"artifact {artifact_id}"
                    )
            evidence_identity = (kind, "" if platform is None else str(platform))
            if kind in {
                "sbom",
                "install-receipt",
                "provenance-attestation",
                "publication-receipt",
            }:
                if evidence_identity in evidence_identities:
                    raise ContractError(
                        f"artifact {artifact_id} repeats {kind} evidence for "
                        f"platform {platform or 'unspecified'}"
                    )
                evidence_identities.add(evidence_identity)
            if kind == "install-receipt" and (
                related.get("evidence_level") != "runtime"
                or related.get("status") != "passed"
                or related.get("platform") is None
            ):
                raise ContractError(
                    "install receipts must be passed runtime evidence with a platform"
                )
            if (
                kind == "install-receipt"
                and platform not in package["runtime_platforms"]
            ):
                raise ContractError(
                    f"install receipt platform {platform} is not a runtime target for "
                    f"package {package_id}"
                )
            if kind == "publication-receipt" and (
                related.get("evidence_level") != "publication"
                or related.get("status") != "passed"
            ):
                raise ContractError(
                    "publication receipts must be passed publication evidence"
                )
            if kind in {"sbom", "provenance-attestation"} and (
                related.get("evidence_level") not in {"static", "publication"}
                or related.get("status") != "passed"
            ):
                raise ContractError(
                    f"{kind} must be passed static/publication evidence"
                )
            declare(related, f"artifact {artifact_id} related file {related_index}")
            output_related.append(
                {
                    key: value
                    for key, value in related.items()
                    if key not in {"source_path", "media_type"}
                }
            )
        manifest_artifacts.append(
            {
                "id": artifact_id,
                "package_id": package_id,
                "roles": artifact["roles"],
                "kind": artifact["kind"],
                "path": artifact["path"],
                "media_type": artifact["media_type"],
                "size_bytes": artifact["size_bytes"],
                "sha256": artifact["sha256"],
                "targets": targets,
                "version": artifact["version"],
                "version_manifest_sha256": version_ref["sha256"],
                "provenance": provenance,
                "related_files": output_related,
            }
        )
    for index, raw in enumerate(
        require_array(input_manifest.get("supporting_files"), "supporting_files")
    ):
        supporting = require_object(raw, f"supporting_files[{index}]")
        declare(supporting, f"supporting_files[{index}]")

    declared_paths = {
        canonical_relative_path(reference.get("path"), f"{label}.path")
        for label, reference, _, _ in staged_entries
    } | {"release/package-matrix.json"}
    for artifact in manifest_artifacts:
        recipe = canonical_relative_path(
            artifact["provenance"]["build_recipe"],
            f"artifact {artifact['id']} build recipe",
        )
        if recipe not in declared_paths:
            raise ContractError(
                f"artifact {artifact['id']} build recipe is not a staged input: {recipe}"
            )

    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.assemble-", dir=output.parent)
    )
    try:
        staged_digests: dict[str, str] = {}
        for label, reference, staged_kind, staged_targets in staged_entries:
            relative, digest, _ = _copy_declared_file(
                source_root,
                reference,
                temporary,
                label,
                epoch,
                artifact_kind=staged_kind,
                targets=staged_targets,
            )
            staged_digests[relative] = digest
        matrix_destination = temporary / "release" / "package-matrix.json"
        _write_bytes_atomic(matrix_destination, matrix_bytes)
        _set_mtime(matrix_destination, epoch)
        staged_digests["release/package-matrix.json"] = sha256_bytes(matrix_bytes)

        version_path = temporary / "release" / "version.json"
        proof_path = temporary / "release" / "proof-index.json"
        version_manifest = load_json(version_path)
        proof_index = load_json(proof_path)
        _validate_assembly_bindings(
            input_manifest,
            version_manifest,
            proof_index,
            staged_digests,
            temporary,
        )
        artifact_manifest = {
            "schema_version": "contextdb.release-artifact-manifest/v1",
            "release": {
                **{
                    key: value
                    for key, value in release.items()
                    if key in {"version", "channel", "candidate"}
                },
                "created_at": generated_at,
            },
            "source": input_manifest["source"],
            "version_manifest": {
                "path": version_ref["path"],
                "sha256": version_ref["sha256"],
            },
            "package_matrix": {
                "path": "release/package-matrix.json",
                "sha256": sha256_bytes(matrix_bytes),
            },
            "proof_index": {
                "path": proof_ref["path"],
                "sha256": proof_ref["sha256"],
            },
            "checksum_file": {
                "path": "SHA256SUMS",
                "algorithm": "sha256",
                "format": "sha256sum-v1",
            },
            "signature_set": {"path": "release/signatures.json"},
            "artifacts": sorted(manifest_artifacts, key=lambda value: value["id"]),
            "limitations": input_manifest["limitations"],
        }
        validate_json_contract(artifact_manifest, "generated artifact manifest")
        manifest_destination = temporary / "release" / "artifact-manifest.json"
        _write_json_atomic(manifest_destination, artifact_manifest)
        _set_mtime(manifest_destination, epoch)

        checksum_members = sorted(
            (
                path
                for path in temporary.rglob("*")
                if path.is_file() and path.name != "SHA256SUMS"
            ),
            key=lambda path: path.relative_to(temporary).as_posix().encode("utf-8"),
        )
        checksum_value = "".join(
            f"{sha256_file(path)}  {path.relative_to(temporary).as_posix()}\n"
            for path in checksum_members
        ).encode("utf-8")
        checksum_destination = temporary / "SHA256SUMS"
        _write_bytes_atomic(checksum_destination, checksum_value)
        _set_mtime(checksum_destination, epoch)

        for directory in sorted(
            (path for path in temporary.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            os.chmod(directory, 0o755)
            _set_mtime(directory, epoch)
        os.chmod(temporary, 0o755)
        _set_mtime(temporary, epoch)

        inventory = sorted(
            (path for path in temporary.rglob("*") if path.is_file()),
            key=lambda path: path.relative_to(temporary).as_posix().encode("utf-8"),
        )
        tree_value = "".join(
            f"{sha256_file(path)} {path.stat().st_size} "
            f"{path.relative_to(temporary).as_posix()}\n"
            for path in inventory
        ).encode("utf-8")
        unresolved = _assembly_unresolved_gates(input_manifest, matrix, packages)
        receipt = {
            "schema_version": "contextdb.release-bundle-assembly-receipt/v1",
            "assembler_version": RELEASE_TOOL_VERSION,
            "generated_at": generated_at,
            "release": {
                "version": release["version"],
                "channel": release["channel"],
            },
            "sources": {
                "input_manifest": {
                    "sha256": sha256_bytes(input_bytes),
                    "size_bytes": len(input_bytes),
                    "media_type": "application/json",
                },
                "package_matrix": {
                    "sha256": sha256_bytes(matrix_bytes),
                    "size_bytes": len(matrix_bytes),
                    "media_type": "application/json",
                },
            },
            "output": {
                "directory_name": output.name,
                "artifact_manifest_sha256": sha256_file(manifest_destination),
                "checksum_file_sha256": sha256_file(checksum_destination),
                "tree_sha256": sha256_bytes(tree_value),
                "file_count": len(inventory),
                "total_size_bytes": sum(path.stat().st_size for path in inventory),
                "deterministic_mtime_epoch": epoch,
            },
            "checks": [
                {
                    "id": "declared-input-integrity",
                    "status": "passed",
                    "detail": f"verified and copied {len(staged_entries)} declared files",
                },
                {
                    "id": "package-matrix-bindings",
                    "status": "passed",
                    "detail": f"validated {len(packages)} package definitions",
                },
                {
                    "id": "deterministic-output",
                    "status": "passed",
                    "detail": "canonical JSON/checksum ordering, fixed modes, and fixed mtimes applied",
                },
                {
                    "id": "secret-and-link-boundary",
                    "status": "passed",
                    "detail": "links, traversal, custody sidecars, private keys, and pre-generated signatures rejected",
                },
            ],
            "unresolved_release_gates": unresolved,
            "release_ready": False,
            "evidence_boundary": {
                "network_accessed": False,
                "artifacts_built": False,
                "signatures_created": False,
                "publication_verified": False,
                "platform_install_receipts_generated": False,
                "release_readiness_decided_by_assembler": False,
            },
        }
        validate_json_contract(receipt, "assembly receipt")
        if output.exists() or _is_link_like(output):
            raise ContractError(f"assembly output appeared during assembly: {output}")
        temporary.rename(output)
        return receipt
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def _portable_custody_material(relative: str) -> str | None:
    lower_name = relative.casefold()
    basename = PurePosixPath(relative).name.casefold()
    if lower_name.endswith((".key", ".pem", ".p12", ".pfx")):
        return "key material"
    normalized_basename = basename.replace("_", "-")
    if "state-head" in normalized_basename or normalized_basename.startswith(
        "statehead"
    ):
        return "state-head authority material"
    return None


def package_example(source: Path, output: Path, force: bool) -> dict[str, Any]:
    source = source.resolve(strict=True)
    output = output.resolve(strict=False)
    if not source.is_dir():
        raise ContractError("example source must be a directory")
    try:
        output.relative_to(source)
    except ValueError:
        pass
    else:
        raise ContractError("example output must be outside its source directory")
    if output.exists() and not force:
        raise ContractError(f"output already exists: {output}")
    files: list[Path] = []
    logical_archives = 0
    total_size = 0
    for path in sorted(
        source.rglob("*"), key=lambda item: item.as_posix().encode("utf-8")
    ):
        if path.is_symlink():
            raise ContractError(f"example payload contains a symbolic link: {path}")
        if path.is_file():
            relative = canonical_relative_path(
                path.relative_to(source).as_posix(), "example payload path"
            )
            custody_material = _portable_custody_material(relative)
            if custody_material is not None:
                raise ContractError(
                    f"portable example must not contain {custody_material}: {relative}"
                )
            lower_name = relative.lower()
            if lower_name.endswith(".ctxb"):
                logical_archives += 1
            size = path.stat().st_size
            if size > 256 * 1024 * 1024:
                raise ContractError(f"example payload file is too large: {relative}")
            total_size += size
            if total_size > 512 * 1024 * 1024 or len(files) >= 128:
                raise ContractError("example payload exceeds package limits")
            files.append(path)
    if not files:
        raise ContractError("example payload is empty")
    if logical_archives != 1:
        raise ContractError(
            "portable example must contain exactly one .ctxb archive, "
            f"found {logical_archives}"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    if temporary.exists():
        temporary.unlink()
    entries: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for path in files:
                relative = path.relative_to(source).as_posix()
                data = path.read_bytes()
                info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(
                    info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9
                )
                entries.append(
                    {
                        "path": relative,
                        "size_bytes": len(data),
                        "sha256": sha256_bytes(data),
                    }
                )
        with zipfile.ZipFile(temporary, "r") as archive:
            names = archive.namelist()
            if names != [entry["path"] for entry in entries]:
                raise ContractError("deterministic archive entry order changed")
            for entry in entries:
                if sha256_bytes(archive.read(entry["path"])) != entry["sha256"]:
                    raise ContractError(f"archive verification failed: {entry['path']}")
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {
        "schema_version": "contextdb.portable-example-package-receipt/v1",
        "packager_version": RELEASE_TOOL_VERSION,
        "output": output.name,
        "size_bytes": output.stat().st_size,
        "sha256": sha256_file(output),
        "entries": entries,
        "determinism": {
            "entry_order": "utf8-bytewise",
            "timestamp": "1980-01-01T00:00:00Z",
            "unix_mode": "0644",
            "compression": "deflate-9",
        },
        "release_ready": False,
    }


EXTERNAL_RECEIPT_KINDS = frozenset(
    {
        "install-receipt",
        "operational-receipt",
        "publication-receipt",
        "provenance-attestation",
        "sbom",
    }
)
REQUIRED_OPERATIONAL_PROBES = frozenset(
    {
        "old-version",
        "old-import-seed",
        "old-seed-import-custody",
        "old-seed-status",
        "old-doctor",
        "old-export-for-upgrade",
        "upgrade-export-custody",
        "snapshot-old-before-upgrade",
        "snapshot-migration-export",
        "activate-old-1",
        "new-version",
        "candidate-import",
        "candidate-import-custody",
        "candidate-doctor",
        "candidate-export-for-activation",
        "candidate-activation-export-custody",
        "snapshot-candidate",
        "activate-candidate-2",
        "activate-old-3",
        "rollback-old-doctor",
        "rollback-old-export",
        "rollback-export-custody",
        "snapshot-old-after-rollback",
        "rollback-logical-state-unchanged",
        "candidate-export-for-dr",
        "dr-export-custody",
        "snapshot-disaster-recovery-export",
        "recovered-import",
        "recovered-import-custody",
        "recovered-doctor",
        "recovered-export-for-activation",
        "recovered-export-custody",
        "snapshot-recovered",
        "disaster-recovery-logical-state-identity",
        "activate-recovered-4",
        "operational-authority-cleanup",
    }
)
REQUIRED_CONTEXTDB_INSTALL_PROBES = frozenset(
    {
        "contextdb-version",
        "contextdb-init",
        "contextdb-init-key-boundary",
        "contextdb-doctor",
        "contextdb-export",
        "contextdb-export-key-boundary",
        "contextdb-state-authority-cleanup",
    }
)
REQUIRED_CONTEXTDB_EXAMPLE_PROBES = frozenset(
    {
        "portable-example-extract",
        "contextdb-import-example",
        "contextdb-import-key-boundary",
        "contextdb-doctor-imported",
    }
)


def _paths_overlap(left: Path, right: Path) -> bool:
    try:
        left.relative_to(right)
        return True
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return True
    except ValueError:
        return False


def _verify_intake_install_receipt(
    artifact: dict[str, Any], receipt: dict[str, Any], platform_id: str, label: str
) -> None:
    if receipt.get("schema_version") != "contextdb.clean-install-receipt/v1":
        raise ContractError(f"{label} has an unsupported install receipt schema")
    validate_json_contract(receipt, label)
    if receipt.get("host_target") != platform_id:
        raise ContractError(f"{label} host target does not match intake platform")
    verification = require_object(receipt.get("verification"), f"{label}.verification")
    probes = require_array(receipt.get("probes"), f"{label}.probes")
    probe_ids = [
        require_string(
            require_object(probe, f"{label}.probe").get("id"), f"{label}.probe.id"
        )
        for probe in probes
    ]
    if (
        verification.get("contract_valid") is not True
        or receipt.get("isolated_copy") is not True
        or receipt.get("passed") is not True
        or not probes
        or any(
            not isinstance(probe, dict) or probe.get("status") != "passed"
            for probe in probes
        )
    ):
        raise ContractError(f"{label} is not an all-passing isolated install")
    if len(probe_ids) != len(set(probe_ids)):
        raise ContractError(f"{label} repeats install probe IDs")
    expected = BundleVerifier._artifact_subject(artifact)
    subjects = require_array(
        receipt.get("subject_artifacts"), f"{label}.subject_artifacts"
    )
    if expected not in subjects:
        raise ContractError(f"{label} is not bound to artifact {expected['id']}")
    required_probes: set[str] = set()
    if artifact.get("package_id") == "contextdb-binary":
        required_probes.update(REQUIRED_CONTEXTDB_INSTALL_PROBES)
        has_example_subject = any(
            isinstance(subject, dict)
            and subject.get("id") != expected["id"]
            and subject.get("path", "").endswith((".ctxb", ".zip"))
            for subject in subjects
        )
        if has_example_subject:
            required_probes.update(REQUIRED_CONTEXTDB_EXAMPLE_PROBES)
    missing_probes = sorted(required_probes - set(probe_ids))
    if missing_probes:
        raise ContractError(f"{label} lacks required install probes: {missing_probes}")
    if (
        artifact.get("kind") == "docker-image"
        and receipt.get("docker_runtime_executed") is not True
    ):
        raise ContractError(f"{label} lacks Docker runtime evidence")


def _verify_intake_publication_receipt(
    artifact: dict[str, Any], receipt: dict[str, Any], platform_id: str, label: str
) -> None:
    if receipt.get("schema_version") != "contextdb.release-publication-receipt/v1":
        raise ContractError(f"{label} has an unsupported publication schema")
    validate_json_contract(receipt, label)
    expected = BundleVerifier._artifact_subject(artifact)
    if require_object(receipt.get("artifact"), f"{label}.artifact") != expected:
        raise ContractError(f"{label} artifact binding does not match")
    if (
        receipt.get("status") != "passed"
        or receipt.get("immutable_reference") is not True
        or receipt.get("retrieved_sha256") != expected["sha256"]
    ):
        raise ContractError(f"{label} is not an exact immutable publication")
    _ = require_public_https_uri(receipt.get("immutable_uri"), f"{label}.immutable_uri")
    published_at = parse_timestamp(receipt.get("published_at"), f"{label}.published_at")
    verified_at = parse_timestamp(receipt.get("verified_at"), f"{label}.verified_at")
    if verified_at < published_at:
        raise ContractError(f"{label}.verified_at predates publication")
    observed_platform = receipt.get("platform")
    if observed_platform is not None and observed_platform != platform_id:
        raise ContractError(f"{label} platform binding does not match")
    if platform_id != "platform-independent" and observed_platform is None:
        raise ContractError(f"{label} omits the required target platform binding")
    receipt_uri = receipt.get("receipt_uri")
    if receipt_uri is not None:
        _ = require_public_https_uri(receipt_uri, f"{label}.receipt_uri")


def _verify_intake_operational_receipt(
    artifact: dict[str, Any],
    receipt: dict[str, Any],
    platform_id: str,
    manifest: dict[str, Any],
    manifest_digest: str,
    plan: dict[str, Any],
    plan_digest: str,
    old_manifest: dict[str, Any],
    old_manifest_digest: str,
    label: str,
) -> None:
    if receipt.get("schema_version") != "contextdb.release-operational-receipt/v1":
        raise ContractError(f"{label} has an unsupported operational schema")
    validate_json_contract(receipt, label)
    if receipt.get("host_target") != platform_id:
        raise ContractError(f"{label} host target does not match intake platform")
    if receipt.get("new_artifact") != BundleVerifier._artifact_subject(artifact):
        raise ContractError(f"{label} new artifact binding does not match")
    if receipt.get("plan_sha256") != plan_digest:
        raise ContractError(f"{label} operational plan binding does not match")
    if (
        plan.get("host_target") != platform_id
        or plan.get("profile") != receipt.get("profile")
        or plan.get("scenarios") != receipt.get("scenarios")
    ):
        raise ContractError(f"{label} operational plan semantics do not match")
    old_spec = require_object(plan.get("old_release"), f"{label}.plan.old_release")
    new_spec = require_object(plan.get("new_release"), f"{label}.plan.new_release")
    if (
        new_spec.get("manifest_sha256") != manifest_digest
        or new_spec.get("version") != artifact.get("version")
        or new_spec.get("binary_artifact_id") != artifact.get("id")
    ):
        raise ContractError(f"{label} plan new-release subject does not match")
    if old_spec.get("manifest_sha256") != old_manifest_digest:
        raise ContractError(f"{label} plan old-manifest binding does not match")
    old_version = require_semver(
        require_object(
            old_manifest.get("release"), f"{label}.old_manifest.release"
        ).get("version"),
        f"{label}.old_manifest.release.version",
    )
    if old_version != old_spec.get("version"):
        raise ContractError(f"{label} old-manifest version does not match the plan")
    old_artifact_id = require_string(
        old_spec.get("binary_artifact_id"), f"{label}.old_release.binary_artifact_id"
    )
    old_matches = [
        require_object(value, f"{label}.old artifact")
        for value in require_array(
            old_manifest.get("artifacts"), f"{label}.old_manifest.artifacts"
        )
        if isinstance(value, dict) and value.get("id") == old_artifact_id
    ]
    if len(old_matches) != 1:
        raise ContractError(f"{label} old binary artifact is not unique")
    old_manifest_artifact = old_matches[0]
    if (
        old_manifest_artifact.get("package_id") != "contextdb-binary"
        or old_manifest_artifact.get("kind") != "executable"
        or platform_id not in old_manifest_artifact.get("targets", [])
        or receipt.get("old_artifact")
        != BundleVerifier._artifact_subject(old_manifest_artifact)
    ):
        raise ContractError(f"{label} old artifact binding does not match")
    seed_spec = require_object(plan.get("seed_artifact"), f"{label}.plan.seed_artifact")
    seed_bundle = seed_spec.get("bundle")
    if seed_bundle == "old":
        seed_manifest = old_manifest
    elif seed_bundle == "new":
        seed_manifest = manifest
    else:
        raise ContractError(f"{label} seed bundle is not old or new")
    seed_id = require_string(
        seed_spec.get("artifact_id"), f"{label}.plan.seed_artifact.artifact_id"
    )
    seed_matches = [
        require_object(value, f"{label}.seed artifact")
        for value in require_array(
            seed_manifest.get("artifacts"), f"{label}.seed_manifest.artifacts"
        )
        if isinstance(value, dict) and value.get("id") == seed_id
    ]
    if len(seed_matches) != 1:
        raise ContractError(f"{label} seed artifact is not unique")
    seed_artifact = seed_matches[0]
    if (
        seed_artifact.get("package_id") != "portable-example-database"
        or seed_artifact.get("kind") != "example-database"
        or seed_artifact.get("sha256") != seed_spec.get("sha256")
        or seed_artifact.get("size_bytes") != seed_spec.get("size_bytes")
        or receipt.get("seed_artifact")
        != BundleVerifier._artifact_subject(seed_artifact)
        or receipt.get("minimum_seed_commit_seq") != seed_spec.get("minimum_commit_seq")
    ):
        raise ContractError(f"{label} non-empty seed binding does not match")
    verifications = require_object(
        receipt.get("bundle_verifications"), f"{label}.bundle_verifications"
    )
    new_verification = require_object(
        verifications.get("new"), f"{label}.bundle_verifications.new"
    )
    if new_verification.get("manifest_sha256") != manifest_digest:
        raise ContractError(f"{label} new manifest binding does not match")
    old_verification = require_object(
        verifications.get("old"), f"{label}.bundle_verifications.old"
    )
    if old_verification.get("manifest_sha256") != old_manifest_digest:
        raise ContractError(f"{label} old manifest verification binding does not match")
    old_artifact = require_object(receipt.get("old_artifact"), f"{label}.old_artifact")
    new_artifact = require_object(receipt.get("new_artifact"), f"{label}.new_artifact")
    old_version = require_semver(
        old_artifact.get("version"), f"{label}.old_artifact.version"
    )
    new_version = require_semver(
        new_artifact.get("version"), f"{label}.new_artifact.version"
    )
    require_semver_upgrade(old_version, new_version, label)
    expected_scenarios = {
        "side-by-side-upgrade",
        "explicit-rollback",
        "disaster-recovery",
    }
    scenarios = require_array(receipt.get("scenarios"), f"{label}.scenarios")
    if len(scenarios) != 3 or set(scenarios) != expected_scenarios:
        raise ContractError(f"{label} does not cover every operational scenario")
    if receipt.get("activation_sequence") != [
        "old",
        "candidate",
        "old",
        "recovered",
    ]:
        raise ContractError(f"{label} activation sequence is incomplete")
    snapshots = require_array(receipt.get("state_snapshots"), f"{label}.snapshots")
    snapshots_by_role: dict[str, dict[str, Any]] = {}
    for index, raw_snapshot in enumerate(snapshots):
        snapshot = require_object(raw_snapshot, f"{label}.snapshots[{index}]")
        role = require_string(snapshot.get("role"), f"{label}.snapshots[{index}].role")
        if role in snapshots_by_role:
            raise ContractError(f"{label} repeats operational snapshot role {role}")
        snapshots_by_role[role] = snapshot
    old_roles = {
        "old-before-upgrade",
        "old-after-rollback",
        "migration-export",
    }
    recovered_roles = {"candidate", "disaster-recovery-export", "recovered"}
    if set(snapshots_by_role) != old_roles | recovered_roles:
        raise ContractError(f"{label} operational snapshot coverage is incomplete")
    if (
        len(
            {
                (
                    snapshots_by_role[role].get("sha256"),
                    snapshots_by_role[role].get("file_count"),
                    snapshots_by_role[role].get("total_size_bytes"),
                )
                for role in old_roles
            }
        )
        != 1
    ):
        raise ContractError(f"{label} old logical state changed across rollback")
    if (
        len(
            {
                (
                    snapshots_by_role[role].get("sha256"),
                    snapshots_by_role[role].get("file_count"),
                    snapshots_by_role[role].get("total_size_bytes"),
                )
                for role in recovered_roles
            }
        )
        != 1
    ):
        raise ContractError(f"{label} disaster-recovery logical state differs")
    probes = require_array(receipt.get("probes"), f"{label}.probes")
    probe_ids = [
        require_string(
            require_object(probe, f"{label}.probe").get("id"), f"{label}.probe.id"
        )
        for probe in probes
    ]
    if (
        receipt.get("passed") is not True
        or receipt.get("release_ready") is not False
        or receipt.get("network_commands_invoked") is not False
        or receipt.get("network_isolation_enforced") is not False
        or receipt.get("docker_runtime_executed") is not False
        or not probes
        or any(
            not isinstance(probe, dict) or probe.get("status") != "passed"
            for probe in probes
        )
    ):
        raise ContractError(f"{label} is not an all-passing local operational drill")
    if len(probe_ids) != len(set(probe_ids)):
        raise ContractError(f"{label} repeats operational probe IDs")
    missing_probes = sorted(REQUIRED_OPERATIONAL_PROBES - set(probe_ids))
    if missing_probes:
        raise ContractError(f"{label} lacks required probes: {missing_probes}")
    if any(
        isinstance(argument, str)
        and (argument == "--force" or argument.startswith("--force="))
        for probe in probes
        for argument in require_array(
            require_object(probe, f"{label}.probe").get("argv"),
            f"{label}.probe.argv",
        )
    ):
        raise ContractError(f"{label} contains a forbidden --force probe")


def intake_external_receipts(
    subject_root: Path, input_root: Path, receipt_set_path: Path
) -> dict[str, Any]:
    """Validate a digest-pinned external landing zone without copying evidence."""
    _reject_link_chain(subject_root.absolute(), "subject root")
    _reject_link_chain(input_root.absolute(), "external receipt input root")
    subject = subject_root.resolve(strict=True)
    intake_root = input_root.resolve(strict=True)
    if _paths_overlap(subject, intake_root):
        raise ContractError("subject bundle and receipt input roots must be disjoint")

    _reject_link_chain(receipt_set_path, "external receipt set")
    set_path = receipt_set_path.resolve(strict=True)
    try:
        set_relative = set_path.relative_to(intake_root).as_posix()
    except ValueError as error:
        raise ContractError(
            "external receipt set must be under the input root"
        ) from error
    canonical_relative_path(set_relative, "external receipt set path")
    set_bytes = _read_regular_file(
        set_path, "external receipt set", max_bytes=16 * 1024 * 1024
    )
    receipt_set = _decode_json_bytes(set_bytes, "external receipt set")
    _reject_json_secrets(receipt_set, "external receipt set")
    validate_json_contract(receipt_set, "external receipt set")
    if receipt_set.get("schema_version") != "contextdb.release-external-receipt-set/v1":
        raise ContractError("unsupported external receipt set schema")

    manifest_source = require_object(
        receipt_set.get("subject_manifest"), "subject_manifest"
    )
    manifest_relative = canonical_relative_path(
        manifest_source.get("path"), "subject_manifest.path"
    )
    manifest_path = subject.joinpath(*PurePosixPath(manifest_relative).parts)
    manifest_bytes = _read_regular_file(
        manifest_path, "subject artifact manifest", max_bytes=16 * 1024 * 1024
    )
    if sha256_bytes(manifest_bytes) != require_sha256(
        manifest_source.get("sha256"), "subject_manifest.sha256"
    ) or len(manifest_bytes) != manifest_source.get("size_bytes"):
        raise ContractError("subject artifact manifest digest or size mismatch")
    manifest = _decode_json_bytes(manifest_bytes, "subject artifact manifest")
    validate_json_contract(manifest, "subject artifact manifest")
    if manifest.get("schema_version") != "contextdb.release-artifact-manifest/v1":
        raise ContractError("subject is not a release artifact manifest")
    version = require_semver(
        require_object(manifest.get("release"), "manifest.release").get("version"),
        "manifest.release.version",
    )
    if receipt_set.get("release_version") != version:
        raise ContractError("receipt set release version differs from subject manifest")
    source_commit = require_string(
        require_object(manifest.get("source"), "manifest.source").get("git_commit"),
        "manifest.source.git_commit",
    )

    artifacts: dict[str, dict[str, Any]] = {}
    for index, raw_artifact in enumerate(
        require_array(manifest.get("artifacts"), "manifest.artifacts")
    ):
        artifact = require_object(raw_artifact, f"manifest.artifacts[{index}]")
        artifact_id = require_string(artifact.get("id"), f"artifact[{index}].id")
        if artifact_id in artifacts:
            raise ContractError(f"subject manifest repeats artifact ID {artifact_id}")
        artifacts[artifact_id] = artifact

    expected_keys: set[tuple[str, str, str]] = set()
    coverage_values: list[dict[str, Any]] = []
    for index, raw_coverage in enumerate(
        require_array(receipt_set.get("expected_coverage"), "expected_coverage")
    ):
        coverage = require_object(raw_coverage, f"expected_coverage[{index}]")
        artifact_id = require_string(
            coverage.get("artifact_id"), f"expected_coverage[{index}].artifact_id"
        )
        kind = require_string(coverage.get("kind"), f"expected_coverage[{index}].kind")
        platform_id = require_string(
            coverage.get("platform"), f"expected_coverage[{index}].platform"
        )
        if kind not in EXTERNAL_RECEIPT_KINDS:
            raise ContractError(f"unsupported external receipt kind {kind}")
        if artifact_id not in artifacts:
            raise ContractError(
                f"expected coverage names unknown artifact {artifact_id}"
            )
        key = (artifact_id, kind, platform_id)
        if key in expected_keys:
            raise ContractError(f"duplicate expected receipt coverage {key}")
        expected_keys.add(key)
        coverage_values.append(
            {
                "artifact_id": artifact_id,
                "kind": kind,
                "platform": platform_id,
                "complete": True,
            }
        )

    declarations = require_array(receipt_set.get("receipts"), "receipts")
    observed_keys: set[tuple[str, str, str]] = set()
    receipt_ids: set[str] = set()
    receipt_paths: dict[str, str] = {set_relative.casefold(): set_relative}
    entries: list[dict[str, Any]] = []
    declared_inventory = {set_relative}
    verified_artifact_files: set[str] = set()

    def load_companion(raw_source: Any, label: str) -> tuple[dict[str, Any], str]:
        source = require_object(raw_source, label)
        relative = canonical_relative_path(source.get("path"), f"{label}.path")
        folded = relative.casefold()
        if folded in receipt_paths:
            raise ContractError(
                f"receipt path collision: {receipt_paths[folded]} and {relative}"
            )
        receipt_paths[folded] = relative
        declared_inventory.add(relative)
        companion_path = intake_root.joinpath(*PurePosixPath(relative).parts)
        companion_bytes = _read_regular_file(
            companion_path, label, max_bytes=16 * 1024 * 1024
        )
        companion_digest = sha256_bytes(companion_bytes)
        if companion_digest != require_sha256(
            source.get("sha256"), f"{label}.sha256"
        ) or len(companion_bytes) != source.get("size_bytes"):
            raise ContractError(f"{label} digest or size mismatch")
        _reject_private_key_bytes(companion_bytes, label)
        companion = _decode_json_bytes(companion_bytes, label)
        _reject_json_secrets(companion, label)
        validate_json_contract(companion, label)
        return companion, companion_digest

    for index, raw_declaration in enumerate(declarations):
        declaration = require_object(raw_declaration, f"receipts[{index}]")
        receipt_id = require_string(declaration.get("id"), f"receipts[{index}].id")
        if receipt_id in receipt_ids:
            raise ContractError(f"duplicate receipt ID {receipt_id}")
        receipt_ids.add(receipt_id)
        kind = require_string(declaration.get("kind"), f"receipts[{index}].kind")
        artifact_id = require_string(
            declaration.get("artifact_id"), f"receipts[{index}].artifact_id"
        )
        platform_id = require_string(
            declaration.get("platform"), f"receipts[{index}].platform"
        )
        key = (artifact_id, kind, platform_id)
        if key in observed_keys:
            raise ContractError(f"duplicate receipt coverage {key}")
        observed_keys.add(key)
        if artifact_id not in artifacts:
            raise ContractError(
                f"receipt {receipt_id} names unknown artifact {artifact_id}"
            )
        artifact = artifacts[artifact_id]
        if kind in {"install-receipt", "operational-receipt"}:
            if platform_id not in NORMATIVE_PLATFORMS:
                raise ContractError(
                    f"receipt {receipt_id} requires a declared native platform"
                )
            artifact_targets = set(
                require_array(
                    artifact.get("targets"), f"artifact {artifact_id}.targets"
                )
            )
            if platform_id not in artifact_targets and "platform-independent" not in (
                artifact_targets
            ):
                raise ContractError(
                    f"receipt {receipt_id} platform is not supported by the artifact"
                )
        elif platform_id != "platform-independent" and platform_id not in artifact.get(
            "targets", []
        ):
            raise ContractError(
                f"receipt {receipt_id} platform is not bound to the artifact target"
            )
        if kind == "operational-receipt" and (
            artifact.get("package_id") != "contextdb-binary"
            or artifact.get("kind") != "executable"
        ):
            raise ContractError(
                f"operational receipt {receipt_id} must bind a ContextDB binary"
            )
        relative = canonical_relative_path(
            declaration.get("source_path"), f"receipts[{index}].source_path"
        )
        folded = relative.casefold()
        if folded in receipt_paths:
            raise ContractError(
                f"receipt path collision: {receipt_paths[folded]} and {relative}"
            )
        receipt_paths[folded] = relative
        declared_inventory.add(relative)
        path = intake_root.joinpath(*PurePosixPath(relative).parts)
        receipt_bytes = _read_regular_file(
            path, f"external receipt {receipt_id}", max_bytes=256 * 1024 * 1024
        )
        declared_digest = require_sha256(
            declaration.get("sha256"), f"receipts[{index}].sha256"
        )
        if sha256_bytes(receipt_bytes) != declared_digest or len(
            receipt_bytes
        ) != declaration.get("size_bytes"):
            raise ContractError(
                f"external receipt {receipt_id} digest or size mismatch"
            )
        _reject_private_key_bytes(receipt_bytes, f"external receipt {receipt_id}")
        value = _decode_json_bytes(receipt_bytes, f"external receipt {receipt_id}")
        _reject_json_secrets(value, f"external receipt {receipt_id}")
        if artifact_id not in verified_artifact_files:
            artifact_relative = canonical_relative_path(
                artifact.get("path"), f"artifact {artifact_id}.path"
            )
            artifact_path = subject.joinpath(*PurePosixPath(artifact_relative).parts)
            artifact_digest, artifact_size = _digest_regular_file(
                artifact_path, f"artifact {artifact_id}"
            )
            if artifact_digest != require_sha256(
                artifact.get("sha256"), f"artifact {artifact_id}.sha256"
            ) or artifact_size != artifact.get("size_bytes"):
                raise ContractError(f"artifact {artifact_id} digest or size mismatch")
            verified_artifact_files.add(artifact_id)
        if kind == "install-receipt":
            _verify_intake_install_receipt(artifact, value, platform_id, receipt_id)
        elif kind == "publication-receipt":
            _verify_intake_publication_receipt(artifact, value, platform_id, receipt_id)
        elif kind == "operational-receipt":
            operational_inputs = require_object(
                declaration.get("operational_inputs"),
                f"receipts[{index}].operational_inputs",
            )
            operational_plan, operational_plan_digest = load_companion(
                operational_inputs.get("plan"),
                f"receipt {receipt_id} operational plan",
            )
            old_manifest_value, old_manifest_digest = load_companion(
                operational_inputs.get("old_manifest"),
                f"receipt {receipt_id} old artifact manifest",
            )
            if (
                operational_plan.get("schema_version")
                != "contextdb.release-operational-plan/v1"
                or old_manifest_value.get("schema_version")
                != "contextdb.release-artifact-manifest/v1"
            ):
                raise ContractError(
                    f"receipt {receipt_id} has unsupported operational companions"
                )
            _verify_intake_operational_receipt(
                artifact,
                value,
                platform_id,
                manifest,
                sha256_bytes(manifest_bytes),
                operational_plan,
                operational_plan_digest,
                old_manifest_value,
                old_manifest_digest,
                receipt_id,
            )
        elif kind == "sbom":
            BundleVerifier._verify_cyclonedx_value(artifact, value, receipt_id)
        elif kind == "provenance-attestation":
            BundleVerifier._verify_slsa_provenance_value(artifact, value, receipt_id)
        else:
            raise ContractError(f"unsupported external receipt kind {kind}")
        entries.append(
            {
                "id": receipt_id,
                "kind": kind,
                "source_path": relative,
                "sha256": declared_digest,
                "size_bytes": len(receipt_bytes),
                "artifact_id": artifact_id,
                "platform": platform_id,
                "status": "accepted",
            }
        )

    if observed_keys != expected_keys:
        missing = sorted(expected_keys - observed_keys)
        extra = sorted(observed_keys - expected_keys)
        raise ContractError(
            f"external receipt coverage mismatch; missing={missing}; extra={extra}"
        )

    observed_inventory: set[str] = set()
    for path in intake_root.rglob("*"):
        if _is_link_like(path):
            raise ContractError(f"external receipt input contains a link: {path}")
        if path.is_file():
            observed_inventory.add(path.relative_to(intake_root).as_posix())
    if observed_inventory != declared_inventory:
        raise ContractError(
            "external receipt input inventory is not exhaustive; "
            f"undeclared={sorted(observed_inventory - declared_inventory)}; "
            f"missing={sorted(declared_inventory - observed_inventory)}"
        )

    entries.sort(key=lambda value: value["id"].encode("utf-8"))
    coverage_values.sort(
        key=lambda value: (
            value["artifact_id"].encode("utf-8"),
            value["kind"].encode("utf-8"),
            value["platform"].encode("utf-8"),
        )
    )
    result = {
        "schema_version": "contextdb.release-external-receipt-intake/v1",
        "tool_version": RELEASE_TOOL_VERSION,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "release_version": version,
        "subject_manifest": {
            "path": manifest_relative,
            "sha256": sha256_bytes(manifest_bytes),
            "size_bytes": len(manifest_bytes),
            "source_commit": source_commit,
        },
        "receipt_set": {
            "sha256": sha256_bytes(set_bytes),
            "size_bytes": len(set_bytes),
        },
        "entries": entries,
        "coverage": coverage_values,
        "checks": [
            {
                "id": "digest-pinned-inputs",
                "status": "passed",
                "detail": f"validated {len(entries)} immutable receipt inputs",
            },
            {
                "id": "exact-coverage",
                "status": "passed",
                "detail": "receipt coverage exactly matches the declared expectation set",
            },
            {
                "id": "subject-bindings",
                "status": "passed",
                "detail": "every receipt binds an exact manifest artifact and platform",
            },
            {
                "id": "quarantine-inventory",
                "status": "passed",
                "detail": "input root contains no undeclared files, links, or secret material",
            },
        ],
        "accepted": True,
        "release_ready": False,
        "evidence_boundary": {
            "network_accessed": False,
            "runtime_executed": False,
            "files_copied": False,
            "signatures_created": False,
            "live_publication_retrieval_performed": False,
            "release_readiness_decided_by_intake": False,
        },
    }
    validate_json_contract(result, "external receipt intake")
    return result


def _copy_operational_bundle(source: Path, destination: Path, label: str) -> None:
    _reject_link_chain(source.absolute(), label)
    resolved = source.resolve(strict=True)
    if not resolved.is_dir():
        raise ContractError(f"{label} must be a directory")
    for path in resolved.rglob("*"):
        if _is_link_like(path):
            raise ContractError(f"{label} contains a link or junction: {path}")
    shutil.copytree(resolved, destination)


def _load_operational_subject(
    bundle_root: Path,
    raw_subject: Any,
    host_target: str,
    profile: str,
    trusted_keys: dict[str, Path],
    allow_test_keys: bool,
    label: str,
) -> tuple[dict[str, Any], dict[str, Any], Path, dict[str, Any]]:
    subject = require_object(raw_subject, label)
    manifest_relative = canonical_relative_path(
        subject.get("manifest_path"), f"{label}.manifest_path"
    )
    manifest_path = bundle_root.joinpath(*PurePosixPath(manifest_relative).parts)
    manifest_bytes = _read_regular_file(
        manifest_path, f"{label} artifact manifest", max_bytes=16 * 1024 * 1024
    )
    expected_manifest_digest = require_sha256(
        subject.get("manifest_sha256"), f"{label}.manifest_sha256"
    )
    if sha256_bytes(manifest_bytes) != expected_manifest_digest:
        raise ContractError(f"{label} artifact manifest digest mismatch")
    manifest = _decode_json_bytes(manifest_bytes, f"{label} artifact manifest")
    validate_json_contract(manifest, f"{label} artifact manifest")
    version = require_semver(
        require_object(manifest.get("release"), f"{label}.manifest.release").get(
            "version"
        ),
        f"{label}.manifest.release.version",
    )
    if version != subject.get("version"):
        raise ContractError(f"{label} release version differs from the drill plan")

    artifact_id = require_string(
        subject.get("binary_artifact_id"), f"{label}.binary_artifact_id"
    )
    matches = [
        require_object(value, f"{label}.manifest artifact")
        for value in require_array(
            manifest.get("artifacts"), f"{label}.manifest.artifacts"
        )
        if isinstance(value, dict) and value.get("id") == artifact_id
    ]
    if len(matches) != 1:
        raise ContractError(
            f"{label} must contain exactly one binary artifact {artifact_id}"
        )
    artifact = matches[0]
    if (
        artifact.get("package_id") != "contextdb-binary"
        or artifact.get("kind") != "executable"
        or host_target not in artifact.get("targets", [])
    ):
        raise ContractError(
            f"{label} artifact {artifact_id} is not a ContextDB binary for {host_target}"
        )
    binary_relative = canonical_relative_path(
        artifact.get("path"), f"{label}.artifact.path"
    )
    binary = bundle_root.joinpath(*PurePosixPath(binary_relative).parts)
    binary_digest, binary_size = _digest_regular_file(binary, f"{label} binary")
    if binary_digest != require_sha256(
        artifact.get("sha256"), f"{label}.artifact.sha256"
    ) or binary_size != artifact.get("size_bytes"):
        raise ContractError(f"{label} binary digest or size mismatch")

    verification = BundleVerifier(
        bundle_root,
        manifest_relative,
        profile,
        trusted_keys,
        allow_test_keys,
    ).verify()
    if verification.get("contract_valid") is not True:
        raise ContractError(f"{label} bundle failed contract verification")
    return manifest, artifact, binary, verification


def _load_operational_seed(
    bundle_root: Path,
    manifest: dict[str, Any],
    raw_seed: Any,
) -> tuple[dict[str, Any], Path, int]:
    seed = require_object(raw_seed, "seed_artifact")
    artifact_id = require_string(seed.get("artifact_id"), "seed_artifact.artifact_id")
    matches = [
        require_object(value, "seed artifact")
        for value in require_array(manifest.get("artifacts"), "seed manifest artifacts")
        if isinstance(value, dict) and value.get("id") == artifact_id
    ]
    if len(matches) != 1:
        raise ContractError(
            f"seed bundle must contain exactly one artifact {artifact_id}"
        )
    artifact = matches[0]
    if (
        artifact.get("package_id") != "portable-example-database"
        or artifact.get("kind") != "example-database"
        or artifact.get("targets") != ["platform-independent"]
    ):
        raise ContractError("operational seed must be the portable example database")
    relative = canonical_relative_path(artifact.get("path"), "seed artifact path")
    path = bundle_root.joinpath(*PurePosixPath(relative).parts)
    observed_digest, observed_size = _digest_regular_file(path, "seed artifact")
    artifact_digest = require_sha256(artifact.get("sha256"), "seed artifact sha256")
    if (
        observed_digest != artifact_digest
        or observed_size != artifact.get("size_bytes")
        or observed_digest != seed.get("sha256")
        or observed_size != seed.get("size_bytes")
    ):
        raise ContractError("operational seed digest or size does not match the plan")
    minimum_commit_seq = seed.get("minimum_commit_seq")
    if not isinstance(minimum_commit_seq, int) or minimum_commit_seq < 1:
        raise ContractError("operational seed must require a non-empty commit sequence")
    return artifact, path, minimum_commit_seq


def _snapshot_operational_state(path: Path, role: str) -> dict[str, Any]:
    members: list[tuple[str, Path]] = []
    if path.is_file():
        members.append(("archive", path))
    store = Path(f"{path}.fjall")
    if store.is_dir():
        for member in store.rglob("*"):
            if _is_link_like(member):
                raise ContractError(f"operational state contains a link: {member}")
            if member.is_file():
                relative = member.relative_to(store).as_posix()
                members.append((f"store/{relative}", member))
    if not members:
        raise ContractError(f"operational state is absent for snapshot {role}")
    members.sort(key=lambda value: value[0].encode("utf-8"))
    tree_lines: list[str] = []
    total_size = 0
    for relative, member in members:
        digest, size = _digest_regular_file(member, f"operational snapshot {role}")
        total_size += size
        tree_lines.append(f"{digest} {size} {relative}\n")
    return {
        "role": role,
        "sha256": sha256_bytes("".join(tree_lines).encode("utf-8")),
        "file_count": len(members),
        "total_size_bytes": total_size,
    }


def _record_operational_activation(
    marker: Path,
    slot: str,
    state_digest: str,
    probes: list[dict[str, Any]],
    sequence: list[str],
) -> bool:
    identifier = f"activate-{slot}-{len(sequence) + 1}"
    try:
        _write_json_atomic(marker, {"slot": slot, "state_sha256": state_digest})
        observed = load_json(marker)
        passed = observed == {"slot": slot, "state_sha256": state_digest}
    except (ContractError, OSError) as error:
        probes.append(
            {
                "id": identifier,
                "status": "failed",
                "evidence_level": "runtime",
                "argv": ["atomic-activate", slot],
                "detail": str(error),
            }
        )
        return False
    probes.append(
        {
            "id": identifier,
            "status": "passed" if passed else "failed",
            "evidence_level": "runtime",
            "argv": ["atomic-activate", slot],
            "detail": (
                "isolated supervisor marker atomically selected the declared state digest"
                if passed
                else "isolated supervisor marker did not preserve the declared state digest"
            ),
        }
    )
    if passed:
        sequence.append(slot)
    return passed


def run_operational_drill(
    old_bundle_root: Path,
    new_bundle_root: Path,
    plan_path: Path,
    profile: str,
    trusted_keys: dict[str, Path],
    allow_test_keys: bool,
) -> dict[str, Any]:
    """Exercise upgrade, rollback, and DR with a disposable activation marker."""
    plan_bytes = _read_regular_file(
        plan_path, "operational drill plan", max_bytes=16 * 1024 * 1024
    )
    plan = _decode_json_bytes(plan_bytes, "operational drill plan")
    _reject_json_secrets(plan, "operational drill plan")
    validate_json_contract(plan, "operational drill plan")
    if plan.get("schema_version") != "contextdb.release-operational-plan/v1":
        raise ContractError("unsupported operational drill plan schema")
    if plan.get("profile") != profile:
        raise ContractError("operational plan profile differs from command profile")
    host_target = _host_target()
    if plan.get("host_target") != host_target:
        raise ContractError(
            f"operational plan targets {plan.get('host_target')}, host is {host_target}"
        )
    scenarios = require_array(plan.get("scenarios"), "operational plan scenarios")
    required_scenarios = {
        "side-by-side-upgrade",
        "explicit-rollback",
        "disaster-recovery",
    }
    if set(scenarios) != required_scenarios or len(scenarios) != 3:
        raise ContractError("operational plan must request all three release scenarios")
    old_spec = require_object(plan.get("old_release"), "old_release")
    new_spec = require_object(plan.get("new_release"), "new_release")
    old_version = require_semver(old_spec.get("version"), "old_release.version")
    new_version = require_semver(new_spec.get("version"), "new_release.version")
    require_semver_upgrade(old_version, new_version, "operational upgrade")
    old_source = old_bundle_root.resolve(strict=True)
    new_source = new_bundle_root.resolve(strict=True)
    if _paths_overlap(old_source, new_source):
        raise ContractError("old and new release bundle roots must be disjoint")

    with tempfile.TemporaryDirectory(prefix="contextdb-operational-drill-") as value:
        work = Path(value)
        old_bundle = work / "old-bundle"
        new_bundle = work / "new-bundle"
        _copy_operational_bundle(old_source, old_bundle, "old release bundle")
        _copy_operational_bundle(new_source, new_bundle, "new release bundle")
        old_manifest, old_artifact, old_binary, old_verification = (
            _load_operational_subject(
                old_bundle,
                old_spec,
                host_target,
                profile,
                trusted_keys,
                allow_test_keys,
                "old release",
            )
        )
        new_manifest, new_artifact, new_binary, new_verification = (
            _load_operational_subject(
                new_bundle,
                new_spec,
                host_target,
                profile,
                trusted_keys,
                allow_test_keys,
                "new release",
            )
        )
        seed_spec = require_object(plan.get("seed_artifact"), "seed_artifact")
        seed_bundle_id = require_string(seed_spec.get("bundle"), "seed_artifact.bundle")
        if seed_bundle_id == "old":
            seed_bundle, seed_manifest = old_bundle, old_manifest
        elif seed_bundle_id == "new":
            seed_bundle, seed_manifest = new_bundle, new_manifest
        else:
            raise ContractError("operational seed bundle must be old or new")
        seed_artifact, seed_package, minimum_seed_commit_seq = _load_operational_seed(
            seed_bundle, seed_manifest, seed_spec
        )
        seed_archive = _extract_portable_example(seed_package, work / "seed")

        states = work / "states"
        states.mkdir()
        marker = work / "active-slot.json"
        old_state = states / "old.ctxb"
        migration_export = states / "migration-input.ctxb"
        rollback_export = states / "rollback-check.ctxb"
        candidate_state = states / "candidate.ctxb"
        candidate_activation_export = states / "candidate-activation.ctxb"
        recovery_export = states / "disaster-recovery-input.ctxb"
        recovered_state = states / "recovered.ctxb"
        recovered_export = states / "recovered-check.ctxb"
        probes: list[dict[str, Any]] = []
        snapshots: list[dict[str, Any]] = []
        activation_sequence: list[str] = []

        probe_environment = {"PATH": os.environ.get("PATH", "")}
        for name in (
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "TMP",
            "TEMP",
            "LOCALAPPDATA",
        ):
            if value := os.environ.get(name):
                probe_environment[name] = value
        probe_environment["CONTEXTDB_TOKEN_KEY_HEX"] = os.urandom(32).hex()
        authority_directory: tempfile.TemporaryDirectory[str] | None = None
        windows_authority_digests: list[str] = []

        def authority_environment(slot: str) -> dict[str, str]:
            nonlocal authority_directory
            environment = probe_environment.copy()
            if host_target == "windows-x86-64":
                authority_id = f"contextdb-operational-{slot}-{os.urandom(16).hex()}"
                windows_authority_digests.append(
                    _windows_state_head_digest(authority_id)
                )
                environment["CONTEXTDB_STATE_HEAD_ID"] = authority_id
                return environment
            if host_target in {"linux-x86-64", "linux-arm64", "macos-arm64"}:
                if authority_directory is None:
                    authority_directory = tempfile.TemporaryDirectory(
                        prefix="contextdb-operational-authority-"
                    )
                    os.chmod(authority_directory.name, 0o700)
                environment["CONTEXTDB_STATE_HEAD_FILE"] = str(
                    Path(authority_directory.name) / f"{slot}.json"
                )
                return environment
            raise ContractError(f"unsupported operational host target {host_target}")

        try:
            old_environment = authority_environment("old")
            candidate_environment = authority_environment("candidate")
            recovered_environment = authority_environment("recovered")
        except (ContractError, OSError) as error:
            if not _finish_probe_authority_custody(
                host_target,
                authority_directory,
                windows_authority_digests,
                probe_environment,
            ):
                raise ContractError(
                    "operational authority selection and cleanup both failed"
                ) from error
            raise

        def run(
            binary: Path,
            identifier: str,
            arguments: list[str],
            environment: dict[str, str],
            expected_first_stdout_line: str | None = None,
            expected_json_minimums: dict[str, int] | None = None,
        ) -> bool:
            return _run_contextdb_probe_command(
                binary,
                states,
                probes,
                identifier,
                arguments,
                environment,
                expected_first_stdout_line,
                expected_json_minimums,
            )

        def custody(
            identifier: str, archive: Path, environment: dict[str, str]
        ) -> bool:
            return _check_probe_custody_boundary(
                probes, identifier, archive, environment, host_target
            )

        def snapshot(path: Path, role: str) -> dict[str, Any] | None:
            try:
                value = _snapshot_operational_state(path, role)
            except (ContractError, OSError) as error:
                probes.append(
                    {
                        "id": f"snapshot-{role}",
                        "status": "failed",
                        "evidence_level": "runtime",
                        "argv": ["snapshot-state", role],
                        "detail": str(error),
                    }
                )
                return None
            snapshots.append(value)
            probes.append(
                {
                    "id": f"snapshot-{role}",
                    "status": "passed",
                    "evidence_level": "runtime",
                    "argv": ["snapshot-state", role],
                    "detail": "content-free deterministic state digest recorded",
                }
            )
            return value

        recovery_ok = False
        try:
            old_ok = run(
                old_binary,
                "old-version",
                ["version"],
                old_environment,
                f"contextdb {old_spec['version']}",
            )
            old_ok = old_ok and run(
                old_binary,
                "old-import-seed",
                ["--json", "import", str(old_state), str(seed_archive)],
                old_environment,
            )
            old_ok = old_ok and custody(
                "old-seed-import-custody", old_state, old_environment
            )
            old_ok = old_ok and run(
                old_binary,
                "old-seed-status",
                ["--json", "status", str(old_state)],
                old_environment,
                expected_json_minimums={"commit_seq": minimum_seed_commit_seq},
            )
            old_ok = old_ok and run(
                old_binary,
                "old-doctor",
                ["--json", "doctor", str(old_state)],
                old_environment,
            )
            old_ok = old_ok and run(
                old_binary,
                "old-export-for-upgrade",
                ["--json", "export", str(old_state), str(migration_export)],
                old_environment,
            )
            old_ok = old_ok and custody(
                "upgrade-export-custody", migration_export, old_environment
            )
            old_before = (
                snapshot(migration_export, "old-before-upgrade") if old_ok else None
            )
            migration_snapshot = (
                snapshot(migration_export, "migration-export") if old_ok else None
            )
            old_ok = bool(old_ok and old_before and migration_snapshot)
            if old_ok:
                old_ok = _record_operational_activation(
                    marker,
                    "old",
                    old_before["sha256"],
                    probes,
                    activation_sequence,
                )

            candidate_ok = old_ok and run(
                new_binary,
                "new-version",
                ["version"],
                candidate_environment,
                f"contextdb {new_spec['version']}",
            )
            candidate_ok = candidate_ok and run(
                new_binary,
                "candidate-import",
                ["--json", "import", str(candidate_state), str(migration_export)],
                candidate_environment,
            )
            candidate_ok = candidate_ok and custody(
                "candidate-import-custody", candidate_state, candidate_environment
            )
            candidate_ok = candidate_ok and run(
                new_binary,
                "candidate-doctor",
                ["--json", "doctor", str(candidate_state)],
                candidate_environment,
            )
            candidate_ok = candidate_ok and run(
                new_binary,
                "candidate-export-for-activation",
                [
                    "--json",
                    "export",
                    str(candidate_state),
                    str(candidate_activation_export),
                ],
                candidate_environment,
            )
            candidate_ok = candidate_ok and custody(
                "candidate-activation-export-custody",
                candidate_activation_export,
                candidate_environment,
            )
            candidate_snapshot = (
                snapshot(candidate_activation_export, "candidate")
                if candidate_ok
                else None
            )
            candidate_ok = bool(candidate_ok and candidate_snapshot)
            if candidate_ok:
                candidate_ok = _record_operational_activation(
                    marker,
                    "candidate",
                    candidate_snapshot["sha256"],
                    probes,
                    activation_sequence,
                )

            rollback_ok = candidate_ok and _record_operational_activation(
                marker,
                "old",
                old_before["sha256"] if old_before else "0" * 64,
                probes,
                activation_sequence,
            )
            rollback_ok = rollback_ok and run(
                old_binary,
                "rollback-old-doctor",
                ["--json", "doctor", str(old_state)],
                old_environment,
            )
            rollback_ok = rollback_ok and run(
                old_binary,
                "rollback-old-export",
                ["--json", "export", str(old_state), str(rollback_export)],
                old_environment,
            )
            rollback_ok = rollback_ok and custody(
                "rollback-export-custody", rollback_export, old_environment
            )
            old_after = (
                snapshot(rollback_export, "old-after-rollback") if rollback_ok else None
            )
            if rollback_ok and old_before and old_after:
                unchanged = old_before["sha256"] == old_after["sha256"]
                probes.append(
                    {
                        "id": "rollback-logical-state-unchanged",
                        "status": "passed" if unchanged else "failed",
                        "evidence_level": "runtime",
                        "argv": ["compare-logical-export-digests"],
                        "detail": (
                            "old release logical state remained byte-identical across candidate activation and rollback"
                            if unchanged
                            else "old release logical state changed during the rollback drill"
                        ),
                    }
                )
                rollback_ok = unchanged
            else:
                rollback_ok = False

            recovery_ok = rollback_ok and run(
                new_binary,
                "candidate-export-for-dr",
                ["--json", "export", str(candidate_state), str(recovery_export)],
                candidate_environment,
            )
            recovery_ok = recovery_ok and custody(
                "dr-export-custody", recovery_export, candidate_environment
            )
            recovery_snapshot = (
                snapshot(recovery_export, "disaster-recovery-export")
                if recovery_ok
                else None
            )
            recovery_ok = bool(recovery_ok and recovery_snapshot)
            recovery_ok = recovery_ok and run(
                new_binary,
                "recovered-import",
                ["--json", "import", str(recovered_state), str(recovery_export)],
                recovered_environment,
            )
            recovery_ok = recovery_ok and custody(
                "recovered-import-custody", recovered_state, recovered_environment
            )
            recovery_ok = recovery_ok and run(
                new_binary,
                "recovered-doctor",
                ["--json", "doctor", str(recovered_state)],
                recovered_environment,
            )
            recovery_ok = recovery_ok and run(
                new_binary,
                "recovered-export-for-activation",
                [
                    "--json",
                    "export",
                    str(recovered_state),
                    str(recovered_export),
                ],
                recovered_environment,
            )
            recovery_ok = recovery_ok and custody(
                "recovered-export-custody", recovered_export, recovered_environment
            )
            recovered_snapshot = (
                snapshot(recovered_export, "recovered") if recovery_ok else None
            )
            recovery_ok = bool(recovery_ok and recovered_snapshot)
            if (
                recovery_ok
                and candidate_snapshot
                and recovery_snapshot
                and recovered_snapshot
            ):
                identical = (
                    candidate_snapshot["sha256"]
                    == recovery_snapshot["sha256"]
                    == recovered_snapshot["sha256"]
                )
                probes.append(
                    {
                        "id": "disaster-recovery-logical-state-identity",
                        "status": "passed" if identical else "failed",
                        "evidence_level": "runtime",
                        "argv": ["compare-candidate-dr-recovered-export-digests"],
                        "detail": (
                            "candidate, DR input, and recovered logical exports are byte-identical"
                            if identical
                            else "recovered logical state differs from the candidate DR source"
                        ),
                    }
                )
                recovery_ok = identical
            if recovery_ok:
                recovery_ok = _record_operational_activation(
                    marker,
                    "recovered",
                    recovered_snapshot["sha256"],
                    probes,
                    activation_sequence,
                )
        finally:
            custody_cleaned = _finish_probe_authority_custody(
                host_target,
                authority_directory,
                windows_authority_digests,
                probe_environment,
            )
            probes.append(
                {
                    "id": "operational-authority-cleanup",
                    "status": "passed" if custody_cleaned else "failed",
                    "evidence_level": "runtime",
                    "argv": ["cleanup-owned-operational-authorities"],
                    "detail": (
                        "exact drill-owned external authorities and locks removed"
                        if custody_cleaned
                        else "drill-owned external authority cleanup failed"
                    ),
                }
            )

        passed = bool(
            recovery_ok
            and activation_sequence == ["old", "candidate", "old", "recovered"]
            and len(snapshots) == 6
            and all(probe.get("status") == "passed" for probe in probes)
        )
        result = {
            "schema_version": "contextdb.release-operational-receipt/v1",
            "tool_version": RELEASE_TOOL_VERSION,
            "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "drill_id": plan["drill_id"],
            "plan_sha256": sha256_bytes(plan_bytes),
            "host_target": host_target,
            "profile": profile,
            "isolated_copy": True,
            "old_artifact": BundleVerifier._artifact_subject(old_artifact),
            "new_artifact": BundleVerifier._artifact_subject(new_artifact),
            "seed_artifact": BundleVerifier._artifact_subject(seed_artifact),
            "minimum_seed_commit_seq": minimum_seed_commit_seq,
            "bundle_verifications": {
                "old": {
                    "manifest_sha256": old_spec["manifest_sha256"],
                    "contract_valid": True,
                    "release_ready": bool(old_verification["release_ready"]),
                },
                "new": {
                    "manifest_sha256": new_spec["manifest_sha256"],
                    "contract_valid": True,
                    "release_ready": bool(new_verification["release_ready"]),
                },
            },
            "scenarios": scenarios,
            "activation_sequence": activation_sequence,
            "state_snapshots": snapshots,
            "probes": probes,
            "passed": passed,
            "release_ready": False,
            "network_commands_invoked": False,
            "network_isolation_enforced": False,
            "docker_runtime_executed": False,
        }
        validate_json_contract(result, "operational drill receipt")
        return result


def run_clean_install(
    bundle_root: Path,
    manifest_path: str,
    profile: str,
    trusted_keys: dict[str, Path],
    allow_test_keys: bool,
) -> dict[str, Any]:
    source = bundle_root.resolve(strict=True)
    for path in source.rglob("*"):
        if _is_link_like(path):
            raise ContractError(f"bundle contains a link or junction: {path}")
    with tempfile.TemporaryDirectory(
        prefix="contextdb-clean-install-"
    ) as temporary_value:
        isolated = Path(temporary_value) / "bundle"
        shutil.copytree(source, isolated)
        verifier = BundleVerifier(
            isolated, manifest_path, profile, trusted_keys, allow_test_keys
        )
        verification = verifier.verify()
        probes: list[dict[str, Any]] = []
        subject_artifacts: list[dict[str, str]] = []
        if verification["contract_valid"]:
            manifest = load_json(isolated.joinpath(*PurePosixPath(manifest_path).parts))
            binaries = [
                artifact
                for artifact in manifest.get("artifacts", [])
                if artifact.get("package_id") == "contextdb-binary"
                and _host_target() in artifact.get("targets", [])
            ]
            if binaries:
                binary = isolated.joinpath(*PurePosixPath(binaries[0]["path"]).parts)
                probes.extend(_probe_contextdb_binary(binary, isolated, manifest))
                subject_artifacts.append(BundleVerifier._artifact_subject(binaries[0]))
            else:
                probes.append(
                    {
                        "id": "contextdb-binary-host",
                        "status": "not-run",
                        "evidence_level": "runtime",
                        "argv": [],
                        "detail": f"no artifact for host target {_host_target()}",
                    }
                )
            examples = [
                artifact
                for artifact in manifest.get("artifacts", [])
                if artifact.get("package_id") == "portable-example-database"
            ]
            if examples and any(
                probe["id"] == "contextdb-doctor-imported"
                and probe["status"] == "passed"
                for probe in probes
            ):
                subject_artifacts.append(BundleVerifier._artifact_subject(examples[0]))
        passed = (
            verification["contract_valid"]
            and bool(probes)
            and all(probe["status"] == "passed" for probe in probes)
        )
        return {
            "schema_version": "contextdb.clean-install-receipt/v1",
            "verifier_version": RELEASE_TOOL_VERSION,
            "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "profile": profile,
            "host_target": _host_target(),
            "isolated_copy": True,
            "verification": verification,
            "subject_artifacts": subject_artifacts,
            "probes": probes,
            "passed": passed,
            "release_ready": bool(verification["release_ready"] and passed),
            "docker_runtime_executed": False,
        }


def _windows_state_head_digest(authority_id: str) -> str:
    try:
        import blake3
    except ImportError as error:
        raise ContractError(
            "the blake3 package is required before a Windows state-head probe can start"
        ) from error
    return blake3.blake3(authority_id.encode("utf-8")).hexdigest()


def _cleanup_windows_probe_authorities(
    authority_digests: Iterable[str], local_app_data: str
) -> bool:
    """Delete only exact registry/lock objects derived from verifier-owned IDs."""
    import winreg

    succeeded = True
    lock_directory = Path(local_app_data) / "ContextDB" / "authority-locks"
    for digest in authority_digests:
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            succeeded = False
            continue
        subkey = f"Software\\ContextDB\\StateHeads\\{digest}"
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)
        except FileNotFoundError:
            pass
        except OSError:
            succeeded = False
        try:
            (lock_directory / f"{digest}.lock").unlink()
        except FileNotFoundError:
            pass
        except OSError:
            succeeded = False
    return succeeded


def _finish_probe_authority_custody(
    host_target: str,
    authority_directory: tempfile.TemporaryDirectory[str] | None,
    windows_authority_digests: list[str],
    environment: dict[str, str],
) -> bool:
    if host_target == "windows-x86-64":
        local_app_data = environment.get("LOCALAPPDATA")
        if not local_app_data:
            return False
        try:
            return _cleanup_windows_probe_authorities(
                windows_authority_digests, local_app_data
            )
        except (ImportError, OSError):
            return False
    if authority_directory is None:
        return True
    try:
        authority_directory.cleanup()
    except OSError:
        return False
    return True


def _run_contextdb_probe_command(
    binary: Path,
    isolated: Path,
    probes: list[dict[str, Any]],
    identifier: str,
    arguments: list[str],
    environment: dict[str, str],
    expected_first_stdout_line: str | None = None,
    expected_json_minimums: dict[str, int] | None = None,
) -> bool:
    recorded_argv = [binary.name, *arguments]
    try:
        completed = subprocess.run(
            [str(binary), *arguments],
            cwd=isolated,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
            check=False,
            env=environment,
        )
        passed = completed.returncode == 0
        output_contract_valid = True
        if expected_first_stdout_line is not None:
            try:
                first_line = completed.stdout.decode("utf-8").splitlines()[0]
            except (UnicodeDecodeError, IndexError):
                output_contract_valid = False
            else:
                output_contract_valid = first_line == expected_first_stdout_line
            passed = passed and output_contract_valid
        if expected_json_minimums is not None:
            try:
                output_value = _decode_json_bytes(
                    completed.stdout, f"{identifier} stdout"
                )
            except ContractError:
                output_contract_valid = False
            else:
                output_contract_valid = all(
                    isinstance(output_value.get(key), int)
                    and output_value[key] >= minimum
                    for key, minimum in expected_json_minimums.items()
                )
            passed = passed and output_contract_valid
        detail = None
        if completed.returncode == 0 and not output_contract_valid:
            detail = "command output does not match the declared probe contract"
        probes.append(
            {
                "id": identifier,
                "status": "passed" if passed else "failed",
                "evidence_level": "runtime",
                "argv": recorded_argv,
                "exit_code": completed.returncode,
                "stdout_sha256": sha256_bytes(completed.stdout),
                "stderr_sha256": sha256_bytes(completed.stderr),
                **({"detail": detail} if detail is not None else {}),
            }
        )
        return passed
    except (OSError, subprocess.SubprocessError) as error:
        probes.append(
            {
                "id": identifier,
                "status": "failed",
                "evidence_level": "runtime",
                "argv": recorded_argv,
                "detail": str(error),
            }
        )
        return False


def _check_probe_custody_boundary(
    probes: list[dict[str, Any]],
    identifier: str,
    archive: Path,
    environment: dict[str, str],
    host_target: str,
) -> bool:
    forbidden: list[Path] = []
    try:
        for candidate in archive.parent.iterdir():
            lowered = candidate.name.lower()
            if candidate.is_file() and (
                lowered.endswith((".key", ".pem", ".p12", ".pfx"))
                or "state-head" in lowered
                or "state_head" in lowered
            ):
                forbidden.append(candidate)
    except OSError:
        forbidden.append(archive.parent / "[unreadable]")

    token_contract_valid = (
        "CONTEXTDB_TOKEN_KEY_HEX" in environment
        and "CONTEXTDB_TOKEN_KEY_FILE" not in environment
    )
    if host_target == "windows-x86-64":
        authority_contract_valid = (
            bool(environment.get("CONTEXTDB_STATE_HEAD_ID"))
            and "CONTEXTDB_STATE_HEAD_FILE" not in environment
        )
    else:
        authority_value = environment.get("CONTEXTDB_STATE_HEAD_FILE")
        authority_path = Path(authority_value) if authority_value else None
        try:
            authority_external = bool(
                authority_path
                and not authority_path.resolve().is_relative_to(
                    archive.parent.resolve()
                )
            )
        except OSError:
            authority_external = False
        authority_contract_valid = bool(
            authority_path
            and authority_external
            and authority_path.is_file()
            and "CONTEXTDB_STATE_HEAD_ID" not in environment
        )
    passed = token_contract_valid and authority_contract_valid and not forbidden
    probes.append(
        {
            "id": identifier,
            "status": "passed" if passed else "failed",
            "evidence_level": "runtime",
            "argv": ["assert-external-custody", archive.name],
            "detail": (
                "one ephemeral token-key source and one platform authority selected; no key or state-head sidecar in the archive directory"
                if passed
                else "external token-key/state-head custody contract failed or forbidden sidecar material appeared"
            ),
        }
    )
    return passed


def _exercise_contextdb_binary(
    binary: Path,
    isolated: Path,
    manifest: dict[str, Any],
    expected_version: str,
    host_target: str,
    state_environment: dict[str, str],
    import_environment: dict[str, str],
    probes: list[dict[str, Any]],
) -> None:
    def run(
        identifier: str,
        arguments: list[str],
        environment: dict[str, str],
        expected_first_stdout_line: str | None = None,
    ) -> bool:
        return _run_contextdb_probe_command(
            binary,
            isolated,
            probes,
            identifier,
            arguments,
            environment,
            expected_first_stdout_line,
        )

    if not run(
        "contextdb-version",
        ["version"],
        state_environment,
        f"contextdb {expected_version}",
    ):
        return
    state = isolated / "clean-install" / "state.ctxb"
    initialized = run(
        "contextdb-init", ["--json", "init", str(state)], state_environment
    )
    custody_valid = initialized and _check_probe_custody_boundary(
        probes,
        "contextdb-init-key-boundary",
        state,
        state_environment,
        host_target,
    )
    if custody_valid:
        healthy = run(
            "contextdb-doctor",
            ["--json", "doctor", str(state)],
            state_environment,
        )
        exported = isolated / "clean-install" / "exported.ctxb"
        if healthy and run(
            "contextdb-export",
            ["--json", "export", str(state), str(exported)],
            state_environment,
        ):
            _check_probe_custody_boundary(
                probes,
                "contextdb-export-key-boundary",
                exported,
                state_environment,
                host_target,
            )
    examples = [
        artifact
        for artifact in manifest.get("artifacts", [])
        if artifact.get("package_id") == "portable-example-database"
    ]
    if not examples:
        return
    example = isolated.joinpath(*PurePosixPath(examples[0]["path"]).parts)
    destination = isolated / "clean-install" / "imported.ctxb"
    try:
        logical_archive = _extract_portable_example(example, isolated)
    except ContractError as error:
        probes.append(
            {
                "id": "portable-example-extract",
                "status": "failed",
                "evidence_level": "runtime",
                "argv": ["extract-portable-example", example.name],
                "detail": str(error),
            }
        )
        return
    imported = run(
        "contextdb-import-example",
        ["--json", "import", str(destination), str(logical_archive)],
        import_environment,
    )
    import_custody_valid = imported and _check_probe_custody_boundary(
        probes,
        "contextdb-import-key-boundary",
        destination,
        import_environment,
        host_target,
    )
    if import_custody_valid:
        run(
            "contextdb-doctor-imported",
            ["--json", "doctor", str(destination)],
            import_environment,
        )


def _probe_contextdb_binary(
    binary: Path, isolated: Path, manifest: dict[str, Any]
) -> list[dict[str, Any]]:
    probes: list[dict[str, Any]] = []
    release = require_object(manifest.get("release"), "manifest.release")
    expected_version = require_semver(
        release.get("version"), "manifest.release.version"
    )
    probe_environment = {"PATH": os.environ.get("PATH", "")}
    for name in (
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TMP",
        "TEMP",
        "LOCALAPPDATA",
    ):
        if value := os.environ.get(name):
            probe_environment[name] = value
    # This secret exists only for the lifetime of the isolated probe and is never
    # written to the receipt. The CLI must not persist a key or state-head
    # authority in the archive directory.
    probe_environment["CONTEXTDB_TOKEN_KEY_HEX"] = os.urandom(32).hex()
    host_target = _host_target()
    authority_directory: tempfile.TemporaryDirectory[str] | None = None
    windows_authority_digests: list[str] = []

    def authority_environment(slot: str) -> dict[str, str]:
        nonlocal authority_directory
        environment = probe_environment.copy()
        if host_target == "windows-x86-64":
            # The ID is deliberately neither accepted as input nor copied into
            # the receipt. Each destination gets an independent HKCU authority.
            authority_id = f"contextdb-release-probe-{slot}-{os.urandom(16).hex()}"
            windows_authority_digests.append(_windows_state_head_digest(authority_id))
            environment["CONTEXTDB_STATE_HEAD_ID"] = authority_id
            return environment
        if host_target in {"linux-x86-64", "linux-arm64", "macos-arm64"}:
            if authority_directory is None:
                authority_directory = tempfile.TemporaryDirectory(
                    prefix="contextdb-probe-authority-"
                )
                os.chmod(authority_directory.name, 0o700)
            environment["CONTEXTDB_STATE_HEAD_FILE"] = str(
                Path(authority_directory.name) / f"{slot}.json"
            )
            return environment
        raise ContractError(
            f"the host target {host_target!r} has no external state-head custody contract"
        )

    try:
        state_environment = authority_environment("state")
        import_environment = authority_environment("import")
    except (ContractError, OSError) as error:
        probes.append(
            {
                "id": "contextdb-state-authority-selection",
                "status": "failed",
                "evidence_level": "runtime",
                "argv": [],
                "detail": str(error),
            }
        )
        _finish_probe_authority_custody(
            host_target,
            authority_directory,
            windows_authority_digests,
            probe_environment,
        )
        return probes

    try:
        _exercise_contextdb_binary(
            binary,
            isolated,
            manifest,
            expected_version,
            host_target,
            state_environment,
            import_environment,
            probes,
        )
    finally:
        custody_cleaned = _finish_probe_authority_custody(
            host_target,
            authority_directory,
            windows_authority_digests,
            probe_environment,
        )
        probes.append(
            {
                "id": "contextdb-state-authority-cleanup",
                "status": "passed" if custody_cleaned else "failed",
                "evidence_level": "runtime",
                "argv": ["cleanup-owned-probe-authorities"],
                "detail": (
                    "exact verifier-owned state-head authorities and transaction locks removed"
                    if custody_cleaned
                    else "exact verifier-owned state-head authority cleanup failed"
                ),
            }
        )
    return probes


def _extract_portable_example(package: Path, isolated: Path) -> Path:
    if package.suffix.lower() == ".ctxb":
        return package
    if package.suffix.lower() != ".zip":
        raise ContractError(
            "portable example must be a .ctxb archive or deterministic ZIP"
        )
    destination = isolated / "clean-install" / "portable-example"
    candidates: list[tuple[zipfile.ZipInfo, str]] = []
    seen: set[str] = set()
    total_size = 0
    try:
        with zipfile.ZipFile(package, "r") as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                relative = canonical_relative_path(
                    info.filename, f"portable ZIP entry {info.filename!r}"
                )
                custody_material = _portable_custody_material(relative)
                if custody_material is not None:
                    raise ContractError(
                        f"portable ZIP must not contain {custody_material}: {relative}"
                    )
                if relative in seen:
                    raise ContractError(f"portable ZIP repeats entry {relative}")
                seen.add(relative)
                unix_type = (info.external_attr >> 16) & 0o170000
                if unix_type == 0o120000:
                    raise ContractError(f"portable ZIP contains symlink {relative}")
                if info.flag_bits & 0x1:
                    raise ContractError(f"portable ZIP entry is encrypted: {relative}")
                if info.file_size > 256 * 1024 * 1024:
                    raise ContractError(f"portable ZIP entry is too large: {relative}")
                total_size += info.file_size
                if total_size > 512 * 1024 * 1024 or len(seen) > 128:
                    raise ContractError("portable ZIP exceeds extraction limits")
                if relative.endswith(".ctxb"):
                    candidates.append((info, relative))
            if len(candidates) != 1:
                raise ContractError(
                    f"portable ZIP must contain exactly one .ctxb archive, found {len(candidates)}"
                )
            info, relative = candidates[0]
            payload = archive.read(info)
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise ContractError(f"cannot inspect portable example ZIP: {error}") from error
    if len(payload) != info.file_size:
        raise ContractError(f"portable ZIP extracted size mismatch: {relative}")
    destination.mkdir(parents=True, exist_ok=False)
    output = destination / Path(relative).name
    output.write_bytes(payload)
    return output


def _host_target() -> str:
    import platform

    os_name = platform.system().lower()
    machine = platform.machine().lower()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "x86-64"
    if os_name == "darwin":
        return f"macos-{arch}"
    if os_name == "windows":
        return f"windows-{arch}"
    return f"linux-{arch}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {RELEASE_TOOL_VERSION}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser("verify-bundle", help="verify a release bundle")
    verify.add_argument("--bundle-root", required=True, type=Path)
    verify.add_argument("--manifest", default="release/artifact-manifest.json")
    verify.add_argument("--profile", choices=("contract", "release"), default="release")
    verify.add_argument("--trusted-key", action="append", default=[], metavar="ID=PEM")
    verify.add_argument("--allow-test-keys", action="store_true")
    verify.add_argument("--report", type=Path)

    audit = subparsers.add_parser("audit-source", help="audit source/package inventory")
    audit.add_argument("--repo-root", required=True, type=Path)
    audit.add_argument("--matrix", required=True, type=Path)
    audit.add_argument("--report", type=Path)

    readiness = subparsers.add_parser(
        "readiness-report", help="report exact unresolved Alpha/Beta/v1 requirements"
    )
    readiness.add_argument("--repo-root", required=True, type=Path)
    readiness.add_argument("--ledger", required=True, type=Path)
    readiness.add_argument("--matrix", required=True, type=Path)
    readiness.add_argument(
        "--stage", required=True, choices=("alpha", "beta", "stable")
    )
    readiness.add_argument("--report", type=Path)

    assemble = subparsers.add_parser(
        "assemble-bundle",
        help="stage pre-built, digest-pinned inputs into an offline release bundle",
    )
    assemble.add_argument("--input-root", required=True, type=Path)
    assemble.add_argument("--input-manifest", required=True, type=Path)
    assemble.add_argument("--matrix", required=True, type=Path)
    assemble.add_argument("--output-dir", required=True, type=Path)
    assemble.add_argument("--source-date-epoch", type=int)
    assemble.add_argument("--report", type=Path)

    package = subparsers.add_parser(
        "package-example", help="create a deterministic portable-example ZIP"
    )
    package.add_argument("--source", required=True, type=Path)
    package.add_argument("--output", required=True, type=Path)
    package.add_argument("--force", action="store_true")
    package.add_argument("--report", type=Path)

    clean = subparsers.add_parser(
        "clean-install", help="copy, verify, and probe a bundle without Docker"
    )
    clean.add_argument("--bundle-root", required=True, type=Path)
    clean.add_argument("--manifest", default="release/artifact-manifest.json")
    clean.add_argument("--profile", choices=("contract", "release"), default="release")
    clean.add_argument("--trusted-key", action="append", default=[], metavar="ID=PEM")
    clean.add_argument("--allow-test-keys", action="store_true")
    clean.add_argument("--report", type=Path)

    intake = subparsers.add_parser(
        "intake-receipts",
        help="validate a digest-pinned external receipt landing zone",
    )
    intake.add_argument("--subject-root", required=True, type=Path)
    intake.add_argument("--input-root", required=True, type=Path)
    intake.add_argument("--receipt-set", required=True, type=Path)
    intake.add_argument("--report", type=Path)

    operational = subparsers.add_parser(
        "operational-drill",
        help="exercise side-by-side upgrade, rollback, and disaster recovery",
    )
    operational.add_argument("--old-bundle-root", required=True, type=Path)
    operational.add_argument("--new-bundle-root", required=True, type=Path)
    operational.add_argument("--plan", required=True, type=Path)
    operational.add_argument(
        "--profile", choices=("contract", "release"), default="release"
    )
    operational.add_argument(
        "--trusted-key", action="append", default=[], metavar="ID=PEM"
    )
    operational.add_argument("--allow-test-keys", action="store_true")
    operational.add_argument("--report", type=Path)
    return parser


def emit_result(value: dict[str, Any], report: Path | None) -> None:
    validate_json_contract(value, "generated report")
    if report is not None:
        _write_json_atomic(report, value)
    json.dump(value, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def _require_report_outside_roots(
    report: Path | None, roots: Iterable[Path], label: str
) -> None:
    if report is None:
        return
    report_path = report.absolute().resolve(strict=False)
    for root in roots:
        resolved_root = root.resolve(strict=True)
        try:
            report_path.relative_to(resolved_root)
        except ValueError:
            continue
        raise ContractError(f"{label} report must be outside {resolved_root.name}")


def _require_output_distinct_from_inputs(
    output: Path | None, inputs: Iterable[Path], label: str
) -> None:
    if output is None:
        return
    output_path = output.absolute().resolve(strict=False)
    for input_path in inputs:
        if output_path == input_path.absolute().resolve(strict=False):
            raise ContractError(f"{label} output must not overwrite an input file")


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "verify-bundle":
            _require_report_outside_roots(
                arguments.report,
                [arguments.bundle_root],
                "bundle verification",
            )
            verifier = BundleVerifier(
                arguments.bundle_root,
                arguments.manifest,
                arguments.profile,
                parse_trusted_keys(arguments.trusted_key),
                arguments.allow_test_keys,
            )
            result = verifier.verify()
            emit_result(result, arguments.report)
            return 0 if result["contract_valid"] else 2
        if arguments.command == "audit-source":
            result = audit_source(arguments.repo_root, arguments.matrix)
            emit_result(result, arguments.report)
            return 0 if result["outcome"] == "source_inventory_valid" else 2
        if arguments.command == "readiness-report":
            result = readiness_report(
                arguments.repo_root,
                arguments.ledger,
                arguments.matrix,
                arguments.stage,
            )
            emit_result(result, arguments.report)
            return 0
        if arguments.command == "assemble-bundle":
            report = arguments.report
            output = arguments.output_dir.absolute()
            if report is not None:
                report_absolute = report.absolute()
                try:
                    report_absolute.relative_to(output)
                except ValueError:
                    pass
                else:
                    raise ContractError(
                        "assembly receipt must be outside the assembled bundle"
                    )
            result = assemble_bundle(
                arguments.input_root,
                arguments.input_manifest,
                arguments.matrix,
                arguments.output_dir,
                arguments.source_date_epoch,
            )
            emit_result(result, report)
            return 0
        if arguments.command == "package-example":
            result = package_example(
                arguments.source, arguments.output, arguments.force
            )
            emit_result(result, arguments.report)
            return 0
        if arguments.command == "clean-install":
            _require_report_outside_roots(
                arguments.report,
                [arguments.bundle_root],
                "clean-install",
            )
            result = run_clean_install(
                arguments.bundle_root,
                arguments.manifest,
                arguments.profile,
                parse_trusted_keys(arguments.trusted_key),
                arguments.allow_test_keys,
            )
            emit_result(result, arguments.report)
            return 0 if result["passed"] else 2
        if arguments.command == "intake-receipts":
            _require_report_outside_roots(
                arguments.report,
                [arguments.subject_root, arguments.input_root],
                "external receipt intake",
            )
            result = intake_external_receipts(
                arguments.subject_root,
                arguments.input_root,
                arguments.receipt_set,
            )
            emit_result(result, arguments.report)
            return 0 if result["accepted"] else 2
        if arguments.command == "operational-drill":
            _require_report_outside_roots(
                arguments.report,
                [arguments.old_bundle_root, arguments.new_bundle_root],
                "operational drill",
            )
            trusted_keys = parse_trusted_keys(arguments.trusted_key)
            _require_output_distinct_from_inputs(
                arguments.report,
                [arguments.plan, *trusted_keys.values()],
                "operational drill",
            )
            result = run_operational_drill(
                arguments.old_bundle_root,
                arguments.new_bundle_root,
                arguments.plan,
                arguments.profile,
                trusted_keys,
                arguments.allow_test_keys,
            )
            emit_result(result, arguments.report)
            return 0 if result["passed"] else 2
    except (ContractError, OSError) as error:
        print(f"contextdb-release: {error}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
