#!/usr/bin/env python3
"""Verify and package ContextDB's listener-free local MCP developer preview."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, Sequence


PROFILE_SCHEMA = "contextdb.local-mcp-profile/v1"
RECEIPT_SCHEMA = "contextdb.local-mcp-package-receipt/v1"
PROFILE_PATH = Path("release/local-mcp-profile.json")
CLI_MANIFEST_PATH = Path("crates/contextdb-cli/Cargo.toml")
MCP_SERVER_PATH = Path("crates/contextdb-mcp/src/server.rs")
SUPPLY_CHAIN_TOOL_PATH = Path("tools/local-mcp-preview/generate_supply_chain.py")
SUPPLY_CHAIN_MANIFEST_PATH = Path("release/contextdb-local-mcp-supply-chain.json")
NOTICE_PATH = Path("release/THIRD_PARTY_NOTICES.txt")
SBOM_PATH = Path("release/contextdb-local-mcp.cdx.json")
SUPPLY_CHAIN_SCHEMA = "contextdb.local-mcp-supply-chain/v1"
SUPPLY_CHAIN_ARTIFACTS = {
    "release/THIRD_PARTY_NOTICES.txt",
    "release/contextdb-local-mcp.cdx.json",
    "release/rust-runtime/COPYRIGHT.html",
    "release/rust-runtime/LICENSE-APACHE",
    "release/rust-runtime/LICENSE-MIT",
}
EXPECTED_FEATURES = ["local-mcp"]
EXPECTED_PACKAGE = "contextdb-cli"
EXPECTED_BINARY = "contextdb"
SUPPORTED_ARCHITECTURES = {"amd64", "x86_64"}
LINUX_GLIBC_BASELINE = (2, 35)
PLATFORMS: dict[str, dict[str, Any]] = {
    "windows-x86_64": {
        "operating_system": "windows",
        "architecture": "x86_64",
        "target": "x86_64-pc-windows-msvc",
        "profile_id": "contextdb-local-mcp-windows-x86_64",
        "binary_name": "contextdb.exe",
        "profile_path": PROFILE_PATH,
        "transports": ["mcp-stdio", "windows-local-named-pipe"],
    },
    "linux-x86_64": {
        "operating_system": "linux",
        "architecture": "x86_64",
        "target": "x86_64-unknown-linux-gnu",
        "profile_id": "contextdb-local-mcp-linux-x86_64",
        "binary_name": "contextdb",
        "profile_path": Path("release/platforms/linux-x86_64/local-mcp-profile.json"),
        "transports": ["mcp-stdio", "unix-domain-socket"],
    },
}
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


class ContractError(RuntimeError):
    """The checked-in profile or generated package violates its contract."""


def _fail(message: str) -> NoReturn:
    raise ContractError(message)


def _host_platform() -> str:
    operating_system = platform.system().lower()
    architecture = platform.machine().lower()
    if architecture not in SUPPORTED_ARCHITECTURES:
        _fail(f"unsupported local-MCP preview architecture: {architecture}")
    selected = f"{operating_system}-x86_64"
    if selected not in PLATFORMS:
        _fail(f"unsupported local-MCP preview operating system: {operating_system}")
    return selected


def _platform_configuration(name: str | None = None) -> tuple[str, dict[str, Any]]:
    selected = name or _host_platform()
    configuration = PLATFORMS.get(selected)
    if configuration is None:
        _fail(f"unsupported local-MCP preview platform: {selected}")
    return selected, configuration


def _profile_configuration(profile_id: Any) -> tuple[str, dict[str, Any]]:
    for name, configuration in PLATFORMS.items():
        if profile_id == configuration["profile_id"]:
            return name, configuration
    _fail("package receipt names an unsupported local-MCP profile")


def _platform_source_file(root: Path, relative: str, platform_name: str) -> Path:
    if platform_name == "windows-x86_64" or not relative.startswith("release/"):
        return _safe_repo_file(root, relative)
    platform_relative = f"release/platforms/{platform_name}/{relative.removeprefix('release/')}"
    return _safe_repo_file(root, platform_relative)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _fail(f"cannot read JSON {path}: {error}")
    if not isinstance(value, dict):
        _fail(f"JSON root must be an object: {path}")
    return value


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        _fail(f"cannot read TOML {path}: {error}")


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty string")
    return value


def _require_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        _fail(f"{label} must be a non-empty array")
    if any(not isinstance(item, str) or not item for item in value):
        _fail(f"{label} must contain only non-empty strings")
    if len(set(value)) != len(value):
        _fail(f"{label} must not contain duplicates")
    return list(value)


def _safe_repo_file(root: Path, relative: str) -> Path:
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts or "\\" in relative:
        _fail(f"unsafe repository-relative path: {relative}")
    resolved = (root / Path(*candidate.parts)).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        _fail(f"path escapes repository root: {relative}")
    if not resolved.is_file():
        _fail(f"required package file is missing: {relative}")
    return resolved


def _workspace_version(root: Path) -> str:
    workspace = _require_object(_read_toml(root / "Cargo.toml").get("workspace"), "workspace")
    package = _require_object(workspace.get("package"), "workspace.package")
    return _require_string(package.get("version"), "workspace.package.version")


def _mcp_protocols(root: Path) -> list[str]:
    source = (root / MCP_SERVER_PATH).read_text(encoding="utf-8")
    stateless_match = re.search(
        r'MCP_PROTOCOL_VERSION:\s*&str\s*=\s*"([^"]+)"', source
    )
    standard_match = re.search(
        r"MCP_STANDARD_PROTOCOL_VERSIONS:\s*\[&str;\s*\d+\]\s*=\s*\[([^]]+)\]",
        source,
    )
    if stateless_match is None or standard_match is None:
        _fail("cannot extract MCP protocol constants")
    standard = re.findall(r'"([^"]+)"', standard_match.group(1))
    return [*standard, stateless_match.group(1)]


def validate_profile(root: Path, platform_name: str | None = None) -> dict[str, Any]:
    """Validate the checked-in profile against source-owned version boundaries."""

    selected, configuration = _platform_configuration(platform_name)
    profile = _read_json(root / configuration["profile_path"])
    if profile.get("schema_version") != PROFILE_SCHEMA:
        _fail("unsupported local MCP profile schema")
    if profile.get("profile_id") != configuration["profile_id"]:
        _fail("unexpected local MCP profile identifier")
    if profile.get("profile_revision") != 1:
        _fail("unexpected local MCP profile revision")
    if profile.get("release_class") != "developer-preview":
        _fail("local MCP profile must remain a developer preview")

    version = _workspace_version(root)
    if profile.get("core_version") != version:
        _fail("profile core_version differs from workspace.package.version")

    formal = _require_object(profile.get("formal_release"), "formal_release")
    formal_false_fields = ("m18_alpha", "release_ready", "signed", "published")
    if any(formal.get(field) is not False for field in formal_false_fields):
        _fail("developer preview must not claim formal release, signing, or publication")

    build = _require_object(profile.get("build"), "build")
    expected_build = {
        "package": EXPECTED_PACKAGE,
        "binary": EXPECTED_BINARY,
        "locked": True,
        "release_mode": True,
        "default_features": False,
        "features": EXPECTED_FEATURES,
    }
    if build != expected_build:
        _fail("profile build contract differs from the fixed local MCP build")

    cli_manifest = _read_toml(root / CLI_MANIFEST_PATH)
    features = _require_object(cli_manifest.get("features"), "contextdb-cli.features")
    if features.get("local-mcp") != ["mcp"]:
        _fail("contextdb-cli local-mcp must remain an exact alias for mcp")
    if "local-mcp" in features.get("default", []):
        _fail("local-mcp must not be a default feature")

    runtime = _require_object(profile.get("runtime"), "runtime")
    if runtime.get("network_listeners") is not False:
        _fail("local MCP profile must disable network listeners")
    if runtime.get("excluded_cli_commands") != ["probe", "serve"]:
        _fail("local MCP profile must exclude probe and serve")
    transports = _require_string_list(runtime.get("transports"), "runtime.transports")
    if transports != configuration["transports"]:
        _fail("unexpected local MCP transport surface")
    platforms = runtime.get("supported_platforms")
    expected_platforms = [
        {
            "operating_system": configuration["operating_system"],
            "architecture": configuration["architecture"],
            "support": "developer-preview",
        }
    ]
    if platforms != expected_platforms:
        _fail(f"developer-preview package support must match {selected} exactly")

    compatibility = _require_object(profile.get("compatibility"), "compatibility")
    if compatibility.get("mcp_protocols") != _mcp_protocols(root):
        _fail("profile MCP protocols differ from the implementation constants")
    expected_versions: dict[str, Any] = {
        "wire_schema": 1,
        "semantic_schema": 1,
        "storage_format": 1,
        "context_pack_schema": 1,
    }
    for field, expected in expected_versions.items():
        if compatibility.get(field) != expected:
            _fail(f"unexpected compatibility.{field}")
    if compatibility.get("logical_archive") != "contextdb.logical.v1":
        _fail("unexpected logical archive identifier")
    if compatibility.get("consumer_binding") != "exact-core-version-and-artifact-sha256":
        _fail("consumer compatibility must bind the exact core artifact")

    package_files = _require_string_list(profile.get("package_files"), "package_files")
    if package_files != sorted(package_files):
        _fail("package_files must be sorted")
    for relative in package_files:
        _platform_source_file(root, relative, selected)
    _require_string_list(profile.get("limitations"), "limitations")
    return profile


def _run(command: Sequence[str], root: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(command),
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        _fail(f"command failed ({result.returncode}): {' '.join(command)}\n{detail}")
    return result


def _validate_feature_tree(tree: str) -> None:
    required = re.compile(r"(?m)^contextdb-cli\s+v[^\n]*\[[^]]*\blocal-mcp\b[^]]*\]")
    if required.search(tree) is None:
        _fail("resolved feature graph does not contain contextdb-cli/local-mcp")

    forbidden_patterns = {
        "contextdb-cli/current-server": (
            r"contextdb-cli feature \"current-server\"|"
            r"contextdb-cli\s+v[^\n]*\[[^]]*\bcurrent-server\b"
        ),
        "contextdb-cli/server-v1": (
            r"contextdb-cli feature \"server-v1\"|"
            r"contextdb-cli\s+v[^\n]*\[[^]]*\bserver-v1\b"
        ),
        "contextdb-server/http": (
            r"contextdb-server feature \"http\"|"
            r"contextdb-server\s+v[^\n]*\[[^]]*\bhttp\b"
        ),
        "contextdb-server/server": (
            r"contextdb-server feature \"server\"|"
            r"contextdb-server\s+v[^\n]*\[[^]]*\bserver\b"
        ),
        "contextdb-runtime": r"(?m)^.*contextdb-runtime\s+v",
        "axum listener runtime": r"(?m)^.*\baxum\s+v",
        "tonic listener runtime": r"(?m)^.*\btonic(?:-prost)?\s+v",
    }
    for label, pattern in forbidden_patterns.items():
        if re.search(pattern, tree):
            _fail(f"resolved local MCP graph includes forbidden {label}")


def verify_feature_surface(
    root: Path, cargo: str, target: str | None = None
) -> tuple[str, list[str]]:
    command = [
        cargo,
        "tree",
        "--locked",
        "-p",
        EXPECTED_PACKAGE,
        "--no-default-features",
        "--features",
        ",".join(EXPECTED_FEATURES),
        "--target",
        target or _platform_configuration()[1]["target"],
        "-e",
        "normal,features",
        "-f",
        "{p} [{f}]",
    ]
    tree = _run(command, root).stdout.replace("\r\n", "\n")
    _validate_feature_tree(tree)
    return hashlib.sha256(tree.encode("utf-8")).hexdigest(), command


def verify_supply_chain_source(
    root: Path, cargo: str, platform_name: str | None = None
) -> dict[str, Any]:
    """Verify notices, SBOM, Rust runtime notices, and exact graph coverage."""

    selected, configuration = _platform_configuration(platform_name)
    command = [
        sys.executable,
        str(root / SUPPLY_CHAIN_TOOL_PATH),
        "verify",
        "--root",
        str(root),
        "--cargo",
        cargo,
        "--platform",
        selected,
    ]
    result = _run(command, root)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        _fail(f"supply-chain verifier returned invalid JSON: {error}")
    if not isinstance(value, dict) or value.get("status") != "passed":
        _fail("supply-chain verifier did not return a passing result")
    if value.get("profile_id") != configuration["profile_id"]:
        _fail("supply-chain verifier returned an unexpected profile")
    if value.get("target") != configuration["target"]:
        _fail("supply-chain verifier returned an unexpected Rust target")
    return value


def _command_names(help_text: str) -> set[str]:
    commands: set[str] = set()
    in_commands = False
    for line in help_text.replace("\r\n", "\n").splitlines():
        if line.strip() == "Commands:":
            in_commands = True
            continue
        if in_commands and line and not line.startswith(" "):
            break
        match = re.match(r"^\s{2}([a-z][a-z0-9-]*)\s", line) if in_commands else None
        if match is not None:
            commands.add(match.group(1))
    return commands


def _validate_binary_surface(help_text: str, version_text: str, core_version: str) -> None:
    commands = _command_names(help_text)
    if "mcp" not in commands:
        _fail("packaged binary does not expose the MCP command")
    forbidden = {"probe", "serve"} & commands
    if forbidden:
        _fail(f"packaged binary exposes network commands: {sorted(forbidden)}")

    lines = set(version_text.replace("\r\n", "\n").splitlines())
    required_lines = {
        f"contextdb {core_version}",
        "build_profile local-mcp",
        "network_listeners disabled",
        "wire_schema 1",
        "semantic_schema 1",
        "storage_format 1",
        "context_pack_schema 1",
        "mcp_protocol 2026-07-28",
    }
    missing = required_lines - lines
    if missing:
        _fail(f"packaged binary version surface is incomplete: {sorted(missing)}")
    if (
        "build_profile mixed-local-mcp-current-server" in lines
        or "network_listeners enabled" in lines
    ):
        _fail("packaged binary reports a mixed network-enabled feature set")


def _version_tuple_text(version: tuple[int, ...]) -> str:
    return ".".join(str(component) for component in version)


def _validate_linux_glibc_version_info(version_info: str) -> dict[str, Any]:
    versions = {
        tuple(int(component) for component in match.split("."))
        for match in re.findall(r"\bGLIBC_(\d+(?:\.\d+)+)\b", version_info)
    }
    if not versions:
        _fail("Linux ELF has no readable versioned GLIBC imports")

    maximum_required = max(versions)
    comparison_width = max(len(maximum_required), len(LINUX_GLIBC_BASELINE))
    required_key = maximum_required + (0,) * (comparison_width - len(maximum_required))
    baseline_key = LINUX_GLIBC_BASELINE + (0,) * (
        comparison_width - len(LINUX_GLIBC_BASELINE)
    )
    if required_key > baseline_key:
        _fail(
            "Linux ELF requires "
            f"GLIBC_{_version_tuple_text(maximum_required)}; the Ubuntu 22.04 "
            f"compatibility ceiling is GLIBC_{_version_tuple_text(LINUX_GLIBC_BASELINE)}"
        )
    return {
        "libc": "glibc",
        "support_baseline": "Ubuntu 22.04 LTS",
        "maximum_allowed_symbol_version": _version_tuple_text(LINUX_GLIBC_BASELINE),
        "maximum_required_symbol_version": _version_tuple_text(maximum_required),
        "required_symbol_versions": [
            _version_tuple_text(value) for value in sorted(versions)
        ],
    }


def _validate_linux_abi_receipt(value: Any) -> dict[str, Any]:
    receipt = _require_object(value, "receipt.binary.linux_abi")
    versions = _require_string_list(
        receipt.get("required_symbol_versions"),
        "receipt.binary.linux_abi.required_symbol_versions",
    )
    if any(re.fullmatch(r"\d+(?:\.\d+)+", version) is None for version in versions):
        _fail("Linux ABI receipt contains a malformed GLIBC symbol version")
    expected = _validate_linux_glibc_version_info(
        " ".join(f"GLIBC_{version}" for version in versions)
    )
    if receipt != expected:
        _fail("Linux ABI receipt does not canonically bind the GLIBC compatibility floor")
    return expected


def verify_linux_abi(binary: Path, root: Path, readelf: str = "readelf") -> dict[str, Any]:
    """Reject Linux ELFs that cannot run on the advertised Ubuntu 22.04 floor."""

    if not binary.is_file():
        _fail(f"built Linux binary is missing: {binary}")
    try:
        version_info = _run(
            [readelf, "--version-info", "--wide", str(binary)], root
        ).stdout
    except OSError as error:
        _fail(f"cannot execute readelf for Linux ABI verification: {error}")
    result = _validate_linux_glibc_version_info(version_info)
    return {
        "status": "passed",
        "binary": str(binary),
        **result,
    }


def inspect_binary(
    binary: Path,
    root: Path,
    version: str,
    platform_name: str | None = None,
) -> dict[str, Any]:
    if not binary.is_file():
        _fail(f"built binary is missing: {binary}")
    selected, _ = _platform_configuration(platform_name)
    help_text = _run([str(binary), "--help"], root).stdout
    version_text = _run([str(binary), "version"], root).stdout
    _validate_binary_surface(help_text, version_text, version)
    result = {
        "path": str(binary),
        "sha256": _sha256_file(binary),
        "size_bytes": binary.stat().st_size,
        "commands": sorted(_command_names(help_text)),
        "version_output": version_text.replace("\r\n", "\n").splitlines(),
    }
    if selected == "linux-x86_64":
        linux_abi = verify_linux_abi(binary, root)
        result["linux_abi"] = {
            key: value
            for key, value in linux_abi.items()
            if key not in {"status", "binary"}
        }
    return result


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_state(root: Path) -> tuple[str, bool]:
    revision = _run(["git", "rev-parse", "HEAD"], root).stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        _fail("git returned an invalid source revision")
    status = _run(["git", "status", "--porcelain=v1", "--untracked-files=all"], root).stdout
    return revision, bool(status.strip())


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _write_checksums(bundle_root: Path) -> None:
    entries: list[str] = []
    for path in sorted(item for item in bundle_root.rglob("*") if item.is_file()):
        if path.name == "SHA256SUMS":
            continue
        relative = path.relative_to(bundle_root).as_posix()
        entries.append(f"{_sha256_file(path)}  {relative}")
    (bundle_root / "SHA256SUMS").write_text(
        "\n".join(entries) + "\n", encoding="utf-8", newline="\n"
    )


def _write_deterministic_zip(bundle_root: Path, archive: Path) -> None:
    with zipfile.ZipFile(
        archive,
        mode="x",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as output:
        for source in sorted(item for item in bundle_root.rglob("*") if item.is_file()):
            relative = source.relative_to(bundle_root.parent).as_posix()
            info = zipfile.ZipInfo(relative, FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            mode = 0o755 if source.name in {"contextdb", "contextdb.exe"} else 0o644
            info.external_attr = mode << 16
            output.writestr(
                info,
                source.read_bytes(),
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )


def _verify_packaged_supply_chain(
    payloads: dict[str, bytes],
    receipt: dict[str, Any],
    core_version: str,
    configuration: dict[str, Any],
) -> dict[str, Any]:
    manifest_bytes = payloads.get(SUPPLY_CHAIN_MANIFEST_PATH.as_posix())
    if manifest_bytes is None:
        _fail("package is missing its local-MCP supply-chain manifest")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        _fail(f"invalid packaged supply-chain manifest: {error}")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SUPPLY_CHAIN_SCHEMA:
        _fail("unsupported packaged supply-chain manifest")
    if manifest.get("profile_id") != configuration["profile_id"]:
        _fail("packaged supply-chain profile differs from the binary profile")
    if manifest.get("target") != configuration["target"]:
        _fail("packaged supply-chain target differs from the binary profile")
    if manifest.get("core_version") != core_version:
        _fail("packaged supply-chain manifest targets a different core version")
    if manifest.get("canonical_repository") != "https://github.com/mikhailbovt/ContextDB":
        _fail("packaged supply-chain manifest contains a stale repository URL")
    claims = _require_object(manifest.get("claims"), "supply-chain.claims")
    if claims != {
        "developer_preview": True,
        "network_listeners": False,
        "signed": False,
        "published": False,
        "formal_release_ready": False,
    }:
        _fail("packaged supply-chain manifest overclaims release status")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        _fail("packaged supply-chain manifest lacks artifact receipts")
    artifact_paths: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            _fail("packaged supply-chain artifact receipt is invalid")
        relative = item["path"]
        payload = payloads.get(relative)
        if payload is None:
            _fail(f"package is missing supply-chain artifact: {relative}")
        if item.get("sha256") != hashlib.sha256(payload).hexdigest():
            _fail(f"packaged supply-chain artifact digest mismatch: {relative}")
        if item.get("bytes") != len(payload):
            _fail(f"packaged supply-chain artifact size mismatch: {relative}")
        artifact_paths.add(relative)
    if artifact_paths != SUPPLY_CHAIN_ARTIFACTS:
        _fail("packaged supply-chain artifact set is incomplete")

    graph = _require_object(manifest.get("graph"), "supply-chain.graph")
    graph_hash = graph.get("sha256")
    component_count = graph.get("component_count")
    third_party_count = graph.get("third_party_component_count")
    if (
        not isinstance(graph_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", graph_hash) is None
        or not isinstance(component_count, int)
        or component_count < 2
        or not isinstance(third_party_count, int)
        or third_party_count < 1
    ):
        _fail("packaged supply-chain graph receipt is invalid")
    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, list) or len(dependencies) != third_party_count:
        _fail("packaged third-party dependency receipt has the wrong coverage")
    identities: set[tuple[str, str]] = set()
    for item in dependencies:
        if not isinstance(item, dict):
            _fail("packaged dependency receipt contains an invalid item")
        name = item.get("name")
        version = item.get("version")
        selected = item.get("selected_licenses")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
            or not isinstance(selected, list)
            or not selected
            or any(not isinstance(value, str) or not value for value in selected)
        ):
            _fail("packaged dependency receipt lacks license coverage")
        identities.add((name, version))
    if len(identities) != third_party_count:
        _fail("packaged dependency receipt repeats a component")

    notice = payloads["release/THIRD_PARTY_NOTICES.txt"].decode("utf-8")
    for name, version in identities:
        if f"\n{name} {version}\n" not in notice:
            _fail(f"packaged notice index is missing {name} {version}")
    try:
        sbom = json.loads(payloads["release/contextdb-local-mcp.cdx.json"].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        _fail(f"invalid packaged CycloneDX SBOM: {error}")
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        _fail("packaged SBOM is not CycloneDX 1.5 JSON")
    components = sbom.get("components")
    metadata = sbom.get("metadata")
    if (
        not isinstance(components, list)
        or not isinstance(metadata, dict)
        or not isinstance(metadata.get("component"), dict)
        or len(components) + 1 != component_count
    ):
        _fail("packaged SBOM component coverage differs from the graph receipt")
    sbom_text = payloads["release/contextdb-local-mcp.cdx.json"].decode("utf-8")
    for forbidden in ("file:///", "file://.", "contextdb/contextdb"):
        if forbidden.lower() in sbom_text.lower():
            _fail(f"packaged SBOM contains a local or stale value: {forbidden}")

    rust = _require_object(manifest.get("rust_toolchain"), "supply-chain.rust_toolchain")
    if (
        rust.get("release") != "1.97.1"
        or rust.get("commit_hash") != "8bab26f4f68e0e26f0bb7960be334d5b520ea452"
        or rust.get("host")
        not in {platform_config["target"] for platform_config in PLATFORMS.values()}
    ):
        _fail("packaged Rust runtime notices target a different toolchain")
    rust_files = rust.get("files")
    if not isinstance(rust_files, list) or {
        item.get("path") for item in rust_files if isinstance(item, dict)
    } != {
        "release/rust-runtime/COPYRIGHT.html",
        "release/rust-runtime/LICENSE-APACHE",
        "release/rust-runtime/LICENSE-MIT",
    }:
        _fail("packaged Rust runtime notice set is incomplete")

    receipt_supply_chain = _require_object(
        receipt.get("supply_chain"), "receipt.supply_chain"
    )
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    expected_receipt = {
        "manifest_path": SUPPLY_CHAIN_MANIFEST_PATH.as_posix(),
        "manifest_sha256": manifest_sha256,
        "graph_sha256": graph_hash,
        "component_count": component_count,
        "third_party_component_count": third_party_count,
        "sbom_path": "release/contextdb-local-mcp.cdx.json",
        "notices_path": "release/THIRD_PARTY_NOTICES.txt",
        "rust_runtime_notice_paths": [
            "release/rust-runtime/COPYRIGHT.html",
            "release/rust-runtime/LICENSE-APACHE",
            "release/rust-runtime/LICENSE-MIT",
        ],
    }
    if receipt_supply_chain != expected_receipt:
        _fail("package receipt does not bind the supply-chain bundle")
    return expected_receipt


def verify_archive(archive: Path, hash_sidecar: Path | None = None) -> dict[str, Any]:
    """Re-read an archive and verify every staged byte and non-release claim."""

    if not archive.is_file():
        _fail(f"package archive is missing: {archive}")
    archive_sha256 = _sha256_file(archive)
    sidecar = hash_sidecar or archive.with_suffix(archive.suffix + ".sha256")
    if not sidecar.is_file():
        _fail(f"package hash sidecar is missing: {sidecar}")
    expected_sidecar = f"{archive_sha256}  {archive.name}\n"
    try:
        actual_sidecar = sidecar.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        _fail(f"cannot read package hash sidecar: {error}")
    if actual_sidecar.replace("\r\n", "\n") != expected_sidecar:
        _fail("package hash sidecar does not bind the archive")

    try:
        with zipfile.ZipFile(archive, "r") as package:
            infos = [info for info in package.infolist() if not info.is_dir()]
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                _fail("package archive contains duplicate paths")
            if not names:
                _fail("package archive is empty")
            for name in names:
                path = PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts or "\\" in name:
                    _fail(f"package archive contains an unsafe path: {name}")
            roots = {PurePosixPath(name).parts[0] for name in names}
            if len(roots) != 1:
                _fail("package archive must have exactly one top-level directory")
            bundle_name = next(iter(roots))
            checksum_name = f"{bundle_name}/SHA256SUMS"
            receipt_name = f"{bundle_name}/RECEIPT.json"
            if checksum_name not in names or receipt_name not in names:
                _fail("package archive is missing SHA256SUMS or RECEIPT.json")

            checksum_text = package.read(checksum_name).decode("ascii")
            checksums: dict[str, str] = {}
            for line in checksum_text.replace("\r\n", "\n").splitlines():
                match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
                if match is None:
                    _fail("package SHA256SUMS contains a malformed line")
                relative = match.group(2)
                if relative in checksums:
                    _fail("package SHA256SUMS repeats a path")
                safe = PurePosixPath(relative)
                if safe.is_absolute() or ".." in safe.parts or "\\" in relative:
                    _fail(f"package SHA256SUMS contains an unsafe path: {relative}")
                checksums[relative] = match.group(1)

            expected_paths = {
                str(PurePosixPath(name).relative_to(bundle_name))
                for name in names
                if name != checksum_name
            }
            if set(checksums) != expected_paths:
                _fail("package SHA256SUMS coverage differs from archive contents")
            for relative, expected in checksums.items():
                payload = package.read(f"{bundle_name}/{relative}")
                actual = hashlib.sha256(payload).hexdigest()
                if actual != expected:
                    _fail(f"package content digest mismatch: {relative}")

            try:
                receipt = json.loads(package.read(receipt_name).decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as error:
                _fail(f"invalid package receipt JSON: {error}")
            if not isinstance(receipt, dict):
                _fail("package receipt JSON must be an object")
            _, configuration = _profile_configuration(receipt.get("profile_id"))
            binary_name = configuration["binary_name"]
            binary_entry = package.getinfo(f"{bundle_name}/{binary_name}")
            if ((binary_entry.external_attr >> 16) & 0o111) == 0:
                _fail("packaged binary does not preserve executable permissions")
            binary_payload = package.read(binary_entry)
            packaged_payloads = {
                str(PurePosixPath(name).relative_to(bundle_name)): package.read(name)
                for name in names
            }
    except (OSError, zipfile.BadZipFile, KeyError) as error:
        _fail(f"cannot verify package archive: {error}")

    if not isinstance(receipt, dict) or receipt.get("schema_version") != RECEIPT_SCHEMA:
        _fail("unsupported package receipt schema")
    claims = _require_object(receipt.get("claims"), "receipt.claims")
    if claims.get("package_smoke_passed") is not True:
        _fail("package receipt lacks a passing binary smoke result")
    for field in ("network_listeners", "formal_release_ready", "m18_alpha", "signed", "published"):
        if claims.get(field) is not False:
            _fail(f"package receipt has an invalid {field} claim")
    source = _require_object(receipt.get("source"), "receipt.source")
    dirty = source.get("dirty")
    if not isinstance(dirty, bool):
        _fail("package receipt source.dirty must be boolean")
    if claims.get("distributable") is not (not dirty):
        _fail("package distributable claim differs from source dirty state")

    binary = _require_object(receipt.get("binary"), "receipt.binary")
    if binary.get("path") != configuration["binary_name"]:
        _fail("package receipt binary path differs from its target platform")
    if configuration["operating_system"] == "linux":
        _validate_linux_abi_receipt(binary.get("linux_abi"))
    elif "linux_abi" in binary:
        _fail("non-Linux package receipt must not contain Linux ABI evidence")
    if binary.get("sha256") != hashlib.sha256(binary_payload).hexdigest():
        _fail("package receipt does not bind the binary digest")
    if binary.get("size_bytes") != len(binary_payload):
        _fail("package receipt does not bind the binary size")
    commands = _require_string_list(binary.get("commands"), "receipt.binary.commands")
    if "mcp" not in commands or {"probe", "serve"} & set(commands):
        _fail("package receipt binary command surface is not local-MCP-only")
    version_output = _require_string_list(
        binary.get("version_output"), "receipt.binary.version_output"
    )
    core_version = _require_string(receipt.get("core_version"), "receipt.core_version")
    receipt_platform = _require_object(receipt.get("platform"), "receipt.platform")
    if receipt_platform != {
        "operating_system": configuration["operating_system"],
        "architecture": configuration["architecture"],
        "rust_target": configuration["target"],
    }:
        _fail("package receipt platform does not match its native profile")
    packaged_profile = packaged_payloads.get(PROFILE_PATH.as_posix())
    if packaged_profile is None:
        _fail("package is missing its target-specific local-MCP profile")
    try:
        profile_document = json.loads(packaged_profile.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        _fail(f"invalid packaged local-MCP profile: {error}")
    if (
        not isinstance(profile_document, dict)
        or profile_document.get("schema_version") != PROFILE_SCHEMA
        or profile_document.get("profile_id") != configuration["profile_id"]
        or profile_document.get("core_version") != core_version
    ):
        _fail("packaged local-MCP profile does not match the package receipt")
    supply_chain = _verify_packaged_supply_chain(
        packaged_payloads, receipt, core_version, configuration
    )
    _validate_binary_surface(
        "Usage:\n\nCommands:\n" + "".join(f"  {name}  command\n" for name in commands),
        "\n".join(version_output),
        core_version,
    )
    return {
        "status": "passed",
        "archive": str(archive.resolve()),
        "archive_sha256": archive_sha256,
        "profile_id": receipt.get("profile_id"),
        "target": configuration["target"],
        "source_dirty": dirty,
        "distributable": claims.get("distributable"),
        "formal_release_ready": False,
        "m18_alpha": False,
        "supply_chain_manifest_sha256": supply_chain["manifest_sha256"],
        "third_party_component_count": supply_chain["third_party_component_count"],
    }


def _package(root: Path, profile: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    selected, configuration = _platform_configuration(args.platform)
    if selected != _host_platform():
        _fail("local-MCP packages must be built and smoke-tested on their native target host")

    revision, dirty = _git_state(root)
    if dirty and not args.allow_dirty:
        _fail(
            "refusing to package a dirty checkout; "
            "--allow-dirty is for local tool development only"
        )

    feature_tree_sha256, tree_command = verify_feature_surface(
        root, args.cargo, configuration["target"]
    )
    supply_chain_check = verify_supply_chain_source(root, args.cargo, selected)
    supply_chain_manifest = _read_json(
        _platform_source_file(root, SUPPLY_CHAIN_MANIFEST_PATH.as_posix(), selected)
    )
    supply_chain_graph = _require_object(
        supply_chain_manifest.get("graph"), "supply-chain.graph"
    )
    version = _require_string(profile.get("core_version"), "core_version")
    target_dir = (args.target_dir or root / "target/local-mcp-preview/cargo").resolve()
    build_command = [
        args.cargo,
        "build",
        "--locked",
        "--release",
        "-p",
        EXPECTED_PACKAGE,
        "--bin",
        EXPECTED_BINARY,
        "--no-default-features",
        "--features",
        ",".join(EXPECTED_FEATURES),
        "--target-dir",
        str(target_dir),
    ]
    _run(build_command, root)
    binary = target_dir / "release" / configuration["binary_name"]
    binary_receipt = inspect_binary(binary, root, version, selected)

    output_dir = (args.output_dir or root / "target/local-mcp-preview/packages").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_name = f"contextdb-local-mcp-{version}-{selected}"
    archive = output_dir / f"{bundle_name}.zip"
    hash_sidecar = output_dir / f"{bundle_name}.zip.sha256"
    if archive.exists() or hash_sidecar.exists():
        _fail(f"refusing to overwrite existing package output: {archive}")

    with tempfile.TemporaryDirectory(prefix="contextdb-local-mcp-", dir=output_dir) as temporary:
        bundle_root = Path(temporary) / bundle_name
        bundle_root.mkdir()
        shutil.copy2(binary, bundle_root / configuration["binary_name"])
        copied_files: list[dict[str, Any]] = []
        for relative in profile["package_files"]:
            source = _platform_source_file(root, relative, selected)
            destination = bundle_root / Path(*PurePosixPath(relative).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            copied_files.append(
                {
                    "path": relative,
                    "sha256": _sha256_file(destination),
                    "size_bytes": destination.stat().st_size,
                }
            )

        recorded_build_command = [
            "cargo",
            *build_command[1:-1],
            "<isolated-target-dir>",
        ]
        recorded_tree_command = ["cargo", *tree_command[1:]]
        receipt = {
            "schema_version": RECEIPT_SCHEMA,
            "profile_id": profile["profile_id"],
            "profile_revision": profile["profile_revision"],
            "core_version": version,
            "platform": {
                "operating_system": configuration["operating_system"],
                "architecture": configuration["architecture"],
                "rust_target": configuration["target"],
            },
            "source": {"git_revision": revision, "dirty": dirty},
            "build": {
                "command": recorded_build_command,
                "feature_tree_command": recorded_tree_command,
                "feature_tree_sha256": feature_tree_sha256,
                "default_features": False,
                "features": EXPECTED_FEATURES,
            },
            "binary": {
                "path": configuration["binary_name"],
                "sha256": binary_receipt["sha256"],
                "size_bytes": binary_receipt["size_bytes"],
                "commands": binary_receipt["commands"],
                "version_output": binary_receipt["version_output"],
                **(
                    {"linux_abi": binary_receipt["linux_abi"]}
                    if selected == "linux-x86_64"
                    else {}
                ),
            },
            "supply_chain": {
                "manifest_path": SUPPLY_CHAIN_MANIFEST_PATH.as_posix(),
                "manifest_sha256": supply_chain_check["manifest_sha256"],
                "graph_sha256": supply_chain_graph["sha256"],
                "component_count": supply_chain_graph["component_count"],
                "third_party_component_count": supply_chain_graph[
                    "third_party_component_count"
                ],
                "sbom_path": SBOM_PATH.as_posix(),
                "notices_path": NOTICE_PATH.as_posix(),
                "rust_runtime_notice_paths": [
                    "release/rust-runtime/COPYRIGHT.html",
                    "release/rust-runtime/LICENSE-APACHE",
                    "release/rust-runtime/LICENSE-MIT",
                ],
            },
            "included_source_files": copied_files,
            "claims": {
                "package_smoke_passed": True,
                "network_listeners": False,
                "formal_release_ready": False,
                "m18_alpha": False,
                "signed": False,
                "published": False,
                "distributable": not dirty,
            },
            "limitations": profile["limitations"],
        }
        _write_json(bundle_root / "RECEIPT.json", receipt)
        _write_checksums(bundle_root)
        temporary_archive = Path(temporary) / archive.name
        temporary_sidecar = Path(temporary) / hash_sidecar.name
        _write_deterministic_zip(bundle_root, temporary_archive)
        archive_sha256 = _sha256_file(temporary_archive)
        temporary_sidecar.write_text(
            f"{archive_sha256}  {archive.name}\n", encoding="ascii", newline="\n"
        )
        verify_archive(temporary_archive, temporary_sidecar)
        try:
            os.link(temporary_archive, archive)
            try:
                os.link(temporary_sidecar, hash_sidecar)
            except OSError:
                archive.unlink(missing_ok=True)
                raise
        except OSError as error:
            _fail(f"cannot publish package output without overwrite: {error}")

    result = {
        "status": "passed",
        "profile_id": profile["profile_id"],
        "target": configuration["target"],
        "archive": str(archive),
        "archive_sha256": archive_sha256,
        "hash_sidecar": str(hash_sidecar),
        "source_dirty": dirty,
        "distributable": not dirty,
        "formal_release_ready": False,
        "m18_alpha": False,
        "supply_chain_manifest_sha256": supply_chain_check["manifest_sha256"],
        "third_party_component_count": supply_chain_graph[
            "third_party_component_count"
        ],
    }
    if selected == "linux-x86_64":
        result["linux_abi"] = binary_receipt["linux_abi"]
    return result


def _repo_root(value: Path | None) -> Path:
    root = (value or Path(__file__).resolve().parents[2]).resolve()
    if not (root / "Cargo.toml").is_file() or not (root / PROFILE_PATH).is_file():
        _fail(f"not a ContextDB repository root: {root}")
    return root


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, help="ContextDB repository root")
    parser.add_argument("--cargo", default="cargo", help="Cargo executable")
    parser.add_argument(
        "--platform",
        choices=sorted(PLATFORMS),
        help="target profile; defaults to the current supported x86_64 host",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify", help="validate contract and resolved Cargo feature surface")
    package = subparsers.add_parser("package", help="build, smoke-test, and package the profile")
    package.add_argument("--output-dir", type=Path, help="new package output directory")
    package.add_argument("--target-dir", type=Path, help="isolated Cargo target directory")
    package.add_argument(
        "--allow-dirty",
        action="store_true",
        help="allow a non-distributable dirty development package",
    )
    verify_package = subparsers.add_parser(
        "verify-package", help="re-read and verify a generated package and hash sidecar"
    )
    verify_package.add_argument("archive", type=Path, help="local MCP preview ZIP")
    verify_package.add_argument("--hash-sidecar", type=Path, help="archive SHA-256 sidecar")
    verify_linux = subparsers.add_parser(
        "verify-linux-abi",
        help="enforce the Ubuntu 22.04 / GLIBC 2.35 ELF compatibility ceiling",
    )
    verify_linux.add_argument("--binary", required=True, type=Path, help="native Linux ELF")
    verify_linux.add_argument("--readelf", default="readelf", help="readelf executable")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        root = _repo_root(args.repo_root)
        if args.command == "verify-package":
            result = verify_archive(args.archive.resolve(), args.hash_sidecar)
        elif args.command == "verify-linux-abi":
            selected, _ = _platform_configuration(args.platform)
            if selected != "linux-x86_64":
                _fail("Linux ABI verification requires --platform linux-x86_64")
            result = verify_linux_abi(args.binary.resolve(), root, args.readelf)
        else:
            profile = validate_profile(root, args.platform)
        if args.command == "verify":
            selected, configuration = _platform_configuration(args.platform)
            feature_tree_sha256, command = verify_feature_surface(
                root, args.cargo, configuration["target"]
            )
            result = {
                "status": "passed",
                "profile_id": profile["profile_id"],
                "core_version": profile["core_version"],
                "platform": selected,
                "target": configuration["target"],
                "feature_tree_command": command,
                "feature_tree_sha256": feature_tree_sha256,
                "network_listeners": False,
                "formal_release_ready": False,
                "m18_alpha": False,
            }
        elif args.command == "package":
            result = _package(root, profile, args)
    except ContractError as error:
        print(f"local-mcp-preview: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
