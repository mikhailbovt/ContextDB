#!/usr/bin/env python3
"""Generate and verify the local-MCP third-party notices and CycloneDX SBOM."""

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
from collections import defaultdict
from pathlib import Path
from typing import Any, NoReturn, Sequence


SCHEMA = "contextdb.local-mcp-supply-chain/v1"
PLATFORM_TARGETS = {
    "windows-x86_64": {
        "profile_id": "contextdb-local-mcp-windows-x86_64",
        "target": "x86_64-pc-windows-msvc",
        "display_name": "Windows x86_64",
    },
    "linux-x86_64": {
        "profile_id": "contextdb-local-mcp-linux-x86_64",
        "target": "x86_64-unknown-linux-gnu",
        "display_name": "Linux x86_64",
    },
}
ACTIVE_PLATFORM = "windows-x86_64"
PROFILE_ID = PLATFORM_TARGETS[ACTIVE_PLATFORM]["profile_id"]
TARGET = PLATFORM_TARGETS[ACTIVE_PLATFORM]["target"]
TOOL_CARGO = "cargo"
PACKAGE = "contextdb-cli"
FEATURES = ["local-mcp"]
CANONICAL_REPOSITORY = "https://github.com/mikhailbovt/ContextDB"
ABOUT_VERSION = "0.9.2"
CYCLONEDX_VERSION = "0.5.9"
RUSTC_VERSION = "1.97.1"
RUSTC_COMMIT = "8bab26f4f68e0e26f0bb7960be334d5b520ea452"

ABOUT_CONFIG = Path("supply-chain/about.toml")
CLI_MANIFEST = Path("crates/contextdb-cli/Cargo.toml")
LOCK_FILE = Path("Cargo.lock")
NOTICE_PATH = Path("release/THIRD_PARTY_NOTICES.txt")
SBOM_PATH = Path("release/contextdb-local-mcp.cdx.json")
MANIFEST_PATH = Path("release/contextdb-local-mcp-supply-chain.json")
RUST_RUNTIME_FILES = {
    "release/rust-runtime/COPYRIGHT.html": "share/doc/rust/COPYRIGHT-library.html",
    "release/rust-runtime/LICENSE-APACHE": "share/doc/rust/licenses/Apache-2.0.txt",
    "release/rust-runtime/LICENSE-MIT": "share/doc/rust/licenses/MIT.txt",
}

_PACKAGE_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+) v(?P<version>[^ ]+)"
    r"(?: \(proc-macro\))?(?: \((?P<location>.+)\))?$"
)


class SupplyChainError(RuntimeError):
    """The checked or generated supply-chain bundle violates its contract."""


def _fail(message: str) -> NoReturn:
    raise SupplyChainError(message)


def _host_platform() -> str:
    operating_system = platform.system().lower()
    architecture = platform.machine().lower()
    if architecture not in {"amd64", "x86_64"}:
        _fail(f"unsupported local-MCP supply-chain architecture: {architecture}")
    selected = f"{operating_system}-x86_64"
    if selected not in PLATFORM_TARGETS:
        _fail(f"unsupported local-MCP supply-chain operating system: {operating_system}")
    return selected


def _activate_platform(value: str | None) -> str:
    global ACTIVE_PLATFORM, PROFILE_ID, TARGET

    selected = value or _host_platform()
    if selected not in PLATFORM_TARGETS:
        _fail(f"unsupported local-MCP supply-chain target: {selected}")
    ACTIVE_PLATFORM = selected
    PROFILE_ID = PLATFORM_TARGETS[selected]["profile_id"]
    TARGET = PLATFORM_TARGETS[selected]["target"]
    return selected


def _evidence_path(root: Path, relative: Path | str) -> Path:
    path = Path(relative)
    if ACTIVE_PLATFORM == "windows-x86_64":
        return root / path
    try:
        within_release = path.relative_to("release")
    except ValueError:
        _fail(f"platform evidence must use a canonical release path: {path}")
    return root / "release" / "platforms" / ACTIVE_PLATFORM / within_release


def _run(
    command: Sequence[str],
    root: Path,
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(command),
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        _fail(f"command failed ({result.returncode}): {' '.join(command)}\n{detail}")
    return result


def _tool_argument_path(path: Path, root: Path) -> str:
    if os.name != "nt" and TOOL_CARGO.lower().endswith(".exe"):
        translated = _run(["wslpath", "-w", str(path)], root).stdout.strip()
        if not translated:
            _fail("cannot translate a WSL output path for the pinned Windows Cargo tools")
        return translated
    return str(path)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        _fail(f"cannot read JSON {path}: {error}")
    if not isinstance(value, dict):
        _fail(f"JSON root must be an object: {path}")
    return value


def _workspace_package(root: Path) -> dict[str, Any]:
    try:
        with (root / "Cargo.toml").open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        _fail(f"cannot read workspace Cargo.toml: {error}")
    package = value.get("workspace", {}).get("package", {})
    if not isinstance(package, dict):
        _fail("workspace.package is missing")
    if package.get("repository") != CANONICAL_REPOSITORY:
        _fail("workspace repository is not the canonical ContextDB repository")
    if package.get("homepage") != CANONICAL_REPOSITORY:
        _fail("workspace homepage is not the canonical ContextDB repository")
    return package


def _tool_version(command: Sequence[str], root: Path, pattern: str, expected: str) -> str:
    output = _run(command, root).stdout.strip()
    match = re.search(pattern, output)
    if match is None or match.group(1) != expected:
        _fail(f"expected {' '.join(command)} version {expected}, got: {output!r}")
    return match.group(1)


def _rust_toolchain(root: Path) -> tuple[Path, dict[str, str]]:
    verbose = _run(["rustc", "--version", "--verbose"], root).stdout
    release = re.search(r"(?m)^release: (\S+)$", verbose)
    commit = re.search(r"(?m)^commit-hash: ([0-9a-f]{40})$", verbose)
    host = re.search(r"(?m)^host: (\S+)$", verbose)
    if (
        release is None
        or release.group(1) != RUSTC_VERSION
        or commit is None
        or commit.group(1) != RUSTC_COMMIT
        or host is None
        or host.group(1)
        not in {configuration["target"] for configuration in PLATFORM_TARGETS.values()}
    ):
        _fail("rustc is not a supported pinned Rust 1.97.1 x86_64 toolchain")
    sysroot = Path(_run(["rustc", "--print", "sysroot"], root).stdout.strip()).resolve()
    if not sysroot.is_dir():
        _fail("rustc returned a missing sysroot")
    return sysroot, {
        "release": release.group(1),
        "commit_hash": commit.group(1),
        "host": host.group(1),
    }


def _tree_command(cargo: str, *, no_dedupe: bool) -> list[str]:
    command = [
        cargo,
        "tree",
        "--locked",
        "--offline",
        "-p",
        PACKAGE,
        "--no-default-features",
        "--features",
        ",".join(FEATURES),
        "--target",
        TARGET,
        "-e",
        "normal,build",
        "--prefix",
        "depth",
        "-f",
        "|{p}|{l}|{r}",
    ]
    if no_dedupe:
        command.insert(-2, "--no-dedupe")
    return command


def _parse_tree_line(line: str) -> tuple[int, tuple[str, str], str, str, bool]:
    match = re.fullmatch(r"(\d+)\|([^|]+)\|([^|]*)\|(.*)", line)
    if match is None:
        _fail(f"cannot parse cargo tree line: {line!r}")
    package = _PACKAGE_RE.fullmatch(match.group(2))
    if package is None:
        _fail(f"cannot parse cargo package identity: {match.group(2)!r}")
    location = package.group("location")
    local = location is not None and (
        re.match(r"^[A-Za-z]:[\\/]", location) is not None
        or location.startswith("/")
    )
    return (
        int(match.group(1)),
        (package.group("name"), package.group("version")),
        match.group(3),
        match.group(4),
        local,
    )


def resolve_graph(root: Path, cargo: str = "cargo") -> dict[str, Any]:
    lines = _run(_tree_command(cargo, no_dedupe=True), root).stdout.splitlines()
    if not lines:
        _fail("cargo tree returned an empty local-MCP graph")

    nodes: dict[tuple[str, str], dict[str, Any]] = {}
    edges: dict[tuple[str, str], set[tuple[str, str]]] = defaultdict(set)
    stack: list[tuple[str, str]] = []
    for line in lines:
        depth, identity, license_expression, repository, local = _parse_tree_line(line)
        existing = nodes.get(identity)
        current = {
            "name": identity[0],
            "version": identity[1],
            "license_expression": license_expression,
            "repository": repository,
            "local": local,
        }
        if existing is not None and existing != current:
            _fail(f"cargo tree returned conflicting metadata for {identity}")
        nodes[identity] = current
        if depth > len(stack):
            _fail(f"cargo tree depth jumped unexpectedly at {identity}")
        stack = stack[:depth]
        if depth > 0:
            edges[stack[-1]].add(identity)
        stack.append(identity)

    root_identity = (PACKAGE, str(_workspace_package(root).get("version", "")))
    if root_identity not in nodes:
        _fail("local-MCP graph does not contain contextdb-cli")
    external = {identity for identity, value in nodes.items() if not value["local"]}
    canonical = {
        "components": [
            {"name": name, "version": version}
            for name, version in sorted(nodes)
        ],
        "edges": [
            {
                "from": {"name": parent[0], "version": parent[1]},
                "to": [
                    {"name": child[0], "version": child[1]}
                    for child in sorted(children)
                ],
            }
            for parent, children in sorted(edges.items())
        ],
    }
    return {
        "root": root_identity,
        "nodes": nodes,
        "edges": edges,
        "external": external,
        "sha256": _sha256_bytes(_json_bytes(canonical)),
    }


def _generate_about(root: Path, destination: Path) -> dict[str, Any]:
    command = [
        TOOL_CARGO,
        "about",
        "generate",
        "--frozen",
        "--fail",
        "--manifest-path",
        CLI_MANIFEST.as_posix(),
        "--no-default-features",
        "--features",
        ",".join(FEATURES),
        "--target",
        TARGET,
        "--config",
        ABOUT_CONFIG.as_posix(),
        "--format",
        "json",
        "--output-file",
        _tool_argument_path(destination, root),
    ]
    _run(command, root)
    return _read_json(destination)


def _identity(package: dict[str, Any]) -> tuple[str, str]:
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        _fail("cargo-about returned an invalid package identity")
    return name, version


def _build_notices(about: dict[str, Any], graph: dict[str, Any]) -> tuple[bytes, list[dict[str, Any]]]:
    external = graph["external"]
    package_by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in about.get("crates", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("package"), dict):
            _fail("cargo-about crates entry is invalid")
        package = entry["package"]
        identity = _identity(package)
        if identity in external and package.get("source") is not None:
            package_by_identity[identity] = package
    if set(package_by_identity) != external:
        missing = sorted(external - set(package_by_identity))
        extra = sorted(set(package_by_identity) - external)
        _fail(f"cargo-about coverage differs from cargo tree; missing={missing}, extra={extra}")

    selected: dict[tuple[str, str], set[str]] = defaultdict(set)
    blocks: dict[tuple[str, str, str], set[tuple[str, str]]] = defaultdict(set)
    for license_record in about.get("licenses", []):
        if not isinstance(license_record, dict):
            _fail("cargo-about license record is invalid")
        license_id = license_record.get("id")
        license_name = license_record.get("name")
        text = license_record.get("text")
        if not all(isinstance(value, str) and value for value in (license_id, license_name, text)):
            _fail("cargo-about returned an incomplete license record")
        normalized_text = text.replace("\r\n", "\n").rstrip() + "\n"
        used: set[tuple[str, str]] = set()
        for item in license_record.get("used_by", []):
            if not isinstance(item, dict) or not isinstance(item.get("crate"), dict):
                _fail("cargo-about used_by record is invalid")
            identity = _identity(item["crate"])
            if identity in external:
                used.add(identity)
                selected[identity].add(license_id)
        if used:
            blocks[(license_id, license_name, normalized_text)].update(used)
    uncovered = sorted(external - set(selected))
    if uncovered:
        _fail(f"dependencies have no selected license text: {uncovered}")

    dependency_records: list[dict[str, Any]] = []
    for identity in sorted(external):
        package = package_by_identity[identity]
        dependency_records.append(
            {
                "name": identity[0],
                "version": identity[1],
                "source": package.get("source"),
                "declared_license": package.get("license"),
                "repository": package.get("repository"),
                "selected_licenses": sorted(selected[identity]),
            }
        )

    output: list[str] = [
        "ContextDB local-MCP third-party notices",
        "=======================================",
        "",
        f"Release profile: {PROFILE_ID}",
        f"Target: {TARGET}",
        f"Cargo package: {PACKAGE}",
        f"Cargo features: {','.join(FEATURES)} (default features disabled)",
        f"Dependency graph SHA-256: {graph['sha256']}",
        f"Third-party Cargo packages: {len(dependency_records)}",
        f"Generated with cargo-about {ABOUT_VERSION} using {ABOUT_CONFIG.as_posix()}.",
        "",
        "This generated file records the license texts selected by cargo-about for",
        (
            f"the locked {PLATFORM_TARGETS[ACTIVE_PLATFORM]['display_name']} "
            "local-MCP Cargo graph. It is not legal advice."
        ),
        "ContextDB workspace crates and the Rust standard library are covered by",
        "the repository LICENSE and the separate rust-runtime notice files.",
        "",
        "Dependency index",
        "----------------",
    ]
    for dependency in dependency_records:
        output.extend(
            [
                "",
                f"{dependency['name']} {dependency['version']}",
                f"  Declared license: {dependency['declared_license']}",
                f"  Selected notice licenses: {', '.join(dependency['selected_licenses'])}",
                f"  Source: {dependency['source']}",
                f"  Repository: {dependency['repository'] or '(not declared)'}",
            ]
        )
    output.extend(["", "License texts", "-------------", ""])
    sorted_blocks = sorted(
        blocks.items(),
        key=lambda item: (item[0][0], _sha256_bytes(item[0][2].encode("utf-8"))),
    )
    for (license_id, license_name, text), packages in sorted_blocks:
        output.extend(
            [
                "=" * 79,
                f"License: {license_id} — {license_name}",
                "Applies to: " + ", ".join(f"{name} {version}" for name, version in sorted(packages)),
                f"License text SHA-256: {_sha256_bytes(text.encode('utf-8'))}",
                "=" * 79,
                "",
                text.rstrip(),
                "",
            ]
        )
    return ("\n".join(output).rstrip() + "\n").encode("utf-8"), dependency_records


def _snapshot_cyclonedx_files(root: Path) -> dict[Path, bytes]:
    snapshot = {}
    for directory, children, filenames in os.walk(root):
        # Prune build output before traversal; filtering rglob results still
        # walks every compiler artifact, especially costly across WSL mounts.
        children[:] = [name for name in children if name not in {"target", ".git"}]
        for filename in filenames:
            if filename.endswith(".cdx.json"):
                path = Path(directory) / filename
                snapshot[path] = path.read_bytes()
    return snapshot


def _generate_raw_sbom(root: Path) -> dict[str, Any]:
    # cargo-cyclonedx 0.5.9 emits one file for every workspace member. Preserve
    # all checked-in member SBOMs byte-for-byte and retain only the CLI result.
    before = _snapshot_cyclonedx_files(root)
    cli_output = root / "crates/contextdb-cli/contextdb-cli.cdx.json"
    environment = dict(os.environ)
    environment["SOURCE_DATE_EPOCH"] = "0"
    environment["CARGO_NET_OFFLINE"] = "true"
    command = [
        TOOL_CARGO,
        "cyclonedx",
        "--manifest-path",
        CLI_MANIFEST.as_posix(),
        "--no-default-features",
        "--features",
        ",".join(FEATURES),
        "--target",
        TARGET,
        "--format",
        "json",
        "--spec-version",
        "1.5",
        "-q",
    ]
    raw: bytes | None = None
    try:
        _run(command, root, env=environment)
        if not cli_output.is_file():
            _fail("cargo-cyclonedx did not emit the contextdb-cli SBOM")
        raw = cli_output.read_bytes()
    finally:
        after = _snapshot_cyclonedx_files(root)
        for path, payload in before.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        for path in set(after) - set(before):
            path.unlink(missing_ok=True)
    if raw is None:
        _fail("cargo-cyclonedx generation failed")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        _fail(f"cargo-cyclonedx emitted invalid JSON: {error}")
    if not isinstance(value, dict):
        _fail("cargo-cyclonedx emitted a non-object SBOM")
    return value


def _local_ref(identity: tuple[str, str]) -> str:
    return f"pkg:cargo/{identity[0]}@{identity[1]}"


def _sanitize_local_component(component: dict[str, Any], identity: tuple[str, str]) -> dict[str, Any]:
    sanitized = json.loads(json.dumps(component))
    reference = _local_ref(identity)
    sanitized["bom-ref"] = reference
    sanitized["purl"] = reference
    sanitized["externalReferences"] = [
        {"type": "website", "url": CANONICAL_REPOSITORY},
        {"type": "vcs", "url": CANONICAL_REPOSITORY},
    ]
    return sanitized


def _build_sbom(raw: dict[str, Any], graph: dict[str, Any]) -> bytes:
    if raw.get("bomFormat") != "CycloneDX" or raw.get("specVersion") != "1.5":
        _fail("cargo-cyclonedx did not emit CycloneDX 1.5")
    metadata = raw.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("component"), dict):
        _fail("cargo-cyclonedx SBOM lacks a metadata component")
    root_identity = graph["root"]
    if _identity(metadata["component"]) != root_identity:
        _fail("cargo-cyclonedx SBOM root is not contextdb-cli")

    by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    for component in raw.get("components", []):
        if not isinstance(component, dict):
            _fail("cargo-cyclonedx returned an invalid component")
        identity = _identity(component)
        if identity in graph["nodes"]:
            by_identity.setdefault(identity, component)
    expected_components = set(graph["nodes"]) - {root_identity}
    if set(by_identity) != expected_components:
        _fail("cargo-cyclonedx cannot cover the exact local-MCP graph")

    references: dict[tuple[str, str], str] = {root_identity: _local_ref(root_identity)}
    components: list[dict[str, Any]] = []
    for identity in sorted(expected_components):
        component = by_identity[identity]
        if graph["nodes"][identity]["local"]:
            component = _sanitize_local_component(component, identity)
        reference = component.get("bom-ref")
        if not isinstance(reference, str) or not reference:
            _fail(f"SBOM component has no bom-ref: {identity}")
        references[identity] = reference
        components.append(component)

    root_component = _sanitize_local_component(metadata["component"], root_identity)
    binary_components = root_component.get("components", [])
    if isinstance(binary_components, list):
        for component in binary_components:
            if isinstance(component, dict) and component.get("name") == "contextdb":
                component["bom-ref"] = _local_ref(root_identity) + "#contextdb"
                component["purl"] = _local_ref(root_identity) + "#contextdb"
    root_component["properties"] = [
        {"name": "contextdb:release-profile", "value": PROFILE_ID},
        {"name": "contextdb:target", "value": TARGET},
        {"name": "contextdb:cargo-features", "value": ",".join(FEATURES)},
        {"name": "contextdb:default-features", "value": "false"},
        {"name": "contextdb:network-listeners", "value": "false"},
        {"name": "contextdb:dependency-graph-sha256", "value": graph["sha256"]},
    ]

    dependencies = []
    for identity in sorted(graph["nodes"]):
        dependencies.append(
            {
                "ref": references[identity],
                "dependsOn": [
                    references[child]
                    for child in sorted(graph["edges"].get(identity, set()))
                ],
            }
        )
    output = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": "1970-01-01T00:00:00.000000000Z",
            "tools": {
                "vendor": "CycloneDX",
                "name": "cargo-cyclonedx",
                "version": CYCLONEDX_VERSION,
            },
            "component": root_component,
            "properties": [
                {"name": "contextdb:postprocessor", "value": "generate_supply_chain.py"},
                {"name": "contextdb:workspace-union-pruned", "value": "true"},
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }
    payload = _json_bytes(output)
    forbidden = [str(Path.cwd()), "file:///", "file://.", "contextdb/contextdb"]
    text = payload.decode("utf-8")
    for value in forbidden:
        if value and value.lower() in text.lower():
            _fail(f"sanitized SBOM contains a machine-local or stale value: {value}")
    return payload


def _copy_rust_runtime(root: Path, output_root: Path) -> tuple[dict[str, str], list[dict[str, Any]]]:
    sysroot, toolchain = _rust_toolchain(root)
    records = []
    for output_relative, source_relative in sorted(RUST_RUNTIME_FILES.items()):
        source = sysroot / Path(source_relative)
        if not source.is_file():
            _fail(f"pinned Rust notice file is missing: {source_relative}")
        payload = source.read_bytes()
        destination = output_root / output_relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        records.append(
            {
                "path": output_relative,
                "sysroot_relative_source": source_relative.replace("\\", "/"),
                "sha256": _sha256_bytes(payload),
                "bytes": len(payload),
            }
        )
    return toolchain, records


def _generate_to(root: Path, output_root: Path) -> dict[str, Any]:
    _workspace_package(root)
    _tool_version(
        [TOOL_CARGO, "about", "--version"], root, r"cargo-about (\S+)", ABOUT_VERSION
    )
    _tool_version(
        [TOOL_CARGO, "cyclonedx", "--version"],
        root,
        r"cargo-cyclonedx(?:-cyclonedx)? (\S+)",
        CYCLONEDX_VERSION,
    )
    graph = resolve_graph(root)
    target_dir = root / "target/local-mcp-supply-chain"
    target_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cargo-about-", dir=target_dir) as temporary:
        about = _generate_about(root, Path(temporary) / "about.json")
    notices, dependencies = _build_notices(about, graph)
    sbom = _build_sbom(_generate_raw_sbom(root), graph)

    notice_output = output_root / NOTICE_PATH
    sbom_output = output_root / SBOM_PATH
    notice_output.parent.mkdir(parents=True, exist_ok=True)
    notice_output.write_bytes(notices)
    sbom_output.write_bytes(sbom)
    toolchain, rust_files = _copy_rust_runtime(root, output_root)

    artifacts = []
    for relative in [NOTICE_PATH.as_posix(), SBOM_PATH.as_posix(), *RUST_RUNTIME_FILES]:
        path = output_root / relative
        artifacts.append(
            {"path": relative, "sha256": _sha256_file(path), "bytes": path.stat().st_size}
        )
    workspace = _workspace_package(root)
    manifest = {
        "schema_version": SCHEMA,
        "profile_id": PROFILE_ID,
        "release_class": "developer-preview",
        "canonical_repository": CANONICAL_REPOSITORY,
        "core_version": workspace["version"],
        "target": TARGET,
        "cargo": {
            "package": PACKAGE,
            "locked": True,
            "default_features": False,
            "features": FEATURES,
            "dependency_kinds": ["normal", "build"],
            "cargo_lock_sha256": _sha256_file(root / LOCK_FILE),
        },
        "tools": {"cargo_about": ABOUT_VERSION, "cargo_cyclonedx": CYCLONEDX_VERSION},
        "graph": {
            "sha256": graph["sha256"],
            "component_count": len(graph["nodes"]),
            "third_party_component_count": len(graph["external"]),
        },
        "dependencies": dependencies,
        "rust_toolchain": {**toolchain, "files": rust_files},
        "artifacts": sorted(artifacts, key=lambda item: item["path"]),
        "claims": {
            "developer_preview": True,
            "network_listeners": False,
            "signed": False,
            "published": False,
            "formal_release_ready": False,
        },
    }
    manifest_output = output_root / MANIFEST_PATH
    manifest_output.parent.mkdir(parents=True, exist_ok=True)
    manifest_output.write_bytes(_json_bytes(manifest))
    return manifest


def _sbom_identities(sbom: dict[str, Any]) -> set[tuple[str, str]]:
    metadata = sbom.get("metadata", {})
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(component, dict):
        _fail("checked SBOM lacks its root component")
    identities = {_identity(component)}
    for item in sbom.get("components", []):
        if not isinstance(item, dict):
            _fail("checked SBOM contains an invalid component")
        identities.add(_identity(item))
    return identities


def verify_artifacts(root: Path, cargo: str = "cargo") -> dict[str, Any]:
    workspace = _workspace_package(root)
    manifest_path = _evidence_path(root, MANIFEST_PATH)
    manifest = _read_json(manifest_path)
    if manifest.get("schema_version") != SCHEMA or manifest.get("profile_id") != PROFILE_ID:
        _fail("unsupported local-MCP supply-chain manifest")
    if manifest.get("canonical_repository") != CANONICAL_REPOSITORY:
        _fail("supply-chain manifest has a stale repository URL")
    if manifest.get("core_version") != workspace.get("version"):
        _fail("supply-chain manifest core version differs from the workspace")
    if manifest.get("target") != TARGET:
        _fail("supply-chain manifest target differs from the package profile")
    tools = manifest.get("tools")
    if tools != {"cargo_about": ABOUT_VERSION, "cargo_cyclonedx": CYCLONEDX_VERSION}:
        _fail("supply-chain generator versions are not pinned")
    cargo_contract = manifest.get("cargo")
    if not isinstance(cargo_contract, dict) or cargo_contract != {
        "package": PACKAGE,
        "locked": True,
        "default_features": False,
        "features": FEATURES,
        "dependency_kinds": ["normal", "build"],
        "cargo_lock_sha256": _sha256_file(root / LOCK_FILE),
    }:
        _fail("supply-chain Cargo contract or Cargo.lock digest differs")

    graph = resolve_graph(root, cargo)
    graph_receipt = manifest.get("graph")
    if not isinstance(graph_receipt, dict) or graph_receipt != {
        "sha256": graph["sha256"],
        "component_count": len(graph["nodes"]),
        "third_party_component_count": len(graph["external"]),
    }:
        _fail("supply-chain graph receipt differs from the exact local-MCP graph")

    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, list):
        _fail("supply-chain dependency receipt is missing")
    dependency_identities = set()
    for item in dependencies:
        if not isinstance(item, dict):
            _fail("supply-chain dependency receipt contains an invalid item")
        identity = _identity(item)
        selected = item.get("selected_licenses")
        if not isinstance(selected, list) or not selected or not all(
            isinstance(value, str) and value for value in selected
        ):
            _fail(f"dependency has no selected notice licenses: {identity}")
        dependency_identities.add(identity)
    if dependency_identities != graph["external"]:
        _fail("supply-chain dependency receipt does not cover the third-party graph")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        _fail("supply-chain artifact receipt is missing")
    expected_artifacts = {
        NOTICE_PATH.as_posix(),
        SBOM_PATH.as_posix(),
        *RUST_RUNTIME_FILES,
    }
    seen_artifacts = set()
    for item in artifacts:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            _fail("supply-chain artifact receipt contains an invalid item")
        relative = item["path"]
        path = _evidence_path(root, relative)
        if not path.is_file():
            _fail(f"supply-chain artifact is missing: {relative}")
        if item.get("sha256") != _sha256_file(path) or item.get("bytes") != path.stat().st_size:
            _fail(f"supply-chain artifact receipt mismatch: {relative}")
        seen_artifacts.add(relative)
    if seen_artifacts != expected_artifacts:
        _fail("supply-chain artifact set differs from the required bundle")

    notice = _evidence_path(root, NOTICE_PATH).read_text(encoding="utf-8")
    for identity in graph["external"]:
        if f"\n{identity[0]} {identity[1]}\n" not in notice:
            _fail(f"third-party notice index is missing {identity}")
    sbom_path = _evidence_path(root, SBOM_PATH)
    sbom = _read_json(sbom_path)
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        _fail("checked SBOM is not CycloneDX 1.5 JSON")
    if _sbom_identities(sbom) != set(graph["nodes"]):
        _fail("checked SBOM components differ from the exact local-MCP graph")
    sbom_text = sbom_path.read_text(encoding="utf-8")
    for forbidden in ("file:///", "file://.", "contextdb/contextdb", str(root.resolve())):
        if forbidden.lower() in sbom_text.lower():
            _fail(f"checked SBOM contains a local or stale value: {forbidden}")

    sysroot, toolchain = _rust_toolchain(root)
    rust_receipt = manifest.get("rust_toolchain")
    if not isinstance(rust_receipt, dict):
        _fail("Rust runtime notice receipt is missing")
    if (
        rust_receipt.get("release") != toolchain["release"]
        or rust_receipt.get("commit_hash") != toolchain["commit_hash"]
        or rust_receipt.get("host")
        not in {configuration["target"] for configuration in PLATFORM_TARGETS.values()}
    ):
        _fail("Rust runtime notice receipt does not name a supported pinned toolchain")
    rust_files = rust_receipt.get("files")
    if not isinstance(rust_files, list) or len(rust_files) != len(RUST_RUNTIME_FILES):
        _fail("Rust runtime notice receipt is incomplete")
    for item in rust_files:
        if not isinstance(item, dict):
            _fail("Rust runtime notice receipt contains an invalid item")
        output = item.get("path")
        source_relative = item.get("sysroot_relative_source")
        if output not in RUST_RUNTIME_FILES or source_relative != RUST_RUNTIME_FILES[output]:
            _fail("Rust runtime notice receipt contains an unexpected path")
        source = sysroot / source_relative
        packaged = _evidence_path(root, output)
        if (
            not source.is_file()
            or not packaged.is_file()
            or item.get("sha256") != _sha256_file(source)
            or item.get("sha256") != _sha256_file(packaged)
            or item.get("bytes") != source.stat().st_size
        ):
            _fail(f"Rust runtime notice differs from the pinned sysroot: {output}")

    claims = manifest.get("claims")
    if claims != {
        "developer_preview": True,
        "network_listeners": False,
        "signed": False,
        "published": False,
        "formal_release_ready": False,
    }:
        _fail("supply-chain manifest overclaims release status")
    return {
        "status": "passed",
        "profile_id": PROFILE_ID,
        "graph_sha256": graph["sha256"],
        "component_count": len(graph["nodes"]),
        "third_party_component_count": len(graph["external"]),
        "target": TARGET,
        "platform": ACTIVE_PLATFORM,
        "manifest_sha256": _sha256_file(manifest_path),
    }


def _replace_generated(root: Path, generated: Path) -> None:
    required = [NOTICE_PATH, SBOM_PATH, MANIFEST_PATH, *map(Path, RUST_RUNTIME_FILES)]
    for relative in required:
        source = generated / relative
        if not source.is_file():
            _fail(f"generator did not produce {relative.as_posix()}")
        destination = _evidence_path(root, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def _generate(root: Path) -> dict[str, Any]:
    target = root / "target/local-mcp-supply-chain" / ACTIVE_PLATFORM
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="generate-", dir=target) as temporary:
        generated = Path(temporary)
        _generate_to(root, generated)
        _replace_generated(root, generated)
    return verify_artifacts(root)


def _check(root: Path) -> dict[str, Any]:
    verified = verify_artifacts(root)
    target = root / "target/local-mcp-supply-chain" / ACTIVE_PLATFORM
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="check-", dir=target) as temporary:
        generated = Path(temporary)
        _generate_to(root, generated)
        for relative in [NOTICE_PATH, SBOM_PATH, MANIFEST_PATH, *map(Path, RUST_RUNTIME_FILES)]:
            checked = _evidence_path(root, relative)
            fresh = generated / relative
            if checked.read_bytes() != fresh.read_bytes():
                _fail(f"checked-in supply-chain artifact is stale: {relative.as_posix()}")
    return verified


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "verify", "check"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument(
        "--tool-cargo",
        default="cargo",
        help="Cargo executable exposing the pinned cargo-about and cargo-cyclonedx tools",
    )
    parser.add_argument(
        "--platform",
        choices=sorted(PLATFORM_TARGETS),
        help="target evidence set; defaults to the current supported x86_64 host",
    )
    return parser


def main() -> int:
    global TOOL_CARGO

    args = _parser().parse_args()
    root = args.root.resolve()
    try:
        _activate_platform(args.platform)
        TOOL_CARGO = args.tool_cargo
        if args.command == "generate":
            result = _generate(root)
        elif args.command == "check":
            result = _check(root)
        else:
            result = verify_artifacts(root, args.cargo)
    except SupplyChainError as error:
        print(f"local-mcp-supply-chain: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
