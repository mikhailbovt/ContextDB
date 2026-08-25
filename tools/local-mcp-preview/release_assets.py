#!/usr/bin/env python3
"""Validate and assemble target-bound ContextDB GitHub prerelease assets."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import sys
import tomllib
import zipfile
from pathlib import Path
from typing import Any, Sequence

import local_mcp_preview as preview


SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$")


class ReleaseAssetError(RuntimeError):
    """The tagged source or generated release asset violates its contract."""


def _version(root: Path) -> str:
    with (root / "version.toml").open("rb") as stream:
        version = tomllib.load(stream).get("version")
    if not isinstance(version, str) or SEMVER.fullmatch(version) is None:
        raise ReleaseAssetError("version.toml contains an invalid release version")
    if version != preview._workspace_version(root):
        raise ReleaseAssetError("version.toml and Cargo workspace versions differ")
    return version


def _asset_names(version: str, platform_name: str) -> list[str]:
    _, configuration = preview._platform_configuration(platform_name)
    extension = ".exe" if configuration["operating_system"] == "windows" else ""
    standalone = f"contextdb-{platform_name}{extension}"
    archive = f"contextdb-local-mcp-{version}-{platform_name}.zip"
    return [standalone, f"{standalone}.sha256", archive, f"{archive}.sha256"]


def validate_tag(root: Path, tag: str, github_env: Path | None) -> dict[str, Any]:
    version = _version(root)
    expected = f"v{version}"
    if tag != expected:
        raise ReleaseAssetError(f"release tag {tag!r} does not match {expected!r}")
    if github_env is not None:
        with github_env.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"VERSION={version}\n")
    return {"status": "passed", "tag": expected, "version": version}


def prepare(root: Path, platform_name: str, dist: Path, target_dir: Path) -> dict[str, Any]:
    version = _version(root)
    _, configuration = preview._platform_configuration(platform_name)
    names = _asset_names(version, platform_name)
    standalone, standalone_sidecar, archive, archive_sidecar = (dist / name for name in names)
    verification = preview.verify_archive(archive, archive_sidecar)
    if verification.get("profile_id") != configuration["profile_id"]:
        raise ReleaseAssetError("verified package targets a different platform profile")
    if verification.get("distributable") is not True:
        raise ReleaseAssetError("refusing to publish a package produced from a dirty checkout")

    built = target_dir / "release" / configuration["binary_name"]
    binary = preview.inspect_binary(built, root, version, platform_name)
    shutil.copy2(built, standalone)
    if configuration["operating_system"] == "linux":
        standalone.chmod(standalone.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    digest = preview._sha256_file(standalone)
    standalone_sidecar.write_text(
        f"{digest}  {standalone.name}\n", encoding="ascii", newline="\n"
    )
    with zipfile.ZipFile(archive) as package:
        package_root = archive.name.removesuffix(".zip")
        packaged = package.read(f"{package_root}/{configuration['binary_name']}")
    if preview.hashlib.sha256(packaged).hexdigest() != digest or binary["sha256"] != digest:
        raise ReleaseAssetError("standalone bytes differ from the verified packaged binary")

    actual = {path.name for path in dist.iterdir() if path.is_file()}
    if actual != set(names):
        raise ReleaseAssetError("target distribution must contain its exact four release assets")
    return {
        "status": "passed",
        "version": version,
        "platform": platform_name,
        "target": configuration["target"],
        "binary_sha256": digest,
        "archive_sha256": verification["archive_sha256"],
        "assets": names,
    }


def verify_release_set(root: Path, dist: Path) -> dict[str, Any]:
    version = _version(root)
    expected = {
        name
        for platform_name in preview.PLATFORMS
        for name in _asset_names(version, platform_name)
    }
    actual = {path.name for path in dist.iterdir() if path.is_file()}
    if actual != expected:
        raise ReleaseAssetError(
            f"release asset set mismatch: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )
    for platform_name in preview.PLATFORMS:
        standalone_name, standalone_sidecar_name, archive_name, archive_sidecar_name = _asset_names(
            version, platform_name
        )
        verification = preview.verify_archive(dist / archive_name, dist / archive_sidecar_name)
        _, configuration = preview._platform_configuration(platform_name)
        if verification.get("profile_id") != configuration["profile_id"]:
            raise ReleaseAssetError(f"release archive profile mismatch: {platform_name}")
        standalone = dist / standalone_name
        expected_sidecar = f"{preview._sha256_file(standalone)}  {standalone_name}\n"
        if (dist / standalone_sidecar_name).read_text(encoding="ascii") != expected_sidecar:
            raise ReleaseAssetError(f"standalone hash sidecar mismatch: {platform_name}")
    return {"status": "passed", "version": version, "assets": sorted(expected)}


def write_notes(root: Path, destination: Path, source_commit: str) -> dict[str, Any]:
    version = _version(root)
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ReleaseAssetError("release source commit is not a full lowercase SHA-1")
    lines = [
        f"ContextDB {version} local MCP developer preview for Linux and Windows x86-64.",
        "",
        "Both native builds are unsigned, listener-free, local-only previews for trusted "
        "single-user workstations. Each exposes `build_profile local-mcp`, "
        "`network_listeners disabled`, and an authenticated single-owner local MCP broker; "
        "the `serve` and `probe` commands are not compiled into the CLI surface.",
        "",
        "### Linux x86-64",
        "",
        "- `contextdb-linux-x86_64` — standalone native ELF executable.",
        "- `contextdb-linux-x86_64.sha256` — exact executable SHA-256.",
        "- Compatibility baseline: Ubuntu 22.04 LTS / glibc 2.35 or newer; the "
        "release gate rejects ELFs importing newer GLIBC symbol versions.",
        f"- `contextdb-local-mcp-{version}-linux-x86_64.zip` — verified Linux package "
        "with its Linux-target graph, notices, CycloneDX SBOM, profile, and receipt.",
        f"- `contextdb-local-mcp-{version}-linux-x86_64.zip.sha256` — package SHA-256.",
        "",
        "### Windows x86-64",
        "",
        "- `contextdb-windows-x86_64.exe` — standalone native executable.",
        "- `contextdb-windows-x86_64.exe.sha256` — exact executable SHA-256.",
        f"- `contextdb-local-mcp-{version}-windows-x86_64.zip` — verified Windows package "
        "with its Windows-target graph, notices, CycloneDX SBOM, profile, and receipt.",
        f"- `contextdb-local-mcp-{version}-windows-x86_64.zip.sha256` — package SHA-256.",
        "",
        "This developer preview is not the formal ContextDB M18 Alpha release and makes no "
        "production hard-delete, hostile-local-user, multi-tenant, remote-service, signing, "
        "automatic-update, Linux arm64, or macOS support claim. Pin the exact SHA-256 and "
        "use synthetic or non-critical data.",
        "",
        f"Source commit: `{source_commit}`",
        "",
    ]
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return {"status": "passed", "version": version, "notes": str(destination)}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    subparsers = parser.add_subparsers(dest="command", required=True)
    tagged = subparsers.add_parser("validate-tag")
    tagged.add_argument("--tag", required=True)
    tagged.add_argument("--github-env", type=Path)
    prepared = subparsers.add_parser("prepare")
    prepared.add_argument("--platform", required=True, choices=sorted(preview.PLATFORMS))
    prepared.add_argument("--dist", required=True, type=Path)
    prepared.add_argument("--target-dir", required=True, type=Path)
    verified = subparsers.add_parser("verify-release-set")
    verified.add_argument("--dist", required=True, type=Path)
    notes = subparsers.add_parser("write-notes")
    notes.add_argument("--output", required=True, type=Path)
    notes.add_argument("--source-commit", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    root = arguments.root.resolve()
    try:
        if arguments.command == "validate-tag":
            result = validate_tag(root, arguments.tag, arguments.github_env)
        elif arguments.command == "prepare":
            result = prepare(root, arguments.platform, arguments.dist, arguments.target_dir)
        elif arguments.command == "verify-release-set":
            result = verify_release_set(root, arguments.dist)
        else:
            result = write_notes(root, arguments.output, arguments.source_commit)
    except (OSError, UnicodeError, preview.ContractError, ReleaseAssetError) as error:
        print(f"local-mcp-release-assets: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
