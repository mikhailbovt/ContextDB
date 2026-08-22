from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

TOOL_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOL_ROOT.parents[1]
sys.path.insert(0, str(TOOL_ROOT))

from contextdb_release import (
    ContractError,
    _verify_declared_media_type,
    assemble_bundle,
)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def file_reference(
    source_root: Path, source: str, destination: str
) -> dict[str, object]:
    path = source_root.joinpath(*Path(source).parts)
    return {
        "source_path": source,
        "path": destination,
        "sha256": digest(path),
        "size_bytes": path.stat().st_size,
        "media_type": "application/json",
    }


class BundleAssemblerTests(unittest.TestCase):
    epoch = 1786492800

    def make_inputs(self, root: Path) -> tuple[Path, Path]:
        source = root / "inputs"
        source.mkdir()
        commit = "1" * 40
        version = "0.1.0-alpha.1"
        write_json(
            source / "version-source.json",
            {
                "schema_version": "contextdb.version-manifest/v1",
                "product_version": version,
                "release_channel": "alpha",
                "source": {
                    "git_commit": commit,
                    "dirty": False,
                    "repository": "https://example.invalid/contextdb",
                    "rfc_revision": "RFC-0001-v0.3",
                    "errata": [],
                    "adrs": [],
                },
                "build": {
                    "timestamp": "2026-08-12T00:00:00Z",
                    "rustc": "rustc-test",
                    "cargo": "cargo-test",
                    "target": "platform-independent",
                    "profile": "release-safe",
                    "reproducible": True,
                },
                "formats": {
                    "logical": {
                        "writer": 1,
                        "read_min": 1,
                        "read_max": 1,
                        "required_features": [],
                    }
                },
                "feature_profile": "conformance",
                "features": [],
            },
        )
        write_json(
            source / "ledger-source.json",
            {
                "schema_version": "contextdb.roadmap-gate-ledger/v1",
                "roadmap_revision": "assembler-test-v1",
                "status_vocabulary": [
                    "not_started",
                    "in_progress",
                    "blocked",
                    "passed",
                    "failed",
                    "waived",
                ],
                "rules": {
                    "dependency_closure_required": True,
                    "proof_required": True,
                    "waiver_policy": "Test waiver requires an ADR.",
                    "release_gate": "M19",
                },
                "milestones": [
                    {
                        "id": f"M{number}",
                        "title": f"Test {number}",
                        "status": "in_progress" if number == 0 else "not_started",
                        "depends_on": [] if number == 0 else [f"M{number - 1}"],
                        "objective": "Test",
                        "artifacts": ["test"],
                        "tests": ["test"],
                        "benchmarks": ["test"],
                        "demo": "test",
                        "exit_criteria": [{"id": f"M{number}-E01", "text": "test"}],
                        "required_proof": [
                            {
                                "kind": "test_report",
                                "path": f"proof/M{number}/evidence.json",
                            }
                        ],
                    }
                    for number in range(20)
                ],
            },
        )
        write_json(source / "proof-source.json", {"passed": False})
        write_json(source / "artifact-source.json", {"dataset": "fixture"})
        ledger_ref = file_reference(
            source, "ledger-source.json", "docs/roadmap/gates.json"
        )
        proof_ref = file_reference(
            source, "proof-source.json", "proof/M0/evidence.json"
        )
        write_json(
            source / "proof-index-source.json",
            {
                "schema_version": "contextdb.release-proof-index/v1",
                "release_version": version,
                "release_stage": "alpha",
                "generated_at": "2026-08-12T00:00:00Z",
                "ledger": {
                    "path": ledger_ref["path"],
                    "sha256": ledger_ref["sha256"],
                    "roadmap_revision": "assembler-test-v1",
                },
                "milestones": [
                    {
                        "id": "M0",
                        "status": "in-progress",
                        "exit_criteria": [
                            {
                                "id": "M0-E01",
                                "status": "in-progress",
                                "evidence": [
                                    {
                                        "kind": "test_report",
                                        "path": proof_ref["path"],
                                        "sha256": proof_ref["sha256"],
                                        "evidence_level": "source",
                                    }
                                ],
                            }
                        ],
                        "required_proofs": [
                            {
                                "kind": "test_report",
                                "path": proof_ref["path"],
                                "sha256": proof_ref["sha256"],
                                "evidence_level": "source",
                            }
                        ],
                        "limitations": ["test fixture"],
                    }
                ],
                "known_gaps": [
                    {"gate_id": "M0-E01", "reason": "test fixture", "blocking": True}
                ],
            },
        )
        artifact_ref = file_reference(
            source, "artifact-source.json", "artifacts/benchmark-dataset.json"
        )
        input_manifest = {
            "schema_version": "contextdb.release-bundle-input/v1",
            "release": {
                "version": version,
                "channel": "alpha",
                "created_at": "2026-08-12T00:00:00Z",
                "candidate": 1,
            },
            "source": {
                "repository": "https://example.invalid/contextdb",
                "git_commit": commit,
                "dirty": False,
            },
            "version_manifest": file_reference(
                source, "version-source.json", "release/version.json"
            ),
            "proof_index": file_reference(
                source, "proof-index-source.json", "release/proof-index.json"
            ),
            "artifacts": [
                {
                    "id": "benchmark-dataset-fixture",
                    "package_id": "benchmark-datasets",
                    "roles": ["benchmark-datasets"],
                    "kind": "benchmark-dataset",
                    **artifact_ref,
                    "targets": ["platform-independent"],
                    "version": version,
                    "provenance": {
                        "source_commit": commit,
                        "builder": "unit-test",
                        "build_recipe": "release/package-matrix.json",
                        "reproducible": True,
                    },
                    "related_files": [],
                }
            ],
            "supporting_files": [
                {**ledger_ref, "purpose": "roadmap-ledger"},
                {**proof_ref, "purpose": "proof"},
            ],
            "limitations": ["offline partial assembly fixture; not a release"],
        }
        manifest_path = root / "input-manifest.json"
        write_json(manifest_path, input_manifest)
        return source, manifest_path

    def assemble(
        self, root: Path, output_name: str = "bundle"
    ) -> tuple[Path, dict[str, Any]]:
        source, manifest = self.make_inputs(root)
        output = root / output_name
        receipt = assemble_bundle(
            source,
            manifest,
            REPO_ROOT / "release" / "package-matrix.json",
            output,
            self.epoch,
        )
        return output, receipt

    def test_assembles_only_declared_and_generated_files(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            with patch(
                "contextdb_release.subprocess.run",
                side_effect=AssertionError(
                    "assembler must not execute child processes"
                ),
            ):
                output, receipt = self.assemble(root)
            files = sorted(
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file()
            )
            self.assertEqual(
                files,
                [
                    "SHA256SUMS",
                    "artifacts/benchmark-dataset.json",
                    "docs/roadmap/gates.json",
                    "proof/M0/evidence.json",
                    "release/artifact-manifest.json",
                    "release/package-matrix.json",
                    "release/proof-index.json",
                    "release/version.json",
                ],
            )
            self.assertFalse((output / "release" / "signatures.json").exists())
            self.assertFalse(receipt["release_ready"])
            self.assertIn("production-signatures", receipt["unresolved_release_gates"])
            manifest = json.loads(
                (output / "release" / "artifact-manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(manifest["release"]["created_at"], "2026-08-12T00:00:00Z")
            self.assertEqual(manifest["artifacts"][0]["version"], "0.1.0-alpha.1")
            self.assertNotIn("source_path", manifest["artifacts"][0])

    def test_canonical_checksums_are_sorted_and_exhaustive(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            output, _ = self.assemble(Path(value))
            checksum = (output / "SHA256SUMS").read_bytes()
            self.assertNotIn(b"\r", checksum)
            self.assertTrue(checksum.endswith(b"\n"))
            lines = checksum.decode("utf-8").splitlines()
            paths = [line.split("  ", 1)[1] for line in lines]
            self.assertEqual(
                paths, sorted(paths, key=lambda item: item.encode("utf-8"))
            )
            expected = {
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file() and path.name != "SHA256SUMS"
            }
            self.assertEqual(set(paths), expected)
            for line in lines:
                expected_digest, relative = line.split("  ", 1)
                self.assertEqual(expected_digest, digest(output / relative))

    def test_repeated_assembly_is_byte_identical(self) -> None:
        with (
            tempfile.TemporaryDirectory() as first_value,
            tempfile.TemporaryDirectory() as second_value,
        ):
            first_output, first_receipt = self.assemble(Path(first_value))
            second_output, second_receipt = self.assemble(Path(second_value))
            first_files = {
                path.relative_to(first_output).as_posix(): path.read_bytes()
                for path in first_output.rglob("*")
                if path.is_file()
            }
            second_files = {
                path.relative_to(second_output).as_posix(): path.read_bytes()
                for path in second_output.rglob("*")
                if path.is_file()
            }
            self.assertEqual(first_files, second_files)
            self.assertEqual(
                first_receipt["output"]["tree_sha256"],
                second_receipt["output"]["tree_sha256"],
            )
            self.assertTrue(
                all(
                    int(path.stat().st_mtime) == self.epoch
                    for path in first_output.rglob("*")
                )
            )

    def test_rejects_preexisting_output(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest = self.make_inputs(root)
            output = root / "bundle"
            output.mkdir()
            with self.assertRaisesRegex(ContractError, "must not already exist"):
                assemble_bundle(
                    source,
                    manifest,
                    REPO_ROOT / "release" / "package-matrix.json",
                    output,
                    self.epoch,
                )

    def test_failed_transaction_leaves_no_output_or_staging_directory(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["artifacts"][0]["sha256"] = "0" * 64
            write_json(manifest_path, data)
            with self.assertRaisesRegex(ContractError, "SHA-256 mismatch"):
                assemble_bundle(
                    source,
                    manifest_path,
                    REPO_ROOT / "release" / "package-matrix.json",
                    root / "bundle",
                    self.epoch,
                )
            self.assertFalse((root / "bundle").exists())
            self.assertEqual(list(root.glob(".bundle.assemble-*")), [])

    def test_rejects_digest_size_media_version_and_target_mismatches(self) -> None:
        mutations: dict[str, Callable[[dict[str, Any]], None]] = {
            "SHA-256 mismatch": lambda data: data["artifacts"][0].__setitem__(
                "sha256", "0" * 64
            ),
            "size mismatch": lambda data: data["artifacts"][0].__setitem__(
                "size_bytes", 999999
            ),
            "not a valid ZIP": lambda data: data["artifacts"][0].__setitem__(
                "media_type", "application/zip"
            ),
            "version differs": lambda data: data["artifacts"][0].__setitem__(
                "version", "0.1.0-alpha.2"
            ),
            "undeclared targets": lambda data: data["artifacts"][0].__setitem__(
                "targets", ["linux-x86-64"]
            ),
        }
        for expected, mutate in mutations.items():
            with (
                self.subTest(expected=expected),
                tempfile.TemporaryDirectory() as value,
            ):
                root = Path(value)
                source, manifest_path = self.make_inputs(root)
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
                mutate(data)
                write_json(manifest_path, data)
                with self.assertRaisesRegex(ContractError, expected):
                    assemble_bundle(
                        source,
                        manifest_path,
                        REPO_ROOT / "release" / "package-matrix.json",
                        root / "bundle",
                        self.epoch,
                    )

    def test_executable_media_is_bound_to_target_magic(self) -> None:
        cases = (
            ("windows-x86-64", b"MZ\x00\x00", True),
            ("linux-x86-64", b"\x7fELF", True),
            ("macos-arm64", b"\xcf\xfa\xed\xfe", True),
            ("windows-x86-64", b"\x7fELF", False),
        )
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            for index, (target, payload, accepted) in enumerate(cases):
                with self.subTest(target=target, accepted=accepted):
                    path = root / f"binary-{index}"
                    path.write_bytes(payload)
                    if accepted:
                        _verify_declared_media_type(
                            path,
                            "application/octet-stream",
                            "binary",
                            artifact_kind="executable",
                            targets=[target],
                        )
                    else:
                        with self.assertRaisesRegex(ContractError, "lacks PE MZ magic"):
                            _verify_declared_media_type(
                                path,
                                "application/octet-stream",
                                "binary",
                                artifact_kind="executable",
                                targets=[target],
                            )

    def test_rejects_unreadable_declared_format_version(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            version_path = source / "version-source.json"
            version = json.loads(version_path.read_text(encoding="utf-8"))
            version["formats"]["logical"]["writer"] = 2
            write_json(version_path, version)
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["version_manifest"] = file_reference(
                source, "version-source.json", "release/version.json"
            )
            write_json(manifest_path, data)
            with self.assertRaisesRegex(ContractError, "outside its readable range"):
                assemble_bundle(
                    source,
                    manifest_path,
                    REPO_ROOT / "release" / "package-matrix.json",
                    root / "bundle",
                    self.epoch,
                )

    def test_rejects_traversal_and_duplicate_paths(self) -> None:
        mutations: dict[str, Callable[[dict[str, Any]], None]] = {
            "schema violation": lambda data: data["supporting_files"][0].__setitem__(
                "path", "../escape.json"
            ),
            "case-colliding": lambda data: data["supporting_files"][1].__setitem__(
                "path", "DOCS/ROADMAP/GATES.JSON"
            ),
            "prefix collision": lambda data: data["supporting_files"][1].__setitem__(
                "path", "artifacts"
            ),
        }
        for expected, mutate in mutations.items():
            with (
                self.subTest(expected=expected),
                tempfile.TemporaryDirectory() as value,
            ):
                root = Path(value)
                source, manifest_path = self.make_inputs(root)
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
                mutate(data)
                write_json(manifest_path, data)
                with self.assertRaisesRegex(ContractError, expected):
                    assemble_bundle(
                        source,
                        manifest_path,
                        REPO_ROOT / "release" / "package-matrix.json",
                        root / "bundle",
                        self.epoch,
                    )

    def test_rejects_duplicate_package_target_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            write_json(source / "artifact-source-two.json", {"dataset": "second"})
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            second = json.loads(json.dumps(data["artifacts"][0]))
            second["id"] = "benchmark-dataset-fixture-two"
            second.update(
                file_reference(
                    source,
                    "artifact-source-two.json",
                    "artifacts/benchmark-dataset-two.json",
                )
            )
            data["artifacts"].append(second)
            write_json(manifest_path, data)
            with self.assertRaisesRegex(ContractError, "both claim package target"):
                assemble_bundle(
                    source,
                    manifest_path,
                    REPO_ROOT / "release" / "package-matrix.json",
                    root / "bundle",
                    self.epoch,
                )

    def test_rejects_key_sidecars_and_private_key_content(self) -> None:
        for mode in (
            "sidecar",
            "source-sidecar",
            "content",
            "encrypted-content",
            "secret-field",
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as value:
                root = Path(value)
                source, manifest_path = self.make_inputs(root)
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
                if mode == "sidecar":
                    data["artifacts"][0]["path"] = "artifacts/token.key"
                    expected = "key material"
                elif mode == "source-sidecar":
                    write_json(source / "token.key", {"dataset": "fixture"})
                    data["artifacts"][0].update(
                        file_reference(
                            source,
                            "token.key",
                            "artifacts/benchmark-dataset.json",
                        )
                    )
                    expected = "source_path names forbidden key material"
                else:
                    if mode == "content":
                        content = {
                            "value": (
                                "-----BEGIN PRIVATE KEY-----\n"
                                "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=\n"
                                "-----END PRIVATE KEY-----"
                            )
                        }
                        expected = "private-key material"
                    elif mode == "encrypted-content":
                        content = {
                            "value": (
                                "-----BEGIN RSA PRIVATE KEY-----\n"
                                "Proc-Type: 4,ENCRYPTED\n"
                                "DEK-Info: AES-256-CBC,0000000000000000\n\n"
                                "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=\n"
                                "-----END RSA PRIVATE KEY-----"
                            )
                        }
                        expected = "private-key material"
                    else:
                        content = {"api_key": "should-not-ship"}
                        expected = "non-redacted secret-bearing JSON field"
                    write_json(source / "artifact-source.json", content)
                    data["artifacts"][0].update(
                        file_reference(
                            source,
                            "artifact-source.json",
                            "artifacts/benchmark-dataset.json",
                        )
                    )
                write_json(manifest_path, data)
                with self.assertRaisesRegex(ContractError, expected):
                    assemble_bundle(
                        source,
                        manifest_path,
                        REPO_ROOT / "release" / "package-matrix.json",
                        root / "bundle",
                        self.epoch,
                    )
        with tempfile.TemporaryDirectory() as value:
            redacted = Path(value) / "redacted.json"
            write_json(redacted, {"api_key": "<redacted>"})
            _verify_declared_media_type(
                redacted,
                "application/json",
                "redacted JSON",
            )
            array_json = Path(value) / "dataset.json"
            array_json.write_text('[{"value": 1}]\n', encoding="utf-8")
            _verify_declared_media_type(
                array_json,
                "application/json",
                "array dataset JSON",
            )

        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["limitations"] = [
                (
                    "-----BEGIN PRIVATE KEY-----\n"
                    "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=\n"
                    "-----END PRIVATE KEY-----"
                )
            ]
            write_json(manifest_path, data)
            with self.assertRaisesRegex(ContractError, "private-key material"):
                assemble_bundle(
                    source,
                    manifest_path,
                    REPO_ROOT / "release" / "package-matrix.json",
                    root / "bundle",
                    self.epoch,
                )

    def test_rejects_broken_output_symlink_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            output = root / "bundle"
            try:
                output.symlink_to(root / "missing-output", target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlink creation is unavailable: {error}")
            with self.assertRaisesRegex(ContractError, "must not already exist"):
                assemble_bundle(
                    source,
                    manifest_path,
                    REPO_ROOT / "release" / "package-matrix.json",
                    output,
                    self.epoch,
                )

    def test_rejects_credentials_in_source_repository_uri(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["source"]["repository"] = "https://user:secret@example.org/repo"
            write_json(manifest_path, data)
            with self.assertRaisesRegex(ContractError, "credential-free HTTPS"):
                assemble_bundle(
                    source,
                    manifest_path,
                    REPO_ROOT / "release" / "package-matrix.json",
                    root / "bundle",
                    self.epoch,
                )

    def test_rejects_archive_traversal_and_embedded_key_sidecar(self) -> None:
        for member, expected in (
            ("../escape", "canonical relative"),
            ("token.key", "key material"),
        ):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as value:
                root = Path(value)
                source, manifest_path = self.make_inputs(root)
                archive_path = source / "artifact.zip"
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr(member, b"payload")
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
                reference = file_reference(
                    source, "artifact.zip", "artifacts/dataset.zip"
                )
                reference["media_type"] = "application/zip"
                data["artifacts"][0].update(reference)
                write_json(manifest_path, data)
                with self.assertRaisesRegex(ContractError, expected):
                    assemble_bundle(
                        source,
                        manifest_path,
                        REPO_ROOT / "release" / "package-matrix.json",
                        root / "bundle",
                        self.epoch,
                    )
        with tempfile.TemporaryDirectory() as value:
            source_archive = Path(value) / "source.zip"
            with zipfile.ZipFile(source_archive, "w") as archive:
                archive.writestr("src/state_head.rs", b"pub struct StateHead;\n")
                archive.writestr("src/token_key.rs", b"pub struct TokenKey;\n")
            _verify_declared_media_type(
                source_archive,
                "application/zip",
                "source archive",
            )

    def test_rejects_renamed_state_head_and_archived_json_secret(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            write_json(
                source / "artifact-source.json",
                {
                    "schema_version": 1,
                    "authority_binding": "fixture",
                    "active": None,
                    "pending": None,
                    "mac": "0" * 64,
                },
            )
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["artifacts"][0].update(
                file_reference(
                    source,
                    "artifact-source.json",
                    "artifacts/innocent-name.json",
                )
            )
            write_json(manifest_path, data)
            with self.assertRaisesRegex(ContractError, "state-head authority JSON"):
                assemble_bundle(
                    source,
                    manifest_path,
                    REPO_ROOT / "release" / "package-matrix.json",
                    root / "bundle",
                    self.epoch,
                )

        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            archive_path = source / "artifact.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("config.json", b'{"api_key":"must-not-ship"}\n')
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            reference = file_reference(source, "artifact.zip", "artifacts/dataset.zip")
            reference["media_type"] = "application/zip"
            data["artifacts"][0].update(reference)
            write_json(manifest_path, data)
            with self.assertRaisesRegex(ContractError, "secret-bearing JSON field"):
                assemble_bundle(
                    source,
                    manifest_path,
                    REPO_ROOT / "release" / "package-matrix.json",
                    root / "bundle",
                    self.epoch,
                )

    def test_rejects_tar_link_member(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            path = Path(value) / "payload.tar"
            with tarfile.open(path, "w") as archive:
                member = tarfile.TarInfo("linked")
                member.type = tarfile.SYMTYPE
                member.linkname = "../../outside"
                archive.addfile(member)
            with self.assertRaisesRegex(ContractError, "link or special TAR member"):
                _verify_declared_media_type(
                    path,
                    "application/x-tar",
                    "tar artifact",
                )

    def test_rejects_source_symlink_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            link = source / "linked-artifact.json"
            try:
                link.symlink_to(source / "artifact-source.json")
            except OSError:
                self.skipTest("symlink creation is unavailable")
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            reference = file_reference(
                source, "linked-artifact.json", "artifacts/benchmark-dataset.json"
            )
            data["artifacts"][0].update(reference)
            write_json(manifest_path, data)
            with self.assertRaisesRegex(ContractError, "symbolic link"):
                assemble_bundle(
                    source,
                    manifest_path,
                    REPO_ROOT / "release" / "package-matrix.json",
                    root / "bundle",
                    self.epoch,
                )

    @unittest.skipUnless(os.name == "nt", "Windows junction semantics")
    def test_rejects_windows_source_junction(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            external = source / "junction-target"
            external.mkdir()
            write_json(external / "artifact.json", {"dataset": "junction"})
            junction = source / "junction"
            completed = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(external)],
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                self.skipTest(f"junction creation unavailable: {completed.stderr}")
            try:
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
                reference = file_reference(
                    source,
                    "junction/artifact.json",
                    "artifacts/benchmark-dataset.json",
                )
                data["artifacts"][0].update(reference)
                write_json(manifest_path, data)
                with self.assertRaisesRegex(ContractError, "symbolic link or junction"):
                    assemble_bundle(
                        source,
                        manifest_path,
                        REPO_ROOT / "release" / "package-matrix.json",
                        root / "bundle",
                        self.epoch,
                    )
            finally:
                os.rmdir(junction)

    def test_rejects_unstaged_proof_reference(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            data["supporting_files"] = data["supporting_files"][:1]
            write_json(manifest_path, data)
            with self.assertRaisesRegex(ContractError, "proof reference is absent"):
                assemble_bundle(
                    source,
                    manifest_path,
                    REPO_ROOT / "release" / "package-matrix.json",
                    root / "bundle",
                    self.epoch,
                )

    def test_source_date_epoch_conflict_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            with (
                patch.dict(os.environ, {"SOURCE_DATE_EPOCH": str(self.epoch + 1)}),
                self.assertRaisesRegex(ContractError, "conflicts"),
            ):
                assemble_bundle(
                    source,
                    manifest_path,
                    REPO_ROOT / "release" / "package-matrix.json",
                    root / "bundle",
                    self.epoch,
                )

    def test_source_date_epoch_environment_is_applied(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": str(self.epoch)}):
                receipt = assemble_bundle(
                    source,
                    manifest_path,
                    REPO_ROOT / "release" / "package-matrix.json",
                    root / "bundle",
                    None,
                )
            self.assertEqual(receipt["output"]["deterministic_mtime_epoch"], self.epoch)

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"), "jsonschema unavailable"
    )
    def test_repository_input_example_is_valid_but_not_assemblable(self) -> None:
        import jsonschema  # type: ignore[import-untyped]

        example_path = REPO_ROOT / "release" / "bundle-input.example.json"
        schema = json.loads(
            (
                REPO_ROOT / "assets" / "schemas" / "release-bundle-input.schema.json"
            ).read_text(encoding="utf-8")
        )
        example = json.loads(example_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(example)

        artifact = example["artifacts"][0]
        matrix = json.loads(
            (REPO_ROOT / "release" / "package-matrix.json").read_text(encoding="utf-8")
        )
        package = next(
            package
            for package in matrix["packages"]
            if package["id"] == artifact["package_id"]
        )
        self.assertEqual(artifact["roles"], package["roles"])
        self.assertEqual(artifact["kind"], package["artifact_kind"])
        self.assertEqual(artifact["targets"], package["platforms"])
        self.assertTrue(example["source"]["dirty"])
        self.assertEqual(artifact["sha256"], "0" * 64)
        self.assertIn("placeholder", " ".join(example["limitations"]).lower())

        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            input_root = root / "inputs"
            input_root.mkdir()
            output = root / "bundle"
            with self.assertRaisesRegex(ContractError, "source file is absent"):
                assemble_bundle(
                    input_root,
                    example_path,
                    REPO_ROOT / "release" / "package-matrix.json",
                    output,
                    self.epoch,
                )
            self.assertFalse(output.exists())

    def test_cli_writes_external_schema_valid_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            output = root / "bundle"
            report = root / "assembly-receipt.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_ROOT / "contextdb_release.py"),
                    "assemble-bundle",
                    "--input-root",
                    str(source),
                    "--input-manifest",
                    str(manifest_path),
                    "--matrix",
                    str(REPO_ROOT / "release" / "package-matrix.json"),
                    "--output-dir",
                    str(output),
                    "--source-date-epoch",
                    str(self.epoch),
                    "--report",
                    str(report),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                json.loads(completed.stdout), json.loads(report.read_text())
            )
            self.assertTrue(output.is_dir())

    def test_cli_rejects_receipt_inside_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, manifest_path = self.make_inputs(root)
            output = root / "bundle"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_ROOT / "contextdb_release.py"),
                    "assemble-bundle",
                    "--input-root",
                    str(source),
                    "--input-manifest",
                    str(manifest_path),
                    "--matrix",
                    str(REPO_ROOT / "release" / "package-matrix.json"),
                    "--output-dir",
                    str(output),
                    "--report",
                    str(output / "receipt.json"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("receipt must be outside", completed.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
