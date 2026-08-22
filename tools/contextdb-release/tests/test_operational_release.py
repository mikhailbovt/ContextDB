from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

import contextdb_release as release


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact_manifest(
    root: Path,
    *,
    version: str = "0.1.0-alpha.1",
    artifact_id: str = "contextdb-windows",
    artifact_kind: str = "executable",
    package_id: str = "contextdb-binary",
    target: str = "windows-x86-64",
) -> tuple[dict[str, object], Path]:
    payload = root / "artifacts" / "contextdb.exe"
    payload.parent.mkdir(parents=True, exist_ok=True)
    payload.write_bytes(b"MZ synthetic executable fixture\n")
    seed_payload = root / "artifacts" / "portable-seed.ctxb"
    seed_payload.write_bytes(b"synthetic non-empty logical seed fixture\n")
    source_commit = "1" * 40
    manifest: dict[str, object] = {
        "schema_version": "contextdb.release-artifact-manifest/v1",
        "release": {
            "version": version,
            "channel": "alpha",
            "created_at": "2026-08-13T00:00:00Z",
            "candidate": 1,
        },
        "source": {
            "repository": "https://github.com/mikhailbovt/ContextDB",
            "git_commit": source_commit,
            "dirty": False,
        },
        "version_manifest": {"path": "release/version.json", "sha256": "2" * 64},
        "package_matrix": {
            "path": "release/package-matrix.json",
            "sha256": "3" * 64,
        },
        "proof_index": {"path": "release/proof-index.json", "sha256": "4" * 64},
        "checksum_file": {
            "path": "SHA256SUMS",
            "algorithm": "sha256",
            "format": "sha256sum-v1",
        },
        "signature_set": {"path": "release/signatures.json"},
        "artifacts": [
            {
                "id": artifact_id,
                "package_id": package_id,
                "roles": ["server", "cli"],
                "kind": artifact_kind,
                "path": "artifacts/contextdb.exe",
                "media_type": "application/vnd.microsoft.portable-executable",
                "size_bytes": payload.stat().st_size,
                "sha256": digest(payload),
                "targets": [target],
                "version": version,
                "version_manifest_sha256": "2" * 64,
                "provenance": {
                    "source_commit": source_commit,
                    "builder": "release-contract-test",
                    "build_recipe": "release/package-matrix.json",
                    "reproducible": False,
                },
                "related_files": [],
            },
            {
                "id": "portable-seed",
                "package_id": "portable-example-database",
                "roles": ["example-databases"],
                "kind": "example-database",
                "path": "artifacts/portable-seed.ctxb",
                "media_type": "application/vnd.contextdb.logical+json",
                "size_bytes": seed_payload.stat().st_size,
                "sha256": digest(seed_payload),
                "targets": ["platform-independent"],
                "version": version,
                "version_manifest_sha256": "2" * 64,
                "provenance": {
                    "source_commit": source_commit,
                    "builder": "release-contract-test",
                    "build_recipe": "release/package-matrix.json",
                    "reproducible": True,
                },
                "related_files": [],
            },
        ],
        "limitations": ["synthetic contract fixture; not a release"],
    }
    manifest_path = root / "release" / "artifact-manifest.json"
    write_json(manifest_path, manifest)
    return manifest, manifest_path


def publication_receipt(artifact: dict[str, object]) -> dict[str, object]:
    subject = {key: artifact[key] for key in ("id", "path", "sha256", "version")}
    return {
        "schema_version": "contextdb.release-publication-receipt/v1",
        "artifact": subject,
        "registry_type": "github-release",
        "immutable_uri": (
            "https://github.com/mikhailbovt/ContextDB/releases/download/"
            f"fixture/{artifact['sha256']}"
        ),
        "immutable_reference": True,
        "published_at": "2026-08-13T00:00:00Z",
        "verified_at": "2026-08-13T00:01:00Z",
        "retrieved_sha256": artifact["sha256"],
        "status": "passed",
    }


def operational_receipt(
    artifact: dict[str, object],
    manifest_path: Path,
    *,
    old_artifact: dict[str, object] | None = None,
    old_manifest_digest: str = "a" * 64,
    plan_digest: str = "8" * 64,
) -> dict[str, object]:
    subject = {key: artifact[key] for key in ("id", "path", "sha256", "version")}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    seed_artifact = manifest["artifacts"][1]
    seed_subject = {
        key: seed_artifact[key] for key in ("id", "path", "sha256", "version")
    }
    return {
        "schema_version": "contextdb.release-operational-receipt/v1",
        "tool_version": "0.1.0-alpha.4",
        "generated_at": "2026-08-13T00:00:00Z",
        "drill_id": "fixture-operational-drill",
        "plan_sha256": plan_digest,
        "host_target": "windows-x86-64",
        "profile": "contract",
        "isolated_copy": True,
        "old_artifact": old_artifact
        or {
            "id": "contextdb-old",
            "path": "artifacts/contextdb-old.exe",
            "sha256": "9" * 64,
            "version": "0.0.9",
        },
        "new_artifact": subject,
        "seed_artifact": seed_subject,
        "minimum_seed_commit_seq": 1,
        "bundle_verifications": {
            "old": {
                "manifest_sha256": old_manifest_digest,
                "contract_valid": True,
                "release_ready": False,
            },
            "new": {
                "manifest_sha256": digest(manifest_path),
                "contract_valid": True,
                "release_ready": False,
            },
        },
        "scenarios": [
            "side-by-side-upgrade",
            "explicit-rollback",
            "disaster-recovery",
        ],
        "activation_sequence": ["old", "candidate", "old", "recovered"],
        "state_snapshots": [
            {
                "role": role,
                "sha256": (
                    "1" * 64
                    if role
                    in {
                        "old-before-upgrade",
                        "old-after-rollback",
                        "migration-export",
                    }
                    else "2" * 64
                ),
                "file_count": 1,
                "total_size_bytes": 1,
            }
            for role in (
                "old-before-upgrade",
                "old-after-rollback",
                "migration-export",
                "candidate",
                "disaster-recovery-export",
                "recovered",
            )
        ],
        "probes": [
            {
                "id": identifier,
                "status": "passed",
                "evidence_level": "runtime",
                "argv": ["fixture-operational-drill", identifier],
            }
            for identifier in sorted(release.REQUIRED_OPERATIONAL_PROBES)
        ],
        "passed": True,
        "release_ready": False,
        "network_commands_invoked": False,
        "network_isolation_enforced": False,
        "docker_runtime_executed": False,
    }


class ExternalReceiptIntakeTests(unittest.TestCase):
    def make_landing_zone(
        self, root: Path
    ) -> tuple[Path, Path, Path, dict[str, object]]:
        subject_root = root / "subject"
        input_root = root / "landing"
        input_root.mkdir(parents=True)
        manifest, manifest_path = artifact_manifest(subject_root)
        artifact = manifest["artifacts"][0]
        assert isinstance(artifact, dict)
        receipt_path = input_root / "publication.json"
        write_json(receipt_path, publication_receipt(artifact))
        receipt_set: dict[str, object] = {
            "schema_version": "contextdb.release-external-receipt-set/v1",
            "release_version": "0.1.0-alpha.1",
            "subject_manifest": {
                "path": "release/artifact-manifest.json",
                "sha256": digest(manifest_path),
                "size_bytes": manifest_path.stat().st_size,
            },
            "expected_coverage": [
                {
                    "artifact_id": "contextdb-windows",
                    "kind": "publication-receipt",
                    "platform": "platform-independent",
                }
            ],
            "receipts": [
                {
                    "id": "contextdb-publication",
                    "kind": "publication-receipt",
                    "source_path": "publication.json",
                    "sha256": digest(receipt_path),
                    "size_bytes": receipt_path.stat().st_size,
                    "artifact_id": "contextdb-windows",
                    "platform": "platform-independent",
                }
            ],
            "limitations": ["synthetic contract fixture; no live retrieval"],
        }
        set_path = input_root / "receipt-set.json"
        write_json(set_path, receipt_set)
        return subject_root, input_root, set_path, receipt_set

    def test_accepts_exact_digest_pinned_quarantine_without_release_claim(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            subject, landing, set_path, _ = self.make_landing_zone(Path(value))
            result = release.intake_external_receipts(subject, landing, set_path)
            self.assertTrue(result["accepted"])
            self.assertFalse(result["release_ready"])
            self.assertFalse(result["evidence_boundary"]["network_accessed"])
            self.assertFalse(result["evidence_boundary"]["files_copied"])
            self.assertEqual(result["entries"][0]["status"], "accepted")
            release.validate_json_contract(result, "test intake")

    def test_accepts_every_supported_receipt_kind_with_exact_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            subject_root = root / "subject"
            landing = root / "landing"
            landing.mkdir(parents=True)
            manifest, manifest_path = artifact_manifest(subject_root)
            artifact = manifest["artifacts"][0]
            assert isinstance(artifact, dict)
            subject = {
                key: artifact[key] for key in ("id", "path", "sha256", "version")
            }
            source_commit = artifact["provenance"]["source_commit"]
            old_manifest, _ = artifact_manifest(
                root / "old-subject",
                version="0.0.9",
                artifact_id="contextdb-old",
            )
            old_manifest_path = landing / "operational-old-manifest.json"
            write_json(old_manifest_path, old_manifest)
            old_artifact = old_manifest["artifacts"][0]
            assert isinstance(old_artifact, dict)
            old_subject = {
                key: old_artifact[key] for key in ("id", "path", "sha256", "version")
            }
            seed_artifact = manifest["artifacts"][1]
            assert isinstance(seed_artifact, dict)
            operational_plan = {
                "schema_version": "contextdb.release-operational-plan/v1",
                "drill_id": "fixture-operational-drill",
                "created_at": "2026-08-13T00:00:00Z",
                "host_target": "windows-x86-64",
                "profile": "contract",
                "old_release": {
                    "manifest_path": "release/artifact-manifest.json",
                    "manifest_sha256": digest(old_manifest_path),
                    "version": "0.0.9",
                    "binary_artifact_id": "contextdb-old",
                },
                "new_release": {
                    "manifest_path": "release/artifact-manifest.json",
                    "manifest_sha256": digest(manifest_path),
                    "version": artifact["version"],
                    "binary_artifact_id": artifact["id"],
                },
                "seed_artifact": {
                    "bundle": "new",
                    "artifact_id": seed_artifact["id"],
                    "sha256": seed_artifact["sha256"],
                    "size_bytes": seed_artifact["size_bytes"],
                    "minimum_commit_seq": 1,
                },
                "scenarios": [
                    "side-by-side-upgrade",
                    "explicit-rollback",
                    "disaster-recovery",
                ],
                "limitations": ["synthetic operational intake fixture"],
            }
            operational_plan_path = landing / "operational-plan.json"
            write_json(operational_plan_path, operational_plan)

            values: dict[str, tuple[str, str, dict[str, object]]] = {
                "publication": (
                    "publication-receipt",
                    "platform-independent",
                    publication_receipt(artifact),
                ),
                "install": (
                    "install-receipt",
                    "windows-x86-64",
                    {
                        "schema_version": "contextdb.clean-install-receipt/v1",
                        "verifier_version": "0.1.0-alpha.4",
                        "generated_at": "2026-08-13T00:00:00Z",
                        "profile": "contract",
                        "host_target": "windows-x86-64",
                        "isolated_copy": True,
                        "verification": {
                            "schema_version": "contextdb.release-verification-report/v1",
                            "profile": "contract",
                            "contract_valid": True,
                            "release_ready": False,
                        },
                        "subject_artifacts": [subject],
                        "probes": [
                            {
                                "id": identifier,
                                "status": "passed",
                                "evidence_level": "runtime",
                                "argv": ["fixture-clean-install", identifier],
                            }
                            for identifier in sorted(
                                release.REQUIRED_CONTEXTDB_INSTALL_PROBES
                            )
                        ],
                        "passed": True,
                        "release_ready": False,
                        "docker_runtime_executed": False,
                    },
                ),
                "operational": (
                    "operational-receipt",
                    "windows-x86-64",
                    operational_receipt(
                        artifact,
                        manifest_path,
                        old_artifact=old_subject,
                        old_manifest_digest=digest(old_manifest_path),
                        plan_digest=digest(operational_plan_path),
                    ),
                ),
                "sbom": (
                    "sbom",
                    "platform-independent",
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.6",
                        "metadata": {
                            "component": {
                                "hashes": [
                                    {"alg": "SHA-256", "content": artifact["sha256"]}
                                ]
                            }
                        },
                    },
                ),
                "provenance": (
                    "provenance-attestation",
                    "platform-independent",
                    {
                        "_type": "https://in-toto.io/Statement/v1",
                        "subject": [
                            {
                                "name": artifact["path"],
                                "digest": {"sha256": artifact["sha256"]},
                            }
                        ],
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "predicate": {
                            "buildDefinition": {
                                "buildType": "https://github.com/mikhailbovt/ContextDB/actions",
                                "resolvedDependencies": [
                                    {
                                        "uri": "https://github.com/mikhailbovt/ContextDB",
                                        "digest": {"gitCommit": source_commit},
                                    }
                                ],
                            },
                            "runDetails": {
                                "builder": {
                                    "id": "https://github.com/mikhailbovt/ContextDB/actions"
                                }
                            },
                        },
                    },
                ),
            }
            declarations = []
            expected = []
            for identifier, (kind, platform_id, receipt) in values.items():
                path = landing / f"{identifier}.json"
                write_json(path, receipt)
                declarations.append(
                    {
                        "id": f"fixture-{identifier}",
                        "kind": kind,
                        "source_path": path.name,
                        "sha256": digest(path),
                        "size_bytes": path.stat().st_size,
                        "artifact_id": artifact["id"],
                        "platform": platform_id,
                        **(
                            {
                                "operational_inputs": {
                                    "plan": {
                                        "path": operational_plan_path.name,
                                        "sha256": digest(operational_plan_path),
                                        "size_bytes": operational_plan_path.stat().st_size,
                                    },
                                    "old_manifest": {
                                        "path": old_manifest_path.name,
                                        "sha256": digest(old_manifest_path),
                                        "size_bytes": old_manifest_path.stat().st_size,
                                    },
                                }
                            }
                            if kind == "operational-receipt"
                            else {}
                        ),
                    }
                )
                expected.append(
                    {
                        "artifact_id": artifact["id"],
                        "kind": kind,
                        "platform": platform_id,
                    }
                )
            receipt_set = {
                "schema_version": "contextdb.release-external-receipt-set/v1",
                "release_version": artifact["version"],
                "subject_manifest": {
                    "path": "release/artifact-manifest.json",
                    "sha256": digest(manifest_path),
                    "size_bytes": manifest_path.stat().st_size,
                },
                "expected_coverage": expected,
                "receipts": declarations,
                "limitations": ["synthetic all-kinds contract fixture"],
            }
            set_path = landing / "receipt-set.json"
            write_json(set_path, receipt_set)

            result = release.intake_external_receipts(subject_root, landing, set_path)
            self.assertTrue(result["accepted"])
            self.assertEqual(len(result["entries"]), len(values))
            self.assertEqual(
                {entry["kind"] for entry in result["entries"]},
                {value[0] for value in values.values()},
            )

    def test_operational_intake_rejects_incomplete_or_inconsistent_drill(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            manifest, manifest_path = artifact_manifest(root / "subject")
            artifact = manifest["artifacts"][0]
            assert isinstance(artifact, dict)
            old_manifest, old_manifest_path = artifact_manifest(
                root / "old-subject",
                version="0.0.9",
                artifact_id="contextdb-old",
            )
            old_artifact = old_manifest["artifacts"][0]
            seed_artifact = manifest["artifacts"][1]
            assert isinstance(old_artifact, dict)
            assert isinstance(seed_artifact, dict)
            old_subject = {
                key: old_artifact[key] for key in ("id", "path", "sha256", "version")
            }
            plan = {
                "schema_version": "contextdb.release-operational-plan/v1",
                "drill_id": "fixture-operational-drill",
                "created_at": "2026-08-13T00:00:00Z",
                "host_target": "windows-x86-64",
                "profile": "contract",
                "old_release": {
                    "manifest_path": "release/artifact-manifest.json",
                    "manifest_sha256": digest(old_manifest_path),
                    "version": "0.0.9",
                    "binary_artifact_id": "contextdb-old",
                },
                "new_release": {
                    "manifest_path": "release/artifact-manifest.json",
                    "manifest_sha256": digest(manifest_path),
                    "version": artifact["version"],
                    "binary_artifact_id": artifact["id"],
                },
                "seed_artifact": {
                    "bundle": "new",
                    "artifact_id": seed_artifact["id"],
                    "sha256": seed_artifact["sha256"],
                    "size_bytes": seed_artifact["size_bytes"],
                    "minimum_commit_seq": 1,
                },
                "scenarios": [
                    "side-by-side-upgrade",
                    "explicit-rollback",
                    "disaster-recovery",
                ],
                "limitations": [],
            }
            plan_path = root / "plan.json"
            write_json(plan_path, plan)

            def verify(receipt: dict[str, object]) -> None:
                release._verify_intake_operational_receipt(
                    artifact,
                    receipt,
                    "windows-x86-64",
                    manifest,
                    digest(manifest_path),
                    plan,
                    digest(plan_path),
                    old_manifest,
                    digest(old_manifest_path),
                    "fixture",
                )

            missing_probe = operational_receipt(
                artifact,
                manifest_path,
                old_artifact=old_subject,
                old_manifest_digest=digest(old_manifest_path),
                plan_digest=digest(plan_path),
            )
            probes = missing_probe["probes"]
            assert isinstance(probes, list)
            probes.pop()
            with self.assertRaisesRegex(release.ContractError, "lacks required probes"):
                verify(missing_probe)

            changed_state = operational_receipt(
                artifact,
                manifest_path,
                old_artifact=old_subject,
                old_manifest_digest=digest(old_manifest_path),
                plan_digest=digest(plan_path),
            )
            snapshots = changed_state["state_snapshots"]
            assert isinstance(snapshots, list)
            snapshot = next(
                item
                for item in snapshots
                if isinstance(item, dict) and item["role"] == "old-after-rollback"
            )
            snapshot["sha256"] = "3" * 64
            with self.assertRaisesRegex(
                release.ContractError, "changed across rollback"
            ):
                verify(changed_state)

    def test_rejects_tamper_missing_coverage_and_undeclared_files(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            subject, landing, set_path, receipt_set = self.make_landing_zone(root)
            (landing / "publication.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(release.ContractError, "digest or size"):
                release.intake_external_receipts(subject, landing, set_path)

            subject, landing, set_path, receipt_set = self.make_landing_zone(
                root / "two"
            )
            coverage = receipt_set["expected_coverage"]
            assert isinstance(coverage, list)
            coverage.append(
                {
                    "artifact_id": "contextdb-windows",
                    "kind": "sbom",
                    "platform": "platform-independent",
                }
            )
            write_json(set_path, receipt_set)
            with self.assertRaisesRegex(release.ContractError, "coverage mismatch"):
                release.intake_external_receipts(subject, landing, set_path)

            subject, landing, set_path, _ = self.make_landing_zone(root / "three")
            (landing / "undeclared.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(release.ContractError, "not exhaustive"):
                release.intake_external_receipts(subject, landing, set_path)

    def test_rejects_receipt_set_nested_in_subject_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            subject, landing, set_path, _ = self.make_landing_zone(Path(value))
            nested = subject / "landing"
            landing.rename(nested)
            with self.assertRaisesRegex(release.ContractError, "disjoint"):
                release.intake_external_receipts(
                    subject, nested, nested / set_path.name
                )

    def test_reports_must_remain_outside_verified_or_quarantined_roots(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            bundle = root / "bundle"
            landing = root / "landing"
            bundle.mkdir()
            landing.mkdir()
            release._require_report_outside_roots(
                root / "external-report.json", [bundle, landing], "test"
            )
            with self.assertRaisesRegex(release.ContractError, "must be outside"):
                release._require_report_outside_roots(
                    bundle / "verification.json", [bundle], "test"
                )
            with self.assertRaisesRegex(release.ContractError, "must be outside"):
                release._require_report_outside_roots(
                    landing / "intake.json", [bundle, landing], "test"
                )
            source = root / "plan.json"
            source.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(release.ContractError, "overwrite an input"):
                release._require_output_distinct_from_inputs(source, [source], "test")


class OperationalDrillTests(unittest.TestCase):
    def test_semver_upgrade_requires_strict_precedence(self) -> None:
        release.require_semver_upgrade(
            "1.0.0-beta.2", "1.0.0-beta.11", "fixture upgrade"
        )
        release.require_semver_upgrade("1.0.0-rc.1", "1.0.0", "fixture upgrade")
        for old, new in (
            ("1.0.0", "1.0.0+rebuilt"),
            ("2.0.0", "1.9.9"),
        ):
            with self.assertRaisesRegex(release.ContractError, "precedence greater"):
                release.require_semver_upgrade(old, new, "fixture upgrade")

    def test_runs_upgrade_rollback_and_dr_without_force_or_release_claim(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            old_root = root / "old"
            new_root = root / "new"
            old_value, old_manifest = artifact_manifest(
                old_root, version="0.1.0-alpha.1"
            )
            _, new_manifest = artifact_manifest(new_root, version="0.1.0-beta.1")
            old_seed = old_value["artifacts"][1]
            assert isinstance(old_seed, dict)
            plan = {
                "schema_version": "contextdb.release-operational-plan/v1",
                "drill_id": "windows-upgrade-drill",
                "created_at": "2026-08-13T00:00:00Z",
                "host_target": "windows-x86-64",
                "profile": "contract",
                "old_release": {
                    "manifest_path": "release/artifact-manifest.json",
                    "manifest_sha256": digest(old_manifest),
                    "version": "0.1.0-alpha.1",
                    "binary_artifact_id": "contextdb-windows",
                },
                "new_release": {
                    "manifest_path": "release/artifact-manifest.json",
                    "manifest_sha256": digest(new_manifest),
                    "version": "0.1.0-beta.1",
                    "binary_artifact_id": "contextdb-windows",
                },
                "seed_artifact": {
                    "bundle": "old",
                    "artifact_id": old_seed["id"],
                    "sha256": old_seed["sha256"],
                    "size_bytes": old_seed["size_bytes"],
                    "minimum_commit_seq": 1,
                },
                "scenarios": [
                    "side-by-side-upgrade",
                    "explicit-rollback",
                    "disaster-recovery",
                ],
                "limitations": ["synthetic command runner"],
            }
            plan_path = root / "plan.json"
            write_json(plan_path, plan)

            def fake_run(
                binary: Path,
                isolated: Path,
                probes: list[dict[str, object]],
                identifier: str,
                arguments: list[str],
                environment: dict[str, str],
                expected_first_stdout_line: str | None = None,
                expected_json_minimums: dict[str, int] | None = None,
            ) -> bool:
                del (
                    binary,
                    isolated,
                    environment,
                    expected_first_stdout_line,
                    expected_json_minimums,
                )
                operation = (
                    arguments[1]
                    if arguments and arguments[0] == "--json"
                    else arguments[0]
                )
                if operation == "init":
                    destination = Path(arguments[-1])
                    destination.write_bytes(b"logical-state\n")
                    store = Path(f"{destination}.fjall")
                    store.mkdir()
                    (store / "state.bin").write_bytes(b"durable-state\n")
                elif operation == "import":
                    destination = Path(arguments[-2])
                    source = Path(arguments[-1])
                    destination.write_bytes(source.read_bytes())
                    store = Path(f"{destination}.fjall")
                    store.mkdir()
                    (store / "state.bin").write_bytes(b"durable-state\n")
                elif operation == "export":
                    output = Path(arguments[-1])
                    output.write_bytes(b"canonical-logical-export\n")
                probes.append(
                    {
                        "id": identifier,
                        "status": "passed",
                        "evidence_level": "runtime",
                        "argv": ["contextdb", *arguments],
                    }
                )
                return True

            def fake_custody(
                probes: list[dict[str, object]],
                identifier: str,
                archive: Path,
                environment: dict[str, str],
                host_target: str,
            ) -> bool:
                del archive, environment, host_target
                probes.append(
                    {
                        "id": identifier,
                        "status": "passed",
                        "evidence_level": "runtime",
                        "argv": ["assert-external-custody"],
                    }
                )
                return True

            verification = {"contract_valid": True, "release_ready": False}
            with (
                patch.object(
                    release.BundleVerifier, "verify", return_value=verification
                ),
                patch.object(release, "_host_target", return_value="windows-x86-64"),
                patch.object(
                    release, "_windows_state_head_digest", return_value="a" * 64
                ),
                patch.object(
                    release, "_run_contextdb_probe_command", side_effect=fake_run
                ),
                patch.object(
                    release, "_check_probe_custody_boundary", side_effect=fake_custody
                ),
                patch.object(
                    release, "_finish_probe_authority_custody", return_value=True
                ),
            ):
                result = release.run_operational_drill(
                    old_root, new_root, plan_path, "contract", {}, False
                )

            self.assertTrue(result["passed"])
            self.assertFalse(result["release_ready"])
            self.assertFalse(result["network_commands_invoked"])
            self.assertFalse(result["network_isolation_enforced"])
            self.assertFalse(result["docker_runtime_executed"])
            self.assertEqual(
                result["activation_sequence"],
                ["old", "candidate", "old", "recovered"],
            )
            self.assertEqual(len(result["state_snapshots"]), 6)
            self.assertFalse(
                any("--force" in probe["argv"] for probe in result["probes"])
            )
            release.validate_json_contract(result, "test operational receipt")

            def failed_run(
                binary: Path,
                isolated: Path,
                probes: list[dict[str, object]],
                identifier: str,
                arguments: list[str],
                environment: dict[str, str],
                expected_first_stdout_line: str | None = None,
                expected_json_minimums: dict[str, int] | None = None,
            ) -> bool:
                del (
                    binary,
                    isolated,
                    environment,
                    expected_first_stdout_line,
                    expected_json_minimums,
                )
                probes.append(
                    {
                        "id": identifier,
                        "status": "failed",
                        "evidence_level": "runtime",
                        "argv": ["contextdb", *arguments],
                        "detail": "synthetic command failure",
                    }
                )
                return False

            with (
                patch.object(
                    release.BundleVerifier, "verify", return_value=verification
                ),
                patch.object(release, "_host_target", return_value="windows-x86-64"),
                patch.object(
                    release, "_windows_state_head_digest", return_value="a" * 64
                ),
                patch.object(
                    release, "_run_contextdb_probe_command", side_effect=failed_run
                ),
                patch.object(
                    release, "_finish_probe_authority_custody", return_value=True
                ),
            ):
                failed = release.run_operational_drill(
                    old_root, new_root, plan_path, "contract", {}, False
                )
            self.assertFalse(failed["passed"])
            self.assertEqual(failed["activation_sequence"], [])
            self.assertEqual(failed["probes"][0]["id"], "old-version")
            self.assertEqual(
                failed["probes"][-1]["id"], "operational-authority-cleanup"
            )
            release.validate_json_contract(failed, "failed operational receipt")

    def test_rejects_same_version_and_wrong_host_before_running_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            old_root = root / "old"
            new_root = root / "new"
            old_value, old_manifest = artifact_manifest(old_root)
            _, new_manifest = artifact_manifest(new_root)
            old_seed = old_value["artifacts"][1]
            assert isinstance(old_seed, dict)
            plan = {
                "schema_version": "contextdb.release-operational-plan/v1",
                "drill_id": "invalid-upgrade-drill",
                "created_at": "2026-08-13T00:00:00Z",
                "host_target": "windows-x86-64",
                "profile": "contract",
                "old_release": {
                    "manifest_path": "release/artifact-manifest.json",
                    "manifest_sha256": digest(old_manifest),
                    "version": "0.1.0-alpha.1",
                    "binary_artifact_id": "contextdb-windows",
                },
                "new_release": {
                    "manifest_path": "release/artifact-manifest.json",
                    "manifest_sha256": digest(new_manifest),
                    "version": "0.1.0-alpha.1",
                    "binary_artifact_id": "contextdb-windows",
                },
                "seed_artifact": {
                    "bundle": "old",
                    "artifact_id": old_seed["id"],
                    "sha256": old_seed["sha256"],
                    "size_bytes": old_seed["size_bytes"],
                    "minimum_commit_seq": 1,
                },
                "scenarios": [
                    "side-by-side-upgrade",
                    "explicit-rollback",
                    "disaster-recovery",
                ],
                "limitations": [],
            }
            plan_path = root / "plan.json"
            write_json(plan_path, plan)
            with (
                patch.object(release, "_host_target", return_value="windows-x86-64"),
                self.assertRaisesRegex(release.ContractError, "precedence greater"),
            ):
                release.run_operational_drill(
                    old_root, new_root, plan_path, "contract", {}, False
                )

            plan["new_release"]["version"] = "0.1.0-beta.1"
            plan["host_target"] = "linux-x86-64"
            write_json(plan_path, plan)
            with (
                patch.object(release, "_host_target", return_value="windows-x86-64"),
                self.assertRaisesRegex(release.ContractError, "host is"),
            ):
                release.run_operational_drill(
                    old_root, new_root, plan_path, "contract", {}, False
                )


class CandidateWorkflowContractTests(unittest.TestCase):
    def test_version_manifest_preserves_archived_design_baseline_ids(self) -> None:
        root = TOOL_ROOT.parents[1]
        workflow = (root / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )

        errata_match = re.search(r'"errata":\s*(\[[^\]]*\])', workflow)
        adrs_match = re.search(r'"adrs":\s*(\[[^\]]*\])', workflow, re.DOTALL)
        self.assertIsNotNone(errata_match)
        self.assertIsNotNone(adrs_match)
        assert errata_match is not None and adrs_match is not None

        expected_errata = ["ERRATA-0001"]
        expected_adrs = [f"ADR-{number:04d}" for number in range(1, 9)]
        self.assertEqual(ast.literal_eval(errata_match.group(1)), expected_errata)
        self.assertEqual(ast.literal_eval(adrs_match.group(1)), expected_adrs)


if __name__ == "__main__":
    unittest.main()
