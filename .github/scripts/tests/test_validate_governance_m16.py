from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
VALIDATOR_PATH = REPOSITORY_ROOT / ".github" / "scripts" / "validate_governance.py"
SPEC = importlib.util.spec_from_file_location("validate_governance", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
governance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(governance)
governance.ROOT = REPOSITORY_ROOT
governance.SCHEMA_DIR = REPOSITORY_ROOT / "assets" / "schemas"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class M16ProofValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas, cls.registry = governance.build_registry()
        cls.version_manifest = json.loads(
            (
                REPOSITORY_ROOT
                / "docs"
                / "architecture"
                / "examples"
                / "version-manifest.json"
            ).read_text(encoding="utf-8")
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self._write_text(
            "Cargo.toml",
            '[workspace]\nresolver = "3"\nmembers = ["test-crate"]\n',
        )
        self._write_text(
            "Cargo.lock",
            'version = 4\n\n[[package]]\nname = "contextdb-test"\nversion = "0.0.0"\n',
        )
        self._write_text(
            "test-crate/Cargo.toml",
            '[package]\nname = "contextdb-test"\nversion = "0.0.0"\n',
        )
        self._write_text("test-crate/src/lib.rs", "pub fn fixture() {}\n")
        cargo_metadata = governance.load_cargo_metadata(self.root)
        self.cargo_root_id = cargo_metadata["workspace_members"][0]
        self._write_text("src/security.rs", "pub fn checked() -> bool { true }\n")
        self._write_text("fuzz/fuzz_targets/record_envelope.rs", "fn main() {}\n")
        self._write_text("fuzz/fuzz_targets/security_envelope.rs", "fn main() {}\n")
        self._write_text("crates/fault/examples/process_kill.rs", "fn main() {}\n")
        self._write_json(
            "docs/architecture/examples/version-manifest.json", self.version_manifest
        )
        self._write_json(
            "test-crate/contextdb-test.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "metadata": {
                    "component": {
                        "type": "library",
                        "bom-ref": self.cargo_root_id,
                        "name": "contextdb-test",
                        "version": "0.0.0",
                        "purl": "pkg:cargo/contextdb-test@0.0.0?download_url=file://.",
                    }
                },
                "components": [],
                "dependencies": [{"ref": self.cargo_root_id, "dependsOn": []}],
            },
        )
        self.milestone = {
            "id": "M16",
            "status": "not_started",
            "required_proof": [
                {"path": path, **copy.deepcopy(contract)}
                for path, contract in governance.M16_PROOF_CONTRACTS.items()
            ],
        }
        self._write_receipts()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_text(self, path: str, content: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="")

    def _write_json(self, path: str, document: dict) -> None:
        self._write_text(
            path,
            json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        )

    def _artifact(self, path: str, *, include_bytes: bool = False) -> dict:
        result = {"path": path, "sha256": digest(self.root / path)}
        if include_bytes:
            result["bytes"] = (self.root / path).stat().st_size
        return result

    def _frozen_inputs(self, source_manifest_sha256: str) -> dict:
        return {
            "workspace_manifest_sha256": digest(self.root / "Cargo.toml"),
            "cargo_lock_sha256": digest(self.root / "Cargo.lock"),
            "security_source_manifest_sha256": source_manifest_sha256,
        }

    def _write_receipts(self) -> None:
        source_artifacts = [
            self._artifact(path)
            for path in governance.trusted_m16_security_inventory(self.root)
        ]
        source_rows = b"".join(
            f"{artifact['path']}\t{artifact['sha256']}\n".encode()
            for artifact in source_artifacts
        )
        source_manifest_sha256 = hashlib.sha256(source_rows).hexdigest()
        frozen = self._frozen_inputs(source_manifest_sha256)
        generated_at = "2026-08-12T20:00:00Z"
        scan_id = "130a8333-affa-4ed8-b02b-a7d58b89bd61"
        snapshot_digest = f"codex-security-snapshot/v1:sha256:{source_manifest_sha256}"

        canonical_findings = {
            "documentType": "codex-security.findings",
            "schemaVersion": "1.0",
            "findings": [],
        }
        canonical_coverage = {
            "documentType": "codex-security.coverage",
            "schemaVersion": "1.0",
            "scanId": scan_id,
            "mode": "repository",
            "inventoryStrategy": "repository",
            "completeness": "partial",
            "includePaths": ["."],
            "excludePaths": [],
            "deferred": [
                {"id": "synthetic", "paths": ["."], "reason": "Unit fixture."}
            ],
            "openQuestions": [],
            "surfaces": [],
        }
        findings_path = governance.M16_CODEX_SECURITY_ARTIFACTS["findings"]
        coverage_path = governance.M16_CODEX_SECURITY_ARTIFACTS["coverage"]
        manifest_path = governance.M16_CODEX_SECURITY_ARTIFACTS["scan_manifest"]
        self._write_json(findings_path, canonical_findings)
        self._write_json(coverage_path, canonical_coverage)
        canonical_manifest = {
            "documentType": "codex-security.scan-manifest",
            "schemaVersion": "1.0",
            "scan": {
                "id": scan_id,
                "status": "completed",
                "producer": {
                    "name": "codex-security-plugin",
                    "version": "0.1.18",
                },
                "startedAt": "2026-08-12T19:00:00Z",
                "completedAt": "2026-08-12T19:30:00Z",
                "sealedAt": "2026-08-12T19:30:00Z",
                "findingsRef": "findings.json",
                "coverageRef": "coverage.json",
                "target": {
                    "kind": "directory_snapshot",
                    "targetId": "target_sha256_synthetic",
                    "snapshotDigest": snapshot_digest,
                },
                "scope": {
                    "includePaths": ["."],
                    "excludePaths": [],
                    "limitations": ["Synthetic partial scan."],
                    "artifactsReviewed": [
                        artifact["path"] for artifact in source_artifacts
                    ],
                },
                "artifacts": [
                    {
                        "path": "findings.json",
                        "mediaType": "application/json",
                        "sha256": digest(self.root / findings_path),
                    },
                    {
                        "path": "coverage.json",
                        "mediaType": "application/json",
                        "sha256": digest(self.root / coverage_path),
                    },
                ],
            },
        }
        self._write_json(manifest_path, canonical_manifest)
        codex_security = {
            "scan_id": scan_id,
            "snapshot_digest": snapshot_digest,
            "scan_manifest": self._artifact(manifest_path),
            "findings": self._artifact(findings_path),
            "coverage": self._artifact(coverage_path),
        }

        security = {
            "schema_version": "contextdb.m16-security-gates/v1",
            "milestone": "M16",
            "generated_at": generated_at,
            "status": "observation_only",
            "frozen_inputs": frozen,
            "source_manifest": {
                "algorithm": "sha256",
                "row_format": "path<TAB>sha256<LF>",
                "sort": "utf8_path_bytes_ascending",
                "file_count": len(source_artifacts),
                "sha256": source_manifest_sha256,
                "files": source_artifacts,
            },
            "codex_security": codex_security,
            "scan": {
                "profile": "deep",
                "started_at": "2026-08-12T19:00:00Z",
                "finished_at": "2026-08-12T19:30:00Z",
                "command": "codex-security deep scan",
                "exit_code": 0,
                "completed": True,
            },
            "findings": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
                "unresolved_critical": 0,
                "unresolved_high": 0,
                "unresolved_high_critical": 0,
            },
            "gates": [
                {
                    "id": "deep-security-scan",
                    "status": "passed",
                    "command": "codex-security deep scan",
                    "exit_code": 0,
                }
            ],
            "supply_chain": {
                "cargo_audit_passed": True,
                "cargo_deny_passed": True,
                "passed": True,
            },
            "unsafe_review": {
                "rust_unsafe_code_tokens": 0,
                "reviewed_files": len(source_artifacts),
                "passed": True,
            },
            "artifacts": [
                codex_security["scan_manifest"],
                codex_security["findings"],
                codex_security["coverage"],
            ],
            "limitations": ["Synthetic unit-test receipt."],
        }
        self._write_json("proof/M16/security-gates.json", security)

        version_path = "docs/architecture/examples/version-manifest.json"
        benchmark = {
            "schema_version": "contextdb.benchmark-result/v1",
            "run_id": "019ff4a7-bd0e-7140-b8ec-fc5c2fdd3068",
            "started_at": "2026-08-12T19:30:00Z",
            "finished_at": "2026-08-12T19:31:00Z",
            "status": "observation_only",
            "benchmark": {
                "id": "BENCH-0007",
                "family": "BENCH-G",
                "name": "M16 isolation proof",
                "version": "1",
                "dataset_version": "1",
                "scenario": "synthetic unit fixture",
                "tier": "unit",
            },
            "contextdb": {
                "version_manifest": self.version_manifest,
                "version_manifest_sha256": digest(self.root / version_path),
            },
            "environment": {
                "os": "unit-test",
                "os_version": "1",
                "architecture": "x86_64",
                "cpu": "synthetic",
                "logical_cores": 1,
                "memory_bytes": 1,
                "storage": "temporary",
                "filesystem": "temporary",
                "rustc": "rustc 1.97.1",
                "cargo": "cargo 1.97.1",
                "storage_backend": "memory",
                "build_profile": "test",
            },
            "configuration": {
                "seed": 1,
                "features": [],
                "budgets": {},
                "parameters": {
                    "security_source_manifest_sha256": source_manifest_sha256
                },
                "index_watermarks": {},
            },
            "metrics": [
                {
                    "name": "prohibited_touches",
                    "unit": "count",
                    "direction": "informational",
                    "observed": 0,
                }
            ],
            "artifacts": [
                {
                    "kind": "workspace-manifest",
                    "uri": "Cargo.toml",
                    "sha256": digest(self.root / "Cargo.toml"),
                },
                {
                    "kind": "cargo-lock",
                    "uri": "Cargo.lock",
                    "sha256": digest(self.root / "Cargo.lock"),
                },
                {
                    "kind": "version-manifest",
                    "uri": version_path,
                    "sha256": digest(self.root / version_path),
                },
            ],
            "limitations": ["Synthetic unit-test receipt."],
        }
        self._write_json("proof/M16/BENCH-G.json", benchmark)

        fuzz = {
            "schema_version": "contextdb.m16-fuzz-smoke/v1",
            "milestone": "M16",
            "generated_at": generated_at,
            "status": "observation_only",
            "frozen_inputs": frozen,
            "environment": {
                "os": "unit-test",
                "architecture": "x86_64",
                "rust_toolchain": "nightly-test",
                "cargo_fuzz": "0.13.2",
                "sanitizer": "address",
            },
            "targets": [
                {
                    "name": "record_envelope",
                    "source": self._artifact("fuzz/fuzz_targets/record_envelope.rs"),
                    "command": "cargo fuzz run record_envelope",
                    "configured_seconds": 1,
                    "executions": 1,
                    "crashes": 0,
                    "timeouts": 0,
                    "out_of_memory": 0,
                    "artifact_files": 0,
                    "status": "passed",
                }
            ],
            "summary": {
                "total_targets": 1,
                "passed_targets": 1,
                "failed_targets": 0,
            },
            "limitations": ["Synthetic unit-test receipt."],
        }
        self._write_json("proof/M16/fuzz-smoke.json", fuzz)

        sbom = {
            "schema_version": "contextdb.m16-sbom-index/v1",
            "milestone": "M16",
            "generated_at": generated_at,
            "status": "observation_only",
            "frozen_inputs": frozen,
            "cyclonedx_spec": "1.5",
            "source_date_epoch": 0,
            "files": [
                self._artifact("test-crate/contextdb-test.cdx.json", include_bytes=True)
            ],
            "totals": {
                "files": 1,
                "bytes": (self.root / "test-crate/contextdb-test.cdx.json")
                .stat()
                .st_size,
                "components": 0,
                "dependency_edges": 0,
            },
            "limitations": ["Synthetic unit-test receipt."],
        }
        self._write_json("proof/M16/sbom-index.json", sbom)

        process_kill = {
            "schema_version": "contextdb.m16-process-kill/v1",
            "milestone": "M16",
            "generated_at": generated_at,
            "status": "observation_only",
            "frozen_inputs": frozen,
            "environment": {
                "os": "unit-test",
                "architecture": "x86_64",
                "rust_toolchain": "1.97.1",
                "execution": "native",
            },
            "backend": "redb-test",
            "durability": "sync",
            "command": "cargo run --example process_kill",
            "source_artifacts": [
                self._artifact("crates/fault/examples/process_kill.rs")
            ],
            "cases": [
                {
                    "name": "kill_with_uncommitted_transaction",
                    "child_reached_barrier": True,
                    "child_was_terminated": True,
                    "reopened": True,
                    "expected_value_visible": False,
                    "head_sequence": 0,
                    "deep_verify_records": 0,
                    "status": "passed",
                },
                {
                    "name": "kill_after_sync_ack",
                    "child_reached_barrier": True,
                    "child_was_terminated": True,
                    "reopened": True,
                    "expected_value_visible": True,
                    "head_sequence": 1,
                    "deep_verify_records": 1,
                    "status": "passed",
                },
            ],
            "summary": {
                "acknowledged_commits": 1,
                "acknowledged_commits_recovered": 1,
                "acknowledged_loss": 0,
            },
            "limitations": ["Synthetic unit-test receipt."],
        }
        self._write_json("proof/M16/process-kill-redb.json", process_kill)

        fault = {
            "schema_version": "contextdb.m16-fault-delete-restore/v1",
            "milestone": "M16",
            "generated_at": generated_at,
            "status": "observation_only",
            "frozen_inputs": frozen,
            "acknowledged_durability": {
                "acknowledged_commits": 1,
                "acknowledged_commits_recovered": 1,
                "acknowledged_loss": 0,
                "passed": True,
            },
            "semantic_atomicity": {
                "partial_publications_observed": 0,
                "checks": [{"id": "atomicity", "status": "passed", "exit_code": 0}],
                "passed": True,
            },
            "deletion": {
                "required_target_classes": sorted(governance.M16_DELETION_TARGETS),
                "dispositions": [
                    {
                        "target": target,
                        "disposition": "verified_absent",
                        "verified": True,
                    }
                    for target in sorted(governance.M16_DELETION_TARGETS)
                ],
                "all_dispositions_verified": True,
                "passed": True,
            },
            "backup_restore": {
                "checks": [{"id": "restore", "status": "passed", "exit_code": 0}],
                "passed": True,
            },
            "test_runs": [
                {
                    "id": "fault-matrix",
                    "environment": "unit-test",
                    "command": "cargo test",
                    "exit_code": 0,
                    "status": "passed",
                }
            ],
            "artifacts": [
                self._artifact(path)
                for path in sorted(governance.M16_FAULT_DEPENDENCIES)
            ],
            "limitations": ["Synthetic unit-test receipt."],
        }
        self._write_json("proof/M16/fault-delete-restore.json", fault)

    def _validate(self) -> dict[str, dict]:
        return governance.validate_m16_proofs(
            self.milestone,
            self.schemas,
            self.registry,
            root=self.root,
        )

    def _load_receipt(self, path: str) -> dict:
        return json.loads((self.root / path).read_text(encoding="utf-8"))

    def _write_security_with_refreshed_scan_hashes(self, security: dict) -> None:
        manifest_path = governance.M16_CODEX_SECURITY_ARTIFACTS["scan_manifest"]
        findings_path = governance.M16_CODEX_SECURITY_ARTIFACTS["findings"]
        coverage_path = governance.M16_CODEX_SECURITY_ARTIFACTS["coverage"]
        manifest = self._load_receipt(manifest_path)
        for artifact in manifest["scan"]["artifacts"]:
            if artifact["path"] == "findings.json":
                artifact["sha256"] = digest(self.root / findings_path)
            elif artifact["path"] == "coverage.json":
                artifact["sha256"] = digest(self.root / coverage_path)
        self._write_json(manifest_path, manifest)
        security["codex_security"]["scan_manifest"] = self._artifact(manifest_path)
        security["codex_security"]["findings"] = self._artifact(findings_path)
        security["codex_security"]["coverage"] = self._artifact(coverage_path)
        security["artifacts"] = [
            security["codex_security"]["scan_manifest"],
            security["codex_security"]["findings"],
            security["codex_security"]["coverage"],
        ]
        self._write_json("proof/M16/security-gates.json", security)

    def _promote_all_receipts_to_passed(self) -> None:
        coverage_path = governance.M16_CODEX_SECURITY_ARTIFACTS["coverage"]
        coverage = self._load_receipt(coverage_path)
        coverage["completeness"] = "complete"
        coverage["deferred"] = []
        self._write_json(coverage_path, coverage)

        manifest_path = governance.M16_CODEX_SECURITY_ARTIFACTS["scan_manifest"]
        manifest = self._load_receipt(manifest_path)
        manifest["scan"]["scope"]["limitations"] = []
        for artifact in manifest["scan"]["artifacts"]:
            if artifact["path"] == "coverage.json":
                artifact["sha256"] = digest(self.root / coverage_path)
        self._write_json(manifest_path, manifest)

        security_path = "proof/M16/security-gates.json"
        security = self._load_receipt(security_path)
        security["status"] = "passed"
        security["codex_security"]["scan_manifest"] = self._artifact(manifest_path)
        security["codex_security"]["coverage"] = self._artifact(coverage_path)
        security["artifacts"] = [
            security["codex_security"]["scan_manifest"],
            security["codex_security"]["findings"],
            security["codex_security"]["coverage"],
        ]
        self._write_json(security_path, security)

        benchmark_path = "proof/M16/BENCH-G.json"
        benchmark = self._load_receipt(benchmark_path)
        benchmark["status"] = "passed"
        benchmark["metrics"][0].update(
            {
                "direction": "lower_is_better",
                "threshold": {"operator": "eq", "value": 0},
                "passed": True,
            }
        )
        benchmark["quality_gates"] = [
            {
                "gate_id": "no-prohibited-touch",
                "metric": "prohibited_touches",
                "passed": True,
            }
        ]
        self._write_json(benchmark_path, benchmark)

        fuzz_path = "proof/M16/fuzz-smoke.json"
        fuzz = self._load_receipt(fuzz_path)
        fuzz["status"] = "passed"
        fuzz["targets"].append(
            {
                "name": "security_envelope",
                "source": self._artifact("fuzz/fuzz_targets/security_envelope.rs"),
                "command": "cargo fuzz run security_envelope",
                "configured_seconds": 1,
                "executions": 1,
                "crashes": 0,
                "timeouts": 0,
                "out_of_memory": 0,
                "artifact_files": 0,
                "status": "passed",
            }
        )
        fuzz["summary"] = {
            "total_targets": 2,
            "passed_targets": 2,
            "failed_targets": 0,
        }
        self._write_json(fuzz_path, fuzz)

        for path in (
            "proof/M16/sbom-index.json",
            "proof/M16/process-kill-redb.json",
        ):
            receipt = self._load_receipt(path)
            receipt["status"] = "passed"
            self._write_json(path, receipt)

        fault_path = "proof/M16/fault-delete-restore.json"
        fault = self._load_receipt(fault_path)
        fault["status"] = "passed"
        fault["artifacts"] = [
            self._artifact(path) for path in sorted(governance.M16_FAULT_DEPENDENCIES)
        ]
        self._write_json(fault_path, fault)
        self.milestone["status"] = "passed"

    def test_honest_incomplete_receipts_are_schema_and_hash_valid(self) -> None:
        documents = self._validate()
        self.assertEqual(set(documents), set(governance.M16_PROOF_CONTRACTS))

    def test_coherent_passing_receipt_set_is_accepted(self) -> None:
        self._promote_all_receipts_to_passed()
        documents = self._validate()
        self.assertTrue(
            all(document["status"] == "passed" for document in documents.values())
        )

    def test_not_started_missing_required_proof_is_accepted(self) -> None:
        (self.root / "proof/M16/security-gates.json").unlink()
        documents = self._validate()
        self.assertNotIn("proof/M16/security-gates.json", documents)
        self.assertEqual(
            set(documents),
            set(governance.M16_PROOF_CONTRACTS)
            - {"proof/M16/security-gates.json"},
        )

    def test_passed_missing_required_proof_is_rejected(self) -> None:
        self.milestone["status"] = "passed"
        (self.root / "proof/M16/security-gates.json").unlink()
        with self.assertRaisesRegex(AssertionError, "required proof is missing"):
            self._validate()

    def test_waived_missing_required_proof_is_rejected(self) -> None:
        self.milestone["status"] = "waived"
        (self.root / "proof/M16/security-gates.json").unlink()
        with self.assertRaisesRegex(AssertionError, "required proof is missing"):
            self._validate()

    def test_wrong_schema_mapping_is_rejected(self) -> None:
        self.milestone["required_proof"][0]["schema_id"] = (
            "https://contextdb.dev/schemas/m16-fuzz-smoke/v1.json"
        )
        with self.assertRaisesRegex(AssertionError, "schema mapping mismatch"):
            self._validate()

    def test_wrong_document_schema_version_is_rejected(self) -> None:
        path = "proof/M16/fuzz-smoke.json"
        receipt = self._load_receipt(path)
        receipt["schema_version"] = "contextdb.fuzz-smoke/v0"
        self._write_json(path, receipt)
        with self.assertRaisesRegex(AssertionError, "Schema validation failed"):
            self._validate()

    def test_passed_milestone_rejects_non_passing_status(self) -> None:
        self.milestone["status"] = "passed"
        with self.assertRaisesRegex(AssertionError, "non-passing receipt statuses"):
            self._validate()

    def test_cargo_hash_mismatch_is_rejected(self) -> None:
        path = "proof/M16/fuzz-smoke.json"
        receipt = self._load_receipt(path)
        receipt["frozen_inputs"]["cargo_lock_sha256"] = "0" * 64
        self._write_json(path, receipt)
        with self.assertRaisesRegex(AssertionError, "frozen source/Cargo hash"):
            self._validate()

    def test_source_hash_mismatch_is_rejected(self) -> None:
        self._write_text("src/security.rs", "pub fn checked() -> bool { false }\n")
        with self.assertRaisesRegex(AssertionError, "security source hash mismatch"):
            self._validate()

    def test_artifact_hash_mismatch_is_rejected(self) -> None:
        self._write_json(
            "test-crate/contextdb-test.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 2,
                "components": [],
                "dependencies": [],
            },
        )
        with self.assertRaisesRegex(AssertionError, "M16 SBOM hash mismatch"):
            self._validate()

    def test_passed_security_receipt_rejects_unresolved_high(self) -> None:
        self._promote_all_receipts_to_passed()
        path = "proof/M16/security-gates.json"
        receipt = self._load_receipt(path)
        receipt["findings"]["high"] = 1
        receipt["findings"]["unresolved_high"] = 1
        receipt["findings"]["unresolved_high_critical"] = 1
        findings_path = governance.M16_CODEX_SECURITY_ARTIFACTS["findings"]
        canonical_findings = self._load_receipt(findings_path)
        canonical_findings["findings"] = [{"severity": {"level": "high"}}]
        self._write_json(findings_path, canonical_findings)
        self._write_security_with_refreshed_scan_hashes(receipt)
        with self.assertRaisesRegex(AssertionError, "unresolved high/critical"):
            self._validate()

    def test_passed_security_receipt_rejects_self_selected_inventory(self) -> None:
        self._promote_all_receipts_to_passed()
        self._write_text("src/unreviewed.rs", "pub fn unreviewed() {}\n")
        with self.assertRaisesRegex(AssertionError, "exact trusted source inventory"):
            self._validate()

    def test_passed_security_receipt_rejects_deferred_canonical_coverage(self) -> None:
        self._promote_all_receipts_to_passed()
        coverage_path = governance.M16_CODEX_SECURITY_ARTIFACTS["coverage"]
        coverage = self._load_receipt(coverage_path)
        coverage["completeness"] = "partial"
        coverage["deferred"] = [
            {"id": "omitted", "paths": ["src/**"], "reason": "Not reviewed."}
        ]
        self._write_json(coverage_path, coverage)
        security = self._load_receipt("proof/M16/security-gates.json")
        self._write_security_with_refreshed_scan_hashes(security)
        with self.assertRaisesRegex(
            AssertionError, "incomplete Codex Security coverage"
        ):
            self._validate()

    def test_passed_security_receipt_rejects_snapshot_not_bound_to_inventory(
        self,
    ) -> None:
        self._promote_all_receipts_to_passed()
        security = self._load_receipt("proof/M16/security-gates.json")
        security["codex_security"]["snapshot_digest"] = (
            "codex-security-snapshot/v1:sha256:" + "0" * 64
        )
        self._write_json("proof/M16/security-gates.json", security)
        with self.assertRaisesRegex(
            AssertionError, "target snapshot differs from the receipt binding"
        ):
            self._validate()

    def test_passed_sbom_rejects_semantically_empty_dependency_graph(self) -> None:
        self._promote_all_receipts_to_passed()
        sbom_artifact_path = "test-crate/contextdb-test.cdx.json"
        self._write_json(
            sbom_artifact_path,
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "components": [],
                "dependencies": [],
            },
        )
        receipt_path = "proof/M16/sbom-index.json"
        receipt = self._load_receipt(receipt_path)
        receipt["files"] = [self._artifact(sbom_artifact_path, include_bytes=True)]
        receipt["totals"] = {
            "files": 1,
            "bytes": (self.root / sbom_artifact_path).stat().st_size,
            "components": 0,
            "dependency_edges": 0,
        }
        self._write_json(receipt_path, receipt)
        fault_path = "proof/M16/fault-delete-restore.json"
        fault = self._load_receipt(fault_path)
        fault["artifacts"] = [
            self._artifact(path) for path in sorted(governance.M16_FAULT_DEPENDENCIES)
        ]
        self._write_json(fault_path, fault)
        with self.assertRaisesRegex(AssertionError, "CycloneDX dependency graph"):
            self._validate()


class GovernanceSecurityBoundaryTests(unittest.TestCase):
    def _waiver_fixture(self, *, status: str = "Accepted") -> tuple[Path, list[dict]]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        adr = root / "docs" / "adr" / "ADR-0001-synthetic-waiver.md"
        adr.parent.mkdir(parents=True)
        adr.write_text(
            "\n".join(
                (
                    "# ADR-0001: Synthetic waiver",
                    "",
                    f"- Status: {status}",
                    "- Waived milestone: M1",
                    "- Waiver expires: 2099-01-01",
                    "- Residual risk: Synthetic bounded risk.",
                    "",
                )
            ),
            encoding="utf-8",
        )
        milestones = [
            {"id": "M0", "status": "passed", "depends_on": []},
            {
                "id": "M1",
                "status": "waived",
                "status_reason": "Synthetic waiver test.",
                "depends_on": ["M0"],
                "waiver": {
                    "adr": "ADR-0001",
                    "expires": "2099-01-01",
                    "residual_risk": "Synthetic bounded risk.",
                },
            },
        ]
        return root, milestones

    def test_m19_waiver_is_never_allowed(self) -> None:
        milestones = [
            {
                "id": "M19",
                "status": "waived",
                "depends_on": [],
                "waiver": {
                    "adr": "ADR-0001",
                    "expires": "2099-01-01",
                    "residual_risk": "Synthetic risk.",
                },
            }
        ]
        with self.assertRaisesRegex(AssertionError, "M19 cannot be waived"):
            governance.validate_waivers(milestones, root=REPOSITORY_ROOT)

    def test_json_loader_rejects_oversized_input_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oversized.json"
            path.write_bytes(b" " * (governance.MAX_JSON_BYTES + 1))
            with self.assertRaisesRegex(AssertionError, "exceeds.*byte limit"):
                governance.load_json(path, root=Path(temporary))

    def test_json_loader_rejects_excessive_depth(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deep.json"
            path.write_text(
                "[" * (governance.MAX_DOCUMENT_DEPTH + 1)
                + "0"
                + "]" * (governance.MAX_DOCUMENT_DEPTH + 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AssertionError, "depth limit"):
                governance.load_json(path, root=Path(temporary))

    def test_json_loader_accepts_small_bounded_document(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "small.json"
            path.write_text('{"safe": [1, 2, 3]}', encoding="utf-8")
            self.assertEqual(
                governance.load_json(path, root=Path(temporary)),
                {"safe": [1, 2, 3]},
            )

    def test_json_loader_rejects_non_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "directory.json"
            path.mkdir()
            with self.assertRaisesRegex(AssertionError, "not a regular file"):
                governance.load_json(path, root=Path(temporary))

    def test_json_loader_rejects_excessive_node_count(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "nodes.json"
            path.write_text("[0, 1, 2, 3]", encoding="utf-8")
            with (
                mock.patch.object(governance, "MAX_DOCUMENT_NODES", 4),
                self.assertRaisesRegex(AssertionError, "node limit"),
            ):
                governance.load_json(path, root=Path(temporary))

    def test_json_loader_rejects_oversized_scalar_token(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "token.json"
            path.write_text('{"value": "123456789"}', encoding="utf-8")
            with (
                mock.patch.object(governance, "MAX_SCALAR_UTF8_BYTES", 8),
                self.assertRaisesRegex(AssertionError, "string exceeding"),
            ):
                governance.load_json(path, root=Path(temporary))

    def test_valid_non_release_waiver_is_accepted(self) -> None:
        root, milestones = self._waiver_fixture()
        governance.validate_waivers(milestones, root=root, trusted_on=date(2026, 8, 13))

    def test_expired_non_release_waiver_is_rejected(self) -> None:
        root, milestones = self._waiver_fixture()
        milestones[1]["waiver"]["expires"] = "2026-08-12"
        with self.assertRaisesRegex(AssertionError, "waiver expired"):
            governance.validate_waivers(
                milestones, root=root, trusted_on=date(2026, 8, 13)
            )

    def test_nonaccepted_waiver_adr_is_rejected(self) -> None:
        root, milestones = self._waiver_fixture(status="Proposed")
        with self.assertRaisesRegex(AssertionError, "is not Accepted"):
            governance.validate_waivers(
                milestones, root=root, trusted_on=date(2026, 8, 13)
            )

    def test_waiver_adr_semantics_must_match_ledger(self) -> None:
        root, milestones = self._waiver_fixture()
        milestones[1]["waiver"]["residual_risk"] = "Different risk."
        with self.assertRaisesRegex(AssertionError, "residual risk differs"):
            governance.validate_waivers(
                milestones, root=root, trusted_on=date(2026, 8, 13)
            )


if __name__ == "__main__":
    unittest.main()
