from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import cast
from unittest.mock import patch

TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

from contextdb_release import (
    BundleVerifier,
    ContractError,
    _cleanup_windows_probe_authorities,
    _extract_portable_example,
    _probe_contextdb_binary,
    _windows_state_head_digest,
    audit_source,
    canonical_relative_path,
    package_example,
    readiness_report,
    run_clean_install,
)

HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def gate_ledger(m18_status: str = "in_progress") -> dict[str, object]:
    milestones = []
    for number in range(20):
        milestone_id = f"M{number}"
        proof_name = "alpha-release.json" if number == 18 else "evidence.json"
        milestones.append(
            {
                "id": milestone_id,
                "title": f"Test milestone {number}",
                "status": (
                    m18_status
                    if number == 18
                    else "not_started"
                    if number == 19
                    else "passed"
                ),
                "depends_on": [] if number == 0 else [f"M{number - 1}"],
                "objective": f"Exercise {milestone_id}",
                "artifacts": [f"artifact-{number}"],
                "tests": [f"test-{number}"],
                "benchmarks": [f"benchmark-{number}"],
                "demo": f"demo-{number}",
                "exit_criteria": [
                    {"id": f"{milestone_id}-E01", "text": f"exit {number}"}
                ],
                "required_proof": [
                    {
                        "kind": "release_manifest"
                        if number in {18, 19}
                        else "test_report",
                        "path": f"proof/{milestone_id}/{proof_name}",
                    }
                ],
            }
        )
    return {
        "schema_version": "contextdb.roadmap-gate-ledger/v1",
        "roadmap_revision": "test-ledger-v1",
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
            "waiver_policy": "A test waiver requires an ADR.",
            "release_gate": "M19",
        },
        "milestones": milestones,
    }


def sample_package_matrix(source_path: str = "src") -> dict[str, object]:
    return {
        "schema_version": "contextdb.release-package-matrix/v1",
        "matrix_revision": "test-v1",
        "platforms": [
            {
                "id": "linux-x86-64",
                "os": "linux",
                "architecture": "x86_64",
                "rust_target": "x86_64-unknown-linux-gnu",
                "tier": "required",
            }
        ],
        "packages": [
            {
                "id": "sample",
                "display_name": "Sample package",
                "artifact_kind": "benchmark-suite",
                "roles": ["benchmark-suite"],
                "coverage": "platform-independent",
                "platforms": ["platform-independent"],
                "runtime_platforms": ["linux-x86-64"],
                "source_paths": [source_path],
                "current_state": "source-present",
                "install_probe": {
                    "kind": "source-package",
                    "runtime_required": True,
                },
            }
        ],
        "release_requirements": {
            "alpha": ["sample"],
            "beta": ["sample"],
            "stable": ["sample"],
        },
        "signature_requirements": {
            "alpha": {
                "roles": ["artifact-manifest", "checksums"],
                "minimum_trust": "production",
            },
            "beta": {
                "roles": [
                    "artifact-manifest",
                    "checksums",
                    "proof-index",
                    "version-manifest",
                ],
                "minimum_trust": "production",
            },
            "stable": {
                "roles": [
                    "artifact-manifest",
                    "checksums",
                    "proof-index",
                    "version-manifest",
                ],
                "minimum_trust": "production",
            },
        },
    }


def typed_release_packages(source_path: str) -> list[dict[str, object]]:
    all_targets = [
        "linux-x86-64",
        "linux-arm64",
        "macos-arm64",
        "windows-x86-64",
    ]
    specifications = (
        ("native-package", "executable", ["server", "cli"], "contextdb-binary"),
        (
            "rust-package",
            "rust-crate",
            ["rust-crates", "chat-middleware"],
            "rust-crate",
        ),
        ("python-package", "python-wheel", ["python-package"], "python-wheel"),
        ("go-package", "go-module", ["go-sdk"], "go-module"),
        (
            "typescript-package",
            "typescript-package",
            ["typescript-sdk"],
            "typescript-package",
        ),
        (
            "adapters-package",
            "source-package",
            ["mcp-adapter", "document-adapter", "coding-plugin"],
            "source-package",
        ),
        ("docker-package", "docker-image", ["docker-image"], "docker-image"),
        (
            "example-package",
            "example-database",
            ["example-databases"],
            "portable-database",
        ),
        (
            "benchmark-package",
            "benchmark-suite",
            ["benchmark-suite"],
            "source-package",
        ),
        (
            "dataset-package",
            "benchmark-dataset",
            ["benchmark-datasets"],
            "dataset",
        ),
        ("docs-package", "documentation", ["full-docs"], "documentation"),
        (
            "checksum-package",
            "checksum-set",
            ["signed-checksums"],
            "checksum-set",
        ),
        ("sbom-package", "sbom", ["sbom"], "sbom"),
    )
    runtime_kinds = {
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
    packages: list[dict[str, object]] = []
    for identifier, artifact_kind, roles, probe_kind in specifications:
        runtime_required = artifact_kind in runtime_kinds
        platforms = (
            all_targets
            if artifact_kind == "executable"
            else ["linux-x86-64", "linux-arm64"]
            if artifact_kind == "docker-image"
            else ["platform-independent"]
        )
        runtime_platforms = (
            ["linux-x86-64", "linux-arm64"]
            if artifact_kind == "docker-image"
            else all_targets
            if runtime_required
            else []
        )
        packages.append(
            {
                "id": identifier,
                "display_name": identifier.replace("-", " ").title(),
                "artifact_kind": artifact_kind,
                "roles": roles,
                "coverage": (
                    "per-platform"
                    if artifact_kind == "executable"
                    else "declared-platforms"
                    if artifact_kind == "docker-image"
                    else "platform-independent"
                ),
                "platforms": platforms,
                "runtime_platforms": runtime_platforms,
                "source_paths": [source_path],
                "current_state": "package-built",
                "install_probe": {
                    "kind": probe_kind,
                    "runtime_required": runtime_required,
                },
            }
        )
    return packages


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography is required for signature tests")
class BundleVerifierTests(unittest.TestCase):
    def make_bundle(self, root: Path) -> tuple[Path, Path]:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        bundle = root / "bundle"
        (bundle / "release").mkdir(parents=True)
        (bundle / "artifacts").mkdir()
        (bundle / "proof" / "M18").mkdir(parents=True)
        (bundle / "docs" / "roadmap").mkdir(parents=True)
        payload = bundle / "artifacts" / "contract.txt"
        payload.write_text("contract payload\n", encoding="utf-8", newline="\n")

        version = {
            "schema_version": "contextdb.version-manifest/v1",
            "product_version": "0.1.0-alpha.1",
            "release_channel": "alpha",
            "source": {
                "git_commit": "1" * 40,
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
        }
        version_path = bundle / "release" / "version.json"
        write_json(version_path, version)

        packages = typed_release_packages("artifacts/contract.txt")
        package_ids = [str(package["id"]) for package in packages]
        matrix = {
            "schema_version": "contextdb.release-package-matrix/v1",
            "matrix_revision": "test-v1",
            "platforms": [
                {
                    "id": "linux-x86-64",
                    "os": "linux",
                    "architecture": "x86_64",
                    "rust_target": "x86_64-unknown-linux-gnu",
                    "tier": "required",
                },
                {
                    "id": "linux-arm64",
                    "os": "linux",
                    "architecture": "aarch64",
                    "rust_target": "aarch64-unknown-linux-gnu",
                    "tier": "required",
                },
                {
                    "id": "macos-arm64",
                    "os": "macos",
                    "architecture": "aarch64",
                    "rust_target": "aarch64-apple-darwin",
                    "tier": "required",
                },
                {
                    "id": "windows-x86-64",
                    "os": "windows",
                    "architecture": "x86_64",
                    "rust_target": "x86_64-pc-windows-msvc",
                    "tier": "best-effort",
                },
            ],
            "packages": packages,
            "release_requirements": {
                "alpha": package_ids,
                "beta": package_ids,
                "stable": package_ids,
            },
            "signature_requirements": {
                channel: {
                    "roles": (
                        ["artifact-manifest", "checksums"]
                        if channel == "alpha"
                        else [
                            "artifact-manifest",
                            "checksums",
                            "proof-index",
                            "version-manifest",
                        ]
                    ),
                    "minimum_trust": "production",
                }
                for channel in ("alpha", "beta", "stable")
            },
        }
        matrix_path = bundle / "release" / "package-matrix.json"
        write_json(matrix_path, matrix)

        ledger = gate_ledger()
        ledger_path = bundle / "docs" / "roadmap" / "gates.json"
        write_json(ledger_path, ledger)
        alpha_proof = bundle / "proof" / "M18" / "alpha-release.json"
        write_json(alpha_proof, {"status": "not-a-release-fixture"})
        proof = {
            "schema_version": "contextdb.release-proof-index/v1",
            "release_version": "0.1.0-alpha.1",
            "release_stage": "alpha",
            "generated_at": "2026-08-12T00:00:00Z",
            "ledger": {
                "path": "docs/roadmap/gates.json",
                "sha256": digest(ledger_path),
                "roadmap_revision": "test-ledger-v1",
            },
            "milestones": [
                {
                    "id": "M18",
                    "status": "in-progress",
                    "exit_criteria": [
                        {
                            "id": "M18-E01",
                            "status": "not-started",
                            "evidence": [],
                        }
                    ],
                    "required_proofs": [
                        {
                            "kind": "release_manifest",
                            "path": "proof/M18/alpha-release.json",
                            "sha256": digest(alpha_proof),
                            "evidence_level": "source",
                        }
                    ],
                    "limitations": ["contract fixture"],
                }
            ],
            "known_gaps": [
                {"gate_id": "M18-E01", "reason": "contract fixture", "blocking": True}
            ],
        }
        proof_path = bundle / "release" / "proof-index.json"
        write_json(proof_path, proof)

        manifest = {
            "schema_version": "contextdb.release-artifact-manifest/v1",
            "release": {
                "version": "0.1.0-alpha.1",
                "channel": "alpha",
                "created_at": "2026-08-12T00:00:00Z",
                "candidate": 1,
            },
            "source": {
                "repository": "https://example.invalid/contextdb",
                "git_commit": "1" * 40,
                "dirty": False,
            },
            "version_manifest": {
                "path": "release/version.json",
                "sha256": digest(version_path),
            },
            "package_matrix": {
                "path": "release/package-matrix.json",
                "sha256": digest(matrix_path),
            },
            "proof_index": {
                "path": "release/proof-index.json",
                "sha256": digest(proof_path),
            },
            "checksum_file": {
                "path": "SHA256SUMS",
                "algorithm": "sha256",
                "format": "sha256sum-v1",
            },
            "signature_set": {"path": "release/signatures.json"},
            "artifacts": [
                {
                    "id": "contract-artifact",
                    "package_id": "adapters-package",
                    "roles": ["mcp-adapter", "document-adapter", "coding-plugin"],
                    "kind": "source-package",
                    "path": "artifacts/contract.txt",
                    "media_type": "text/plain",
                    "size_bytes": payload.stat().st_size,
                    "sha256": digest(payload),
                    "targets": ["platform-independent"],
                    "version": "0.1.0-alpha.1",
                    "version_manifest_sha256": digest(version_path),
                    "provenance": {
                        "source_commit": "1" * 40,
                        "builder": "unit-test",
                        "build_recipe": "release/package-matrix.json",
                        "reproducible": True,
                    },
                    "related_files": [],
                }
            ],
            "limitations": ["contract fixture; not a release"],
        }
        manifest_path = bundle / "release" / "artifact-manifest.json"
        write_json(manifest_path, manifest)

        checksum_paths = [
            "artifacts/contract.txt",
            "docs/roadmap/gates.json",
            "proof/M18/alpha-release.json",
            "release/artifact-manifest.json",
            "release/package-matrix.json",
            "release/proof-index.json",
            "release/version.json",
        ]
        sums = "".join(
            f"{digest(bundle / path)}  {path}\n" for path in sorted(checksum_paths)
        )
        checksum_path = bundle / "SHA256SUMS"
        checksum_path.write_text(sums, encoding="utf-8", newline="\n")

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_path = root / "trusted-test-key.pem"
        public_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = hashlib.sha256(der).hexdigest()
        signatures = []
        for role, subject_relative in (
            ("artifact-manifest", "release/artifact-manifest.json"),
            ("checksums", "SHA256SUMS"),
        ):
            subject = bundle / subject_relative
            signature_relative = f"release/{role}.sig"
            signature_path = bundle / signature_relative
            signature_path.write_bytes(private_key.sign(subject.read_bytes()))
            signatures.append(
                {
                    "role": role,
                    "subject_path": subject_relative,
                    "subject_sha256": digest(subject),
                    "signature_path": signature_relative,
                    "signature_sha256": digest(signature_path),
                    "algorithm": "ed25519",
                    "encoding": "raw",
                    "key_id": "test-key",
                    "key_fingerprint_sha256": fingerprint,
                    "trust": "test",
                }
            )
        write_json(
            bundle / "release" / "signatures.json",
            {
                "schema_version": "contextdb.release-signature-set/v1",
                "release_version": "0.1.0-alpha.1",
                "created_at": "2026-08-12T00:00:00Z",
                "signatures": signatures,
            },
        )
        return bundle, public_path

    def promote_bundle_to_release(self, root: Path, bundle: Path) -> Path:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        matrix = json.loads(
            (bundle / "release" / "package-matrix.json").read_text(encoding="utf-8")
        )
        ledger_path = bundle / "docs" / "roadmap" / "gates.json"
        ledger = gate_ledger("passed")
        write_json(ledger_path, ledger)

        proof_milestones = []
        for milestone in cast(list[dict[str, object]], ledger["milestones"])[:19]:
            milestone_id = cast(str, milestone["id"])
            required_proofs = []
            for proof in cast(list[dict[str, str]], milestone["required_proof"]):
                proof_path = bundle.joinpath(*Path(proof["path"]).parts)
                write_json(proof_path, {"milestone": milestone_id, "passed": True})
                required_proofs.append(
                    {
                        "kind": proof["kind"],
                        "path": proof["path"],
                        "sha256": digest(proof_path),
                        "evidence_level": "runtime",
                    }
                )
            proof_milestones.append(
                {
                    "id": milestone_id,
                    "status": "passed",
                    "exit_criteria": [
                        {
                            "id": exit_value["id"],
                            "status": "passed",
                            "evidence": required_proofs,
                        }
                        for exit_value in cast(
                            list[dict[str, str]], milestone["exit_criteria"]
                        )
                    ],
                    "required_proofs": required_proofs,
                    "limitations": [],
                }
            )
        proof_path = bundle / "release" / "proof-index.json"
        write_json(
            proof_path,
            {
                "schema_version": "contextdb.release-proof-index/v1",
                "release_version": "0.1.0-alpha.1",
                "release_stage": "alpha",
                "generated_at": "2026-08-12T00:00:00Z",
                "ledger": {
                    "path": "docs/roadmap/gates.json",
                    "sha256": digest(ledger_path),
                    "roadmap_revision": "test-ledger-v1",
                },
                "milestones": proof_milestones,
                "known_gaps": [],
            },
        )

        old_payload = bundle / "artifacts" / "contract.txt"
        old_payload.unlink()
        version_path = bundle / "release" / "version.json"
        artifacts = []
        sbom_kinds = {
            "executable",
            "rust-crate",
            "python-wheel",
            "go-module",
            "typescript-package",
            "source-package",
            "docker-image",
        }
        for package in cast(list[dict[str, object]], matrix["packages"]):
            package_id = cast(str, package["id"])
            artifact_kind = cast(str, package["artifact_kind"])
            package_targets = cast(list[str], package["platforms"])
            coverage = cast(str, package["coverage"])
            target_sets = (
                [[target] for target in package_targets]
                if coverage == "per-platform"
                else [package_targets]
            )
            for artifact_targets in target_sets:
                target_suffix = (
                    f"-{artifact_targets[0]}" if coverage == "per-platform" else ""
                )
                artifact_id = (
                    package_id.removesuffix("-package") + "-artifact" + target_suffix
                )
                artifact_relative = f"artifacts/{artifact_id}.bin"
                artifact_path = bundle.joinpath(*Path(artifact_relative).parts)
                artifact_path.write_bytes(f"{artifact_id}\n".encode())
                artifact = {
                    "id": artifact_id,
                    "package_id": package_id,
                    "roles": package["roles"],
                    "kind": artifact_kind,
                    "path": artifact_relative,
                    "media_type": "application/octet-stream",
                    "size_bytes": artifact_path.stat().st_size,
                    "sha256": digest(artifact_path),
                    "targets": artifact_targets,
                    "version": "0.1.0-alpha.1",
                    "version_manifest_sha256": digest(version_path),
                    "provenance": {
                        "source_commit": "1" * 40,
                        "builder": "positive-release-unit-test",
                        "build_recipe": "release/package-matrix.json",
                        "reproducible": True,
                    },
                    "related_files": [],
                }
                related_files = cast(list[dict[str, object]], artifact["related_files"])
                if artifact_kind in sbom_kinds:
                    sbom_relative = f"release/evidence/{artifact_id}.cdx.json"
                    sbom_path = bundle.joinpath(*Path(sbom_relative).parts)
                    write_json(
                        sbom_path,
                        {
                            "bomFormat": "CycloneDX",
                            "specVersion": "1.6",
                            "metadata": {
                                "component": {
                                    "hashes": [
                                        {
                                            "alg": "SHA-256",
                                            "content": artifact["sha256"],
                                        }
                                    ]
                                }
                            },
                        },
                    )
                    related_files.append(
                        {
                            "kind": "sbom",
                            "path": sbom_relative,
                            "sha256": digest(sbom_path),
                            "size_bytes": sbom_path.stat().st_size,
                            "evidence_level": "static",
                            "status": "passed",
                        }
                    )
                publication_relative = (
                    f"release/evidence/{artifact_id}.publication.json"
                )
                publication_path = bundle.joinpath(*Path(publication_relative).parts)
                subject = {
                    key: artifact[key] for key in ("id", "path", "sha256", "version")
                }
                write_json(
                    publication_path,
                    {
                        "schema_version": "contextdb.release-publication-receipt/v1",
                        "artifact": subject,
                        "registry_type": "static-https",
                        "immutable_uri": (
                            "https://releases.example.org/"
                            f"{artifact_id}/{artifact['sha256']}"
                        ),
                        "immutable_reference": True,
                        "published_at": "2026-08-12T00:00:00Z",
                        "verified_at": "2026-08-12T00:01:00Z",
                        "retrieved_sha256": artifact["sha256"],
                        "status": "passed",
                    },
                )
                related_files.append(
                    {
                        "kind": "publication-receipt",
                        "path": publication_relative,
                        "sha256": digest(publication_path),
                        "size_bytes": publication_path.stat().st_size,
                        "evidence_level": "publication",
                        "status": "passed",
                    }
                )
                install_probe = cast(dict[str, object], package["install_probe"])
                if install_probe["runtime_required"] is True:
                    receipt_platforms = (
                        artifact_targets
                        if coverage == "per-platform"
                        else cast(list[str], package["runtime_platforms"])
                    )
                    for platform_id in receipt_platforms:
                        receipt_relative = (
                            f"release/evidence/{artifact_id}.{platform_id}.install.json"
                        )
                        receipt_path = bundle.joinpath(*Path(receipt_relative).parts)
                        write_json(
                            receipt_path,
                            {
                                "schema_version": "contextdb.clean-install-receipt/v1",
                                "verifier_version": "0.1.0-alpha.2",
                                "generated_at": "2026-08-12T00:02:00Z",
                                "profile": "contract",
                                "host_target": platform_id,
                                "isolated_copy": True,
                                "verification": {
                                    "schema_version": (
                                        "contextdb.release-verification-report/v1"
                                    ),
                                    "profile": "contract",
                                    "contract_valid": True,
                                    "release_ready": False,
                                },
                                "subject_artifacts": [subject],
                                "probes": [
                                    {
                                        "id": "synthetic-positive-fixture",
                                        "status": "passed",
                                        "evidence_level": "runtime",
                                        "argv": ["fixture", package_id],
                                    }
                                ],
                                "passed": True,
                                "release_ready": False,
                                "docker_runtime_executed": (
                                    artifact_kind == "docker-image"
                                ),
                            },
                        )
                        related_files.append(
                            {
                                "kind": "install-receipt",
                                "path": receipt_relative,
                                "sha256": digest(receipt_path),
                                "size_bytes": receipt_path.stat().st_size,
                                "platform": platform_id,
                                "evidence_level": "runtime",
                                "status": "passed",
                            }
                        )
                artifacts.append(artifact)

        manifest_path = bundle / "release" / "artifact-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["proof_index"]["sha256"] = digest(proof_path)
        manifest["artifacts"] = artifacts
        manifest["limitations"] = ["synthetic positive verifier fixture"]
        write_json(manifest_path, manifest)

        checksum_path = bundle / "SHA256SUMS"
        signature_set_path = bundle / "release" / "signatures.json"
        for path in (bundle / "release").glob("*.sig"):
            path.unlink()
        tracked = sorted(
            (
                path
                for path in bundle.rglob("*")
                if path.is_file()
                and path not in {checksum_path, signature_set_path}
                and path.suffix != ".sig"
            ),
            key=lambda path: path.relative_to(bundle).as_posix().encode(),
        )
        checksum_path.write_text(
            "".join(
                f"{digest(path)}  {path.relative_to(bundle).as_posix()}\n"
                for path in tracked
            ),
            encoding="utf-8",
            newline="\n",
        )

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_path = root / "trusted-production-key.pem"
        public_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = hashlib.sha256(der).hexdigest()
        signatures = []
        for role, subject_relative in (
            ("artifact-manifest", "release/artifact-manifest.json"),
            ("checksums", "SHA256SUMS"),
        ):
            signature_relative = f"release/{role}.sig"
            subject_path = bundle.joinpath(*Path(subject_relative).parts)
            signature_path = bundle.joinpath(*Path(signature_relative).parts)
            signature_path.write_bytes(private_key.sign(subject_path.read_bytes()))
            signatures.append(
                {
                    "role": role,
                    "subject_path": subject_relative,
                    "subject_sha256": digest(subject_path),
                    "signature_path": signature_relative,
                    "signature_sha256": digest(signature_path),
                    "algorithm": "ed25519",
                    "encoding": "raw",
                    "key_id": "production-key",
                    "key_fingerprint_sha256": fingerprint,
                    "trust": "production",
                }
            )
        write_json(
            signature_set_path,
            {
                "schema_version": "contextdb.release-signature-set/v1",
                "release_version": "0.1.0-alpha.1",
                "created_at": "2026-08-12T00:03:00Z",
                "signatures": signatures,
            },
        )
        return public_path

    def test_contract_profile_verifies_integrity_but_never_claims_release(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            bundle, key = self.make_bundle(root)
            report = BundleVerifier(
                bundle,
                "release/artifact-manifest.json",
                "contract",
                {"test-key": key},
                True,
            ).verify()
            self.assertTrue(report["contract_valid"], report["issues"])
            self.assertFalse(report["release_ready"])
            self.assertEqual(report["outcome"], "contract_valid")
            self.assertIn("M18-E01", report["unresolved_gates"])

    def test_tampered_artifact_fails_before_any_release_claim(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            bundle, key = self.make_bundle(root)
            (bundle / "artifacts" / "contract.txt").write_text(
                "tampered\n", encoding="utf-8"
            )
            report = BundleVerifier(
                bundle,
                "release/artifact-manifest.json",
                "contract",
                {"test-key": key},
                True,
            ).verify()
            self.assertFalse(report["contract_valid"])
            self.assertFalse(report["release_ready"])
            self.assertIn(
                "DIGEST_MISMATCH", {issue["code"] for issue in report["issues"]}
            )

    def test_release_profile_rejects_test_signature(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            bundle, key = self.make_bundle(root)
            report = BundleVerifier(
                bundle,
                "release/artifact-manifest.json",
                "release",
                {"test-key": key},
                True,
            ).verify()
            self.assertFalse(report["release_ready"])
            self.assertIn(
                "SIGNATURE_INVALID", {issue["code"] for issue in report["issues"]}
            )
            self.assertIn(
                "BLOCKING_KNOWN_GAP", {issue["code"] for issue in report["issues"]}
            )
            self.assertIn(
                "PUBLICATION_RECEIPT_MISSING",
                {issue["code"] for issue in report["issues"]},
            )

    def test_release_profile_accepts_complete_production_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            bundle, _test_key = self.make_bundle(root)
            production_key = self.promote_bundle_to_release(root, bundle)
            report = BundleVerifier(
                bundle,
                "release/artifact-manifest.json",
                "release",
                {"production-key": production_key},
                False,
            ).verify()
            self.assertTrue(report["contract_valid"], report["issues"])
            self.assertTrue(report["release_ready"], report["issues"])
            self.assertEqual(report["outcome"], "release_ready")
            self.assertEqual(report["summary"]["errors"], 0)
            self.assertEqual(report["unresolved_gates"], [])

    def test_trusted_key_shipped_inside_bundle_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            bundle, key = self.make_bundle(root)
            bundled_key = bundle / "release" / "untrusted-bundled-key.pem"
            bundled_key.write_bytes(key.read_bytes())
            report = BundleVerifier(
                bundle,
                "release/artifact-manifest.json",
                "contract",
                {"test-key": bundled_key},
                True,
            ).verify()
            self.assertFalse(report["contract_valid"])
            self.assertIn(
                "TRUSTED_KEY_INSIDE_BUNDLE",
                {issue["code"] for issue in report["issues"]},
            )

    def test_duplicate_milestones_and_exit_ids_are_rejected(self) -> None:
        milestone = {
            "id": "M18",
            "exit_criteria": [{"id": "M18-E01"}, {"id": "M18-E01"}],
        }
        with self.assertRaisesRegex(ContractError, "repeats exit"):
            BundleVerifier._milestone_map([milestone], "proof index")
        milestone["exit_criteria"] = [{"id": "M18-E01"}]
        with self.assertRaisesRegex(ContractError, "repeats milestone"):
            BundleVerifier._milestone_map([milestone, milestone], "proof index")

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"), "jsonschema unavailable"
    )
    def test_contract_fixture_validates_every_release_schema(self) -> None:
        import jsonschema  # type: ignore[import-untyped]

        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            bundle, key = self.make_bundle(root)
            repo = TOOL_ROOT.parents[1]
            schema_dir = repo / "assets" / "schemas"
            pairs = (
                (
                    "release-artifact-manifest.schema.json",
                    bundle / "release" / "artifact-manifest.json",
                ),
                (
                    "release-package-matrix.schema.json",
                    bundle / "release" / "package-matrix.json",
                ),
                (
                    "release-proof-index.schema.json",
                    bundle / "release" / "proof-index.json",
                ),
                (
                    "release-signature-set.schema.json",
                    bundle / "release" / "signatures.json",
                ),
                (
                    "roadmap-gate-ledger.schema.json",
                    bundle / "docs" / "roadmap" / "gates.json",
                ),
                ("version-manifest.schema.json", bundle / "release" / "version.json"),
            )
            for schema_name, instance_path in pairs:
                with self.subTest(schema=schema_name):
                    schema = json.loads(
                        (schema_dir / schema_name).read_text(encoding="utf-8")
                    )
                    instance = json.loads(instance_path.read_text(encoding="utf-8"))
                    jsonschema.Draft202012Validator(schema).validate(instance)
            verification = BundleVerifier(
                bundle,
                "release/artifact-manifest.json",
                "contract",
                {"test-key": key},
                True,
            ).verify()
            receipt = run_clean_install(
                bundle,
                "release/artifact-manifest.json",
                "contract",
                {"test-key": key},
                True,
            )
            for schema_name, instance in (
                ("release-verification-report.schema.json", verification),
                ("clean-install-receipt.schema.json", receipt),
            ):
                with self.subTest(schema=schema_name):
                    schema = json.loads(
                        (schema_dir / schema_name).read_text(encoding="utf-8")
                    )
                    jsonschema.Draft202012Validator(schema).validate(instance)

    def test_clean_install_refuses_unprobed_bundle_and_remains_non_release(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            bundle, key = self.make_bundle(root)
            receipt = run_clean_install(
                bundle,
                "release/artifact-manifest.json",
                "contract",
                {"test-key": key},
                True,
            )
            self.assertTrue(receipt["isolated_copy"])
            self.assertFalse(receipt["passed"], receipt)
            self.assertFalse(receipt["release_ready"])
            self.assertFalse(receipt["docker_runtime_executed"])
            self.assertEqual(receipt["subject_artifacts"], [])


class PathAndPackagingTests(unittest.TestCase):
    @staticmethod
    def artifact_fixture() -> dict[str, object]:
        return {
            "id": "contextdb-linux",
            "path": "artifacts/contextdb-linux",
            "sha256": "a" * 64,
            "version": "1.0.0",
            "kind": "executable",
            "provenance": {"source_commit": "b" * 40},
        }

    @staticmethod
    def verifier_fixture(root: Path) -> BundleVerifier:
        root.mkdir(parents=True, exist_ok=True)
        return BundleVerifier(root, "manifest.json", "release", {}, False)

    def test_path_traversal_and_noncanonical_paths_are_rejected(self) -> None:
        for value in (
            "../escape",
            "a/../escape",
            "/absolute",
            "C:/drive",
            "a\\b",
            "./a",
            "CON.txt",
            "trailing.",
            "colon:name",
            "cafe\u0301.json",
        ):
            with self.subTest(value=value), self.assertRaises(ContractError):
                canonical_relative_path(value, "test")

    def test_portable_case_collisions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            verifier = self.verifier_fixture(Path(value))
            verifier.register_path("artifacts/ContextDB.zip", "first")
            verifier.register_path("artifacts/contextdb.zip", "second")
            self.assertIn(
                "PATH_CASE_COLLISION", {issue.code for issue in verifier.issues}
            )

    def test_portable_example_zip_is_byte_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source = root / "payload"
            source.mkdir()
            (source / "example.ctxb").write_bytes(b"canonical-example\x00")
            (source / "README.txt").write_text(
                "example\n", encoding="utf-8", newline="\n"
            )
            first = root / "first.zip"
            second = root / "second.zip"
            first_receipt = package_example(source, first, False)
            second_receipt = package_example(source, second, False)
            self.assertEqual(first_receipt["sha256"], second_receipt["sha256"])
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertFalse(first_receipt["release_ready"])

    def test_portable_packager_rejects_missing_archive_and_key_material(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source = root / "payload"
            source.mkdir()
            (source / "metadata.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ContractError, "exactly one .ctxb"):
                package_example(source, root / "missing.zip", False)
            (source / "memory.ctxb").write_bytes(b"logical")
            (source / "memory.ctxb.key").write_text("forbidden", encoding="utf-8")
            with self.assertRaisesRegex(ContractError, "key material"):
                package_example(source, root / "key.zip", False)
            (source / "memory.ctxb.key").unlink()
            (source / "state_head.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ContractError, "state-head authority"):
                package_example(source, root / "authority.zip", False)

    def test_portable_zip_extraction_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            malicious = root / "malicious.zip"
            with zipfile.ZipFile(malicious, "w") as archive:
                archive.writestr("../escape.ctxb", b"not-safe")
            with self.assertRaises(ContractError):
                _extract_portable_example(malicious, root)

    def test_portable_zip_extraction_rejects_state_head_material(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            malicious = root / "malicious.zip"
            with zipfile.ZipFile(malicious, "w") as archive:
                archive.writestr("memory.ctxb", b"logical")
                archive.writestr("state-head.json", b"{}")
            with self.assertRaisesRegex(ContractError, "state-head authority"):
                _extract_portable_example(malicious, root)

    def test_portable_zip_extracts_exactly_one_logical_archive(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            package = root / "example.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("metadata.json", b"{}")
                archive.writestr("memory.ctxb", b"logical")
            extracted = _extract_portable_example(package, root)
            self.assertEqual(extracted.read_bytes(), b"logical")

    def test_binary_probe_rejects_adjacent_plaintext_key(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            isolated = Path(value)
            (isolated / "example.ctxb").write_bytes(b"logical")
            captured_environments: list[dict[str, str]] = []

            def fake_run(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                environment = cast(dict[str, str], kwargs["env"])
                captured_environments.append(environment.copy())
                if "init" in command:
                    archive = Path(command[-1])
                    archive.parent.mkdir(parents=True, exist_ok=True)
                    archive.write_bytes(b"archive")
                    archive.with_name(f"{archive.name}.key").write_text(
                        "forbidden", encoding="utf-8"
                    )
                stdout = (
                    b"contextdb 0.1.0-alpha.1\n" if command[-1] == "version" else b""
                )
                return subprocess.CompletedProcess(command, 0, stdout, b"")

            with (
                patch("contextdb_release._host_target", return_value="windows-x86-64"),
                patch("contextdb_release.subprocess.run", side_effect=fake_run),
            ):
                probes = _probe_contextdb_binary(
                    isolated / "contextdb",
                    isolated,
                    {
                        "release": {"version": "0.1.0-alpha.1"},
                        "artifacts": [],
                    },
                )

            boundary = next(
                probe
                for probe in probes
                if probe["id"] == "contextdb-init-key-boundary"
            )
            self.assertEqual(boundary["status"], "failed")
            self.assertTrue(captured_environments)
            secret = captured_environments[0]["CONTEXTDB_TOKEN_KEY_HEX"]
            self.assertRegex(secret, r"^[0-9a-f]{64}$")
            self.assertNotIn("CONTEXTDB_TOKEN_KEY_FILE", captured_environments[0])
            self.assertIn("CONTEXTDB_STATE_HEAD_ID", captured_environments[0])
            self.assertNotIn("CONTEXTDB_STATE_HEAD_FILE", captured_environments[0])
            if "LOCALAPPDATA" in os.environ:
                self.assertEqual(
                    captured_environments[0]["LOCALAPPDATA"],
                    os.environ["LOCALAPPDATA"],
                )
            self.assertNotIn(secret, json.dumps(probes))
            self.assertNotIn(
                captured_environments[0]["CONTEXTDB_STATE_HEAD_ID"], json.dumps(probes)
            )

    def test_binary_probe_covers_export_import_and_external_key_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            isolated = Path(value)
            (isolated / "example.ctxb").write_bytes(b"logical")
            captured_secrets: list[str] = []
            captured_authorities: list[str] = []

            def fake_run(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                environment = cast(dict[str, str], kwargs["env"])
                captured_secrets.append(environment["CONTEXTDB_TOKEN_KEY_HEX"])
                captured_authorities.append(environment["CONTEXTDB_STATE_HEAD_ID"])
                if "init" in command or "export" in command:
                    output = Path(command[-1])
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(b"archive")
                elif "import" in command:
                    destination = Path(command[-2])
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(b"archive")
                stdout = (
                    b"contextdb 0.1.0-alpha.1\n" if command[-1] == "version" else b""
                )
                return subprocess.CompletedProcess(command, 0, stdout, b"")

            manifest = {
                "release": {"version": "0.1.0-alpha.1"},
                "artifacts": [
                    {
                        "package_id": "portable-example-database",
                        "path": "example.ctxb",
                    }
                ],
            }
            with (
                patch("contextdb_release._host_target", return_value="windows-x86-64"),
                patch("contextdb_release.subprocess.run", side_effect=fake_run),
            ):
                probes = _probe_contextdb_binary(
                    isolated / "contextdb", isolated, manifest
                )

            by_id = {probe["id"]: probe for probe in probes}
            expected = {
                "contextdb-version",
                "contextdb-init",
                "contextdb-init-key-boundary",
                "contextdb-doctor",
                "contextdb-export",
                "contextdb-export-key-boundary",
                "contextdb-import-example",
                "contextdb-import-key-boundary",
                "contextdb-doctor-imported",
            }
            self.assertTrue(expected.issubset(by_id))
            self.assertTrue(
                all(by_id[identifier]["status"] == "passed" for identifier in expected)
            )
            self.assertEqual(len(set(captured_secrets)), 1)
            state_ids = {
                environment_id
                for command_id, environment_id in zip(
                    [probe["id"] for probe in probes if "exit_code" in probe],
                    captured_authorities,
                    strict=True,
                )
                if command_id
                in {"contextdb-init", "contextdb-doctor", "contextdb-export"}
            }
            import_ids = {
                environment_id
                for command_id, environment_id in zip(
                    [probe["id"] for probe in probes if "exit_code" in probe],
                    captured_authorities,
                    strict=True,
                )
                if command_id
                in {"contextdb-import-example", "contextdb-doctor-imported"}
            }
            self.assertEqual(len(state_ids), 1)
            self.assertEqual(len(import_ids), 1)
            self.assertNotEqual(state_ids, import_ids)
            serialized = json.dumps(probes)
            self.assertTrue(
                all(
                    authority not in serialized
                    for authority in set(captured_authorities)
                )
            )

    def test_binary_probe_uses_external_owner_only_unix_authorities(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            isolated = Path(value)
            captured_environments: list[dict[str, str]] = []

            def fake_run(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                environment = cast(dict[str, str], kwargs["env"])
                captured_environments.append(environment.copy())
                if "init" in command or "import" in command:
                    archive = Path(command[-1] if "init" in command else command[-2])
                    archive.parent.mkdir(parents=True, exist_ok=True)
                    archive.write_bytes(b"archive")
                    authority = Path(environment["CONTEXTDB_STATE_HEAD_FILE"])
                    authority.write_text("{}", encoding="utf-8")
                    authority.chmod(0o600)
                stdout = (
                    b"contextdb 0.1.0-alpha.1\n" if command[-1] == "version" else b""
                )
                return subprocess.CompletedProcess(command, 0, stdout, b"")

            with (
                patch("contextdb_release._host_target", return_value="linux-x86-64"),
                patch("contextdb_release.subprocess.run", side_effect=fake_run),
            ):
                probes = _probe_contextdb_binary(
                    isolated / "contextdb",
                    isolated,
                    {
                        "release": {"version": "0.1.0-alpha.1"},
                        "artifacts": [
                            {
                                "package_id": "portable-example-database",
                                "path": "example.ctxb",
                            }
                        ],
                    },
                )

            self.assertTrue(probes)
            self.assertTrue(all(probe["status"] == "passed" for probe in probes))
            self.assertTrue(captured_environments)
            state_paths = {
                environment["CONTEXTDB_STATE_HEAD_FILE"]
                for environment in captured_environments
            }
            self.assertEqual(len(state_paths), 2)
            self.assertTrue(
                all(not Path(path).is_relative_to(isolated) for path in state_paths)
            )
            self.assertTrue(
                all(
                    "CONTEXTDB_STATE_HEAD_ID" not in environment
                    for environment in captured_environments
                )
            )
            self.assertTrue(
                all(
                    "CONTEXTDB_TOKEN_KEY_FILE" not in environment
                    for environment in captured_environments
                )
            )
            serialized = json.dumps(probes)
            self.assertTrue(all(path not in serialized for path in state_paths))

    def test_binary_probe_rejects_version_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            isolated = Path(value)

            def fake_run(
                command: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                return subprocess.CompletedProcess(
                    command, 0, b"contextdb 9.9.9\n", b""
                )

            with patch("contextdb_release.subprocess.run", side_effect=fake_run):
                probes = _probe_contextdb_binary(
                    isolated / "contextdb",
                    isolated,
                    {
                        "release": {"version": "0.1.0-alpha.1"},
                        "artifacts": [],
                    },
                )
            self.assertEqual(len(probes), 2)
            self.assertEqual(probes[0]["id"], "contextdb-version")
            self.assertEqual(probes[0]["status"], "failed")
            self.assertEqual(probes[0]["argv"], ["contextdb", "version"])
            self.assertEqual(probes[1]["id"], "contextdb-state-authority-cleanup")
            self.assertEqual(probes[1]["status"], "passed")

    def test_windows_probe_authority_cleanup_is_exact_and_removes_locks(
        self,
    ) -> None:
        self.assertEqual(
            _windows_state_head_digest("abc"),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
        )
        with tempfile.TemporaryDirectory() as value:
            local = Path(value)
            digest = _windows_state_head_digest("contextdb-release-probe-test")
            lock = local / "ContextDB" / "authority-locks" / f"{digest}.lock"
            lock.parent.mkdir(parents=True)
            lock.write_bytes(b"")
            deleted: list[tuple[object, str]] = []

            class FakeWinreg:
                HKEY_CURRENT_USER = object()

                @classmethod
                def DeleteKey(cls, root: object, subkey: str) -> None:
                    deleted.append((root, subkey))

            with patch.dict(sys.modules, {"winreg": FakeWinreg}):
                self.assertTrue(
                    _cleanup_windows_probe_authorities([digest], str(local))
                )

            self.assertEqual(
                deleted,
                [
                    (
                        FakeWinreg.HKEY_CURRENT_USER,
                        f"Software\\ContextDB\\StateHeads\\{digest}",
                    )
                ],
            )
            self.assertFalse(lock.exists())

    def test_probe_runs_exact_authority_cleanup_on_unexpected_failure(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            isolated = Path(value)
            with (
                patch("contextdb_release._host_target", return_value="windows-x86-64"),
                patch(
                    "contextdb_release._exercise_contextdb_binary",
                    side_effect=RuntimeError("injected failure"),
                ),
                patch(
                    "contextdb_release._finish_probe_authority_custody",
                    return_value=True,
                ) as cleanup,
                self.assertRaisesRegex(RuntimeError, "injected failure"),
            ):
                _probe_contextdb_binary(
                    isolated / "contextdb",
                    isolated,
                    {"release": {"version": "0.1.0-alpha.1"}, "artifacts": []},
                )
            cleanup.assert_called_once()
            self.assertEqual(len(cleanup.call_args.args[2]), 2)

    def test_install_receipt_is_bound_to_exact_artifact_and_all_passed_probes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            verifier = self.verifier_fixture(root)
            artifact = self.artifact_fixture()
            receipt_path = root / "install.json"
            receipt = {
                "schema_version": "contextdb.clean-install-receipt/v1",
                "verifier_version": "0.1.0-alpha.1",
                "generated_at": "2026-08-12T00:00:00Z",
                "profile": "contract",
                "host_target": "linux-x86-64",
                "isolated_copy": True,
                "verification": {
                    "schema_version": "contextdb.release-verification-report/v1",
                    "profile": "contract",
                    "contract_valid": True,
                    "release_ready": False,
                },
                "subject_artifacts": [
                    {
                        "id": artifact["id"],
                        "path": artifact["path"],
                        "sha256": "c" * 64,
                        "version": artifact["version"],
                    }
                ],
                "probes": [
                    {
                        "id": "install",
                        "status": "passed",
                        "evidence_level": "runtime",
                        "argv": ["contextdb", "version"],
                    }
                ],
                "passed": True,
                "release_ready": False,
                "docker_runtime_executed": False,
            }
            write_json(receipt_path, receipt)
            related = {
                "kind": "install-receipt",
                "status": "passed",
                "evidence_level": "runtime",
                "platform": "linux-x86-64",
            }
            with self.assertRaisesRegex(ContractError, "not bound"):
                verifier._verify_install_receipt(
                    artifact, related, receipt_path, "install"
                )
            receipt["subject_artifacts"][0]["sha256"] = artifact["sha256"]  # type: ignore[index]
            write_json(receipt_path, receipt)
            verifier._verify_install_receipt(artifact, related, receipt_path, "install")
            receipt["probes"][0]["status"] = "not-run"  # type: ignore[index]
            write_json(receipt_path, receipt)
            with self.assertRaisesRegex(ContractError, "all-passing"):
                verifier._verify_install_receipt(
                    artifact, related, receipt_path, "install"
                )

    def test_publication_receipt_rejects_digest_or_nonpublic_uri(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            verifier = self.verifier_fixture(root)
            artifact = self.artifact_fixture()
            receipt_path = root / "publication.json"
            subject = {
                key: artifact[key] for key in ("id", "path", "sha256", "version")
            }
            receipt = {
                "schema_version": "contextdb.release-publication-receipt/v1",
                "artifact": subject,
                "registry_type": "static-https",
                "immutable_uri": "https://localhost/contextdb",
                "immutable_reference": True,
                "published_at": "2026-08-12T00:00:00Z",
                "verified_at": "2026-08-12T00:01:00Z",
                "retrieved_sha256": artifact["sha256"],
                "status": "passed",
            }
            write_json(receipt_path, receipt)
            related = {
                "kind": "publication-receipt",
                "status": "passed",
                "evidence_level": "publication",
            }
            with self.assertRaisesRegex(ContractError, "public HTTPS"):
                verifier._verify_publication_receipt(
                    artifact, related, receipt_path, "publication"
                )
            for uri in (
                "https://10.0.0.1/contextdb",
                "https://releases.invalid",
                "https://user@example.org/contextdb",
            ):
                receipt["immutable_uri"] = uri
                write_json(receipt_path, receipt)
                with (
                    self.subTest(uri=uri),
                    self.assertRaisesRegex(ContractError, "public HTTPS"),
                ):
                    verifier._verify_publication_receipt(
                        artifact, related, receipt_path, "publication"
                    )
            receipt["immutable_uri"] = (
                "https://releases.contextdb.dev/v1/contextdb-linux"
            )
            receipt["retrieved_sha256"] = "d" * 64
            write_json(receipt_path, receipt)
            with self.assertRaisesRegex(ContractError, "digest"):
                verifier._verify_publication_receipt(
                    artifact, related, receipt_path, "publication"
                )
            receipt["retrieved_sha256"] = artifact["sha256"]
            write_json(receipt_path, receipt)
            verifier._verify_publication_receipt(
                artifact, related, receipt_path, "publication"
            )

    def test_sbom_and_slsa_attestation_require_artifact_and_source_bindings(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            artifact = self.artifact_fixture()
            bom_path = root / "artifact.cdx.json"
            write_json(
                bom_path,
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
            )
            BundleVerifier._verify_cyclonedx_binding(artifact, bom_path, "sbom")
            provenance_path = root / "artifact.intoto.json"
            write_json(
                provenance_path,
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
                            "buildType": "https://contextdb.dev/build/rust/v1",
                            "resolvedDependencies": [
                                {
                                    "uri": "git+https://contextdb.dev/repository",
                                    "digest": {"gitCommit": "b" * 40},
                                }
                            ],
                        },
                        "runDetails": {
                            "builder": {"id": "https://contextdb.dev/builder"}
                        },
                    },
                },
            )
            BundleVerifier._verify_slsa_provenance_binding(
                artifact, provenance_path, "provenance"
            )
            statement = json.loads(provenance_path.read_text(encoding="utf-8"))
            statement["subject"][0]["digest"]["sha256"] = "e" * 64
            write_json(provenance_path, statement)
            with self.assertRaisesRegex(ContractError, "does not bind artifact"):
                BundleVerifier._verify_slsa_provenance_binding(
                    artifact, provenance_path, "provenance"
                )

    def test_source_audit_distinguishes_presence_from_runtime_proof(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            (root / "src").mkdir()
            matrix = sample_package_matrix()
            matrix_path = root / "matrix.json"
            write_json(matrix_path, matrix)
            report = audit_source(root, matrix_path)
            self.assertEqual(report["outcome"], "source_inventory_valid")
            self.assertFalse(report["release_ready"])
            self.assertIn(
                "RUNTIME_OR_PUBLICATION_PROOF_ABSENT",
                {issue["code"] for issue in report["issues"]},
            )

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML unavailable")
    def test_source_audit_rejects_duplicate_compose_keys(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            docker = root / "deploy" / "docker"
            docker.mkdir(parents=True)
            (docker / "Dockerfile").write_text(
                "FROM scratch@sha256:" + "a" * 64 + "\n"
                "COPY crates/ crates/\n"
                "COPY bindings/ bindings/\n"
                "COPY examples/embedded-rust/ examples/embedded-rust/\n"
                "RUN cargo build --locked\n"
                "USER contextdb\n"
                "HEALTHCHECK CMD true\n",
                encoding="utf-8",
            )
            (docker / "entrypoint.sh").write_text(
                "set exactly one of CONTEXTDB_TOKEN_KEY_HEX or CONTEXTDB_TOKEN_KEY_FILE\n"
                "CONTEXTDB_TOKEN_KEY_FILE must be outside the archive directory\n",
                encoding="utf-8",
            )
            (docker / "Dockerfile.dockerignore").write_text(
                "**\n!crates/**\n", encoding="utf-8"
            )
            (docker / "compose.yaml").write_text(
                "services:\n  contextdb:\n    read_only: true\n    read_only: false\n",
                encoding="utf-8",
            )
            matrix = sample_package_matrix("deploy/docker")
            package = cast(dict[str, object], cast(list[object], matrix["packages"])[0])
            package.update(
                {
                    "artifact_kind": "docker-image",
                    "roles": ["docker-image"],
                    "coverage": "declared-platforms",
                    "platforms": ["linux-x86-64"],
                    "install_probe": {
                        "kind": "docker-image",
                        "runtime_required": True,
                    },
                }
            )
            matrix_path = root / "matrix.json"
            write_json(matrix_path, matrix)
            report = audit_source(root, matrix_path)
            self.assertEqual(report["outcome"], "failed")
            self.assertIn(
                "COMPOSE_YAML_INVALID",
                {issue["code"] for issue in report["issues"]},
            )

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML unavailable")
    def test_source_audit_requires_separate_docker_state_head_volume(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            docker = root / "deploy" / "docker"
            docker.mkdir(parents=True)
            (docker / "Dockerfile").write_text(
                "FROM scratch@sha256:" + "a" * 64 + "\n"
                "COPY crates/ crates/\n"
                "COPY bindings/ bindings/\n"
                "COPY examples/embedded-rust/ examples/embedded-rust/\n"
                "RUN cargo build --locked\n"
                "USER contextdb\n"
                'VOLUME ["/var/lib/contextdb", "/var/lib/contextdb-authority"]\n'
                "HEALTHCHECK CMD true\n",
                encoding="utf-8",
            )
            (docker / "entrypoint.sh").write_text(
                "set exactly one of CONTEXTDB_TOKEN_KEY_HEX or CONTEXTDB_TOKEN_KEY_FILE\n"
                "CONTEXTDB_TOKEN_KEY_FILE must be outside the archive directory\n"
                "CONTEXTDB_TOKEN_KEY_FILE must be owned by the container user\n"
                "CONTEXTDB_STATE_HEAD_FILE is required\n"
                "CONTEXTDB_STATE_HEAD_FILE must be outside the archive directory\n"
                "state-head authority directory must be owned by the container user\n",
                encoding="utf-8",
            )
            (docker / "Dockerfile.dockerignore").write_text(
                "**\n!crates/**\n", encoding="utf-8"
            )
            (docker / "compose.yaml").write_text(
                "services:\n"
                "  contextdb:\n"
                "    read_only: true\n"
                "    cap_drop: [ALL]\n"
                "    security_opt: [no-new-privileges:true]\n"
                "    ports: [127.0.0.1:7733:7733, 127.0.0.1:7734:7734]\n"
                "    environment:\n"
                "      CONTEXTDB_TOKEN_KEY_FILE: /run/contextdb-secrets/token-key\n"
                "    volumes:\n"
                "      - contextdb-data:/var/lib/contextdb\n"
                "      - type: bind\n"
                "        source: ${CONTEXTDB_DOCKER_TOKEN_KEY_FILE:?set key}\n"
                "        target: /run/contextdb-secrets/token-key\n"
                "        read_only: true\n",
                encoding="utf-8",
            )
            matrix = sample_package_matrix("deploy/docker")
            package = cast(dict[str, object], cast(list[object], matrix["packages"])[0])
            package.update(
                {
                    "artifact_kind": "docker-image",
                    "roles": ["docker-image"],
                    "coverage": "declared-platforms",
                    "platforms": ["linux-x86-64"],
                    "install_probe": {
                        "kind": "docker-image",
                        "runtime_required": True,
                    },
                }
            )
            matrix_path = root / "matrix.json"
            write_json(matrix_path, matrix)
            report = audit_source(root, matrix_path)
            self.assertEqual(report["outcome"], "failed")
            self.assertIn(
                "COMPOSE_HARDENING",
                {issue["code"] for issue in report["issues"]},
            )

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML unavailable")
    def test_source_audit_requires_distinct_external_gateway_key_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            docker = root / "deploy" / "docker"
            docker.mkdir(parents=True)
            (docker / "Dockerfile").write_text(
                "FROM scratch@sha256:" + "a" * 64 + "\n"
                "COPY crates/ crates/\n"
                "COPY bindings/ bindings/\n"
                "COPY examples/embedded-rust/ examples/embedded-rust/\n"
                "RUN cargo build --locked\n"
                "USER contextdb\n"
                'VOLUME ["/var/lib/contextdb", "/var/lib/contextdb-authority"]\n'
                "HEALTHCHECK CMD true\n",
                encoding="utf-8",
            )
            (docker / "Dockerfile.dockerignore").write_text(
                "**\n!crates/**\n", encoding="utf-8"
            )
            entrypoint = (
                "set exactly one of CONTEXTDB_TOKEN_KEY_HEX or CONTEXTDB_TOKEN_KEY_FILE\n"
                "CONTEXTDB_TOKEN_KEY_FILE must be outside the archive directory\n"
                "CONTEXTDB_TOKEN_KEY_FILE must be owned by the container user\n"
                "CONTEXTDB_STATE_HEAD_FILE is required\n"
                "CONTEXTDB_STATE_HEAD_FILE must be outside the archive directory\n"
                "state-head authority directory must be owned by the container user\n"
                "CONTEXTDB_GATEWAY_ID is required for the network daemon\n"
                "set exactly one of CONTEXTDB_GATEWAY_KEY_HEX or CONTEXTDB_GATEWAY_KEY_FILE\n"
                "an external gateway attestation key is required\n"
                "CONTEXTDB_GATEWAY_KEY_FILE must be outside the archive directory\n"
                "CONTEXTDB_GATEWAY_KEY_FILE must be owned by the container user with one link\n"
                "CONTEXTDB_GATEWAY_KEY_FILE must be private and at most 66 bytes\n"
            )
            compose = (
                "services:\n"
                "  contextdb:\n"
                "    read_only: true\n"
                "    cap_drop: [ALL]\n"
                "    security_opt: [no-new-privileges:true]\n"
                "    ports: [127.0.0.1:7733:7733, 127.0.0.1:7734:7734]\n"
                "    environment:\n"
                "      CONTEXTDB_TOKEN_KEY_FILE: /run/contextdb-secrets/token-key\n"
                "      CONTEXTDB_STATE_HEAD_FILE: /var/lib/contextdb-authority/state-head.json\n"
                "      CONTEXTDB_GATEWAY_ID: ${CONTEXTDB_DOCKER_GATEWAY_ID:?set gateway}\n"
                "      CONTEXTDB_GATEWAY_KEY_FILE: /run/contextdb-secrets/gateway-key\n"
                "    volumes:\n"
                "      - contextdb-data:/var/lib/contextdb\n"
                "      - contextdb-authority:/var/lib/contextdb-authority\n"
                "      - type: bind\n"
                "        source: ${CONTEXTDB_DOCKER_TOKEN_KEY_FILE:?set token key}\n"
                "        target: /run/contextdb-secrets/token-key\n"
                "        read_only: true\n"
                "      - type: bind\n"
                "        source: ${CONTEXTDB_DOCKER_GATEWAY_KEY_FILE:?set gateway key}\n"
                "        target: /run/contextdb-secrets/gateway-key\n"
                "        read_only: true\n"
            )
            matrix = sample_package_matrix("deploy/docker")
            package = cast(dict[str, object], cast(list[object], matrix["packages"])[0])
            package.update(
                {
                    "artifact_kind": "docker-image",
                    "roles": ["docker-image"],
                    "coverage": "declared-platforms",
                    "platforms": ["linux-x86-64"],
                    "install_probe": {
                        "kind": "docker-image",
                        "runtime_required": True,
                    },
                }
            )
            matrix_path = root / "matrix.json"
            write_json(matrix_path, matrix)

            def issue_codes(
                compose_text: str = compose, entrypoint_text: str = entrypoint
            ) -> set[str]:
                (docker / "compose.yaml").write_text(compose_text, encoding="utf-8")
                (docker / "entrypoint.sh").write_text(entrypoint_text, encoding="utf-8")
                report = audit_source(root, matrix_path)
                return {str(issue["code"]) for issue in report["issues"]}

            valid_codes = issue_codes()
            self.assertNotIn("COMPOSE_HARDENING", valid_codes)
            self.assertNotIn("DOCKER_KEY_BOUNDARY", valid_codes)

            without_gateway_id = compose.replace(
                "      CONTEXTDB_GATEWAY_ID: ${CONTEXTDB_DOCKER_GATEWAY_ID:?set gateway}\n",
                "",
            )
            self.assertIn("COMPOSE_HARDENING", issue_codes(without_gateway_id))

            shared_key_source = compose.replace(
                "${CONTEXTDB_DOCKER_GATEWAY_KEY_FILE:?set gateway key}",
                "${CONTEXTDB_DOCKER_TOKEN_KEY_FILE:?set token key}",
            )
            self.assertIn("COMPOSE_HARDENING", issue_codes(shared_key_source))

            missing_exact_one = entrypoint.replace(
                "set exactly one of CONTEXTDB_GATEWAY_KEY_HEX or CONTEXTDB_GATEWAY_KEY_FILE\n",
                "",
            )
            self.assertIn(
                "DOCKER_KEY_BOUNDARY", issue_codes(entrypoint_text=missing_exact_one)
            )

    def test_readiness_report_preserves_unresolved_ledger_gate(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            (root / "src").mkdir()
            ledger_path = root / "ledger.json"
            matrix_path = root / "matrix.json"
            write_json(ledger_path, gate_ledger("not_started"))
            write_json(matrix_path, sample_package_matrix())
            report = readiness_report(root, ledger_path, matrix_path, "alpha")
            self.assertFalse(report["release_ready"])
            self.assertEqual(report["target_exit"], "M18-E01")
            self.assertEqual(report["unresolved_milestones"], [])
            self.assertEqual(report["unresolved_exit_criteria"][0]["id"], "M18-E01")
            self.assertFalse(report["required_proofs"][0]["presence_is_pass"])


class SchemaTests(unittest.TestCase):
    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"), "jsonschema unavailable"
    )
    def test_all_release_schemas_and_canonical_matrix_validate(self) -> None:
        import jsonschema

        repo = TOOL_ROOT.parents[1]
        schema_dir = repo / "assets" / "schemas"
        for path in sorted(schema_dir.glob("*.schema.json")):
            schema = json.loads(path.read_text(encoding="utf-8"))
            jsonschema.Draft202012Validator.check_schema(schema)
        matrix_schema = json.loads(
            (schema_dir / "release-package-matrix.schema.json").read_text(
                encoding="utf-8"
            )
        )
        matrix = json.loads(
            (repo / "release" / "package-matrix.json").read_text(encoding="utf-8")
        )
        jsonschema.Draft202012Validator(matrix_schema).validate(matrix)
        verifier = BundleVerifier(
            repo, "release/package-matrix.json", "contract", {}, False
        )
        packages, platforms = verifier._verify_matrix(matrix)
        self.assertEqual(len(packages), 17)
        self.assertEqual(len(platforms), 4)
        weakened = json.loads(json.dumps(matrix))
        weakened["packages"][0]["artifact_kind"] = "source-package"
        with self.assertRaisesRegex(ContractError, "requires artifact kind"):
            verifier._verify_matrix(weakened)
        documentation_schema = json.loads(
            (schema_dir / "release-documentation-matrix.schema.json").read_text(
                encoding="utf-8"
            )
        )
        documentation = json.loads(
            (repo / "release" / "documentation-matrix.json").read_text(encoding="utf-8")
        )
        jsonschema.Draft202012Validator(documentation_schema).validate(documentation)
        example_schema = json.loads(
            (schema_dir / "portable-example.schema.json").read_text(encoding="utf-8")
        )
        example = json.loads(
            (
                repo / "examples" / "portable-database" / "payload" / "example.json"
            ).read_text(encoding="utf-8")
        )
        jsonschema.Draft202012Validator(example_schema).validate(example)
        receipt_schema = json.loads(
            (schema_dir / "portable-example-package-receipt.schema.json").read_text(
                encoding="utf-8"
            )
        )
        receipt = json.loads(
            (
                repo / "examples" / "portable-database" / "package-receipt.json"
            ).read_text(encoding="utf-8")
        )
        jsonschema.Draft202012Validator(receipt_schema).validate(receipt)


if __name__ == "__main__":
    unittest.main()
