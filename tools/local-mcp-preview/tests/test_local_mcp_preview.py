from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
TOOL_PATH = REPO_ROOT / "tools/local-mcp-preview/local_mcp_preview.py"
SPEC = importlib.util.spec_from_file_location("local_mcp_preview", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class LocalMcpPreviewTests(unittest.TestCase):
    def test_checked_in_profile_matches_source_contract(self) -> None:
        profile = TOOL.validate_profile(REPO_ROOT)
        self.assertEqual(profile["release_class"], "developer-preview")
        self.assertFalse(profile["formal_release"]["release_ready"])
        self.assertFalse(profile["runtime"]["network_listeners"])

    def test_wire_only_feature_tree_is_accepted(self) -> None:
        tree = """\
contextdb-cli v0.1.0-alpha.1 [local-mcp,mcp]
├── contextdb-mcp v0.1.0-alpha.1 []
└── contextdb-server feature "wire"
    └── contextdb-server v0.1.0-alpha.1 [wire]
"""
        TOOL._validate_feature_tree(tree)

    def test_listener_features_are_rejected(self) -> None:
        samples = {
            "CLI server": "contextdb-cli v0.1.0 [current-server,local-mcp,mcp]",
            "HTTP adapter": (
                "contextdb-cli v0.1.0 [local-mcp,mcp]\n"
                "contextdb-server feature \"http\""
            ),
            "gRPC adapter": "contextdb-cli v0.1.0 [local-mcp,mcp]\ntonic v0.14.6 []",
            "server v1 runtime": (
                "contextdb-cli v0.1.0 [local-mcp,mcp]\n"
                "contextdb-runtime v0.1.0 []"
            ),
        }
        for label, tree in samples.items():
            with self.subTest(label=label):
                with self.assertRaises(TOOL.ContractError):
                    TOOL._validate_feature_tree(tree)

    def test_binary_surface_requires_mcp_and_rejects_listener_commands(self) -> None:
        version = """\
contextdb 0.1.0-alpha.1
build_profile local-mcp
network_listeners disabled
wire_schema 1
semantic_schema 1
storage_format 1
context_pack_schema 1
mcp_protocol 2026-07-28
"""
        help_text = (
            "Usage: contextdb <COMMAND>\n\n"
            "Commands:\n  version  Print\n  mcp      Run\n\nOptions:\n"
        )
        TOOL._validate_binary_surface(help_text, version, "0.1.0-alpha.1")
        with self.assertRaises(TOOL.ContractError):
            TOOL._validate_binary_surface(
                help_text.replace("  mcp      Run", "  mcp      Run\n  serve    Listen"),
                version,
                "0.1.0-alpha.1",
            )

    def test_zip_bytes_are_deterministic_for_identical_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "contextdb.exe").write_bytes(b"binary")
            (bundle / "doc.txt").write_text("documentation\n", encoding="utf-8")
            first = root / "first.zip"
            second = root / "second.zip"
            TOOL._write_deterministic_zip(bundle, first)
            TOOL._write_deterministic_zip(bundle, second)
            self.assertEqual(
                hashlib.sha256(first.read_bytes()).digest(),
                hashlib.sha256(second.read_bytes()).digest(),
            )

    def test_archive_verifier_checks_sidecar_receipt_and_every_content_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            bundle.mkdir()
            binary_path = bundle / "contextdb.exe"
            binary_path.write_bytes(b"binary")
            supply_manifest_source = REPO_ROOT / TOOL.SUPPLY_CHAIN_MANIFEST_PATH
            supply_manifest = json.loads(supply_manifest_source.read_text(encoding="utf-8"))
            for relative in [
                TOOL.SUPPLY_CHAIN_MANIFEST_PATH.as_posix(),
                *sorted(TOOL.SUPPLY_CHAIN_ARTIFACTS),
            ]:
                source = REPO_ROOT / relative
                destination = bundle / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            graph = supply_manifest["graph"]
            receipt = {
                "schema_version": TOOL.RECEIPT_SCHEMA,
                "profile_id": "test-profile",
                "core_version": "0.1.0-alpha.1",
                "source": {"dirty": True},
                "binary": {
                    "path": "contextdb.exe",
                    "sha256": TOOL._sha256_file(binary_path),
                    "size_bytes": binary_path.stat().st_size,
                    "commands": ["mcp"],
                    "version_output": [
                        "contextdb 0.1.0-alpha.1",
                        "build_profile local-mcp",
                        "network_listeners disabled",
                        "wire_schema 1",
                        "semantic_schema 1",
                        "storage_format 1",
                        "context_pack_schema 1",
                        "mcp_protocol 2026-07-28",
                    ],
                },
                "supply_chain": {
                    "manifest_path": TOOL.SUPPLY_CHAIN_MANIFEST_PATH.as_posix(),
                    "manifest_sha256": TOOL._sha256_file(supply_manifest_source),
                    "graph_sha256": graph["sha256"],
                    "component_count": graph["component_count"],
                    "third_party_component_count": graph[
                        "third_party_component_count"
                    ],
                    "sbom_path": TOOL.SBOM_PATH.as_posix(),
                    "notices_path": TOOL.NOTICE_PATH.as_posix(),
                    "rust_runtime_notice_paths": [
                        "release/rust-runtime/COPYRIGHT.html",
                        "release/rust-runtime/LICENSE-APACHE",
                        "release/rust-runtime/LICENSE-MIT",
                    ],
                },
                "claims": {
                    "package_smoke_passed": True,
                    "network_listeners": False,
                    "formal_release_ready": False,
                    "m18_alpha": False,
                    "signed": False,
                    "published": False,
                    "distributable": False,
                },
            }
            (bundle / "RECEIPT.json").write_text(
                json.dumps(receipt), encoding="utf-8"
            )
            TOOL._write_checksums(bundle)
            archive = root / "bundle.zip"
            TOOL._write_deterministic_zip(bundle, archive)
            sidecar = root / "bundle.zip.sha256"
            sidecar.write_text(
                f"{TOOL._sha256_file(archive)}  {archive.name}\n", encoding="ascii"
            )
            result = TOOL.verify_archive(archive, sidecar)
            self.assertEqual(result["status"], "passed")
            self.assertFalse(result["distributable"])

            notice_path = bundle / TOOL.NOTICE_PATH
            notice_path.write_bytes(notice_path.read_bytes() + b"tampered\n")
            TOOL._write_checksums(bundle)
            supply_tampered = root / "supply-tampered.zip"
            TOOL._write_deterministic_zip(bundle, supply_tampered)
            supply_tampered_sidecar = root / "supply-tampered.zip.sha256"
            supply_tampered_sidecar.write_text(
                f"{TOOL._sha256_file(supply_tampered)}  {supply_tampered.name}\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                TOOL.ContractError, "supply-chain artifact digest mismatch"
            ):
                TOOL.verify_archive(supply_tampered, supply_tampered_sidecar)

            shutil.copyfile(REPO_ROOT / TOOL.NOTICE_PATH, notice_path)
            TOOL._write_checksums(bundle)
            (bundle / "contextdb.exe").write_bytes(b"tampered")
            tampered = root / "tampered.zip"
            TOOL._write_deterministic_zip(bundle, tampered)
            tampered_sidecar = root / "tampered.zip.sha256"
            tampered_sidecar.write_text(
                f"{TOOL._sha256_file(tampered)}  {tampered.name}\n", encoding="ascii"
            )
            with self.assertRaises(TOOL.ContractError):
                TOOL.verify_archive(tampered, tampered_sidecar)

    def test_repository_path_escape_is_rejected(self) -> None:
        with self.assertRaises(TOOL.ContractError):
            TOOL._safe_repo_file(REPO_ROOT, "../outside")


if __name__ == "__main__":
    unittest.main()
