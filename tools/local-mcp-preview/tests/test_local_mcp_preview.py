from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[3]
TOOL_PATH = REPO_ROOT / "tools/local-mcp-preview/local_mcp_preview.py"
SPEC = importlib.util.spec_from_file_location("local_mcp_preview", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class LocalMcpPreviewTests(unittest.TestCase):
    def test_checked_in_profile_matches_source_contract(self) -> None:
        for platform_name, expected in TOOL.PLATFORMS.items():
            with self.subTest(platform=platform_name):
                profile = TOOL.validate_profile(REPO_ROOT, platform_name)
                self.assertEqual(profile["profile_id"], expected["profile_id"])
                self.assertEqual(profile["core_version"], TOOL._workspace_version(REPO_ROOT))
                self.assertEqual(profile["release_class"], "developer-preview")
                self.assertFalse(profile["formal_release"]["release_ready"])
                self.assertFalse(profile["runtime"]["network_listeners"])
                self.assertEqual(profile["runtime"]["transports"], expected["transports"])

    def test_supported_host_profiles_are_selected_without_cross_platform_fallback(self) -> None:
        for operating_system, architecture, expected in (
            ("Windows", "AMD64", "windows-x86_64"),
            ("Linux", "x86_64", "linux-x86_64"),
        ):
            with self.subTest(operating_system=operating_system):
                with (
                    mock.patch.object(TOOL.platform, "system", return_value=operating_system),
                    mock.patch.object(TOOL.platform, "machine", return_value=architecture),
                ):
                    self.assertEqual(TOOL._host_platform(), expected)

        with (
            mock.patch.object(TOOL.platform, "system", return_value="Linux"),
            mock.patch.object(TOOL.platform, "machine", return_value="aarch64"),
        ):
            with self.assertRaisesRegex(TOOL.ContractError, "unsupported.*architecture"):
                TOOL._host_platform()

    def test_wire_only_feature_tree_is_accepted(self) -> None:
        tree = """\
contextdb-cli v0.2.0-alpha.3 [local-mcp,mcp]
├── contextdb-mcp v0.2.0-alpha.3 []
└── contextdb-server feature "wire"
    └── contextdb-server v0.2.0-alpha.3 [wire]
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
contextdb 0.2.0-alpha.3
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
        TOOL._validate_binary_surface(help_text, version, "0.2.0-alpha.3")
        with self.assertRaises(TOOL.ContractError):
            TOOL._validate_binary_surface(
                help_text.replace("  mcp      Run", "  mcp      Run\n  serve    Listen"),
                version,
                "0.2.0-alpha.3",
            )

    def test_linux_glibc_floor_accepts_ubuntu_22_compatible_symbols(self) -> None:
        result = TOOL._validate_linux_glibc_version_info(
            "Version needs section: GLIBC_2.2.5 GLIBC_2.17 GLIBC_2.34 GLIBC_2.35"
        )
        self.assertEqual(result["support_baseline"], "Ubuntu 22.04 LTS")
        self.assertEqual(result["maximum_allowed_symbol_version"], "2.35")
        self.assertEqual(result["maximum_required_symbol_version"], "2.35")

    def test_linux_glibc_floor_rejects_newer_symbols(self) -> None:
        with self.assertRaisesRegex(
            TOOL.ContractError,
            r"requires GLIBC_2\.39.*ceiling is GLIBC_2\.35",
        ):
            TOOL._validate_linux_glibc_version_info(
                "Version needs section: GLIBC_2.2.5 GLIBC_2.35 GLIBC_2.39"
            )

    def test_linux_glibc_floor_rejects_missing_version_evidence(self) -> None:
        with self.assertRaisesRegex(TOOL.ContractError, "no readable versioned GLIBC"):
            TOOL._validate_linux_glibc_version_info("No version information found")

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

    def test_deterministic_zip_preserves_executable_mode_for_both_targets(self) -> None:
        for binary_name in ("contextdb.exe", "contextdb"):
            with self.subTest(binary_name=binary_name):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    bundle = root / "bundle"
                    bundle.mkdir()
                    (bundle / binary_name).write_bytes(b"binary")
                    archive = root / "bundle.zip"
                    TOOL._write_deterministic_zip(bundle, archive)
                    with zipfile.ZipFile(archive) as package:
                        info = package.getinfo(f"bundle/{binary_name}")
                    self.assertEqual((info.external_attr >> 16) & 0o777, 0o755)

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
                TOOL.PROFILE_PATH.as_posix(),
                *sorted(TOOL.SUPPLY_CHAIN_ARTIFACTS),
            ]:
                source = REPO_ROOT / relative
                destination = bundle / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            graph = supply_manifest["graph"]
            current_version = TOOL._workspace_version(REPO_ROOT)
            receipt = {
                "schema_version": TOOL.RECEIPT_SCHEMA,
                "profile_id": TOOL.PLATFORMS["windows-x86_64"]["profile_id"],
                "core_version": current_version,
                "platform": {
                    "operating_system": "windows",
                    "architecture": "x86_64",
                    "rust_target": "x86_64-pc-windows-msvc",
                },
                "source": {"dirty": True},
                "binary": {
                    "path": "contextdb.exe",
                    "sha256": TOOL._sha256_file(binary_path),
                    "size_bytes": binary_path.stat().st_size,
                    "commands": ["mcp"],
                    "version_output": [
                        f"contextdb {current_version}",
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

            receipt["binary"]["linux_abi"] = {
                "libc": "glibc",
                "support_baseline": "Ubuntu 22.04 LTS",
                "maximum_allowed_symbol_version": "2.35",
                "maximum_required_symbol_version": "2.34",
                "required_symbol_versions": ["2.2.5", "2.34"],
            }
            (bundle / "RECEIPT.json").write_text(json.dumps(receipt), encoding="utf-8")
            TOOL._write_checksums(bundle)
            windows_with_linux_abi = root / "windows-with-linux-abi.zip"
            TOOL._write_deterministic_zip(bundle, windows_with_linux_abi)
            windows_with_linux_abi_sidecar = root / "windows-with-linux-abi.zip.sha256"
            windows_with_linux_abi_sidecar.write_text(
                f"{TOOL._sha256_file(windows_with_linux_abi)}  "
                f"{windows_with_linux_abi.name}\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(TOOL.ContractError, "must not contain Linux ABI"):
                TOOL.verify_archive(
                    windows_with_linux_abi,
                    windows_with_linux_abi_sidecar,
                )
            receipt["binary"].pop("linux_abi")
            (bundle / "RECEIPT.json").write_text(json.dumps(receipt), encoding="utf-8")

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

    def test_linux_archive_binds_native_profile_target_and_executable(self) -> None:
        platform_name = "linux-x86_64"
        configuration = TOOL.PLATFORMS[platform_name]
        version = TOOL._workspace_version(REPO_ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "linux-bundle"
            bundle.mkdir()
            binary = bundle / configuration["binary_name"]
            binary.write_bytes(b"native-linux-elf-fixture")
            for relative in [
                TOOL.SUPPLY_CHAIN_MANIFEST_PATH.as_posix(),
                TOOL.PROFILE_PATH.as_posix(),
                *sorted(TOOL.SUPPLY_CHAIN_ARTIFACTS),
            ]:
                source = TOOL._platform_source_file(REPO_ROOT, relative, platform_name)
                destination = bundle / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)

            manifest_path = bundle / TOOL.SUPPLY_CHAIN_MANIFEST_PATH
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            graph = manifest["graph"]
            receipt = {
                "schema_version": TOOL.RECEIPT_SCHEMA,
                "profile_id": configuration["profile_id"],
                "core_version": version,
                "platform": {
                    "operating_system": "linux",
                    "architecture": "x86_64",
                    "rust_target": configuration["target"],
                },
                "source": {"dirty": True},
                "binary": {
                    "path": configuration["binary_name"],
                    "sha256": TOOL._sha256_file(binary),
                    "size_bytes": binary.stat().st_size,
                    "commands": ["mcp", "mcp-broker-stop"],
                    "version_output": [
                        f"contextdb {version}",
                        "build_profile local-mcp",
                        "network_listeners disabled",
                        "wire_schema 1",
                        "semantic_schema 1",
                        "storage_format 1",
                        "context_pack_schema 1",
                        "mcp_protocol 2026-07-28",
                    ],
                    "linux_abi": {
                        "libc": "glibc",
                        "support_baseline": "Ubuntu 22.04 LTS",
                        "maximum_allowed_symbol_version": "2.35",
                        "maximum_required_symbol_version": "2.34",
                        "required_symbol_versions": ["2.2.5", "2.17", "2.34"],
                    },
                },
                "supply_chain": {
                    "manifest_path": TOOL.SUPPLY_CHAIN_MANIFEST_PATH.as_posix(),
                    "manifest_sha256": TOOL._sha256_file(manifest_path),
                    "graph_sha256": graph["sha256"],
                    "component_count": graph["component_count"],
                    "third_party_component_count": graph["third_party_component_count"],
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
            (bundle / "RECEIPT.json").write_text(json.dumps(receipt), encoding="utf-8")
            TOOL._write_checksums(bundle)
            archive = root / "linux-bundle.zip"
            TOOL._write_deterministic_zip(bundle, archive)
            sidecar = root / "linux-bundle.zip.sha256"
            sidecar.write_text(
                f"{TOOL._sha256_file(archive)}  {archive.name}\n", encoding="ascii"
            )
            result = TOOL.verify_archive(archive, sidecar)
            self.assertEqual(result["profile_id"], configuration["profile_id"])
            self.assertEqual(result["target"], configuration["target"])

            linux_abi = receipt["binary"].pop("linux_abi")
            (bundle / "RECEIPT.json").write_text(json.dumps(receipt), encoding="utf-8")
            TOOL._write_checksums(bundle)
            missing_abi = root / "missing-linux-abi.zip"
            TOOL._write_deterministic_zip(bundle, missing_abi)
            missing_abi_sidecar = root / "missing-linux-abi.zip.sha256"
            missing_abi_sidecar.write_text(
                f"{TOOL._sha256_file(missing_abi)}  {missing_abi.name}\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(TOOL.ContractError, "linux_abi must be an object"):
                TOOL.verify_archive(missing_abi, missing_abi_sidecar)

            receipt["binary"]["linux_abi"] = {
                **linux_abi,
                "maximum_required_symbol_version": "2.39",
                "required_symbol_versions": ["2.2.5", "2.17", "2.34", "2.39"],
            }
            (bundle / "RECEIPT.json").write_text(json.dumps(receipt), encoding="utf-8")
            TOOL._write_checksums(bundle)
            incompatible_abi = root / "incompatible-linux-abi.zip"
            TOOL._write_deterministic_zip(bundle, incompatible_abi)
            incompatible_abi_sidecar = root / "incompatible-linux-abi.zip.sha256"
            incompatible_abi_sidecar.write_text(
                f"{TOOL._sha256_file(incompatible_abi)}  {incompatible_abi.name}\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(TOOL.ContractError, "requires GLIBC_2.39"):
                TOOL.verify_archive(incompatible_abi, incompatible_abi_sidecar)

            receipt["binary"]["linux_abi"] = linux_abi

            manifest["target"] = TOOL.PLATFORMS["windows-x86_64"]["target"]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            receipt["supply_chain"]["manifest_sha256"] = TOOL._sha256_file(manifest_path)
            (bundle / "RECEIPT.json").write_text(json.dumps(receipt), encoding="utf-8")
            TOOL._write_checksums(bundle)
            substituted = root / "cross-target-substitution.zip"
            TOOL._write_deterministic_zip(bundle, substituted)
            substituted_sidecar = root / "cross-target-substitution.zip.sha256"
            substituted_sidecar.write_text(
                f"{TOOL._sha256_file(substituted)}  {substituted.name}\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(TOOL.ContractError, "supply-chain target"):
                TOOL.verify_archive(substituted, substituted_sidecar)


if __name__ == "__main__":
    unittest.main()
