from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
TOOL = REPO_ROOT / "tools/local-mcp-preview/release_assets.py"


class LocalMcpReleaseAssetTests(unittest.TestCase):
    def test_release_tag_must_bind_current_core_version(self) -> None:
        passing = subprocess.run(
            [sys.executable, str(TOOL), "validate-tag", "--tag", "v0.2.0-alpha.1"],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(passing.returncode, 0, passing.stderr)
        mismatched = subprocess.run(
            [sys.executable, str(TOOL), "validate-tag", "--tag", "v0.1.0-alpha.1"],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(mismatched.returncode, 2)
        self.assertIn("does not match", mismatched.stderr)

    def test_release_notes_name_both_exact_native_artifact_sets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            notes = Path(temporary) / "notes.md"
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "write-notes",
                    "--output",
                    str(notes),
                    "--source-commit",
                    "a" * 40,
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            content = notes.read_text(encoding="utf-8")
            self.assertIn("contextdb-local-mcp-0.2.0-alpha.1-linux-x86_64.zip", content)
            self.assertIn("contextdb-local-mcp-0.2.0-alpha.1-windows-x86_64.zip", content)
            self.assertIn("network_listeners disabled", content)
            self.assertIn("not the formal ContextDB M18 Alpha", content)

    def test_publication_rejects_incomplete_platform_asset_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "verify-release-set",
                    "--dist",
                    temporary,
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("release asset set mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
