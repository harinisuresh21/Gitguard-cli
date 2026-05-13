from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest
from unittest.mock import patch

from gitguard.core.dependency_guard import PackageMetadata, analyze_dependency_manifests
from gitguard.core.obfuscation_review import analyze_obfuscation

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class FixtureRepoTests(unittest.TestCase):
    @patch("gitguard.core.dependency_guard.fetch_pypi_package_metadata")
    @patch("gitguard.core.dependency_guard.fetch_npm_package_metadata")
    @patch("gitguard.core.dependency_guard.get_state_dir", return_value=FIXTURES_DIR)
    def test_safe_python_fixture_has_no_blocking_findings(
        self,
        _: object,
        mock_npm_metadata: object,
        mock_pypi_metadata: object,
    ) -> None:
        mock_npm_metadata.return_value = PackageMetadata(
            latest_version="1.0.0",
            latest_release_time=datetime.now(timezone.utc) - timedelta(days=30),
        )
        mock_pypi_metadata.return_value = PackageMetadata(
            latest_version="2.31.0",
            latest_release_time=datetime.now(timezone.utc) - timedelta(days=30),
        )

        result = analyze_dependency_manifests(FIXTURES_DIR / "safe_python")

        self.assertFalse(result.blocked)
        self.assertEqual(result.package_count_by_ecosystem, {"python": 2, "node": 0})

    @patch("gitguard.core.dependency_guard.fetch_pypi_package_metadata")
    @patch("gitguard.core.dependency_guard.fetch_npm_package_metadata")
    @patch("gitguard.core.dependency_guard.get_state_dir", return_value=FIXTURES_DIR)
    def test_typosquat_fixture_blocks_before_runtime(
        self,
        _: object,
        mock_npm_metadata: object,
        mock_pypi_metadata: object,
    ) -> None:
        mock_npm_metadata.return_value = PackageMetadata(
            latest_version="1.0.0",
            latest_release_time=datetime.now(timezone.utc) - timedelta(days=30),
        )
        mock_pypi_metadata.return_value = PackageMetadata(
            latest_version="2.31.0",
            latest_release_time=datetime.now(timezone.utc) - timedelta(days=30),
        )

        result = analyze_dependency_manifests(FIXTURES_DIR / "typosquat_python")

        self.assertTrue(result.blocked)
        self.assertIn("typosquatting", {finding.category for finding in result.findings})

    @patch("gitguard.core.dependency_guard.fetch_pypi_package_metadata")
    @patch("gitguard.core.dependency_guard.fetch_npm_package_metadata")
    @patch("gitguard.core.dependency_guard.get_state_dir", return_value=FIXTURES_DIR)
    def test_node_lifecycle_fixture_flags_npm_findings(
        self,
        _: object,
        mock_npm_metadata: object,
        mock_pypi_metadata: object,
    ) -> None:
        mock_npm_metadata.return_value = PackageMetadata(
            latest_version="1.7.0",
            latest_release_time=datetime.now(timezone.utc) - timedelta(days=30),
        )
        mock_pypi_metadata.return_value = PackageMetadata(
            latest_version="2.31.0",
            latest_release_time=datetime.now(timezone.utc) - timedelta(days=30),
        )

        result = analyze_dependency_manifests(FIXTURES_DIR / "node_lifecycle")

        self.assertTrue(result.blocked)
        categories = {finding.category for finding in result.findings}
        self.assertIn("npm_lifecycle_script", categories)
        self.assertIn("npm_typosquatting", categories)

    def test_obfuscated_fixture_surfaces_decode_chain(self) -> None:
        result = analyze_obfuscation(FIXTURES_DIR / "obfuscated_js")

        self.assertIn("nested_eval", {finding.category for finding in result.findings})


if __name__ == "__main__":
    unittest.main()
