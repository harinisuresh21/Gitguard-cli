from __future__ import annotations

import shutil
import unittest
from uuid import uuid4
from unittest.mock import patch

from typer.testing import CliRunner

from gitguard.cli import app
from gitguard.core.models import (
    AIAuditResult,
    DependencyAnalysisResult,
    DependencyFinding,
    ObfuscationAnalysisResult,
    PreflightResult,
    SandboxResult,
    ScanAssessment,
)


class CliTests(unittest.TestCase):
    def test_help_lists_required_doctor_command(self) -> None:
        runner = CliRunner()

        result = runner.invoke(app, ["--help"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("doctor", result.stdout)
        self.assertNotIn("verify-env", result.stdout)

    @patch("gitguard.commands.verify_env.run_preflight_checks")
    def test_doctor_command_invokes_environment_check(self, mock_preflight: object) -> None:
        mock_preflight.return_value.docker_status = "reachable"
        mock_preflight.return_value.available_memory_mb = 2048
        mock_preflight.return_value.memory_ok = True
        mock_preflight.return_value.ai_key_present = False
        runner = CliRunner()

        result = runner.invoke(app, ["doctor"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("GitGuard Environment", result.stdout)

    @patch("gitguard.commands.check.run_sandbox_clone")
    @patch("gitguard.commands.check.analyze_obfuscation")
    @patch("gitguard.commands.check.analyze_dependency_manifests")
    @patch("gitguard.commands.check.clone_repository_to_tempdir")
    @patch("gitguard.commands.check.run_preflight_checks")
    @patch("gitguard.commands.check.validate_repository_url")
    @patch("gitguard.core.state.Path.home")
    def test_check_stops_before_sandbox_on_critical_dependency_findings(
        self,
        mock_home: object,
        mock_validate: object,
        mock_preflight: object,
        mock_clone_checkout: object,
        mock_dependency_guard: object,
        mock_obfuscation: object,
        mock_run_sandbox: object,
    ) -> None:
        fake_home = _make_temp_dir()
        runner = CliRunner()
        try:
            mock_home.return_value = fake_home
            mock_validate.return_value = "https://github.com/octocat/Hello-World"
            checkout_root = fake_home / "repo"
            checkout_root.mkdir(parents=True, exist_ok=True)
            mock_clone_checkout.return_value = checkout_root
            mock_preflight.return_value = PreflightResult(
                docker_status="reachable",
                available_memory_mb=2048,
                memory_ok=True,
                ai_key_present=False,
            )
            mock_dependency_guard.return_value = DependencyAnalysisResult(
                manifests=["requirements.txt"],
                packages=["requsts"],
                findings=[
                    DependencyFinding(
                        severity="CRITICAL",
                        category="typosquatting",
                        package_name="requsts",
                        manifest_path="requirements.txt",
                        message="Package 'requsts' closely matches popular package 'requests'.",
                    )
                ],
                warnings=[],
                blocked=True,
                package_count_by_ecosystem={"python": 1, "node": 0},
            )
            mock_obfuscation.return_value = ObfuscationAnalysisResult(findings=[], warnings=[])

            result = runner.invoke(app, ["check", "https://github.com/octocat/Hello-World"])

            self.assertEqual(result.exit_code, 1)
            mock_run_sandbox.assert_not_called()
        finally:
            shutil.rmtree(fake_home, ignore_errors=True)

    @patch("gitguard.commands.check.run_ai_audit")
    @patch("gitguard.commands.check.assess_runtime_behavior")
    @patch("gitguard.commands.check.run_sandbox_clone")
    @patch("gitguard.commands.check.analyze_obfuscation")
    @patch("gitguard.commands.check.analyze_dependency_manifests")
    @patch("gitguard.commands.check.clone_repository_to_tempdir")
    @patch("gitguard.commands.check.run_preflight_checks")
    @patch("gitguard.commands.check.validate_repository_url")
    @patch("gitguard.core.state.Path.home")
    def test_check_json_outputs_structured_report(
        self,
        mock_home: object,
        mock_validate: object,
        mock_preflight: object,
        mock_clone_checkout: object,
        mock_dependency_guard: object,
        mock_obfuscation: object,
        mock_run_sandbox: object,
        mock_assess_runtime: object,
        mock_run_ai_audit: object,
    ) -> None:
        fake_home = _make_temp_dir()
        runner = CliRunner()
        try:
            mock_home.return_value = fake_home
            checkout_root = fake_home / "repo"
            checkout_root.mkdir(parents=True, exist_ok=True)
            (checkout_root / "README.md").write_text("safe repo", encoding="utf-8")
            mock_clone_checkout.return_value = checkout_root
            mock_validate.return_value = "https://github.com/octocat/Hello-World"
            mock_preflight.return_value = PreflightResult(
                docker_status="reachable",
                available_memory_mb=2048,
                memory_ok=True,
                ai_key_present=False,
            )
            mock_dependency_guard.return_value = DependencyAnalysisResult(
                manifests=["requirements.txt", "package.json"],
                packages=["requests", "react"],
                findings=[],
                warnings=[],
                blocked=False,
                package_count_by_ecosystem={"python": 1, "node": 1},
            )
            mock_obfuscation.return_value = ObfuscationAnalysisResult(findings=[], warnings=[])
            mock_run_sandbox.return_value = SandboxResult(
                image="img",
                container_id="cid",
                exit_code=0,
                logs="",
                runtime_seconds=1.0,
                warnings=[],
                coverage="static_only",
                coverage_reason="unsupported_repo_type",
                telemetry_events=[],
                progress_messages=[],
                entrypoint=None,
            )
            mock_assess_runtime.return_value = ScanAssessment(
                verdict="SAFE",
                summary="No strong malicious indicators were found.",
                evidence=[],
                coverage="static_only",
            )
            mock_run_ai_audit.return_value = None

            result = runner.invoke(app, ["check", "--json", "https://github.com/octocat/Hello-World"])

            self.assertEqual(result.exit_code, 0)
            self.assertIn('"verdict": "SAFE"', result.stdout)
            self.assertIn('"package_count_by_ecosystem"', result.stdout)
            self.assertIn('"report_file"', result.stdout)
        finally:
            shutil.rmtree(fake_home, ignore_errors=True)


def _make_temp_dir():
    from pathlib import Path

    path = Path.cwd() / "tests" / ".tmp" / str(uuid4())
    path.mkdir(parents=True, exist_ok=True)
    return path


if __name__ == "__main__":
    unittest.main()
