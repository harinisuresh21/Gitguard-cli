from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from gitguard.cli import app
from gitguard.core.models import DependencyAnalysisResult, DependencyFinding, PreflightResult


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
    @patch("gitguard.commands.check.run_dependency_guard")
    @patch("gitguard.commands.check.run_preflight_checks")
    @patch("gitguard.commands.check.validate_repository_url")
    @patch("gitguard.core.state.Path.home")
    def test_check_stops_before_sandbox_on_critical_dependency_findings(
        self,
        mock_home: object,
        mock_validate: object,
        mock_preflight: object,
        mock_dependency_guard: object,
        mock_run_sandbox: object,
    ) -> None:
        fake_home = Path(tempfile.mkdtemp(prefix="gitguard-cli-home-"))
        runner = CliRunner()
        try:
            mock_home.return_value = fake_home
            mock_validate.return_value = "https://github.com/octocat/Hello-World"
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
            )

            result = runner.invoke(app, ["check", "https://github.com/octocat/Hello-World"])

            self.assertEqual(result.exit_code, 1)
            mock_run_sandbox.assert_not_called()
        finally:
            shutil.rmtree(fake_home, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
