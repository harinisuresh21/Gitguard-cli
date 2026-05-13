from __future__ import annotations

import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from gitguard.cli import app


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


if __name__ == "__main__":
    unittest.main()
