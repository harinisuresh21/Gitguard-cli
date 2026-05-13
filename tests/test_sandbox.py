from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from gitguard.core.models import ScanRecord
from gitguard.core.sandbox import (
    SANDBOX_CPU_LIMIT,
    SANDBOX_DYNAMIC_TIMEOUT_SECONDS,
    SANDBOX_IMAGE,
    SANDBOX_MEMORY_LIMIT,
    SANDBOX_CLONE_TIMEOUT_SECONDS,
    SANDBOX_ROOT_USER,
    SANDBOX_TOTAL_TIMEOUT_SECONDS,
    SANDBOX_TMP_DIR,
    SANDBOX_USER,
    SandboxTimeoutError,
    _build_container_runtime_options,
    _build_isolation_warnings,
    _build_clone_command,
    _infer_timeout_phase,
    run_sandbox_clone,
)
from gitguard.core.session import ScanSession


class SandboxTests(unittest.TestCase):
    @patch("gitguard.core.state.Path.home")
    @patch("gitguard.core.sandbox.docker.from_env")
    def test_run_sandbox_clone_uses_restricted_container_settings(
        self, mock_from_env: MagicMock, mock_home: MagicMock
    ) -> None:
        mock_home.return_value = MagicMock()
        mock_home.return_value.__truediv__.side_effect = lambda other: MagicMock()
        record = ScanRecord(
            scan_id="scan-1",
            target_url="https://github.com/octocat/Hello-World",
            timestamp="2026-05-13T00:00:00+00:00",
            host_os="Windows",
            status="initializing",
        )

        container = MagicMock()
        container.id = "container-1"
        container.status = "created"
        container.logs.return_value = b"GITGUARD_SANDBOX_EVENT clone_complete\n"

        def reload_side_effect() -> None:
            container.status = "exited"

        container.reload.side_effect = reload_side_effect
        container.wait.return_value = {"StatusCode": 0}

        client = MagicMock()
        client.containers.run.return_value = container
        mock_from_env.return_value = client

        with patch("gitguard.core.session.get_active_scan_file") as mock_active_scan_file:
            active_file = MagicMock()
            active_file.exists.return_value = False
            mock_active_scan_file.return_value = active_file
            with patch("gitguard.core.sandbox.platform.system", return_value="Windows"):
                with ScanSession(record) as session:
                    result = run_sandbox_clone(record.target_url, session)

        self.assertEqual(result.image, SANDBOX_IMAGE)
        self.assertEqual(result.progress_messages, [])
        self.assertIsNone(result.coverage_reason)
        client.images.pull.assert_called_once_with(SANDBOX_IMAGE)
        client.containers.run.assert_called_once()
        _, kwargs = client.containers.run.call_args
        self.assertEqual(kwargs["user"], SANDBOX_USER)
        self.assertEqual(kwargs["working_dir"], SANDBOX_TMP_DIR)
        self.assertEqual(kwargs["network_mode"], "bridge")
        self.assertEqual(kwargs["read_only"], True)
        self.assertEqual(kwargs["cap_drop"], ["ALL"])
        self.assertEqual(kwargs["mem_limit"], SANDBOX_MEMORY_LIMIT)
        self.assertEqual(kwargs["nano_cpus"], SANDBOX_CPU_LIMIT)
        self.assertEqual(kwargs["volumes"], {})

    def test_linux_runtime_options_enable_net_admin_for_lan_blocking(self) -> None:
        options = _build_container_runtime_options("linux")

        self.assertEqual(options["user"], SANDBOX_ROOT_USER)
        self.assertEqual(options["cap_add"], ["NET_ADMIN"])

    def test_non_linux_runtime_options_keep_non_root_user(self) -> None:
        options = _build_container_runtime_options("windows")

        self.assertEqual(options["user"], SANDBOX_USER)
        self.assertEqual(options["cap_add"], [])

    @patch("gitguard.core.sandbox.time.sleep", return_value=None)
    @patch("gitguard.core.sandbox.time.monotonic", side_effect=[0, 0, 361, 361])
    def test_run_sandbox_clone_times_out_and_removes_container(
        self, _: MagicMock, __: MagicMock
    ) -> None:
        container = MagicMock()
        container.status = "running"
        container.id = "container-2"
        container.logs.return_value = b'{"event": "coverage", "mode": "browser_dynamic"}\n'

        with self.assertRaisesRegex(SandboxTimeoutError, "dynamic analysis exceeded 360 seconds"):
            from gitguard.core.sandbox import _wait_for_container

            _wait_for_container(container, timeout_seconds=SANDBOX_TOTAL_TIMEOUT_SECONDS)

        container.remove.assert_called_once_with(force=True)

    def test_timeout_error_preserves_logs(self) -> None:
        container = MagicMock()
        container.status = "running"
        container.id = "container-3"
        container.logs.return_value = b"GITGUARD_PROGRESS: Starting shallow clone\n"

        with patch("gitguard.core.sandbox.time.sleep", return_value=None):
            with patch("gitguard.core.sandbox.time.monotonic", side_effect=[0, 0, 361, 361]):
                with self.assertRaises(SandboxTimeoutError) as context:
                    from gitguard.core.sandbox import _wait_for_container

                    _wait_for_container(container, timeout_seconds=SANDBOX_TOTAL_TIMEOUT_SECONDS)

        self.assertIn("Starting shallow clone", context.exception.logs)

    def test_infer_timeout_phase_defaults_to_clone_setup(self) -> None:
        self.assertEqual(_infer_timeout_phase("plain logs"), "clone/setup stage")

    def test_clone_command_embeds_phase_timeouts(self) -> None:
        command = _build_clone_command()
        self.assertEqual(command[:2], ["/bin/bash", "-lc"])
        script = command[2]
        self.assertIn(f"timeout {SANDBOX_CLONE_TIMEOUT_SECONDS}s git clone --depth 1", script)
        self.assertIn(f"timeout {SANDBOX_DYNAMIC_TIMEOUT_SECONDS}s python - <<'PY'", script)
        self.assertIn("iptables -A OUTPUT -d 10.0.0.0/8 -j REJECT", script)
        self.assertIn(f"su {SANDBOX_USER} -s /bin/bash -c /tmp/gitguard-runner.sh", script)

    def test_isolation_warnings_clear_when_lan_policy_enforced(self) -> None:
        warnings = _build_isolation_warnings(
            "GITGUARD_LAN_POLICY enforced\nGITGUARD_SANDBOX_EVENT clone_complete\n",
            "linux",
        )

        self.assertEqual(warnings, [])

    def test_isolation_warnings_report_linux_degraded_reason(self) -> None:
        warnings = _build_isolation_warnings(
            "GITGUARD_LAN_POLICY unavailable:iptables_missing\nGITGUARD_SANDBOX_EVENT clone_complete\n",
            "linux",
        )

        self.assertEqual(len(warnings), 1)
        self.assertIn("iptables is not available", warnings[0])


if __name__ == "__main__":
    unittest.main()
