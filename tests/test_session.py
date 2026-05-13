from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
import shutil
from uuid import uuid4
from unittest.mock import patch

from gitguard.core.models import ScanRecord
from gitguard.core.session import ConcurrentScanError, ScanSession


class SessionTests(unittest.TestCase):
    def test_scan_session_creates_and_releases_active_scan_lock(self) -> None:
        fake_home = _make_fake_home()
        try:
            with patch("gitguard.core.state.Path.home", return_value=fake_home):
                record = ScanRecord.create(
                    target_url="https://github.com/octocat/Hello-World",
                    created_at=datetime.now(timezone.utc),
                    initial_status="initializing",
                )

                with ScanSession(record) as session:
                    lock_file = session.active_scan_file
                    self.assertTrue(lock_file.exists())
                    lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
                    self.assertEqual(lock_data["scan_id"], record.scan_id)

                self.assertFalse(lock_file.exists())
        finally:
            shutil.rmtree(fake_home, ignore_errors=True)

    def test_scan_session_blocks_concurrent_scan_when_lock_pid_is_active(self) -> None:
        fake_home = _make_fake_home()
        try:
            with patch("gitguard.core.state.Path.home", return_value=fake_home):
                lock_file = fake_home / ".gitguard" / "active_scan.json"
                lock_file.parent.mkdir(parents=True, exist_ok=True)
                lock_file.write_text('{"pid": 12345}', encoding="utf-8")
                record = ScanRecord.create(
                    target_url="https://github.com/octocat/Hello-World",
                    created_at=datetime.now(timezone.utc),
                    initial_status="initializing",
                )

                with patch("gitguard.core.session.psutil.pid_exists", return_value=True):
                    with self.assertRaises(ConcurrentScanError):
                        with ScanSession(record):
                            self.fail("session should not be entered")
        finally:
            shutil.rmtree(fake_home, ignore_errors=True)


def _make_fake_home() -> Path:
    fake_home = Path.cwd() / "tests" / ".tmp" / str(uuid4())
    fake_home.mkdir(parents=True, exist_ok=True)
    return fake_home


if __name__ == "__main__":
    unittest.main()
