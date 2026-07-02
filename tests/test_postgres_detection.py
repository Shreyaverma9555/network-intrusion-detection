from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from check_setup import postgres_windows_service


class PostgresDetectionTests(unittest.TestCase):
    @patch("check_setup.platform.system", return_value="Windows")
    @patch("check_setup.subprocess.run")
    def test_detects_any_running_postgresql_version(self, run, system) -> None:
        listing = MagicMock(stdout="SERVICE_NAME: postgresql-x64-17\nSERVICE_NAME: another-service\n")
        status = MagicMock(stdout="STATE              : 4  RUNNING\n")
        run.side_effect = [listing, status]

        self.assertEqual(postgres_windows_service(), "postgresql-x64-17")


if __name__ == "__main__":
    unittest.main()
