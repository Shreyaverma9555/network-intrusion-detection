from __future__ import annotations

import unittest
from unittest.mock import patch

from backend import init_db


class BackendContainerTests(unittest.TestCase):
    def test_minimal_initializer_does_not_import_cli_entrypoint(self) -> None:
        with patch("backend.init_db.PostgresRepository") as repository:
            instance = repository.return_value
            instance.health.return_value = {
                "ready": True,
                "tables": ["nid_audit_logs", "nid_events", "nid_users"],
                "event_count": 0,
            }

            init_db.main()

        instance.initialize.assert_called_once_with()
        instance.health.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
