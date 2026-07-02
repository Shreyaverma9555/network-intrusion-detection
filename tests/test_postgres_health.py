from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from src.nid.postgres import PostgresRepository


class PostgresHealthTests(unittest.TestCase):
    @patch.object(PostgresRepository, "initialize")
    @patch.object(PostgresRepository, "_connect")
    def test_health_reports_required_schema(self, connect, initialize) -> None:
        health_cursor = MagicMock()
        health_cursor.fetchone.return_value = (
            "nid",
            "nid_user",
            "PostgreSQL 18.0 on Windows",
            12,
        )
        tables_cursor = MagicMock()
        tables_cursor.fetchall.return_value = [
            ("nid_audit_logs",),
            ("nid_events",),
            ("nid_users",),
        ]
        connection = MagicMock()
        connection.execute.side_effect = [health_cursor, tables_cursor]
        context = MagicMock()
        context.__enter__.return_value = connection
        connect.return_value = context

        health = PostgresRepository("postgresql://example").health()

        self.assertTrue(health["ready"])
        self.assertEqual(health["database"], "nid")
        self.assertEqual(health["event_count"], 12)
        self.assertEqual(health["missing_tables"], [])


if __name__ == "__main__":
    unittest.main()
