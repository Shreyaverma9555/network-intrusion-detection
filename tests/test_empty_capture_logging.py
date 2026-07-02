from __future__ import annotations

import unittest

from src.nid.postgres import PostgresRepository
from src.nid.processor import ProcessingPolicy, RealTimeProcessor
from src.nid.realtime import DetectionEvent


class RecordingStore:
    def __init__(self) -> None:
        self.saved: list[DetectionEvent] = []

    def save(self, event: DetectionEvent) -> int:
        self.saved.append(event)
        return 1

    def record_response(self, source_ip: str, action: str, details: str) -> int:
        return 1


class EmptyCaptureLoggingTests(unittest.TestCase):
    def test_empty_capture_is_not_saved(self) -> None:
        store = RecordingStore()
        processor = RealTimeProcessor(
            policy=ProcessingPolicy(save_events=True, save_external=False),
            store=store,
        )
        event = DetectionEvent(0.0, 0, 0.0, False)

        result = processor.process_event(event)

        self.assertEqual(store.saved, [])
        self.assertIn("No packets captured; database logging skipped", result.actions)

    def test_postgres_endpoint_normalization_rejects_non_ips(self) -> None:
        self.assertIsNone(PostgresRepository._valid_ip_or_none(None))
        self.assertIsNone(PostgresRepository._valid_ip_or_none("No packets captured"))
        self.assertIsNone(PostgresRepository._valid_ip_or_none("aa:bb:cc:dd:ee:ff"))
        self.assertEqual(PostgresRepository._valid_ip_or_none("2001:0db8::1"), "2001:db8::1")


if __name__ == "__main__":
    unittest.main()
