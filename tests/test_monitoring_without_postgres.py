from __future__ import annotations

import unittest
from unittest.mock import patch

from src.nid.processor import ProcessingPolicy, RealTimeProcessor
from src.nid.realtime import DetectionEvent
from src.nid.threat_intel import ThreatIntel


class MonitoringWithoutPostgresTests(unittest.TestCase):
    @patch(
        "src.nid.processor.enrich_event",
        return_value=ThreatIntel(ip="", labels=["Private/internal address"], country="Private Network"),
    )
    def test_processor_runs_without_repository_when_logging_is_disabled(self, enrich) -> None:
        processor = RealTimeProcessor(policy=ProcessingPolicy(save_events=False, save_external=False))
        event = DetectionEvent(
            timestamp=1.0,
            rows=20,
            attack_probability=0.1,
            predicted_attack=False,
            category="Normal",
            confidence=0.9,
        )

        result = processor.process_event(event)

        self.assertIsNone(processor.store)
        self.assertEqual(result.errors, [])
        self.assertNotIn("PostgreSQL", " ".join(result.actions))


if __name__ == "__main__":
    unittest.main()
