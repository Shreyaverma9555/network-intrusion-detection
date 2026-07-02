from __future__ import annotations

import unittest
from unittest.mock import patch

from src.nid.processor import ProcessingPolicy, RealTimeProcessor
from src.nid.realtime import DetectionEvent
from src.nid.threat_intel import lookup_ip


class ThreatIntelligenceTests(unittest.TestCase):
    def test_local_cidr_feed_and_port_intelligence(self) -> None:
        intel = lookup_ip("198.51.100.44", use_external=False, port=3389)

        self.assertGreaterEqual(intel.score, 85)
        self.assertEqual(intel.status, "Local blacklist match")
        self.assertEqual(intel.country, "India")
        self.assertIsNotNone(intel.latitude)
        self.assertIsNotNone(intel.longitude)
        self.assertEqual(intel.port_service, "RDP")
        self.assertEqual(intel.port_risk, "Critical")

    def test_public_ip_without_api_key_explains_zero_score(self) -> None:
        with patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "", "NID_ENABLE_GEOIP": "0"}, clear=False):
            intel = lookup_ip("8.8.8.8", use_external=True, port=443)

        self.assertEqual(intel.score, 0)
        self.assertIn("External reputation disabled", intel.status)
        self.assertTrue(any("API key not configured" in label for label in intel.labels or []))

    def test_event_enrichment_adds_provider_and_port_context(self) -> None:
        processor = RealTimeProcessor(policy=ProcessingPolicy(save_events=False, save_external=False))
        event = DetectionEvent(
            timestamp=1.0,
            rows=20,
            attack_probability=0.2,
            predicted_attack=False,
            source_ip="203.0.113.66",
            destination_ip="192.168.31.178",
            statistics={"top_destination_port": 22},
        )

        result = processor.process_event(event)

        stats = result.event.statistics or {}
        self.assertEqual(stats["threat_intel_status"], "Local blacklist match")
        self.assertIn("source_latitude", stats)
        self.assertIn("source_longitude", stats)
        self.assertEqual(stats["port_service"], "SSH")
        self.assertGreaterEqual(result.event.threat_score, 92)
        self.assertTrue(result.event.predicted_attack)


if __name__ == "__main__":
    unittest.main()
