from __future__ import annotations

import unittest
from unittest.mock import patch

from src.nid.alerts import AlertDelivery
from src.nid.processor import ProcessingPolicy, RealTimeProcessor
from src.nid.realtime import DetectionEvent


class FakeStore:
    def __init__(self) -> None:
        self.responses: list[tuple[str, str, str]] = []

    def save(self, event: DetectionEvent) -> int:
        return 42

    def record_response(self, source_ip: str, action: str, details: str) -> int:
        self.responses.append((source_ip, action, details))
        return 1


def threat(severity: str = "High", source_ip: str = "8.8.8.8") -> DetectionEvent:
    return DetectionEvent(
        timestamp=1.0,
        rows=100,
        attack_probability=0.98,
        predicted_attack=True,
        category="DoS",
        confidence=0.95,
        severity=severity,
        source_ip=source_ip,
    )


class AutoResponseTests(unittest.TestCase):
    @patch("src.nid.processor.block_ip", return_value="Blocked 8.8.8.8")
    @patch("src.nid.processor.send_alerts_with_status", return_value=AlertDelivery(sent=["email"]))
    @patch("src.nid.processor.enrich_event")
    def test_high_severity_logs_alerts_then_blocks(self, enrich, send_alerts, block_ip) -> None:
        store = FakeStore()
        engine = RealTimeProcessor(
            policy=ProcessingPolicy(auto_response=True, save_external=False),
            store=store,
        )

        result = engine.process_event(threat())

        self.assertLess(result.actions.index("PostgreSQL event #42"), result.actions.index("email alert sent"))
        self.assertLess(result.actions.index("email alert sent"), result.actions.index("blocked 8.8.8.8"))
        self.assertTrue(result.event.blocked)
        self.assertEqual(store.responses[0][1], "block")
        send_alerts.assert_called_once()
        block_ip.assert_called_once_with("8.8.8.8", execute=True)

    @patch("src.nid.processor.block_ip")
    @patch("src.nid.processor.send_alerts_with_status")
    @patch("src.nid.processor.enrich_event")
    def test_medium_severity_does_not_alert_or_block(self, enrich, send_alerts, block_ip) -> None:
        engine = RealTimeProcessor(
            policy=ProcessingPolicy(auto_response=True, save_external=False),
            store=FakeStore(),
        )

        result = engine.process_event(threat(severity="Medium"))

        self.assertFalse(result.event.blocked)
        send_alerts.assert_not_called()
        block_ip.assert_not_called()

    @patch("src.nid.processor.block_ip")
    @patch("src.nid.processor.send_alerts_with_status", return_value=AlertDelivery(sent=["email"]))
    @patch("src.nid.processor.enrich_event")
    def test_private_source_is_alerted_but_not_blocked(self, enrich, send_alerts, block_ip) -> None:
        engine = RealTimeProcessor(
            policy=ProcessingPolicy(auto_response=True, save_external=False),
            store=FakeStore(),
        )

        result = engine.process_event(threat(source_ip="192.168.1.50"))

        self.assertFalse(result.event.blocked)
        send_alerts.assert_called_once()
        block_ip.assert_not_called()


if __name__ == "__main__":
    unittest.main()
