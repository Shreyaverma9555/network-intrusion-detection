from __future__ import annotations

import asyncio
import unittest

from src.nid.event_bus import EventBus
from src.nid.pdf_report import build_incident_pdf
from src.nid.realtime import DetectionEvent


class SocFeatureTests(unittest.IsolatedAsyncioTestCase):
    async def test_event_bus_streams_detection_to_subscriber(self) -> None:
        bus = EventBus(queue_size=2)
        async with bus.subscribe() as queue:
            await bus.publish({"type": "detection", "event": {"id": 5}})
            message = await asyncio.wait_for(queue.get(), timeout=1)

        self.assertEqual(message["event"]["id"], 5)
        self.assertEqual(bus.subscriber_count, 0)

    async def test_event_bus_drops_oldest_message_when_client_is_slow(self) -> None:
        bus = EventBus(queue_size=1)
        async with bus.subscribe() as queue:
            await bus.publish({"id": 1})
            await bus.publish({"id": 2})
            message = await queue.get()

        self.assertEqual(message["id"], 2)

    async def test_incident_report_is_a_real_pdf(self) -> None:
        event = DetectionEvent(
            timestamp=1.0,
            rows=40,
            attack_probability=0.94,
            predicted_attack=True,
            category="Port Scan",
            confidence=0.98,
            severity="Critical",
            reasons=["Port scan rule matched", "25 unique destination ports"],
            statistics={"mitre_technique_ids": "T1046"},
            source_ip="203.0.113.66",
            destination_ip="192.168.1.10",
            traffic_scope="Inbound",
            threat_score=90,
        )

        result = build_incident_pdf(event)

        self.assertTrue(result.startswith(b"%PDF-"))
        self.assertGreater(len(result), 1500)


if __name__ == "__main__":
    unittest.main()
