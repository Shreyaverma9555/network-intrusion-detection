from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

import requests

from sensor import send_event
from src.nid.realtime import DetectionEvent


class SensorDeliveryTests(unittest.TestCase):
    def test_sensor_sends_api_key_and_event(self) -> None:
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"event_id": 42}
        event = DetectionEvent(
            timestamp=1.0,
            rows=10,
            attack_probability=0.8,
            predicted_attack=True,
            source_ip="203.0.113.5",
            destination_ip="192.168.1.5",
        )

        with patch("sensor.requests.post", return_value=response) as post:
            event_id = send_event("https://soc.example/", "sensor-secret", event, 5, retries=0)

        self.assertEqual(event_id, 42)
        self.assertEqual(post.call_args.args[0], "https://soc.example/sensor/events")
        self.assertEqual(post.call_args.kwargs["headers"], {"X-Sensor-Key": "sensor-secret"})
        self.assertEqual(post.call_args.kwargs["json"]["rows"], 10)

    def test_sensor_retries_temporary_delivery_failure(self) -> None:
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"event_id": 7}
        event = DetectionEvent(1.0, 1, 0.0, False)

        with patch(
            "sensor.requests.post",
            side_effect=[requests.ConnectionError("cold start"), response],
        ) as post, patch("sensor.time.sleep"):
            self.assertEqual(send_event("https://soc.example", "key", event, 5, retries=1), 7)

        self.assertEqual(post.call_count, 2)


if __name__ == "__main__":
    unittest.main()
