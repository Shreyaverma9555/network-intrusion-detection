from __future__ import annotations

import unittest
from unittest.mock import patch

import pandas as pd

from src.nid.processor import ProcessingPolicy, RealTimeProcessor
from src.nid.realtime import RealTimeDetector


def packet_window() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "frame.time_epoch": 1000 + index * 0.01,
                "ip.src": "192.168.1.10",
                "ip.dst": "8.8.8.8",
                "ip.proto": 6,
                "tcp.srcport": 50000,
                "tcp.dstport": 443,
                "frame.len": 300,
                "tcp.flags": "0x018",
            }
            for index in range(20)
        ]
    )


class LatencyMetricsTests(unittest.TestCase):
    @patch("src.nid.realtime.capture_packets", side_effect=lambda **_: packet_window())
    def test_live_detection_reports_capture_and_analysis_latency(self, capture) -> None:
        event = RealTimeDetector("models/sample_ensemble.joblib").detect_live_window(None, 0.5)

        self.assertGreaterEqual(float((event.statistics or {})["capture_latency_ms"]), 0)
        self.assertGreater(float((event.statistics or {})["analysis_latency_ms"]), 0)

    @patch("src.nid.realtime.capture_packets", side_effect=lambda **_: packet_window())
    def test_processor_reports_end_to_end_latency(self, capture) -> None:
        processor = RealTimeProcessor(policy=ProcessingPolicy(save_events=False, save_external=False))

        result = processor.process_live_window(None, 0.5)

        statistics = result.event.statistics or {}
        self.assertGreaterEqual(float(statistics["integration_latency_ms"]), 0)
        self.assertGreater(float(statistics["total_latency_ms"]), 0)
        self.assertEqual(statistics["window_latency_ms"], statistics["total_latency_ms"])


if __name__ == "__main__":
    unittest.main()
