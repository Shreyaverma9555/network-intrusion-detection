from __future__ import annotations

import math
import unittest

import pandas as pd

from src.nid.classification import classify_window
from src.nid.features import FeatureBuilder
from src.nid.realtime import RealTimeDetector
from src.nid.traffic_scope import classify_flow


def normal_https_window() -> pd.DataFrame:
    rows = []
    for index in range(30):
        inbound = index % 2 == 0
        rows.append(
            {
                "frame.time_epoch": 1000 + index * 0.05,
                "ip.src": "8.8.8.8" if inbound else "192.168.1.10",
                "ip.dst": "192.168.1.10" if inbound else "8.8.8.8",
                "ip.proto": 6,
                "tcp.srcport": 443 if inbound else 52000,
                "tcp.dstport": 52000 if inbound else 443,
                "frame.len": 300,
                "tcp.flags": "0x018",
            }
        )
    return pd.DataFrame(rows)


class DetectionQualityTests(unittest.TestCase):
    def test_normal_https_does_not_become_u2r(self) -> None:
        raw = normal_https_window()
        classification = classify_window(raw, FeatureBuilder().transform(raw), 0.70, attack_threshold=0.75)

        self.assertEqual(classification.category, "Normal")
        expected_support = max(1 - 0.70, 1 - float(classification.statistics["behavior_score"]))
        self.assertAlmostEqual(classification.confidence, expected_support, places=4)
        self.assertAlmostEqual(
            float(classification.statistics["decision_uncertainty"]),
            1 - classification.confidence,
            places=4,
        )

    def test_top_flow_is_an_observed_non_self_pair(self) -> None:
        raw = normal_https_window()
        raw.loc[len(raw)] = raw.iloc[0].to_dict() | {"ip.src": "192.168.1.10", "ip.dst": "192.168.1.10"}

        source, destination = RealTimeDetector._top_flow(raw)

        self.assertNotEqual(source, destination)
        self.assertIn((source, destination), set(zip(raw["ip.src"], raw["ip.dst"])))

    def test_strong_port_scan_behavior_still_triggers_attack(self) -> None:
        raw = pd.DataFrame(
            [
                {
                    "frame.time_epoch": 1000 + index * 0.01,
                    "ip.src": "203.0.113.10",
                    "ip.dst": "192.168.1.10",
                    "ip.proto": 6,
                    "tcp.srcport": 40000 + index,
                    "tcp.dstport": 1 + index,
                    "frame.len": 60,
                    "tcp.flags": "0x002",
                }
                for index in range(30)
            ]
        )

        classification = classify_window(raw, FeatureBuilder().transform(raw), 0.90, attack_threshold=0.75)

        self.assertIn(classification.category, {"Probe", "Port Scan"})
        self.assertGreaterEqual(classification.confidence, math.sqrt(0.90 * float(classification.statistics["behavior_score"])))
        self.assertEqual(classification.statistics["rule_override"], 1)

    def test_demo_capture_is_normal_with_robust_window_scoring(self) -> None:
        event = RealTimeDetector("models/sample_ensemble.joblib").detect_file("data/live_packets.csv")

        self.assertEqual(event.category, "Normal")
        self.assertFalse(event.predicted_attack)
        self.assertEqual(event.model_threat_score, event.attack_probability)
        self.assertGreater(event.confidence, event.attack_probability)
        self.assertAlmostEqual(
            event.confidence + float((event.statistics or {})["decision_uncertainty"]),
            1.0,
            places=4,
        )
        self.assertTrue((event.statistics or {}).get("feature_order_valid"))
        self.assertEqual(event.traffic_scope, classify_flow(event.source_ip, event.destination_ip))

    def test_window_shap_changes_for_different_traffic(self) -> None:
        normal = normal_https_window()
        scan = pd.DataFrame(
            [
                {
                    "frame.time_epoch": 1000 + index * 0.01,
                    "ip.src": "203.0.113.10",
                    "ip.dst": "192.168.1.10",
                    "ip.proto": 6,
                    "tcp.srcport": 40000 + index,
                    "tcp.dstport": 1 + index,
                    "frame.len": 60,
                    "tcp.flags": "0x002",
                }
                for index in range(30)
            ]
        )
        detector = RealTimeDetector("models/sample_ensemble.joblib")
        if detector.pipeline is None:
            self.skipTest(f"Trained model unavailable: {detector.fallback_reason}")

        normal_event = detector.detect_frame(normal)
        scan_event = detector.detect_frame(scan)
        normal_signature = [
            (row["raw_feature"], round(float(row["importance"]), 4), row["direction"])
            for row in normal_event.top_features or []
        ]
        scan_signature = [
            (row["raw_feature"], round(float(row["importance"]), 4), row["direction"])
            for row in scan_event.top_features or []
        ]

        self.assertNotEqual(normal_signature, scan_signature)
        self.assertTrue(all("Window SHAP" in str(row["method"]) for row in normal_event.top_features or []))


if __name__ == "__main__":
    unittest.main()
