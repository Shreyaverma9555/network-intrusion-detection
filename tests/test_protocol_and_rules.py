from __future__ import annotations

import unittest

import pandas as pd

from src.nid.classification import classify_window
from src.nid.features import FeatureBuilder
from src.nid.realtime import RealTimeDetector
from src.nid.threat_intel import lookup_ip


class ProtocolAndRuleTests(unittest.TestCase):
    def test_dns_tunneling_rule_can_override_weak_model_score(self) -> None:
        raw = pd.DataFrame(
            [
                {
                    "frame.time_epoch": 1000 + index * 0.01,
                    "ip.src": "203.0.113.10",
                    "ip.dst": "192.168.1.10",
                    "ip.proto": 17,
                    "udp.srcport": 53000 + index,
                    "udp.dstport": 53,
                    "frame.len": 140,
                    "dns.qry.name": f"{'a' * 55}{index}.exfil.example",
                    "dns.query_length": 70,
                }
                for index in range(30)
            ]
        )

        classification = classify_window(raw, FeatureBuilder().transform(raw), 0.60, attack_threshold=0.75)

        self.assertEqual(classification.category, "DNS Tunneling")
        self.assertEqual(classification.statistics["rule_override"], 1)

    def test_top_flow_uses_arp_addresses_instead_of_unknown(self) -> None:
        raw = pd.DataFrame(
            [
                {
                    "frame.time_epoch": 1000,
                    "ip.src": "192.168.1.10",
                    "ip.dst": "192.168.1.1",
                    "frame.protocol": "ARP",
                    "frame.len": 60,
                }
            ]
        )

        self.assertEqual(RealTimeDetector._top_flow(raw), ("192.168.1.10", "192.168.1.1"))

    def test_top_flow_falls_back_to_ethernet_for_non_ip_frames(self) -> None:
        raw = pd.DataFrame(
            [
                {
                    "frame.time_epoch": 1000,
                    "eth.src": "aa:bb:cc:dd:ee:ff",
                    "eth.dst": "ff:ff:ff:ff:ff:ff",
                    "frame.protocol": "LLMNR",
                    "frame.len": 90,
                }
            ]
        )

        self.assertEqual(RealTimeDetector._top_flow(raw), ("aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff"))

    def test_empty_window_is_not_reported_as_unknown_host_pair(self) -> None:
        event = RealTimeDetector("models/sample_ensemble.joblib").detect_frame(pd.DataFrame())

        self.assertIsNone(event.source_ip)
        self.assertIsNone(event.destination_ip)
        self.assertEqual(event.source_display, "No packets captured")
        self.assertEqual(event.destination_display, "No packets captured")
        self.assertEqual((event.statistics or {})["evidence_state"], "No packets captured")

    def test_threat_intel_explains_zero_score_when_api_key_missing(self) -> None:
        intel = lookup_ip("8.8.8.8", use_external=True)

        self.assertEqual(intel.score, 0)
        self.assertTrue(any("API key not configured" in label for label in intel.labels or []))


if __name__ == "__main__":
    unittest.main()
