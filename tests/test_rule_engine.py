from __future__ import annotations

import unittest

from src.nid.attack_generators import ATTACKS, benign_web
from src.nid.features import FeatureBuilder
from src.nid.rules import evaluate_rules


class RuleEngineTests(unittest.TestCase):
    def test_benign_web_does_not_match_attack_signatures(self) -> None:
        frame = benign_web()
        matches = evaluate_rules(frame, FeatureBuilder().transform(frame))

        self.assertEqual(matches, [])

    def test_attack_signatures_match_expected_categories(self) -> None:
        expected = {
            "port-scan": "Port Scan",
            "syn-flood": "SYN Flood",
            "udp-flood": "UDP Flood",
            "icmp-flood": "ICMP Flood",
            "brute-force": "Brute Force",
            "arp-spoofing": "ARP Spoofing",
            "dns-tunnel": "DNS Tunneling",
        }
        for scenario, category in expected.items():
            with self.subTest(scenario=scenario):
                frame = ATTACKS[scenario]()
                matches = evaluate_rules(frame, FeatureBuilder().transform(frame))

                self.assertTrue(matches, scenario)
                self.assertEqual(matches[0].category, category)
                self.assertGreaterEqual(matches[0].score, 0.75)


if __name__ == "__main__":
    unittest.main()
