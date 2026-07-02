from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from src.nid.attack_validation import run_attack_validation


class AttackValidationTests(unittest.TestCase):
    def test_synthetic_attack_validation_passes_without_postgres(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = run_attack_validation(Path(directory) / "attack_validation.json", save_events=False)

        self.assertTrue(report["ready"], report["results"])
        self.assertEqual(report["total"], 8)
        scenarios = {result["scenario"]: result for result in report["results"]}
        self.assertEqual(scenarios["benign-web"]["category"], "Normal")
        self.assertEqual(scenarios["port-scan"]["category"], "Port Scan")
        self.assertEqual(scenarios["syn-flood"]["category"], "SYN Flood")
        self.assertEqual(scenarios["udp-flood"]["category"], "UDP Flood")
        self.assertEqual(scenarios["icmp-flood"]["category"], "ICMP Flood")
        self.assertEqual(scenarios["brute-force"]["category"], "Brute Force")
        self.assertEqual(scenarios["arp-spoofing"]["category"], "ARP Spoofing")
        self.assertEqual(scenarios["dns-tunnel"]["category"], "DNS Tunneling")
        self.assertIn("T1046", scenarios["port-scan"]["mitre_technique_ids"])
        self.assertIn("T1498", scenarios["udp-flood"]["mitre_technique_ids"])
        self.assertIn("T1557.002", scenarios["arp-spoofing"]["mitre_technique_ids"])
        self.assertIn("T1048", scenarios["dns-tunnel"]["mitre_technique_ids"])


if __name__ == "__main__":
    unittest.main()
