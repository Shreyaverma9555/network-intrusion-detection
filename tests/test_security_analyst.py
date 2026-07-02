from __future__ import annotations

import unittest

from src.nid.attack_generators import brute_force, dns_tunnel
from src.nid.processor import ProcessingPolicy, RealTimeProcessor
from src.nid.security_analyst import analyst_context, local_security_analyst_report


class SecurityAnalystTests(unittest.TestCase):
    def test_local_security_analyst_report_contains_soc_sections(self) -> None:
        processor = RealTimeProcessor(policy=ProcessingPolicy(save_events=False, save_external=False))
        result = processor.process_event(processor.detector.detect_frame(dns_tunnel(), xai_mode="adaptive"))
        report = local_security_analyst_report(result.event)

        self.assertIn("AI Security Analyst Assessment", report)
        self.assertIn("Executive Summary", report)
        self.assertIn("Likely Attacker Objective", report)
        self.assertIn("MITRE ATT&CK Context", report)
        self.assertIn("Recommended Response", report)
        self.assertIn("T1048", report)

    def test_analyst_context_exposes_event_risk_inputs(self) -> None:
        processor = RealTimeProcessor(policy=ProcessingPolicy(save_events=False, save_external=False))
        result = processor.process_event(processor.detector.detect_frame(brute_force(), xai_mode="adaptive"))
        context = analyst_context(result.event)

        self.assertEqual(context["category"], "Brute Force")
        self.assertIn("T1110", context["mitre_techniques"])
        self.assertGreaterEqual(context["decision_support"], 0.75)


if __name__ == "__main__":
    unittest.main()
