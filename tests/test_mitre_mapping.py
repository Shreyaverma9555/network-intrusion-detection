from __future__ import annotations

import unittest

from src.nid.attack_generators import dns_tunnel, port_scan
from src.nid.incident_report import local_incident_report
from src.nid.mitre import map_attack, mitre_summary
from src.nid.processor import ProcessingPolicy, RealTimeProcessor


class MitreMappingTests(unittest.TestCase):
    def test_category_and_signature_mapping_dedupes_techniques(self) -> None:
        mappings = map_attack("DNS Tunneling", "SIG-DNS-TUNNEL")
        summary = mitre_summary(mappings)

        ids = {entry["technique_id"] for entry in mappings}
        self.assertIn("T1048", ids)
        self.assertIn("T1071.004", ids)
        self.assertIn("Exfiltration", summary["mitre_tactics"])

    def test_processor_enriches_event_with_mitre_mapping(self) -> None:
        processor = RealTimeProcessor(policy=ProcessingPolicy(save_events=False, save_external=False))
        event = processor.detector.detect_frame(port_scan(), xai_mode="adaptive")
        result = processor.process_event(event)

        stats = result.event.statistics or {}
        self.assertIn("T1046", stats["mitre_technique_ids"])
        self.assertIn("Discovery", stats["mitre_tactics"])

    def test_incident_report_includes_mitre_section(self) -> None:
        processor = RealTimeProcessor(policy=ProcessingPolicy(save_events=False, save_external=False))
        result = processor.process_event(processor.detector.detect_frame(dns_tunnel(), xai_mode="adaptive"))
        report = local_incident_report(result.event)

        self.assertIn("MITRE ATT&CK Mapping", report)
        self.assertIn("T1048", report)


if __name__ == "__main__":
    unittest.main()
