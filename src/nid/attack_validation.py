from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any

from .attack_generators import SCENARIOS
from .processor import ProcessingPolicy, RealTimeProcessor
from .utils import write_json


SEVERITY_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


@dataclass(frozen=True)
class ValidationCase:
    name: str
    expected_categories: set[str]
    expected_attack: bool
    min_decision_support: float
    min_severity: str
    min_threat_score: float = 0.0


VALIDATION_CASES = (
    ValidationCase("benign-web", {"Normal"}, False, 0.20, "Low"),
    ValidationCase("port-scan", {"Port Scan", "Probe"}, True, 0.75, "High", 75.0),
    ValidationCase("syn-flood", {"SYN Flood", "DoS", "DDoS"}, True, 0.75, "High", 75.0),
    ValidationCase("udp-flood", {"UDP Flood", "DoS", "DDoS"}, True, 0.75, "High", 75.0),
    ValidationCase("icmp-flood", {"ICMP Flood", "DoS", "DDoS"}, True, 0.75, "High", 75.0),
    ValidationCase("brute-force", {"Brute Force", "R2L"}, True, 0.75, "High", 75.0),
    ValidationCase("arp-spoofing", {"ARP Spoofing"}, True, 0.75, "High"),
    ValidationCase("dns-tunnel", {"DNS Tunneling"}, True, 0.75, "High", 75.0),
)


def run_attack_validation(
    report_path: str | Path = "reports/attack_validation.json",
    save_events: bool | None = None,
) -> dict[str, Any]:
    """Replay known traffic windows and validate detector behavior end to end."""
    should_save = bool(os.getenv("NID_POSTGRES_DSN")) if save_events is None else save_events
    processor = RealTimeProcessor(policy=ProcessingPolicy(save_events=should_save, save_external=False))

    results = [_run_case(processor, case, should_save) for case in VALIDATION_CASES]
    passed = sum(1 for result in results if result["passed"])
    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "ready": passed == len(results),
        "postgres_requested": should_save,
        "postgres_configured": bool(os.getenv("NID_POSTGRES_DSN")),
        "results": results,
    }
    write_json(report_path, report)
    return report


def _run_case(processor: RealTimeProcessor, case: ValidationCase, postgres_requested: bool) -> dict[str, Any]:
    frame = SCENARIOS[case.name]()
    event = processor.detector.detect_frame(frame, xai_mode="adaptive")
    result = processor.process_event(event)
    details: list[str] = []

    if event.category not in case.expected_categories:
        details.append(
            f"category {event.category!r} not in expected {', '.join(sorted(case.expected_categories))}"
        )
    if bool(event.predicted_attack) != case.expected_attack:
        details.append(f"predicted_attack={event.predicted_attack} expected {case.expected_attack}")
    if event.confidence < case.min_decision_support:
        details.append(
            f"decision support {event.confidence:.1%} below required {case.min_decision_support:.1%}"
        )
    if SEVERITY_RANK.get(event.severity, 0) < SEVERITY_RANK.get(case.min_severity, 0):
        details.append(f"severity {event.severity} below required {case.min_severity}")
    if event.threat_score < case.min_threat_score:
        details.append(f"threat score {event.threat_score:.0f}% below required {case.min_threat_score:.0f}%")

    postgres_logged = any(action.startswith("PostgreSQL event #") for action in result.actions)
    postgres_errors = [error for error in result.errors if error.startswith("PostgreSQL logging:")]
    if postgres_requested and not postgres_logged:
        details.append("PostgreSQL event was not stored")
    if postgres_errors:
        details.extend(postgres_errors)

    failed_errors = [error for error in result.errors if not error.startswith("PostgreSQL logging:")]
    details.extend(failed_errors)

    statistics = event.statistics or {}
    return {
        "scenario": case.name,
        "expected_categories": sorted(case.expected_categories),
        "expected_attack": case.expected_attack,
        "category": event.category,
        "predicted_attack": bool(event.predicted_attack),
        "severity": event.severity,
        "decision_support": round(float(event.confidence), 4),
        "model_threat_score": round(float(event.attack_probability), 4),
        "behavior_score": round(float(statistics.get("behavior_score", 0.0)), 4),
        "threat_score": round(float(event.threat_score), 2),
        "source_country": event.source_country,
        "source_latitude": statistics.get("source_latitude"),
        "source_longitude": statistics.get("source_longitude"),
        "mitre_tactics": statistics.get("mitre_tactics", "None"),
        "mitre_technique_ids": statistics.get("mitre_technique_ids", "None"),
        "mitre_attack": statistics.get("mitre_attack", []),
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "packet_count": event.rows,
        "postgres_logged": postgres_logged,
        "actions": result.actions,
        "errors": result.errors,
        "top_reasons": event.reasons or [],
        "passed": not details,
        "status": "PASS" if not details else "FAIL",
        "details": details or ["Validated"],
    }
