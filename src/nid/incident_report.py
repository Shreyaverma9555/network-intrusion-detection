from __future__ import annotations

from datetime import datetime
import json
import os

import requests

from .realtime import DetectionEvent


def local_incident_report(event: DetectionEvent) -> str:
    stats = event.statistics or {}
    if isinstance(stats, str):
        try:
            stats = json.loads(stats)
        except json.JSONDecodeError:
            stats = {}
    reasons = "\n".join(f"- {reason}" for reason in event.reasons or ["No observed reason available"])
    mitre_entries = stats.get("mitre_attack") or []
    mitre_lines = "\n".join(
        f"- {entry.get('technique_id')} {entry.get('technique')} ({entry.get('tactic')})"
        for entry in mitre_entries
        if isinstance(entry, dict)
    ) or "- No MITRE ATT&CK mapping available"
    top_features = "\n".join(
        f"- {row.get('feature')}: {float(row.get('importance', 0)):.1%}"
        for row in (event.top_features or [])[:5]
    ) or "- No feature attribution available"
    recommended = (
        "1. Block or rate-limit the source after analyst validation\n"
        "2. Review firewall, DNS, authentication, and endpoint logs\n"
        "3. Monitor the source/destination pair for recurrence\n"
        "4. Preserve packet and PostgreSQL event evidence"
        if event.predicted_attack
        else "1. Continue monitoring\n2. Increase the capture window if evidence is insufficient\n3. Review repeated Unknown or non-IP traffic"
    )
    return (
        "# AI Incident Report\n\n"
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"Category: {event.category}\n"
        f"Severity: {event.severity}\n"
        f"Source: {event.source_display}\n"
        f"Destination: {event.destination_display}\n"
        f"Traffic Scope: {event.traffic_scope}\n"
        f"Model Threat Score: {event.model_threat_score:.1%}\n"
        f"Decision Support: {event.confidence:.1%}\n"
        f"Threat Intel Score: {event.threat_score:.0f}%\n"
        f"Threat Intel Status: {stats.get('threat_intel_status', 'Not checked')}\n"
        f"Threat Intel Provider: {stats.get('threat_intel_provider', 'Local')}\n"
        f"Port Intelligence: {stats.get('top_destination_port', 0)} {stats.get('port_service', 'Unknown')} risk={stats.get('port_risk', 'Unknown')}\n"
        f"MITRE Tactics: {stats.get('mitre_tactics', 'None')}\n"
        f"MITRE Techniques: {stats.get('mitre_techniques', 'None')}\n"
        f"Rule Override: {'Yes' if stats.get('rule_override') else 'No'}\n\n"
        "## Evidence\n"
        f"{reasons}\n\n"
        "## MITRE ATT&CK Mapping\n"
        f"{mitre_lines}\n\n"
        "## Top Features\n"
        f"{top_features}\n\n"
        "## Recommended Action\n"
        f"{recommended}\n"
    )


def incident_report(event: DetectionEvent, use_llm: bool = True) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    base_report = local_incident_report(event)
    if not use_llm or not api_key:
        return base_report
    try:
        response = requests.post(
            "https://api.openai.com/v1/responses",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": os.getenv("NID_LLM_MODEL", "gpt-4.1-mini"),
                "input": (
                    "Rewrite this IDS event as a concise SOC incident report. "
                    "Do not invent facts. Keep recommended actions practical.\n\n"
                    + base_report
                ),
            },
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
        return str(payload.get("output_text") or base_report)
    except requests.RequestException:
        return base_report
