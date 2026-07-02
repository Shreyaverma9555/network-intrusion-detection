from __future__ import annotations

from datetime import datetime
import json
import os
from typing import Any

import requests

from .realtime import DetectionEvent


def analyst_context(event: DetectionEvent) -> dict[str, Any]:
    stats = event.statistics or {}
    if isinstance(stats, str):
        try:
            stats = json.loads(stats)
        except json.JSONDecodeError:
            stats = {}
    mitre = stats.get("mitre_attack") if isinstance(stats, dict) else []
    return {
        "category": event.category,
        "severity": event.severity,
        "source_ip": event.source_display,
        "destination_ip": event.destination_display,
        "traffic_scope": event.traffic_scope,
        "decision_support": event.confidence,
        "model_threat_score": event.model_threat_score,
        "threat_score": event.threat_score,
        "threat_labels": event.threat_labels or [],
        "reasons": event.reasons or [],
        "mitre": mitre if isinstance(mitre, list) else [],
        "mitre_tactics": stats.get("mitre_tactics", "None") if isinstance(stats, dict) else "None",
        "mitre_techniques": stats.get("mitre_techniques", "None") if isinstance(stats, dict) else "None",
        "rule_signature": stats.get("rule_engine_top_rule", "None") if isinstance(stats, dict) else "None",
        "rule_score": stats.get("rule_engine_top_score", 0) if isinstance(stats, dict) else 0,
        "port": stats.get("top_destination_port", 0) if isinstance(stats, dict) else 0,
        "port_service": stats.get("port_service", "Unknown") if isinstance(stats, dict) else "Unknown",
        "port_risk": stats.get("port_risk", "Unknown") if isinstance(stats, dict) else "Unknown",
        "protocol_summary": stats.get("protocol_summary", "Unknown") if isinstance(stats, dict) else "Unknown",
        "packets": stats.get("packet_count", event.rows) if isinstance(stats, dict) else event.rows,
        "packets_per_second": stats.get("packets_per_second", 0) if isinstance(stats, dict) else 0,
    }


def local_security_analyst_report(event: DetectionEvent) -> str:
    context = analyst_context(event)
    attack = event.predicted_attack and event.category != "Normal"
    objective = _likely_objective(str(context["category"]))
    risk = _risk_rating(event)
    evidence = "\n".join(f"- {reason}" for reason in context["reasons"][:8]) or "- No specific evidence available"
    mitre_lines = "\n".join(
        f"- {item.get('technique_id')} {item.get('technique')} ({item.get('tactic')})"
        for item in context["mitre"]
        if isinstance(item, dict)
    ) or "- No MITRE ATT&CK technique mapped"
    false_positive_checks = _false_positive_checks(str(context["category"]))
    response = _recommended_response(str(context["category"]), attack)

    return (
        "# AI Security Analyst Assessment\n\n"
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "## Executive Summary\n"
        f"{_summary_sentence(context, attack)}\n\n"
        "## Risk Assessment\n"
        f"- Risk rating: {risk}\n"
        f"- Severity: {context['severity']}\n"
        f"- Decision support: {float(context['decision_support']):.1%}\n"
        f"- Model threat score: {float(context['model_threat_score']):.1%}\n"
        f"- Threat intelligence score: {float(context['threat_score']):.0f}%\n"
        f"- Traffic scope: {context['traffic_scope']}\n\n"
        "## Likely Attacker Objective\n"
        f"{objective}\n\n"
        "## MITRE ATT&CK Context\n"
        f"- Tactics: {context['mitre_tactics']}\n"
        f"- Techniques: {context['mitre_techniques']}\n"
        f"{mitre_lines}\n\n"
        "## Key Evidence\n"
        f"{evidence}\n\n"
        "## Triage Checklist\n"
        f"{_triage_checklist(context)}\n\n"
        "## Recommended Response\n"
        f"{response}\n\n"
        "## False Positive Checks\n"
        f"{false_positive_checks}\n\n"
        "## Analyst Notes\n"
        "- Treat this as decision support, not an automatic verdict.\n"
        "- Preserve packet, dashboard, PostgreSQL, firewall, DNS, and endpoint logs before remediation.\n"
    )


def security_analyst_report(event: DetectionEvent, use_llm: bool = True) -> str:
    base_report = local_security_analyst_report(event)
    api_key = os.getenv("OPENAI_API_KEY")
    if not use_llm or not api_key:
        return base_report
    try:
        response = requests.post(
            "https://api.openai.com/v1/responses",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": os.getenv("NID_LLM_MODEL", "gpt-4.1-mini"),
                "input": (
                    "You are an AI security analyst. Rewrite this IDS assessment as a concise SOC analyst "
                    "brief. Do not invent facts. Preserve MITRE IDs, evidence, and recommended actions.\n\n"
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


def _summary_sentence(context: dict[str, Any], attack: bool) -> str:
    if not attack:
        return (
            f"The current window is classified as {context['category']} with no confirmed attack behavior. "
            "Continue monitoring and collect more evidence if unusual traffic persists."
        )
    return (
        f"{context['severity']} {context['category']} activity was observed from {context['source_ip']} "
        f"toward {context['destination_ip']}. The strongest mapped behavior is {context['mitre_techniques']}."
    )


def _risk_rating(event: DetectionEvent) -> str:
    if not event.predicted_attack:
        return "Low"
    if event.severity == "Critical" or event.threat_score >= 90:
        return "Critical"
    if event.severity == "High" or event.confidence >= 0.75 or event.threat_score >= 75:
        return "High"
    return "Medium"


def _likely_objective(category: str) -> str:
    objectives = {
        "Port Scan": "The source may be performing reconnaissance to discover exposed services before exploitation.",
        "Probe": "The source may be probing network services to identify reachable hosts and attack surface.",
        "SYN Flood": "The source may be attempting to exhaust connection-handling resources and disrupt availability.",
        "UDP Flood": "The source may be attempting to overwhelm a service or host with high-rate UDP traffic.",
        "ICMP Flood": "The source may be attempting to degrade availability with high-rate ICMP traffic.",
        "Brute Force": "The source may be attempting credential guessing against an administrative or login service.",
        "R2L": "The source may be attempting remote access to a local account or service.",
        "U2R": "The activity may indicate an attempt to escalate privileges after initial user-level access.",
        "DNS Tunneling": "The source may be using DNS to hide command-and-control or exfiltration traffic.",
        "ARP Spoofing": "The traffic may indicate an adversary-in-the-middle attempt using ARP cache poisoning.",
        "Botnet": "The traffic may indicate command-and-control or coordinated botnet behavior.",
        "Malware": "The activity may indicate malware communication, payload transfer, or command-and-control.",
    }
    return objectives.get(category, "No clear attacker objective is inferred from the current evidence.")


def _triage_checklist(context: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"1. Confirm whether {context['source_ip']} is expected to contact {context['destination_ip']}.",
            f"2. Review destination service/port {context['port']} ({context['port_service']}, risk={context['port_risk']}).",
            "3. Compare this alert with firewall, DNS, authentication, and endpoint telemetry.",
            "4. Check for repeated alerts from the same source over the last 24 hours.",
            "5. Validate whether the MITRE technique matches observed host or network logs.",
        ]
    )


def _recommended_response(category: str, attack: bool) -> str:
    if not attack:
        return "1. Continue monitoring\n2. Increase capture window if traffic remains unusual\n3. Do not block without stronger evidence"
    category_actions = {
        "Port Scan": "1. Rate-limit or block confirmed hostile source\n2. Review exposed services\n3. Harden unnecessary open ports",
        "SYN Flood": "1. Enable SYN flood protection or rate limiting\n2. Check service health\n3. Escalate to network/provider mitigation if sustained",
        "UDP Flood": "1. Rate-limit UDP traffic to the targeted service\n2. Validate whether the UDP service is required\n3. Escalate if volume persists",
        "ICMP Flood": "1. Rate-limit ICMP where appropriate\n2. Check host availability\n3. Preserve packet evidence",
        "Brute Force": "1. Lock or monitor targeted accounts\n2. Enforce MFA and password reset if confirmed\n3. Block source after validation",
        "DNS Tunneling": "1. Inspect DNS query logs\n2. Block suspicious domains/resolvers\n3. Isolate host if exfiltration is suspected",
        "ARP Spoofing": "1. Validate gateway MAC mappings\n2. Enable dynamic ARP inspection if available\n3. Isolate the suspicious local host",
    }
    return category_actions.get(
        category,
        "1. Validate the alert\n2. Isolate affected host if confirmed\n3. Block malicious source after analyst approval\n4. Preserve evidence",
    )


def _false_positive_checks(category: str) -> str:
    checks = {
        "Port Scan": "- Vulnerability scanners, inventory tools, or security assessments can look like scans.",
        "SYN Flood": "- Load tests, broken clients, or connection storms can resemble SYN floods.",
        "UDP Flood": "- Streaming, discovery protocols, or misconfigured clients can create high UDP rates.",
        "ICMP Flood": "- Monitoring systems or diagnostics can produce ICMP bursts.",
        "Brute Force": "- Password managers, stale service credentials, or scheduled jobs can cause repeated login attempts.",
        "DNS Tunneling": "- CDN, telemetry, or security products can generate long unique DNS names.",
        "ARP Spoofing": "- Gateway failover, virtualization, or NIC teaming can change IP-to-MAC mappings.",
    }
    return checks.get(category, "- Confirm the traffic is not expected maintenance, monitoring, or lab activity.")
