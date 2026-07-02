from __future__ import annotations

import os

import requests

from .realtime import DetectionEvent


def local_explanation(event: DetectionEvent) -> str:
    heading = "Threat Detected" if event.category != "Normal" else "No Threat Detected"
    reasons = "\n".join(f"- {reason}" for reason in event.reasons or ["No explanation available"])
    recommendation = (
        "Recommended action:\n1. Validate the alert\n2. Isolate the affected host if confirmed\n"
        "3. Review authentication and endpoint logs\n4. Block the source only after analyst approval"
        if event.predicted_attack
        else "Recommended action:\nContinue monitoring and collect a larger packet sample."
    )
    return (
        f"{heading}\n\nCategory: {event.category}\nSeverity: {event.severity}\n"
        f"Source IP: {event.source_display}\nTraffic scope: {event.traffic_scope}\n"
        f"Threat intelligence score: {event.threat_score:.0f}%\n\n"
        f"Reason:\n{reasons}\n\nDecision support: {event.confidence:.0%}\n"
        f"Uncertainty: {float((event.statistics or {}).get('decision_uncertainty', 1 - event.confidence)):.0%}\n\n"
        f"{recommendation}"
    )


def explain_event(event: DetectionEvent, use_llm: bool = True) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not use_llm or not api_key:
        return local_explanation(event)

    prompt = (
        "Explain this network intrusion detection result for a SOC analyst in under 120 words. "
        "Do not invent evidence. Include category, reasons, decision support, impact, and one defensive action.\n"
        f"Category: {event.category}\nSeverity: {event.severity}\nDecision support: {event.confidence:.3f}\n"
        f"Reasons: {event.reasons}\nStatistics: {event.statistics}"
    )
    try:
        response = requests.post(
            "https://api.openai.com/v1/responses",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": os.getenv("NID_LLM_MODEL", "gpt-4.1-mini"), "input": prompt},
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("output_text"):
            return str(payload["output_text"])
        parts = [
            item.get("text", "")
            for output in payload.get("output", [])
            for item in output.get("content", [])
            if item.get("type") == "output_text"
        ]
        return "\n".join(parts) or local_explanation(event)
    except requests.RequestException:
        return local_explanation(event)
