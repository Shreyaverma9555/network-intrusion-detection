from __future__ import annotations

from dataclasses import dataclass
import math

import pandas as pd

from .rules import evaluate_rules


ATTACK_CATEGORIES = (
    "Normal",
    "DoS",
    "Probe",
    "R2L",
    "U2R",
    "Botnet",
    "DDoS",
    "Port Scan",
    "Brute Force",
    "Malware",
    "SYN Flood",
    "UDP Flood",
    "ICMP Flood",
    "ARP Spoofing",
    "DNS Tunneling",
)


@dataclass
class Classification:
    category: str
    confidence: float
    severity: str
    reasons: list[str]
    statistics: dict[str, object]


def classify_window(
    raw: pd.DataFrame,
    features: pd.DataFrame,
    model_threat_score: float,
    attack_threshold: float = 0.75,
) -> Classification:
    rows = max(len(raw), 1)
    dst_ports = features["dst_port"]
    flags = features["tcp_flags"]
    syn_rate = float(flags.isin([2, 18]).mean())
    unique_port_rate = float(dst_ports[dst_ports.gt(0)].nunique() / rows)
    suspicious_login_rate = float(dst_ports.isin([21, 22, 23, 25, 110, 143, 445, 1433, 3389]).mean())
    tiny_packet_rate = float(features["packet_length"].between(1, 80).mean())
    max_source_packets = int(features["packets_per_src"].max())
    unique_destinations = int(raw.get("ip.dst", pd.Series(dtype=str)).nunique())
    unique_sources = int(raw.get("ip.src", pd.Series(dtype=str)).nunique())
    repeated_source_rate = max_source_packets / rows
    malware_port_rate = float(dst_ports.isin([135, 139, 445, 4444, 5555, 6667, 8080, 9001]).mean())
    brute_force_rate = float(dst_ports.isin([21, 22, 23, 3389]).mean())
    empty = pd.Series("", index=raw.index, dtype=str)
    dns_names = raw.get("dns.qry.name", empty).fillna("").astype(str)
    dns_query_lengths = pd.to_numeric(raw.get("dns.query_length", pd.Series(0, index=raw.index)), errors="coerce").fillna(0)
    dns_rate = float((dst_ports.eq(53) | dns_names.str.len().gt(0)).mean())
    long_dns_rate = float((dns_query_lengths.gt(50) | dns_names.str.len().gt(50)).mean())
    unique_dns_rate = float(dns_names[dns_names.str.len().gt(0)].nunique() / max(int((dns_names.str.len().gt(0)).sum()), 1))
    icmp_rate = float(features["protocol"].isin([1, 58]).mean())
    arp_rate = float(raw.get("frame.protocol", empty).fillna("").astype(str).str.upper().eq("ARP").mean())
    udp_rate = float(features["protocol"].eq(17).mean())
    source_addresses = raw.get("ip.src", empty).fillna("").astype(str)
    destination_addresses = raw.get("ip.dst", empty).fillna("").astype(str)
    tcp_destination_ports = raw.get("tcp.dstport", empty).fillna("").astype(str)
    udp_destination_ports = raw.get("udp.dstport", empty).fillna("").astype(str)
    destination_ports = tcp_destination_ports.where(tcp_destination_ports.str.len().gt(0), udp_destination_ports)
    top_destination_port = int(dst_ports[dst_ports.gt(0)].mode().iloc[0]) if not dst_ports[dst_ports.gt(0)].empty else 0
    active_connections = int(
        pd.DataFrame(
            {
                "source": source_addresses,
                "destination": destination_addresses,
                "port": destination_ports,
            }
        )
        .drop_duplicates()
        .shape[0]
    )

    scores = {
        "DoS": min(
            0.99,
            (0.70 * syn_rate + 0.30 * max(0.0, repeated_source_rate - 0.50) * 2)
            * (1 - 0.70 * unique_port_rate),
        ),
        "Probe": min(0.99, 0.75 * unique_port_rate + 0.25 * min(unique_destinations / 20, 1)),
        "R2L": min(
            0.99,
            0.80 * suspicious_login_rate * (1 - 0.50 * tiny_packet_rate) * (1 - 0.50 * repeated_source_rate)
            + 0.20 * (1 - tiny_packet_rate),
        ),
        # Packet metadata alone is weak evidence for privilege escalation, so
        # U2R requires an unusually strong combination of shell-port and tiny-packet activity.
        "U2R": min(0.99, float(dst_ports.isin([22, 23]).mean()) * tiny_packet_rate * 0.90),
        "DDoS": min(
            0.99,
            (0.55 * syn_rate + 0.45 * min(unique_sources / 20, 1))
            * (1 - 0.50 * unique_port_rate),
        ),
        "Port Scan": min(0.99, 0.85 * unique_port_rate + 0.15 * repeated_source_rate),
        "SYN Flood": min(0.99, 0.80 * syn_rate + 0.20 * max(0.0, repeated_source_rate - 0.40) * 2),
        "Brute Force": min(0.99, 0.75 * brute_force_rate + 0.25 * repeated_source_rate),
        "DNS Tunneling": min(0.99, 0.65 * long_dns_rate + 0.25 * dns_rate + 0.10 * unique_dns_rate),
        "Malware": min(0.99, 0.75 * malware_port_rate + 0.25 * tiny_packet_rate),
        "Botnet": min(
            0.99,
            0.50 * malware_port_rate + 0.30 * min(unique_destinations / 20, 1) + 0.20 * repeated_source_rate,
        ),
    }
    rule_matches = evaluate_rules(raw, features)
    if rule_matches:
        for match in rule_matches:
            scores[match.category] = max(scores.get(match.category, 0.0), match.score)
    category = max(scores, key=scores.get)
    category_score = scores[category]

    minimum_behavior = 0.72 if category == "U2R" else 0.55
    combined_detection_score = 0.70 * model_threat_score + 0.30 * category_score
    signature_categories = {"Port Scan", "SYN Flood", "UDP Flood", "ICMP Flood", "Brute Force", "ARP Spoofing", "DNS Tunneling"}
    rule_override = category_score >= 0.85 and category in signature_categories
    signature_override = any(match.category == category and match.score >= 0.75 for match in rule_matches)
    attack_decision = (model_threat_score >= attack_threshold and category_score >= minimum_behavior) or rule_override or signature_override
    if not attack_decision:
        category = "Normal"
        # A Normal decision is supported when either the model or behavior gate
        # strongly rejects an attack. This is decision support, not probability.
        confidence = max(1 - model_threat_score, 1 - category_score)
    else:
        # Both independent attack signals must agree; geometric mean penalizes
        # a weak model or behavior signal instead of hiding it with an average.
        confidence = math.sqrt(max(model_threat_score, category_score if rule_override else model_threat_score) * category_score)

    reasons: list[str] = []
    if syn_rate >= 0.25:
        reasons.append(f"High SYN packet rate ({syn_rate:.0%})")
    if unique_port_rate >= 0.20:
        reasons.append(f"Unusual destination-port diversity ({unique_port_rate:.0%})")
    if suspicious_login_rate >= 0.10:
        reasons.append("Traffic targets remote-login or administrative ports")
    if tiny_packet_rate >= 0.35:
        reasons.append(f"High small-packet rate ({tiny_packet_rate:.0%})")
    if max_source_packets >= 20:
        reasons.append(f"Repeated traffic from one source ({max_source_packets} packets)")
    if unique_sources >= 10:
        reasons.append(f"Traffic originates from many sources ({unique_sources})")
    if malware_port_rate >= 0.10:
        reasons.append("Traffic targets ports commonly abused by malware or command-and-control")
    if brute_force_rate >= 0.25 and repeated_source_rate >= 0.25:
        reasons.append("Repeated authentication-service connection attempts")
    if dns_rate >= 0.30 and long_dns_rate >= 0.20:
        reasons.append("Long or high-volume DNS queries resemble tunneling behavior")
    if icmp_rate >= 0.40:
        reasons.append(f"High ICMP traffic rate ({icmp_rate:.0%})")
    if arp_rate >= 0.40:
        reasons.append(f"High ARP or non-routable local discovery traffic ({arp_rate:.0%})")
    for match in rule_matches[:3]:
        reasons.append(f"Rule signature {match.name} matched ({match.score:.0%}): {match.description}")
    if not reasons:
        reasons.append("No strong attack behavior detected")
    if category != "Normal":
        reasons.append(f"Behavior is most similar to a {category} attack")

    severity = "Critical" if confidence >= 0.90 else "High" if confidence >= 0.75 else "Medium"
    if category == "Normal":
        severity = "Low"
    statistics: dict[str, object] = {
        "packet_count": len(raw),
        "syn_rate": round(syn_rate, 4),
        "udp_rate": round(udp_rate, 4),
        "unique_port_rate": round(unique_port_rate, 4),
        "suspicious_login_rate": round(suspicious_login_rate, 4),
        "tiny_packet_rate": round(tiny_packet_rate, 4),
        "dns_rate": round(dns_rate, 4),
        "long_dns_rate": round(long_dns_rate, 4),
        "icmp_rate": round(icmp_rate, 4),
        "arp_rate": round(arp_rate, 4),
        "unique_destinations": unique_destinations,
        "unique_sources": unique_sources,
        "active_connections": active_connections,
        "top_destination_port": top_destination_port,
        "packets_per_second": round(
            len(raw)
            / max(
                float(pd.to_numeric(raw.get("frame.time_epoch", pd.Series([0])), errors="coerce").max())
                - float(pd.to_numeric(raw.get("frame.time_epoch", pd.Series([0])), errors="coerce").min()),
                1,
            ),
            2,
        ),
        "behavior_score": round(category_score, 4),
        "combined_detection_score": round(combined_detection_score, 4),
        "decision_confidence": round(confidence, 4),
        "decision_uncertainty": round(1 - confidence, 4),
        "attack_threshold": round(attack_threshold, 4),
        "minimum_behavior_score": round(minimum_behavior, 4),
        "rule_override": int(rule_override),
        "rule_engine_match_count": len(rule_matches),
        "rule_engine_top_rule": rule_matches[0].name if rule_matches else "None",
        "rule_engine_top_score": round(rule_matches[0].score, 4) if rule_matches else 0.0,
        "rule_engine_matches": ", ".join(match.name for match in rule_matches) if rule_matches else "None",
        "rule_engine_signature_ids": ", ".join(match.signature_id for match in rule_matches) if rule_matches else "None",
    }
    return Classification(category, min(confidence, 0.99), severity, reasons, statistics)
