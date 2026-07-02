from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from typing import Any

import pandas as pd


@dataclass(frozen=True)
class RuleMatch:
    signature_id: str
    name: str
    category: str
    score: float
    severity: str
    description: str
    evidence: dict[str, float | int | str]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["score"] = round(float(self.score), 4)
        return payload


def evaluate_rules(raw: pd.DataFrame, features: pd.DataFrame) -> list[RuleMatch]:
    if raw.empty or features.empty:
        return []

    context = _context(raw, features)
    candidates = [
        _port_scan(context),
        _syn_flood(context),
        _udp_flood(context),
        _icmp_flood(context),
        _brute_force(context),
        _arp_spoofing(context),
        _dns_tunneling(context),
    ]
    matches = [match for match in candidates if match is not None]
    return sorted(matches, key=lambda match: match.score, reverse=True)


def _context(raw: pd.DataFrame, features: pd.DataFrame) -> dict[str, Any]:
    rows = len(raw)
    timestamps = pd.to_numeric(raw.get("frame.time_epoch", pd.Series(0, index=raw.index)), errors="coerce").fillna(0)
    duration = max(float(timestamps.max()) - float(timestamps.min()), 0.001)
    protocols = raw.get("frame.protocol", pd.Series("", index=raw.index)).fillna("").astype(str).str.upper()
    ip_protocols = pd.to_numeric(features.get("protocol", pd.Series(0, index=features.index)), errors="coerce").fillna(0)
    dst_ports = pd.to_numeric(features.get("dst_port", pd.Series(0, index=features.index)), errors="coerce").fillna(0)
    src_ports = pd.to_numeric(features.get("src_port", pd.Series(0, index=features.index)), errors="coerce").fillna(0)
    flags = pd.to_numeric(features.get("tcp_flags", pd.Series(0, index=features.index)), errors="coerce").fillna(0)
    lengths = pd.to_numeric(features.get("packet_length", pd.Series(0, index=features.index)), errors="coerce").fillna(0)

    src_ip = raw.get("ip.src", pd.Series("", index=raw.index)).fillna("").astype(str)
    dst_ip = raw.get("ip.dst", pd.Series("", index=raw.index)).fillna("").astype(str)
    eth_src = raw.get("eth.src", pd.Series("", index=raw.index)).fillna("").astype(str)
    arp_hwsrc = raw.get("arp.hwsrc", eth_src).fillna("").astype(str) if "arp.hwsrc" in raw else eth_src

    tcp_mask = ip_protocols.eq(6) | (
        dst_ports.gt(0) & raw.get("tcp.dstport", pd.Series("", index=raw.index)).fillna("").astype(str).str.len().gt(0)
    )
    udp_mask = ip_protocols.eq(17) | raw.get("udp.dstport", pd.Series("", index=raw.index)).fillna("").astype(str).str.len().gt(0)
    icmp_mask = ip_protocols.isin([1, 58]) | protocols.str.contains("ICMP", regex=False)
    arp_mask = protocols.eq("ARP") | pd.to_numeric(raw.get("arp.op", pd.Series(0, index=raw.index)), errors="coerce").fillna(0).gt(0)
    dns_names = raw.get("dns.qry.name", pd.Series("", index=raw.index)).fillna("").astype(str)
    dns_query_lengths = pd.to_numeric(raw.get("dns.query_length", pd.Series(0, index=raw.index)), errors="coerce").fillna(0)

    return {
        "rows": rows,
        "duration": duration,
        "packets_per_second": rows / duration,
        "protocols": protocols,
        "dst_ports": dst_ports,
        "src_ports": src_ports,
        "flags": flags,
        "lengths": lengths,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "eth_src": eth_src,
        "arp_hwsrc": arp_hwsrc,
        "arp_op": pd.to_numeric(raw.get("arp.op", pd.Series(0, index=raw.index)), errors="coerce").fillna(0),
        "tcp_mask": tcp_mask,
        "udp_mask": udp_mask,
        "icmp_mask": icmp_mask,
        "arp_mask": arp_mask,
        "dns_names": dns_names,
        "dns_query_lengths": dns_query_lengths,
    }


def _port_scan(context: dict[str, Any]) -> RuleMatch | None:
    mask = context["tcp_mask"]
    tcp_count = int(mask.sum())
    if tcp_count == 0:
        return None
    dst_ports = context["dst_ports"][mask]
    unique_ports = int(dst_ports[dst_ports.gt(0)].nunique())
    unique_port_rate = unique_ports / max(tcp_count, 1)
    repeated_source_rate = _top_rate(context["src_ip"][mask])
    syn_rate = float(context["flags"][mask].isin([2, 18]).mean())
    score = min(0.99, 0.45 * unique_port_rate + 0.25 * min(unique_ports / 30, 1) + 0.20 * repeated_source_rate + 0.10 * syn_rate)
    if tcp_count < 20 or unique_ports < 15 or unique_port_rate < 0.40 or repeated_source_rate < 0.45:
        return None
    return _match(
        "SIG-PORT-SCAN",
        "Port Scan",
        "Port Scan",
        score,
        "Many destination ports are touched from the same source in one short window.",
        {
            "tcp_packets": tcp_count,
            "unique_destination_ports": unique_ports,
            "unique_port_rate": unique_port_rate,
            "top_source_rate": repeated_source_rate,
            "syn_rate": syn_rate,
        },
    )


def _syn_flood(context: dict[str, Any]) -> RuleMatch | None:
    mask = context["tcp_mask"]
    tcp_count = int(mask.sum())
    if tcp_count == 0:
        return None
    syn_rate = float(context["flags"][mask].isin([2, 18]).mean())
    tiny_rate = float(context["lengths"][mask].between(1, 90).mean())
    top_destination_rate = _top_rate(context["dst_ip"][mask])
    destination_ports = context["dst_ports"][mask]
    unique_port_rate = float(destination_ports[destination_ports.gt(0)].nunique() / max(tcp_count, 1))
    pps_score = min(float(context["packets_per_second"]) / 100, 1)
    score = min(0.99, 0.55 * syn_rate + 0.20 * pps_score + 0.15 * tiny_rate + 0.10 * top_destination_rate)
    if tcp_count < 30 or syn_rate < 0.65 or unique_port_rate > 0.35 or (context["packets_per_second"] < 30 and tiny_rate < 0.60):
        return None
    return _match(
        "SIG-SYN-FLOOD",
        "SYN Flood",
        "SYN Flood",
        score,
        "High-volume TCP SYN traffic suggests half-open connection flooding.",
        {
            "tcp_packets": tcp_count,
            "syn_rate": syn_rate,
            "tiny_packet_rate": tiny_rate,
            "unique_port_rate": unique_port_rate,
            "packets_per_second": context["packets_per_second"],
            "top_destination_rate": top_destination_rate,
        },
    )


def _udp_flood(context: dict[str, Any]) -> RuleMatch | None:
    mask = context["udp_mask"]
    udp_count = int(mask.sum())
    if udp_count == 0:
        return None
    udp_rate = udp_count / max(context["rows"], 1)
    dns_rate = float(context["dst_ports"][mask].eq(53).mean())
    top_destination_rate = _top_rate(context["dst_ip"][mask])
    top_port_rate = _top_rate(context["dst_ports"][mask].astype(str))
    pps_score = min(float(context["packets_per_second"]) / 120, 1)
    score = min(0.99, 0.40 * udp_rate + 0.25 * pps_score + 0.20 * top_destination_rate + 0.15 * top_port_rate)
    if udp_count < 50 or udp_rate < 0.70 or dns_rate > 0.50 or (context["packets_per_second"] < 40 and top_destination_rate < 0.60):
        return None
    return _match(
        "SIG-UDP-FLOOD",
        "UDP Flood",
        "UDP Flood",
        score,
        "High-rate UDP packets target the same host or service.",
        {
            "udp_packets": udp_count,
            "udp_rate": udp_rate,
            "dns_rate": dns_rate,
            "packets_per_second": context["packets_per_second"],
            "top_destination_rate": top_destination_rate,
            "top_port_rate": top_port_rate,
        },
    )


def _icmp_flood(context: dict[str, Any]) -> RuleMatch | None:
    mask = context["icmp_mask"]
    icmp_count = int(mask.sum())
    if icmp_count == 0:
        return None
    icmp_rate = icmp_count / max(context["rows"], 1)
    top_destination_rate = _top_rate(context["dst_ip"][mask])
    pps_score = min(float(context["packets_per_second"]) / 100, 1)
    score = min(0.99, 0.50 * icmp_rate + 0.25 * pps_score + 0.25 * top_destination_rate)
    if icmp_count < 30 or icmp_rate < 0.65 or (context["packets_per_second"] < 25 and top_destination_rate < 0.60):
        return None
    return _match(
        "SIG-ICMP-FLOOD",
        "ICMP Flood",
        "ICMP Flood",
        score,
        "High-rate ICMP echo or control traffic targets a host.",
        {
            "icmp_packets": icmp_count,
            "icmp_rate": icmp_rate,
            "packets_per_second": context["packets_per_second"],
            "top_destination_rate": top_destination_rate,
        },
    )


def _brute_force(context: dict[str, Any]) -> RuleMatch | None:
    login_ports = {21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5900}
    mask = context["tcp_mask"] & context["dst_ports"].isin(login_ports)
    attempts = int(mask.sum())
    if attempts == 0:
        return None
    login_rate = attempts / max(context["rows"], 1)
    repeated_source_rate = _top_rate(context["src_ip"][mask])
    unique_source_ports = int(context["src_ports"][mask][context["src_ports"][mask].gt(0)].nunique())
    score = min(0.99, 0.55 * login_rate + 0.25 * repeated_source_rate + 0.20 * min(unique_source_ports / 50, 1))
    if attempts < 20 or login_rate < 0.55 or repeated_source_rate < 0.45 or unique_source_ports < 10:
        return None
    return _match(
        "SIG-BRUTE-FORCE",
        "Brute Force",
        "Brute Force",
        score,
        "Repeated attempts against login or administrative services.",
        {
            "login_attempts": attempts,
            "login_port_rate": login_rate,
            "top_source_rate": repeated_source_rate,
            "unique_source_ports": unique_source_ports,
        },
    )


def _arp_spoofing(context: dict[str, Any]) -> RuleMatch | None:
    mask = context["arp_mask"]
    arp_count = int(mask.sum())
    if arp_count == 0:
        return None
    arp_rate = arp_count / max(context["rows"], 1)
    source_ips = context["src_ip"][mask]
    source_macs = context["arp_hwsrc"][mask].where(context["arp_hwsrc"][mask].str.len().gt(0), context["eth_src"][mask])
    mappings = pd.DataFrame({"ip": source_ips, "mac": source_macs}).replace("", pd.NA).dropna()
    conflicting_ips = 0
    if not mappings.empty:
        conflicting_ips = int(mappings.drop_duplicates().groupby("ip")["mac"].nunique().gt(1).sum())
    reply_rate = float(context["arp_op"][mask].eq(2).mean())
    score = min(0.99, 0.55 * min(conflicting_ips, 3) / 3 + 0.25 * arp_rate + 0.20 * reply_rate)
    if conflicting_ips == 0 and not (arp_count >= 20 and arp_rate >= 0.60 and reply_rate >= 0.50):
        return None
    return _match(
        "SIG-ARP-SPOOF",
        "ARP Spoofing",
        "ARP Spoofing",
        max(score, 0.86 if conflicting_ips else score),
        "ARP traffic shows one IP address being claimed by multiple MAC addresses.",
        {
            "arp_packets": arp_count,
            "arp_rate": arp_rate,
            "conflicting_ip_mappings": conflicting_ips,
            "arp_reply_rate": reply_rate,
        },
    )


def _dns_tunneling(context: dict[str, Any]) -> RuleMatch | None:
    names = context["dns_names"]
    name_mask = names.str.len().gt(0) | context["dst_ports"].eq(53)
    dns_count = int(name_mask.sum())
    if dns_count == 0:
        return None
    long_name_rate = float((context["dns_query_lengths"].gt(50) | names.str.len().gt(50))[name_mask].mean())
    unique_name_rate = names[name_mask & names.str.len().gt(0)].nunique() / max(int((name_mask & names.str.len().gt(0)).sum()), 1)
    entropy_score = min(_average_entropy(names[name_mask]) / 4.5, 1)
    dns_rate = dns_count / max(context["rows"], 1)
    score = min(0.99, 0.45 * long_name_rate + 0.25 * unique_name_rate + 0.20 * dns_rate + 0.10 * entropy_score)
    if dns_count < 20 or long_name_rate < 0.45 or unique_name_rate < 0.50:
        return None
    return _match(
        "SIG-DNS-TUNNEL",
        "DNS Tunneling",
        "DNS Tunneling",
        score,
        "Long, unique DNS queries resemble encoded data exfiltration.",
        {
            "dns_queries": dns_count,
            "long_query_rate": long_name_rate,
            "unique_query_rate": unique_name_rate,
            "dns_rate": dns_rate,
            "average_entropy_score": entropy_score,
        },
    )


def _match(
    signature_id: str,
    name: str,
    category: str,
    score: float,
    description: str,
    evidence: dict[str, float | int | str],
) -> RuleMatch:
    severity = "Critical" if score >= 0.90 else "High" if score >= 0.75 else "Medium"
    rounded = {
        key: round(float(value), 4) if isinstance(value, float) else value
        for key, value in evidence.items()
    }
    return RuleMatch(signature_id, name, category, min(float(score), 0.99), severity, description, rounded)


def _top_rate(values: pd.Series) -> float:
    cleaned = values.dropna().astype(str)
    cleaned = cleaned[cleaned.str.len().gt(0)]
    if cleaned.empty:
        return 0.0
    return float(cleaned.value_counts().iloc[0] / len(cleaned))


def _average_entropy(values: pd.Series) -> float:
    cleaned = values.dropna().astype(str)
    cleaned = cleaned[cleaned.str.len().gt(0)]
    if cleaned.empty:
        return 0.0
    return float(cleaned.map(_entropy).mean())


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = pd.Series(list(value)).value_counts(normalize=True)
    return float(-(counts * counts.map(math.log2)).sum())
