from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from typing import Any

import requests

from .paths import project_path
from .realtime import DetectionEvent
from .utils import read_json


@dataclass
class ThreatIntel:
    ip: str
    score: float = 0.0
    labels: list[str] | None = None
    country: str = "Unknown"
    latitude: float | None = None
    longitude: float | None = None
    status: str = "Not checked"
    provider: str = "Local"
    asn: str = ""
    isp: str = ""
    organization: str = ""
    port: int = 0
    port_service: str = ""
    port_risk: str = ""


def lookup_ip(ip: str, use_external: bool = True, port: int = 0) -> ThreatIntel:
    if not ip:
        return _with_port(ThreatIntel(ip="", labels=["No source IP available"], status="No source IP"), port)
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return _with_port(ThreatIntel(ip=ip, labels=["Invalid IP address"], status="Invalid IP"), port)
    local = _local_reputation(ip)
    if local:
        geo = _local_geoip(ip, str(local.get("country", "Unknown")))
        return _with_port(ThreatIntel(
            ip=ip,
            score=float(local.get("score", 0)),
            labels=list(local.get("labels", [])),
            country=str(geo.get("country", local.get("country", "Unknown"))),
            latitude=_optional_float(geo.get("latitude")),
            longitude=_optional_float(geo.get("longitude")),
            status="Local blacklist match",
            provider=str(local.get("provider", "Local blacklist")),
        ), port)
    if address.is_private or address.is_loopback:
        return _with_port(ThreatIntel(
            ip=ip,
            labels=["Private/internal address", "External reputation skipped for private IP"],
            country="Private Network",
            status="Private IP",
        ), port)

    geo = _local_geoip(ip)
    result = ThreatIntel(
        ip=ip,
        labels=["No local blacklist match"],
        country=str(geo.get("country", "Unknown")),
        latitude=_optional_float(geo.get("latitude")),
        longitude=_optional_float(geo.get("longitude")),
        status="Local blacklist only",
        provider=str(geo.get("provider", "Local")) if geo else "Local",
    )
    if geo:
        result.labels = (result.labels or []) + ["Local GeoIP location applied"]
    if use_external and os.getenv("ABUSEIPDB_API_KEY"):
        _abuse_ipdb(result)
    elif use_external:
        result.labels = (result.labels or []) + ["AbuseIPDB API key not configured"]
        result.status = "External reputation disabled"
    else:
        result.labels = (result.labels or []) + ["External reputation disabled for this window"]
        result.status = "External reputation disabled"
    if use_external and os.getenv("VIRUSTOTAL_API_KEY"):
        _virustotal(result)
    elif use_external:
        result.labels = (result.labels or []) + ["VirusTotal API key not configured"]
    if use_external and os.getenv("NID_ENABLE_GEOIP", "0") == "1":
        _geolocate(result)
    elif use_external:
        result.labels = (result.labels or []) + ["GeoIP disabled"]
    if use_external and os.getenv("NID_ENABLE_RDAP", "0") == "1":
        _rdap(result)
    elif use_external:
        result.labels = (result.labels or []) + ["RDAP/WHOIS disabled"]
    return _with_port(result, port)


def enrich_event(event: DetectionEvent, use_external: bool = True) -> ThreatIntel:
    stats = event.statistics or {}
    port = int(float(stats.get("top_destination_port", 0) or 0))
    intel = lookup_ip(event.source_ip, use_external=use_external, port=port)
    event.threat_score = intel.score
    event.threat_labels = intel.labels or []
    event.source_country = intel.country
    stats["threat_intel_status"] = intel.status
    stats["threat_intel_labels"] = "; ".join(intel.labels or [])
    stats["threat_intel_provider"] = intel.provider
    stats["threat_intel_asn"] = intel.asn
    stats["threat_intel_isp"] = intel.isp
    stats["threat_intel_organization"] = intel.organization
    stats["port_service"] = intel.port_service
    stats["port_risk"] = intel.port_risk
    event.statistics = stats
    if intel.latitude is not None and intel.longitude is not None:
        stats = event.statistics or {}
        stats.update({"source_latitude": intel.latitude, "source_longitude": intel.longitude})
        event.statistics = stats
    if intel.score >= 75:
        event.predicted_attack = True
        event.confidence = max(event.confidence, intel.score / 100)
        event.reasons = (event.reasons or []) + [f"Source IP reputation score is {intel.score:.0f}%"]
        stats["decision_confidence"] = round(event.confidence, 4)
        stats["decision_uncertainty"] = round(1 - event.confidence, 4)
        event.statistics = stats
    return intel


def _local_reputation(ip: str) -> dict[str, object]:
    exact_path = project_path("configs/ip_blacklist.json")
    if exact_path.is_file():
        exact = read_json(exact_path).get(ip, {})
        if exact:
            return exact
    feed_path = project_path("configs/threat_feeds.json")
    if not feed_path.is_file():
        return {}
    feeds = read_json(feed_path)
    for entry in feeds.get("ip_reputation", []):
        if ip == entry.get("ip"):
            return entry
        cidr = entry.get("cidr")
        if cidr:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(str(cidr), strict=False):
                    return entry
            except ValueError:
                continue
    return {}


def _local_geoip(ip: str, country_hint: str = "") -> dict[str, object]:
    path = project_path("configs/geoip_locations.json")
    if not path.is_file():
        return {}
    try:
        data = read_json(path)
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    for entry in data.get("ip_locations", []):
        if ip == entry.get("ip"):
            return entry
        cidr = entry.get("cidr")
        if cidr:
            try:
                if address in ipaddress.ip_network(str(cidr), strict=False):
                    return entry
            except ValueError:
                continue
    if country_hint:
        centroid = data.get("country_centroids", {}).get(country_hint)
        if centroid:
            return {"country": country_hint, **centroid, "provider": "Local country centroid"}
    return {}


def _optional_float(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _port_intelligence(port: int) -> dict[str, str]:
    if not port:
        return {}
    path = project_path("configs/port_intel.json")
    if not path.is_file():
        return {}
    data = read_json(path)
    return data.get(str(port), {})


def _with_port(result: ThreatIntel, port: int) -> ThreatIntel:
    result.port = int(port or 0)
    intel = _port_intelligence(result.port)
    if intel:
        result.port_service = str(intel.get("service", ""))
        result.port_risk = str(intel.get("risk", ""))
        label = f"Destination port {result.port}: {result.port_service} ({result.port_risk})"
        result.labels = list(dict.fromkeys((result.labels or []) + [label]))
        if result.port_risk.lower() in {"high", "critical"}:
            result.score = max(result.score, float(intel.get("score", 35)))
    return result


def _abuse_ipdb(result: ThreatIntel) -> None:
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        return
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": result.ip, "maxAgeInDays": 90},
            timeout=8,
        )
        response.raise_for_status()
        data = response.json()["data"]
        result.score = max(result.score, float(data.get("abuseConfidenceScore", 0)))
        result.status = "AbuseIPDB checked"
        result.provider = "AbuseIPDB"
        if data.get("usageType"):
            result.labels = (result.labels or []) + [str(data["usageType"])]
        if data.get("countryCode"):
            result.country = str(data["countryCode"])
    except (requests.RequestException, KeyError, TypeError, ValueError):
        return


def _virustotal(result: ThreatIntel) -> None:
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        return
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{result.ip}",
            headers={"x-apikey": key, "Accept": "application/json"},
            timeout=8,
        )
        response.raise_for_status()
        attributes = response.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        total = sum(int(value or 0) for value in stats.values())
        score = (malicious / total * 100) if total else 0
        result.score = max(result.score, score)
        result.status = "VirusTotal checked"
        result.provider = (
            "AbuseIPDB + VirusTotal" if result.provider == "AbuseIPDB" else "VirusTotal"
        )
        result.labels = (result.labels or []) + [
            f"VirusTotal: {malicious}/{total} engines flagged this IP"
        ]
        if attributes.get("country"):
            result.country = str(attributes["country"])
        if attributes.get("as_owner"):
            result.organization = str(attributes["as_owner"])
    except (requests.RequestException, KeyError, TypeError, ValueError):
        result.labels = (result.labels or []) + ["VirusTotal lookup failed"]


def _geolocate(result: ThreatIntel) -> None:
    if os.getenv("NID_ENABLE_GEOIP", "0") != "1":
        return
    try:
        response = requests.get(
            f"http://ip-api.com/json/{result.ip}",
            params={"fields": "status,country,lat,lon"},
            timeout=5,
        )
        data = response.json()
        if data.get("status") == "success":
            result.country = str(data.get("country", result.country))
            result.latitude = float(data["lat"])
            result.longitude = float(data["lon"])
    except (requests.RequestException, KeyError, TypeError, ValueError):
        return


def _rdap(result: ThreatIntel) -> None:
    try:
        response = requests.get(f"https://rdap.org/ip/{result.ip}", timeout=8)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        result.asn = str(data.get("handle", ""))
        result.organization = str(data.get("name", ""))
        entities = data.get("entities") or []
        if entities and isinstance(entities[0], dict):
            result.isp = str(entities[0].get("handle", ""))
        result.labels = (result.labels or []) + ["RDAP ownership checked"]
        result.provider = result.provider if result.provider != "Local" else "RDAP"
    except (requests.RequestException, KeyError, TypeError, ValueError):
        result.labels = (result.labels or []) + ["RDAP lookup failed"]
