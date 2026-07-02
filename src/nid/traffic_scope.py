from __future__ import annotations

import ipaddress

import pandas as pd


TRAFFIC_SCOPES = (
    "Host-Local",
    "Local LAN",
    "Outbound",
    "Inbound",
    "External",
    "Multicast/Broadcast",
    "Unknown",
)


def classify_flow(source_ip: str, destination_ip: str) -> str:
    source = _address(source_ip)
    destination = _address(destination_ip)
    if source is None or destination is None:
        return "Unknown"
    if destination.is_multicast or str(destination) == "255.255.255.255":
        return "Multicast/Broadcast"
    if source == destination or source.is_loopback or destination.is_loopback:
        return "Host-Local"
    source_local = _is_local(source)
    destination_local = _is_local(destination)
    if source_local and destination_local:
        return "Local LAN"
    if source_local and not destination_local:
        return "Outbound"
    if not source_local and destination_local:
        return "Inbound"
    return "External"


def window_scope(
    frame: pd.DataFrame, source_ip: str = "", destination_ip: str = ""
) -> tuple[str, dict[str, float | int | str]]:
    if "ip.src" not in frame or "ip.dst" not in frame:
        return classify_flow(source_ip, destination_ip), {}
    source_values = frame["ip.src"].fillna("").astype(str)
    destination_values = frame["ip.dst"].fillna("").astype(str)
    scopes = [
        classify_flow(str(source), str(destination))
        for source, destination in zip(source_values, destination_values)
    ]
    valid_endpoint_pairs = source_values.str.len().gt(0) & destination_values.str.len().gt(0)
    same_endpoint_count = int(
        (valid_endpoint_pairs & source_values.eq(destination_values)).sum()
    )
    same_endpoint_addresses = ", ".join(
        source_values[valid_endpoint_pairs & source_values.eq(destination_values)]
        .value_counts()
        .head(5)
        .index
        .tolist()
    )
    valid_endpoint_count = int(valid_endpoint_pairs.sum())
    valid = [scope for scope in scopes if scope != "Unknown"]
    if not valid:
        return classify_flow(source_ip, destination_ip), {
            "unknown_traffic_rate": 1.0,
            "same_endpoint_packet_count": same_endpoint_count,
            "same_endpoint_traffic_rate": 0.0,
            "same_endpoint_addresses": same_endpoint_addresses,
        }
    counts = pd.Series(valid).value_counts()
    rates = {
        f"{scope.lower().replace('-', '_').replace('/', '_').replace(' ', '_')}_traffic_rate": round(
            float(count) / len(valid), 4
        )
        for scope, count in counts.items()
    }
    rates["same_endpoint_packet_count"] = same_endpoint_count
    rates["same_endpoint_traffic_rate"] = round(
        same_endpoint_count / max(valid_endpoint_count, 1), 4
    )
    rates["same_endpoint_addresses"] = same_endpoint_addresses
    dominant = str(counts.index[0])
    return dominant, rates


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_local(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address.is_private or address.is_loopback or address.is_link_local
