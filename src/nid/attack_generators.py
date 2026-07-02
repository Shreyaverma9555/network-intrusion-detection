from __future__ import annotations

import pandas as pd


def benign_web() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "frame.time_epoch": 1000 + index * 0.08,
                "ip.src": "192.168.31.178" if index % 2 == 0 else "142.250.182.14",
                "ip.dst": "142.250.182.14" if index % 2 == 0 else "192.168.31.178",
                "ip.proto": 6,
                "tcp.srcport": 53000 + (index % 5) if index % 2 == 0 else 443,
                "tcp.dstport": 443 if index % 2 == 0 else 53000 + (index % 5),
                "frame.len": 520 + (index % 8) * 30,
                "tcp.flags": "0x018",
                "frame.protocol": "IPv4",
            }
            for index in range(32)
        ]
    )


def port_scan() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "frame.time_epoch": 1000 + index * 0.01,
                "ip.src": "203.0.113.66",
                "ip.dst": "192.168.31.178",
                "ip.proto": 6,
                "tcp.srcport": 40000 + index,
                "tcp.dstport": index + 1,
                "frame.len": 60,
                "tcp.flags": "0x002",
                "frame.protocol": "IPv4",
            }
            for index in range(40)
        ]
    )


def syn_flood() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "frame.time_epoch": 1000 + index * 0.002,
                "ip.src": f"198.51.100.{20 + (index % 8)}",
                "ip.dst": "192.168.31.178",
                "ip.proto": 6,
                "tcp.srcport": 45000 + index,
                "tcp.dstport": 80,
                "frame.len": 54,
                "tcp.flags": "0x002",
                "frame.protocol": "IPv4",
            }
            for index in range(80)
        ]
    )


def brute_force() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "frame.time_epoch": 1000 + index * 0.04,
                "ip.src": "203.0.113.66",
                "ip.dst": "192.168.31.178",
                "ip.proto": 6,
                "tcp.srcport": 51000 + index,
                "tcp.dstport": 22,
                "frame.len": 95,
                "tcp.flags": "0x018",
                "frame.protocol": "IPv4",
            }
            for index in range(45)
        ]
    )


def udp_flood() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "frame.time_epoch": 1000 + index * 0.003,
                "ip.src": f"198.51.100.{30 + (index % 6)}",
                "ip.dst": "192.168.31.178",
                "ip.proto": 17,
                "udp.srcport": 54000 + index,
                "udp.dstport": 1900,
                "frame.len": 96,
                "frame.protocol": "IPv4",
            }
            for index in range(90)
        ]
    )


def icmp_flood() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "frame.time_epoch": 1000 + index * 0.004,
                "ip.src": f"198.51.100.{40 + (index % 4)}",
                "ip.dst": "192.168.31.178",
                "ip.proto": 1,
                "frame.len": 84,
                "frame.protocol": "ICMP",
                "icmp.type": 8,
                "icmp.code": 0,
            }
            for index in range(70)
        ]
    )


def arp_spoofing() -> pd.DataFrame:
    rows = []
    macs = ["00:11:22:33:44:55", "66:77:88:99:aa:bb"]
    for index in range(24):
        rows.append(
            {
                "frame.time_epoch": 1000 + index * 0.02,
                "ip.src": "192.168.31.1",
                "ip.dst": "192.168.31.178",
                "ip.proto": 2054,
                "frame.len": 60,
                "frame.protocol": "ARP",
                "eth.src": macs[index % 2],
                "eth.dst": "ff:ff:ff:ff:ff:ff",
                "arp.op": 2,
                "arp.hwsrc": macs[index % 2],
                "arp.hwdst": "ff:ff:ff:ff:ff:ff",
            }
        )
    return pd.DataFrame(rows)


def dns_tunnel() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "frame.time_epoch": 1000 + index * 0.01,
                "ip.src": "203.0.113.66",
                "ip.dst": "8.8.8.8",
                "ip.proto": 17,
                "udp.srcport": 53000 + index,
                "udp.dstport": 53,
                "frame.len": 150,
                "dns.qry.name": f"{'x' * 60}{index}.exfil.example",
                "dns.query_length": 78,
                "dns.qdcount": 1,
                "frame.protocol": "DNS",
            }
            for index in range(35)
        ]
    )


ATTACKS = {
    "port-scan": port_scan,
    "syn-flood": syn_flood,
    "udp-flood": udp_flood,
    "icmp-flood": icmp_flood,
    "brute-force": brute_force,
    "arp-spoofing": arp_spoofing,
    "dns-tunnel": dns_tunnel,
}

SCENARIOS = {"benign-web": benign_web, **ATTACKS}
