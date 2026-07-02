from __future__ import annotations

from collections import deque
import threading
import time
from typing import Any

import pandas as pd

from .capture import DEFAULT_FIELDS


class PersistentPacketCapture:
    """Keep one Scapy sniffer alive so each window avoids Npcap startup cost."""

    def __init__(self, interface: str | None, debug_packets: bool = False) -> None:
        self.interface = interface
        self.debug_packets = debug_packets
        self._rows: deque[dict[str, Any]] = deque(maxlen=10000)
        self._lock = threading.Lock()
        self._started = threading.Event()
        self._sniffer: Any = None

    def start(self) -> None:
        if self._sniffer is not None:
            return
        try:
            from scapy.all import BOOTP, DHCP, DNS, DNSQR, Ether, ICMP, IP, TCP, UDP, AsyncSniffer
            from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6ND_NA, IPv6
            from scapy.layers.l2 import ARP
        except ImportError as error:
            raise FileNotFoundError(
                "Scapy is not installed. Run: py -3.11 -m pip install -r requirements.txt"
            ) from error

        def collect(packet: Any) -> None:
            if self.debug_packets:
                print(packet.summary())
            ip = packet.getlayer(IP)
            ipv6 = packet.getlayer(IPv6)
            arp = packet.getlayer(ARP)
            tcp = packet.getlayer(TCP)
            udp = packet.getlayer(UDP)
            ether = packet.getlayer(Ether)
            icmp = packet.getlayer(ICMP)
            ndp_ns = packet.getlayer(ICMPv6ND_NS)
            ndp_na = packet.getlayer(ICMPv6ND_NA)
            dns = packet.getlayer(DNS)
            dns_query = packet.getlayer(DNSQR)
            dhcp = packet.getlayer(DHCP)
            bootp = packet.getlayer(BOOTP)
            source_ip = getattr(ip, "src", "") or getattr(ipv6, "src", "") or getattr(arp, "psrc", "")
            destination_ip = getattr(ip, "dst", "") or getattr(ipv6, "dst", "") or getattr(arp, "pdst", "")
            protocol = getattr(ip, "proto", None)
            if protocol is None:
                protocol = getattr(ipv6, "nh", 2054 if arp else 0)
            dns_name = getattr(dns_query, "qname", b"")
            if isinstance(dns_name, bytes):
                dns_name = dns_name.decode("utf-8", errors="replace").rstrip(".")
            dhcp_message = ""
            if dhcp:
                for option in getattr(dhcp, "options", []):
                    if isinstance(option, tuple) and option[0] == "message-type":
                        dhcp_message = str(option[1])
                        break
            row = {
                "frame.time_epoch": float(packet.time),
                "ip.src": source_ip,
                "ip.dst": destination_ip,
                "ip.proto": protocol,
                "tcp.srcport": getattr(tcp, "sport", None),
                "tcp.dstport": getattr(tcp, "dport", None),
                "udp.srcport": getattr(udp, "sport", None),
                "udp.dstport": getattr(udp, "dport", None),
                "frame.len": len(packet),
                "tcp.flags": int(tcp.flags) if tcp else 0,
                "frame.protocol": (
                    "ARP"
                    if arp
                    else "NDP"
                    if ndp_ns or ndp_na
                    else "DHCP"
                    if dhcp or bootp
                    else "DNS"
                    if dns
                    else "IPv6"
                    if ipv6
                    else "IPv4"
                    if ip
                    else packet.__class__.__name__
                ),
                "eth.src": getattr(ether, "src", ""),
                "eth.dst": getattr(ether, "dst", ""),
                "arp.op": getattr(arp, "op", None),
                "arp.hwsrc": getattr(arp, "hwsrc", ""),
                "arp.hwdst": getattr(arp, "hwdst", ""),
                "icmp.type": getattr(icmp, "type", None),
                "icmp.code": getattr(icmp, "code", None),
                "dns.qry.name": dns_name,
                "dns.query_length": len(str(dns_name)),
                "dns.qdcount": getattr(dns, "qdcount", 0) if dns else 0,
                "dhcp.message_type": dhcp_message or ("bootp" if bootp else ""),
            }
            with self._lock:
                self._rows.append(row)

        self._sniffer = AsyncSniffer(
            iface=self.interface or None,
            store=False,
            prn=collect,
            started_callback=self._started.set,
        )
        try:
            self._sniffer.start()
        except PermissionError as error:
            self._sniffer = None
            raise RuntimeError("Packet capture requires an Administrator terminal or Npcap permissions.") from error
        except OSError as error:
            self._sniffer = None
            raise RuntimeError(f"Scapy packet capture failed: {error}") from error
        if not self._started.wait(timeout=5):
            self.stop()
            raise RuntimeError("Scapy packet capture did not start within five seconds.")

    def capture_window(self, seconds: float, packet_limit: int = 0) -> pd.DataFrame:
        self.start()
        with self._lock:
            self._rows.clear()
        time.sleep(seconds)
        with self._lock:
            rows = list(self._rows)
            self._rows.clear()
        if packet_limit > 0:
            rows = rows[-packet_limit:]
        return pd.DataFrame(rows, columns=DEFAULT_FIELDS)

    def stop(self) -> None:
        if self._sniffer is None:
            return
        try:
            if self._sniffer.running:
                self._sniffer.stop()
        finally:
            self._sniffer = None
            self._started.clear()


_capture_lock = threading.Lock()
_persistent_capture: PersistentPacketCapture | None = None


def list_interfaces() -> list[str]:
    try:
        from scapy.all import get_if_list
    except ImportError as error:
        raise FileNotFoundError(
            "Scapy is not installed. Run: py -3.11 -m pip install -r requirements.txt"
        ) from error
    return list(get_if_list())


def capture_packets(
    interface: str | None = None,
    seconds: float = 1.0,
    packet_limit: int = 0,
    debug_packets: bool = False,
) -> pd.DataFrame:
    global _persistent_capture
    if seconds < 0.1:
        raise ValueError("Capture duration must be at least 0.1 seconds.")
    with _capture_lock:
        if (
            _persistent_capture is None
            or _persistent_capture.interface != interface
            or _persistent_capture.debug_packets != debug_packets
        ):
            if _persistent_capture is not None:
                _persistent_capture.stop()
            _persistent_capture = PersistentPacketCapture(interface, debug_packets)
        capture = _persistent_capture
    return capture.capture_window(seconds, packet_limit)
