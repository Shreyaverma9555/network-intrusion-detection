from __future__ import annotations

import csv
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from .paths import project_path


DEFAULT_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
    "tcp.flags",
    "frame.protocol",
    "eth.src",
    "eth.dst",
    "arp.op",
    "arp.hwsrc",
    "arp.hwdst",
    "icmp.type",
    "icmp.code",
    "dns.qry.name",
    "dns.query_length",
    "dns.qdcount",
    "dhcp.message_type",
]

TSHARK_FIELD_MAP = {
    "frame.protocol": "frame.protocols",
    "arp.op": "arp.opcode",
    "arp.hwsrc": "arp.src.hw_mac",
    "arp.hwdst": "arp.dst.hw_mac",
    "dns.query_length": "dns.qry.name.len",
    "dns.qdcount": "dns.count.queries",
    "dhcp.message_type": "bootp.option.dhcp",
}


def find_tshark() -> Path:
    located = shutil.which("tshark")
    candidates = [
        Path(located) if located else None,
        Path(r"C:\Program Files\Wireshark\tshark.exe"),
        Path(r"C:\Program Files (x86)\Wireshark\tshark.exe"),
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "TShark was not found. Install Wireshark with TShark enabled or add "
        "the Wireshark installation folder to PATH."
    )


def build_tshark_command(
    output: str | Path,
    fields: Iterable[str] = DEFAULT_FIELDS,
    interface: str | None = None,
    seconds: int | None = None,
    pcap: str | Path | None = None,
) -> list[str]:
    if not interface and not pcap:
        raise ValueError("Either interface or pcap must be provided.")

    command = [str(find_tshark())]

    if pcap:
        pcap_path = project_path(pcap)
        if not pcap_path.is_file():
            raise FileNotFoundError(f"Capture file not found: {pcap_path}")
        command.extend(["-r", str(pcap_path)])
    else:
        command.extend(["-i", str(interface)])
        if seconds:
            command.extend(["-a", f"duration:{seconds}"])

    command.extend(["-T", "fields", "-E", "header=y", "-E", "separator=,", "-E", "quote=d"])
    for field in fields:
        command.extend(["-e", TSHARK_FIELD_MAP.get(field, field)])

    return command


def capture_to_csv(
    output: str | Path,
    fields: Iterable[str] = DEFAULT_FIELDS,
    interface: str | None = None,
    seconds: int | None = None,
    pcap: str | Path | None = None,
) -> Path:
    target = project_path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    command = build_tshark_command(
        output=target,
        fields=fields,
        interface=interface,
        seconds=seconds,
        pcap=pcap,
    )

    try:
        with target.open("w", newline="", encoding="utf-8") as file:
            subprocess.run(command, stdout=file, stderr=subprocess.PIPE, text=True, check=True)
    except subprocess.CalledProcessError as error:
        target.unlink(missing_ok=True)
        details = error.stderr.strip() or "Unknown TShark error"
        raise RuntimeError(f"TShark capture failed: {details}") from error

    normalize_csv_header(target, fields)
    return target


def normalize_csv_header(path: str | Path, fields: Iterable[str]) -> None:
    """Ensure empty captures still contain a parseable header."""
    target = Path(path)
    if target.stat().st_size > 0:
        rows = list(csv.reader(target.open(newline="", encoding="utf-8")))
        if rows:
            rows[0] = list(fields)
            with target.open("w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerows(rows)
        return

    with target.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(list(fields))
