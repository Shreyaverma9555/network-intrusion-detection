from __future__ import annotations

import ipaddress
import os
import platform
import subprocess


def build_block_command(ip: str) -> list[str]:
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        raise ValueError("Refusing to block a non-public address.")
    if os.name == "nt":
        return [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name=NID Block {address}",
            "dir=in",
            "action=block",
            f"remoteip={address}",
        ]
    if platform.system() == "Linux":
        return ["iptables", "-I", "INPUT", "-s", str(address), "-j", "DROP"]
    raise RuntimeError("Automatic blocking supports Windows Firewall and Linux iptables.")


def block_ip(ip: str, execute: bool = False) -> str:
    command = build_block_command(ip)
    if not execute:
        return "DRY RUN: " + " ".join(command)
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(error.stderr.strip() or "The operating-system firewall rejected the block rule.") from error
    return result.stdout.strip() or f"Blocked {ip}"
