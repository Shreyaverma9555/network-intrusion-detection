from __future__ import annotations

import importlib.util
import os
import platform
import re
import subprocess

from rich.console import Console
from rich.table import Table

from src.nid.postgres import PostgresRepository
from src.nid.scapy_capture import list_interfaces


def configured(*names: str) -> bool:
    return all(bool(os.getenv(name)) for name in names)


def postgres_windows_service() -> str:
    if platform.system() != "Windows":
        return ""
    try:
        result = subprocess.run(
            ["sc.exe", "query", "state=", "all"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return ""
    services = re.findall(r"SERVICE_NAME:\s+(postgresql[^\s]+)", result.stdout, flags=re.IGNORECASE)
    for service in services:
        status = subprocess.run(
            ["sc.exe", "query", service],
            capture_output=True,
            text=True,
            check=False,
        )
        if "RUNNING" in status.stdout:
            return service
    return ""


def main() -> None:
    checks: list[tuple[str, bool, str]] = []
    for name, module in [
        ("Scapy packet capture", "scapy"),
        ("Streamlit dashboard", "streamlit"),
        ("SHAP explanations", "shap"),
        ("PostgreSQL driver", "psycopg"),
    ]:
        installed = importlib.util.find_spec(module) is not None
        checks.append((name, installed, "Installed" if installed else f"Install {module}"))

    try:
        interface_count = len(list_interfaces())
        checks.append(("Capture interfaces", interface_count > 0, f"{interface_count} interfaces available"))
    except Exception as error:
        checks.append(("Capture interfaces", False, str(error)))

    postgres_service = postgres_windows_service()
    postgres_server_running = bool(postgres_service)
    checks.append(
        (
            "PostgreSQL server",
            postgres_server_running or configured("NID_POSTGRES_DSN"),
            f"Running ({postgres_service})" if postgres_server_running else "Server status not detected",
        )
    )
    if configured("NID_POSTGRES_DSN"):
        try:
            health = PostgresRepository().health()
            checks.append(
                (
                    "PostgreSQL primary database",
                    bool(health["ready"]),
                    f"Connected to {health['database']} as {health['user']}; {health['event_count']} stored events",
                )
            )
        except Exception as error:
            checks.append(("PostgreSQL primary database", False, str(error)))
    else:
        checks.append(("PostgreSQL primary database", False, "Run: python soc.py setup-postgres"))
    checks.append(
        (
            "Email alerts",
            configured("NID_EMAIL_TO", "NID_SMTP_HOST"),
            "Configured" if configured("NID_EMAIL_TO", "NID_SMTP_HOST") else "Set email and SMTP values in .env",
        )
    )

    table = Table(title="Network Intrusion Detection Setup")
    table.add_column("Feature")
    table.add_column("Status")
    table.add_column("Details")
    for name, ready, details in checks:
        status = "[green]READY[/green]" if ready else "[yellow]SETUP NEEDED[/yellow]"
        table.add_row(name, status, details)
    Console().print(table)


if __name__ == "__main__":
    main()
