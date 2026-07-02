from __future__ import annotations

import json
import os
import platform
import re
import subprocess
from pathlib import Path

import pandas as pd
from rich.console import Console
from rich.table import Table

from src.nid.postgres import PostgresRepository
from src.nid.realtime import RealTimeDetector
from src.nid.traffic_scope import window_scope


def normal_https_window() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "frame.time_epoch": 1000 + index * 0.05,
                "ip.src": "8.8.8.8" if index % 2 == 0 else "192.168.1.10",
                "ip.dst": "192.168.1.10" if index % 2 == 0 else "8.8.8.8",
                "ip.proto": 6,
                "tcp.srcport": 443 if index % 2 == 0 else 52000,
                "tcp.dstport": 52000 if index % 2 == 0 else 443,
                "frame.len": 300,
                "tcp.flags": "0x018",
            }
            for index in range(30)
        ]
    )


def port_scan_window() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "frame.time_epoch": 1000 + index * 0.01,
                "ip.src": "203.0.113.10",
                "ip.dst": "192.168.1.10",
                "ip.proto": 6,
                "tcp.srcport": 40000 + index,
                "tcp.dstport": index + 1,
                "frame.len": 60,
                "tcp.flags": "0x002",
            }
            for index in range(30)
        ]
    )


def postgres_server_running() -> bool:
    if platform.system() != "Windows":
        return bool(os.getenv("NID_POSTGRES_DSN"))
    result = subprocess.run(
        ["sc.exe", "query", "state=", "all"],
        capture_output=True,
        text=True,
        check=False,
    )
    services = re.findall(r"SERVICE_NAME:\s+(postgresql[^\s]+)", result.stdout, flags=re.IGNORECASE)
    return any(
        "RUNNING"
        in subprocess.run(
            ["sc.exe", "query", service],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        for service in services
    )


def main() -> None:
    detector = RealTimeDetector("models/sample_ensemble.joblib")
    normal_event = detector.detect_frame(normal_https_window())
    scan_event = detector.detect_frame(port_scan_window())

    confidence_valid = all(
        abs(event.confidence + float((event.statistics or {}).get("decision_uncertainty", 1)) - 1) < 1e-4
        for event in (normal_event, scan_event)
    )
    normal_signature = [
        (row["raw_feature"], round(float(row["importance"]), 4), row["direction"])
        for row in normal_event.top_features or []
    ]
    scan_signature = [
        (row["raw_feature"], round(float(row["importance"]), 4), row["direction"])
        for row in scan_event.top_features or []
    ]
    shap_dynamic = normal_signature != scan_signature

    dashboard_ready = False
    dashboard_details = "Streamlit dashboard test failed"
    try:
        from streamlit.testing.v1 import AppTest

        app = AppTest.from_file("dashboard.py", default_timeout=60).run()
        dashboard_ready = len(app.exception) == 0
        dashboard_details = f"{len(app.tabs)} tabs, {len(app.exception)} exceptions"
    except Exception as error:
        dashboard_details = str(error)

    self_frame = pd.DataFrame(
        {"ip.src": ["192.168.1.10", "192.168.1.10"], "ip.dst": ["192.168.1.10", "192.168.1.20"]}
    )
    _, self_rates = window_scope(self_frame)
    self_traffic_ready = self_rates.get("same_endpoint_packet_count") == 1

    dsn_configured = bool(os.getenv("NID_POSTGRES_DSN"))
    server_running = postgres_server_running()
    postgres_ready = False
    postgres_details = f"Server running={server_running}; run: python soc.py setup-postgres"
    if dsn_configured:
        try:
            health = PostgresRepository().health()
            postgres_ready = bool(health["ready"])
            postgres_details = (
                f"Connected to {health['database']} as {health['user']}; "
                f"{health['event_count']} stored events"
            )
        except Exception as error:
            postgres_details = str(error)
    checks = [
        {
            "check": "Confidence metric",
            "ready": confidence_valid,
            "details": (
                f"Normal support={normal_event.confidence:.1%}; "
                f"scan support={scan_event.confidence:.1%}; uncertainty sums verified"
            ),
        },
        {
            "check": "Dynamic SHAP",
            "ready": shap_dynamic,
            "details": "Normal and port-scan Window SHAP signatures differ",
        },
        {
            "check": "PostgreSQL",
            "ready": postgres_ready,
            "details": postgres_details,
        },
        {"check": "Streamlit dashboard", "ready": dashboard_ready, "details": dashboard_details},
        {
            "check": "Same-source/destination investigation",
            "ready": self_traffic_ready,
            "details": (
                f"Self-addressed packets counted; test rate={float(self_rates.get('same_endpoint_traffic_rate', 0)):.1%}"
            ),
        },
    ]

    report_path = Path("reports/project_verification.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(checks, indent=2), encoding="utf-8")

    table = Table(title="NID Project Verification")
    table.add_column("Concern")
    table.add_column("Status")
    table.add_column("Evidence")
    for check in checks:
        table.add_row(
            str(check["check"]),
            "[green]VERIFIED[/green]" if check["ready"] else "[yellow]ACTION NEEDED[/yellow]",
            str(check["details"]),
        )
    Console().print(table)
    print(f"Report written to {report_path.resolve()}")


if __name__ == "__main__":
    main()
