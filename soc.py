from __future__ import annotations

import argparse
import subprocess
import sys

from check_setup import main as check_setup
from src.nid.alerts import send_test_email
from src.nid.postgres import PostgresRepository


def run_script(script: str, arguments: list[str]) -> int:
    return subprocess.call([sys.executable, script, *arguments])


def main() -> None:
    parser = argparse.ArgumentParser(description="Operate the complete Network Intrusion Detection SOC.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="Check Scapy, Streamlit, SHAP, PostgreSQL, and email readiness.")
    commands.add_parser("verify", help="Verify confidence, SHAP, PostgreSQL, dashboard, and self-traffic handling.")
    validate = commands.add_parser("validate-attacks", help="Replay known attack windows and validate detection behavior.")
    validate.add_argument("--no-postgres", action="store_true", help="Skip PostgreSQL writes during validation.")

    live = commands.add_parser("live", help="Start fast real-time Scapy detection.")
    live.add_argument("--interface", help="Scapy interface; omit to use the default interface.")
    live.add_argument("--window-seconds", type=float, default=0.5)
    live.add_argument("--notify", action="store_true")
    live.add_argument("--auto-response", action="store_true")
    live.add_argument("--full-shap", action="store_true")
    live.add_argument("--once", action="store_true")

    api = commands.add_parser("api", help="Launch the FastAPI backend.")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8000)
    api.add_argument("--reload", action="store_true")

    commands.add_parser("dashboard", help="Launch the Streamlit dashboard.")
    commands.add_parser("setup-postgres", help="Create the PostgreSQL database/user and configure .env.")
    commands.add_parser("init-postgres", help="Create PostgreSQL event, user, and audit tables.")
    commands.add_parser("test-postgres", help="Verify PostgreSQL connection, schema, and stored-event count.")
    commands.add_parser("test-email", help="Send one explicit SMTP configuration test email.")
    args = parser.parse_args()

    if args.command == "check":
        check_setup()
        return
    if args.command == "verify":
        raise SystemExit(run_script("verify_project.py", []))
    if args.command == "validate-attacks":
        validate_args = ["--no-postgres"] if args.no_postgres else []
        raise SystemExit(run_script("validate_attacks.py", validate_args))
    if args.command == "dashboard":
        raise SystemExit(run_script("-m", ["streamlit", "run", "dashboard.py", "--server.headless", "true"]))
    if args.command == "api":
        api_args = ["-m", "uvicorn", "api:app", "--host", args.host, "--port", str(args.port)]
        if args.reload:
            api_args.append("--reload")
        raise SystemExit(subprocess.call([sys.executable, *api_args]))
    if args.command == "setup-postgres":
        raise SystemExit(run_script("setup_postgres.py", []))
    if args.command == "init-postgres":
        try:
            PostgresRepository().initialize()
            print("PostgreSQL schema initialized.")
        except Exception as error:
            parser.error(str(error))
        return
    if args.command == "test-postgres":
        try:
            health = PostgresRepository().health()
            print(
                f"PostgreSQL ready: database={health['database']}, user={health['user']}, "
                f"tables={len(health['tables'])}, events={health['event_count']}"
            )
        except Exception as error:
            parser.error(str(error))
        return
    if args.command == "test-email":
        try:
            send_test_email()
            print("Test email sent.")
        except Exception as error:
            parser.error(str(error))
        return

    live_args = ["--fast-live", "--window-seconds", str(args.window_seconds)]
    if args.interface:
        live_args = ["--interface", args.interface, "--window-seconds", str(args.window_seconds)]
    if args.notify:
        live_args.append("--notify")
    if args.auto_response:
        live_args.append("--auto-response")
    if args.full_shap:
        live_args.append("--full-shap-live")
    if args.once:
        live_args.append("--once")
    raise SystemExit(run_script("realtime_detect.py", live_args))


if __name__ == "__main__":
    main()
