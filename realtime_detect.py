from __future__ import annotations

import argparse
from collections import Counter
import os
import time

from rich.console import Console
from rich.table import Table

from src.nid.explain import explain_event
from src.nid.processor import ProcessingPolicy, RealTimeProcessor
from src.nid.scapy_capture import list_interfaces


DEFAULT_DEMO_INPUT = "data/live_packets.csv"


def render_result(
    console: Console,
    result,
    title: str,
    window_counts: Counter[str],
    show_explanation: bool = False,
    feature_frame=None,
) -> None:
    event = result.event
    console.print(
        f"[bold]Source IP:[/bold] {event.source_display}    "
        f"[bold]Destination IP:[/bold] {event.destination_display}    "
        f"[bold]Traffic Scope:[/bold] {event.traffic_scope}"
    )
    table = Table(title=title)
    table.add_column("Packets")
    table.add_column("Source IP")
    table.add_column("Destination IP")
    table.add_column("Traffic Scope")
    table.add_column("Category")
    table.add_column("Model Threat Score")
    table.add_column("Decision Support")
    table.add_column("Severity")
    table.add_column("Latency")
    table.add_column("Status")
    status = "ALERT" if event.predicted_attack else "Normal"
    style = "bold red" if event.predicted_attack else "green"
    table.add_row(
        str(event.rows),
        event.source_display,
        event.destination_display,
        event.traffic_scope,
        event.category,
        f"{event.model_threat_score:.3f}",
        f"{event.confidence:.3f}",
        event.severity,
        f"{(event.statistics or {}).get('window_latency_ms', 0):.0f} ms",
        f"[{style}]{status}[/{style}]",
    )
    console.print(table)
    console.print(
        f"[bold]Threat intelligence:[/bold] Score={event.threat_score:.0f}%  "
        f"Country={event.source_country}  "
        f"Status={(event.statistics or {}).get('threat_intel_status', 'Not checked')}  "
        f"Provider={(event.statistics or {}).get('threat_intel_provider', 'Local')}  "
        f"Reputation={', '.join(event.threat_labels or ['No known malicious reputation'])}"
    )
    if (event.statistics or {}).get("port_service"):
        console.print(
            f"[bold]Port intelligence:[/bold] "
            f"{(event.statistics or {}).get('top_destination_port', 0)} "
            f"{(event.statistics or {}).get('port_service')} "
            f"risk={(event.statistics or {}).get('port_risk')}"
        )
    console.print(
        "[bold]Decision uncertainty:[/bold] "
        + (
            str((event.statistics or {}).get("evidence_state"))
            if (event.statistics or {}).get("evidence_state") in {"Insufficient sample", "No packets captured"}
            else f"{float((event.statistics or {}).get('decision_uncertainty', 1.0)):.1%}"
        )
    )
    console.print(f"[bold]Protocol summary:[/bold] {(event.statistics or {}).get('protocol_summary', 'Unknown')}")
    console.print(
        f"[bold]Calibration:[/bold] method={(event.statistics or {}).get('calibration_method', 'unknown')}  "
        f"raw median={(float((event.statistics or {}).get('raw_model_probability_median', event.model_threat_score))):.3f}  "
        f"calibrated median={(float((event.statistics or {}).get('model_probability_median', event.model_threat_score))):.3f}"
    )
    console.print(
        "[bold]Latency breakdown:[/bold] "
        f"capture={float((event.statistics or {}).get('capture_latency_ms', 0)):.0f} ms, "
        f"analysis={float((event.statistics or {}).get('analysis_latency_ms', 0)):.0f} ms, "
        f"integrations={float((event.statistics or {}).get('integration_latency_ms', 0)):.0f} ms"
    )
    console.print(
        f"[bold]Same source/destination packets:[/bold] "
        f"{int((event.statistics or {}).get('same_endpoint_packet_count', 0))} "
        f"({float((event.statistics or {}).get('same_endpoint_traffic_rate', 0)):.1%})  "
        f"Hosts={(event.statistics or {}).get('same_endpoint_addresses', 'None') or 'None'}"
    )
    if event.top_features:
        console.print("[bold]Top model features:[/bold]")
        for row in event.top_features[:5]:
            console.print(
                f"  - {row['feature']}: {float(row['importance']):.1%} "
                f"({row.get('direction', 'Window activity')}; {row.get('method', 'evidence')})"
            )
    total = sum(window_counts.values())
    distribution = ", ".join(f"{name}: {count}" for name, count in window_counts.most_common())
    console.print(f"[bold]Window statistics:[/bold] Total: {total}, {distribution}")
    if feature_frame is not None:
        console.print("[bold]Feature vector sample (training order):[/bold]")
        console.print(feature_frame.head(10).to_string(index=False))
        console.print(
            f"[bold]Feature order valid:[/bold] "
            f"{(event.statistics or {}).get('feature_order_valid', False)}"
        )
    if result.actions:
        console.print("[cyan]Actions:[/cyan] " + ", ".join(result.actions))
    for error in result.errors:
        console.print(f"[yellow]Integration warning:[/yellow] {error}")
    if show_explanation:
        console.print(explain_event(event))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run real-time network intrusion detection.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--interface", help="Scapy network interface name from `--list-interfaces`.")
    source.add_argument("--input-csv", help="Analyze an existing packet CSV instead of capturing live traffic.")
    source.add_argument("--demo", action="store_true", help="Analyze the included CSV demo instead of live traffic.")
    parser.add_argument("--model", default="models/sample_ensemble.joblib", help="Trained model path.")
    parser.add_argument(
        "--window-seconds",
        type=float,
        default=float(os.getenv("NID_WINDOW_SECONDS", "0.5")),
        help="Capture window size; supports sub-second values.",
    )
    parser.add_argument(
        "--loop-delay",
        type=float,
        default=float(os.getenv("NID_LOOP_DELAY", "0.05")),
        help="Delay between live capture windows.",
    )
    parser.add_argument("--full-shap-live", action="store_true", help="Run full SHAP for every live window (slower).")
    parser.add_argument(
        "--threshold",
        type=float,
        default=float(os.getenv("NID_ALERT_THRESHOLD", "0.75")),
        help="Robust window model threat-score threshold; alerts also require behavioral evidence.",
    )
    parser.add_argument(
        "--min-packets",
        type=int,
        default=int(os.getenv("NID_MIN_PACKETS", "10")),
        help="Minimum packets required before a window can trigger a threat.",
    )
    parser.add_argument("--once", action="store_true", help="Run one detection window and exit.")
    parser.add_argument("--list-interfaces", action="store_true", help="List Scapy capture interfaces and exit.")
    parser.add_argument(
        "--fast-live",
        action="store_true",
        help="Monitor Scapy's default interface with low-latency defaults.",
    )
    parser.add_argument(
        "--packet-limit",
        type=int,
        default=int(os.getenv("NID_PACKET_LIMIT", "500")),
        help="Maximum packets processed per live window.",
    )
    parser.add_argument("--explain", action="store_true", help="Print an AI/local threat explanation.")
    parser.add_argument("--debug-features", action="store_true", help="Print the model feature vector and order check.")
    parser.add_argument("--debug-packets", action="store_true", help="Print Scapy packet summaries during live capture.")
    parser.add_argument("--notify", action="store_true", help="Send configured email/webhook alerts.")
    parser.add_argument(
        "--alert-min-severity",
        choices=["Medium", "High", "Critical"],
        default=os.getenv("NID_ALERT_MIN_SEVERITY", "High"),
        help="Minimum severity that sends external alerts.",
    )
    parser.add_argument(
        "--alert-cooldown-seconds",
        type=int,
        default=int(os.getenv("NID_ALERT_COOLDOWN_SECONDS", "300")),
        help="Suppress duplicate source/category alerts for this duration.",
    )
    parser.add_argument("--threat-intel", action="store_true", help="Check external IP reputation and GeoIP.")
    parser.add_argument("--auto-block", action="store_true", help="Block confirmed public threat IPs using the OS firewall.")
    parser.add_argument(
        "--auto-response",
        action="store_true",
        help="For High/Critical threats: log, alert, then block confirmed public source IPs.",
    )
    parser.add_argument(
        "--block-min-confidence",
        type=float,
        default=float(os.getenv("NID_BLOCK_MIN_CONFIDENCE", "0.90")),
        help="Minimum decision support for automatic blocking.",
    )
    parser.add_argument(
        "--block-min-threat-score",
        type=float,
        default=float(os.getenv("NID_BLOCK_MIN_THREAT_SCORE", "75")),
        help="Minimum IP reputation score for blocking.",
    )
    args = parser.parse_args()

    if args.window_seconds < 0.1:
        parser.error("--window-seconds must be at least 0.1.")
    if args.loop_delay < 0:
        parser.error("--loop-delay cannot be negative.")
    if not 0 <= args.threshold <= 1:
        parser.error("--threshold must be between 0 and 1.")
    if args.min_packets < 1:
        parser.error("--min-packets must be at least 1.")
    if args.packet_limit < 1:
        parser.error("--packet-limit must be at least 1.")
    if not 0 <= args.block_min_confidence <= 1:
        parser.error("--block-min-confidence must be between 0 and 1.")
    if not 0 <= args.block_min_threat_score <= 100:
        parser.error("--block-min-threat-score must be between 0 and 100.")
    if args.alert_cooldown_seconds < 0:
        parser.error("--alert-cooldown-seconds cannot be negative.")

    console = Console()
    try:
        if args.list_interfaces:
            for name in list_interfaces():
                console.print(name)
            return

        postgres_configured = bool(os.getenv("NID_POSTGRES_DSN"))
        policy = ProcessingPolicy(
            use_external_threat_intel=args.threat_intel,
            save_events=postgres_configured,
            save_external=True,
            send_notifications=args.notify,
            alert_min_severity=args.alert_min_severity,
            auto_block=args.auto_block,
            auto_response=args.auto_response,
            alert_cooldown_seconds=args.alert_cooldown_seconds,
            block_min_confidence=args.block_min_confidence,
            block_min_threat_score=args.block_min_threat_score,
        )
        if not postgres_configured:
            console.print(
                "[yellow]PostgreSQL is not configured; detection will run without database logging. "
                "Set NID_POSTGRES_DSN in .env to enable persistence.[/yellow]"
            )
            if args.auto_block or args.auto_response:
                parser.error("--auto-block and --auto-response require NID_POSTGRES_DSN for response auditing.")
        processor = RealTimeProcessor(
            args.model,
            threshold=args.threshold,
            min_packets=args.min_packets,
            live_xai_mode="shap" if args.full_shap_live else "adaptive",
            policy=policy,
        )
        if processor.detector.fallback_reason:
            console.print(
                "[yellow]Ensemble model unavailable; using the heuristic detector.[/yellow]"
            )

        input_csv = DEFAULT_DEMO_INPUT if args.demo else args.input_csv
        if not args.interface and not input_csv:
            console.print(
                "[cyan]No interface supplied. Monitoring Scapy's default network interface.[/cyan]"
            )

        if input_csv:
            result = processor.process_file(input_csv)
            window_counts = Counter([result.event.category])
            render_result(
                console,
                result,
                "Network Intrusion Detection - CSV Analysis",
                window_counts,
                args.explain,
                processor.detector.last_features if args.debug_features else None,
            )
            return

        window_counts: Counter[str] = Counter()
        while True:
            result = processor.process_live_window(
                args.interface,
                args.window_seconds,
                args.packet_limit,
                debug_packets=args.debug_packets,
            )
            window_counts[result.event.category] += 1
            interface_label = args.interface or "Scapy default"
            render_result(
                console,
                result,
                f"Scapy Detection - Interface {interface_label}",
                window_counts,
                args.explain,
                processor.detector.last_features if args.debug_features else None,
            )

            if args.once:
                break
            time.sleep(args.loop_delay)
    except KeyboardInterrupt:
        console.print("\n[yellow]Detection stopped.[/yellow]")
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        console.print(f"[bold red]Error:[/bold red] {error}")
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
