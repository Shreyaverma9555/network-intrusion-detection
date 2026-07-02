from __future__ import annotations

import argparse
from pathlib import Path

from src.nid.attack_generators import ATTACKS
from src.nid.processor import ProcessingPolicy, RealTimeProcessor


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay synthetic IDS attack windows and optionally store them.")
    parser.add_argument("--type", choices=ATTACKS, default="port-scan")
    parser.add_argument("--save-csv", type=Path, help="Optional CSV path for the generated packets.")
    parser.add_argument("--no-postgres", action="store_true", help="Do not save the generated event to PostgreSQL.")
    args = parser.parse_args()

    frame = ATTACKS[args.type]()
    if args.save_csv:
        args.save_csv.parent.mkdir(parents=True, exist_ok=True)
        frame.to_csv(args.save_csv, index=False)

    processor = RealTimeProcessor(policy=ProcessingPolicy(save_events=not args.no_postgres, save_external=False))
    event = processor.detector.detect_frame(frame, xai_mode="adaptive")
    result = processor.process_event(event)

    print(f"Attack simulation: {args.type}")
    print(f"Category: {result.event.category}")
    print(f"Severity: {result.event.severity}")
    print(f"Predicted attack: {result.event.predicted_attack}")
    print(f"Decision support: {result.event.confidence:.1%}")
    print(f"Threat intelligence: {result.event.threat_score:.0f}% ({', '.join(result.event.threat_labels or [])})")
    print(f"Reasons: {'; '.join(result.event.reasons or [])}")
    if result.actions:
        print("Actions: " + ", ".join(result.actions))
    if result.errors:
        print("Errors: " + ", ".join(result.errors))


if __name__ == "__main__":
    main()
