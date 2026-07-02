from __future__ import annotations

import argparse
from pathlib import Path

from src.nid.attack_validation import run_attack_validation


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate IDS behavior against known synthetic traffic windows.")
    parser.add_argument("--report", type=Path, default=Path("reports/attack_validation.json"))
    parser.add_argument("--no-postgres", action="store_true", help="Do not write validation events to PostgreSQL.")
    args = parser.parse_args()

    report = run_attack_validation(args.report, save_events=not args.no_postgres)
    print(
        f"Attack validation: {report['passed']}/{report['total']} passed "
        f"({report['generated_at']})"
    )
    for result in report["results"]:
        print(
            f"{result['status']:4} {result['scenario']:<12} -> {result['category']:<14} "
            f"severity={result['severity']:<8} support={result['decision_support']:.1%} "
            f"threat={result['threat_score']:.0f}%"
        )
        if result["status"] != "PASS":
            print("     " + "; ".join(result["details"]))
    print(f"Report saved: {args.report}")
    if not report["ready"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
