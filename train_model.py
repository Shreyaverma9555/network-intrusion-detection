from __future__ import annotations

import argparse

from src.nid.model import train_from_csv
from src.nid.paths import project_path
from src.nid.utils import write_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Train an ensemble intrusion detection model.")
    parser.add_argument(
        "--input",
        default="data/sample_training.csv",
        help="Training CSV with a label column. Defaults to the included sample dataset.",
    )
    parser.add_argument(
        "--model-out",
        default="models/sample_ensemble.joblib",
        help="Output model path.",
    )
    parser.add_argument(
        "--report",
        default="reports/sample_metrics.json",
        help="Output metrics JSON path.",
    )
    parser.add_argument("--label-column", default="label", help="Name of the label column.")
    args = parser.parse_args()

    try:
        result = train_from_csv(args.input, args.model_out, label_column=args.label_column)
        write_json(args.report, result.metrics)
        print(f"Model saved to {result.model_path}")
        print(f"Metrics written to {project_path(args.report)}")
        print(f"F1 score: {result.metrics['f1']:.4f}")
    except (FileNotFoundError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
