from __future__ import annotations

import argparse

from src.nid.deep_model import train_lstm


def main() -> None:
    parser = argparse.ArgumentParser(description="Train an optional LSTM multiclass intrusion detector.")
    parser.add_argument("--input", required=True, help="Labeled packet or flow CSV.")
    parser.add_argument("--model-out", default="models/deep_lstm.keras")
    parser.add_argument("--metadata-out", default="models/deep_lstm_metadata.joblib")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--epochs", type=int, default=20)
    args = parser.parse_args()
    try:
        result = train_lstm(args.input, args.model_out, args.metadata_out, args.label_column, args.epochs)
        print(result)
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
