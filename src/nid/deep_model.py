from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

from .features import FEATURE_COLUMNS, FeatureBuilder
from .paths import project_path


def train_lstm(
    input_csv: str | Path,
    model_out: str | Path = "models/deep_lstm.keras",
    metadata_out: str | Path = "models/deep_lstm_metadata.joblib",
    label_column: str = "label",
    epochs: int = 20,
) -> dict[str, object]:
    try:
        from tensorflow import keras
    except ImportError as error:
        raise RuntimeError(
            "TensorFlow could not load. Install a compatible TensorFlow build or ask the "
            "administrator to allow its DLLs through Windows Application Control."
        ) from error

    data = pd.read_csv(project_path(input_csv))
    if label_column not in data:
        raise ValueError(f"Missing required label column: {label_column}")
    builder = FeatureBuilder(label_column=label_column)
    x = builder.transform(data)[FEATURE_COLUMNS]
    encoder = LabelEncoder()
    y = encoder.fit_transform(data[label_column].fillna("Normal").astype(str))
    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(x).astype("float32").reshape(len(x), 1, len(FEATURE_COLUMNS))

    model = keras.Sequential(
        [
            keras.layers.Input(shape=(1, len(FEATURE_COLUMNS))),
            keras.layers.LSTM(64, return_sequences=True),
            keras.layers.Dropout(0.2),
            keras.layers.LSTM(32),
            keras.layers.Dense(32, activation="relu"),
            keras.layers.Dense(len(encoder.classes_), activation="softmax"),
        ]
    )
    model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    history = model.fit(x_scaled, y, epochs=epochs, batch_size=min(32, len(x)), validation_split=0.2, verbose=1)
    target = project_path(model_out)
    target.parent.mkdir(parents=True, exist_ok=True)
    model.save(target)
    joblib.dump(
        {"scaler": scaler, "label_encoder": encoder, "feature_builder": builder, "features": FEATURE_COLUMNS},
        project_path(metadata_out),
    )
    return {"model_path": str(target), "classes": encoder.classes_.tolist(), "accuracy": history.history["accuracy"][-1]}
