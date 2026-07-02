from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .calibration import brier_score, expected_calibration_error, fit_logistic_calibrator
from .features import FeatureBuilder, FEATURE_COLUMNS
from .paths import project_path


@dataclass
class TrainingResult:
    model_path: Path
    metrics: dict[str, object]


def build_ensemble(random_state: int = 42) -> VotingClassifier:
    estimators = [
        (
            "random_forest",
            RandomForestClassifier(
                n_estimators=220,
                max_depth=None,
                min_samples_leaf=2,
                n_jobs=1,
                class_weight="balanced",
                random_state=random_state,
            ),
        ),
        (
            "extra_trees",
            ExtraTreesClassifier(
                n_estimators=240,
                min_samples_leaf=2,
                n_jobs=1,
                class_weight="balanced",
                random_state=random_state,
            ),
        ),
        (
            "gradient_boosting",
            GradientBoostingClassifier(
                n_estimators=160,
                learning_rate=0.06,
                max_depth=3,
                random_state=random_state,
            ),
        ),
    ]
    return VotingClassifier(estimators=estimators, voting="soft", weights=[2, 2, 1])


def train_from_csv(
    input_csv: str | Path,
    model_out: str | Path,
    label_column: str = "label",
    test_size: float = 0.25,
    random_state: int = 42,
) -> TrainingResult:
    input_path = project_path(input_csv)
    if not input_path.is_file():
        raise FileNotFoundError(f"Training CSV not found: {input_path}")

    data = pd.read_csv(input_path)
    builder = FeatureBuilder(label_column=label_column)
    x, y = builder.split_xy(data)
    if len(data) < 8:
        raise ValueError("Training data must contain at least 8 rows.")
    if y.nunique() < 2:
        raise ValueError("Training data must contain both benign and attack labels.")

    x_train_full, x_test, y_train_full, y_test = train_test_split(
        x,
        y,
        test_size=test_size,
        stratify=y if y.nunique() > 1 else None,
        random_state=random_state,
    )
    calibration_size = 0.25 if len(x_train_full) >= 16 else 0.0
    if calibration_size and y_train_full.nunique() > 1:
        x_train, x_calibration, y_train, y_calibration = train_test_split(
            x_train_full,
            y_train_full,
            test_size=calibration_size,
            stratify=y_train_full if y_train_full.nunique() > 1 else None,
            random_state=random_state,
        )
    else:
        x_train, y_train = x_train_full, y_train_full
        x_calibration, y_calibration = x_train_full, y_train_full

    pipeline = Pipeline(
        [
            ("scale", StandardScaler()),
            ("ensemble", build_ensemble(random_state=random_state)),
        ]
    )
    pipeline.fit(x_train, y_train)
    predictions = pipeline.predict(x_test)
    raw_probabilities = pipeline.predict_proba(x_test)[:, 1]
    calibration_probabilities = pipeline.predict_proba(x_calibration)[:, 1]
    calibrator = fit_logistic_calibrator(calibration_probabilities, y_calibration.to_numpy())
    probabilities = calibrator.transform(raw_probabilities)
    raw_ece, raw_bins = expected_calibration_error(raw_probabilities, y_test.to_numpy())
    calibrated_ece, calibrated_bins = expected_calibration_error(probabilities, y_test.to_numpy())

    metrics = {
        "rows": int(len(data)),
        "features": FEATURE_COLUMNS,
        "accuracy": accuracy_score(y_test, predictions),
        "precision": precision_score(y_test, predictions, zero_division=0),
        "recall": recall_score(y_test, predictions, zero_division=0),
        "f1": f1_score(y_test, predictions, zero_division=0),
        "roc_auc": roc_auc_score(y_test, probabilities),
        "brier_score_raw": brier_score(raw_probabilities, y_test.to_numpy()),
        "brier_score_calibrated": brier_score(probabilities, y_test.to_numpy()),
        "expected_calibration_error_raw": raw_ece,
        "expected_calibration_error_calibrated": calibrated_ece,
        "calibration_method": calibrator.method,
        "calibration_bins": calibrated_bins,
        "raw_calibration_bins": raw_bins,
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "test_rows": int(len(y_test)),
        "normal_rows": int(y.eq(0).sum()),
        "attack_rows": int(y.eq(1).sum()),
        "evaluation_warning": (
            "Metrics are not deployment-grade because the evaluation set is too small."
            if len(data) < 1000 or len(y_test) < 200
            else ""
        ),
    }

    artifact = {
        "pipeline": pipeline,
        "calibrator": calibrator,
        "feature_builder": builder,
        "feature_columns": FEATURE_COLUMNS,
    }

    target = project_path(model_out)
    target.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, target)
    return TrainingResult(model_path=target, metrics=metrics)


def load_model(path: str | Path) -> dict[str, object]:
    model_path = project_path(path)
    if not model_path.is_file():
        raise FileNotFoundError(f"Trained model not found: {model_path}")
    return joblib.load(model_path)
