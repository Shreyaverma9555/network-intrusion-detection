from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class ProbabilityCalibrator:
    method: str = "none"
    slope: float = 1.0
    intercept: float = 0.0

    def transform(self, probabilities: np.ndarray) -> np.ndarray:
        clipped = np.clip(np.asarray(probabilities, dtype=float), 1e-6, 1 - 1e-6)
        if self.method == "logistic":
            logits = np.log(clipped / (1 - clipped))
            calibrated = 1 / (1 + np.exp(-(self.slope * logits + self.intercept)))
            return np.clip(calibrated, 0, 1)
        return clipped


def fit_logistic_calibrator(probabilities: np.ndarray, labels: np.ndarray) -> ProbabilityCalibrator:
    probabilities = np.clip(np.asarray(probabilities, dtype=float), 1e-6, 1 - 1e-6)
    labels = np.asarray(labels, dtype=int)
    if len(np.unique(labels)) < 2 or len(labels) < 8:
        return ProbabilityCalibrator()
    try:
        from sklearn.linear_model import LogisticRegression

        logits = np.log(probabilities / (1 - probabilities)).reshape(-1, 1)
        model = LogisticRegression(solver="lbfgs")
        model.fit(logits, labels)
        return ProbabilityCalibrator(
            method="logistic",
            slope=float(model.coef_[0][0]),
            intercept=float(model.intercept_[0]),
        )
    except Exception:
        return ProbabilityCalibrator()


def brier_score(probabilities: np.ndarray, labels: np.ndarray) -> float:
    probabilities = np.asarray(probabilities, dtype=float)
    labels = np.asarray(labels, dtype=float)
    return float(np.mean((probabilities - labels) ** 2))


def expected_calibration_error(probabilities: np.ndarray, labels: np.ndarray, bins: int = 10) -> tuple[float, list[dict[str, float]]]:
    probabilities = np.asarray(probabilities, dtype=float)
    labels = np.asarray(labels, dtype=float)
    edges = np.linspace(0, 1, bins + 1)
    rows: list[dict[str, float]] = []
    ece = 0.0
    for index in range(bins):
        lower = edges[index]
        upper = edges[index + 1]
        mask = (probabilities >= lower) & (probabilities <= upper if index == bins - 1 else probabilities < upper)
        count = int(mask.sum())
        if count == 0:
            continue
        confidence = float(probabilities[mask].mean())
        accuracy = float(labels[mask].mean())
        gap = abs(confidence - accuracy)
        ece += (count / max(len(probabilities), 1)) * gap
        rows.append(
            {
                "bin_start": float(lower),
                "bin_end": float(upper),
                "count": count,
                "mean_score": confidence,
                "observed_attack_rate": accuracy,
                "gap": gap,
            }
        )
    return float(ece), rows
