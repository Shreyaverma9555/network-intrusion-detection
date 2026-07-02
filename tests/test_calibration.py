from __future__ import annotations

import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from src.nid.calibration import ProbabilityCalibrator, brier_score, expected_calibration_error
from src.nid.model import train_from_csv


class CalibrationTests(unittest.TestCase):
    def test_calibrator_transforms_probabilities(self) -> None:
        calibrator = ProbabilityCalibrator(method="logistic", slope=1.0, intercept=0.0)
        values = calibrator.transform(np.array([0.2, 0.8]))

        self.assertAlmostEqual(float(values[0]), 0.2, places=5)
        self.assertAlmostEqual(float(values[1]), 0.8, places=5)

    def test_calibration_metrics(self) -> None:
        probabilities = np.array([0.1, 0.8, 0.7, 0.2])
        labels = np.array([0, 1, 1, 0])
        ece, bins = expected_calibration_error(probabilities, labels, bins=2)

        self.assertGreaterEqual(ece, 0)
        self.assertGreater(len(bins), 0)
        self.assertLess(brier_score(probabilities, labels), 0.1)

    def test_training_writes_calibration_metrics(self) -> None:
        target = Path("models/test_calibrated.joblib")
        result = train_from_csv("data/sample_training.csv", target)

        self.assertIn("brier_score_calibrated", result.metrics)
        self.assertIn("expected_calibration_error_calibrated", result.metrics)
        self.assertIn("calibration_method", result.metrics)
        target.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
