from __future__ import annotations

from typing import TYPE_CHECKING

import numpy as np
import pandas as pd

if TYPE_CHECKING:
    from .realtime import DetectionEvent

FEATURE_LABELS = {
    "time_delta": "Irregular packet timing",
    "protocol": "Unusual protocol usage",
    "src_port": "Unusual source ports",
    "dst_port": "Suspicious destination ports",
    "packet_length": "Abnormal packet sizes",
    "tcp_flags": "Suspicious TCP flag pattern",
    "src_private": "Source network type",
    "dst_private": "Destination network type",
    "bytes_per_second": "Abnormal traffic volume",
    "packets_per_src": "High traffic from one source",
    "packets_per_dst": "High traffic toward one destination",
}

_SHAP_EXPLAINERS: dict[int, object] = {}


def model_feature_evidence(
    pipeline: object,
    features: pd.DataFrame,
    prefer_shap: bool = True,
    target_attack: bool = True,
) -> list[dict[str, object]]:
    """Explain the final class using traffic from the current packet window."""
    try:
        scaled = pipeline.named_steps["scale"].transform(features)
        estimator = pipeline.named_steps["ensemble"].estimators_[0]
    except (AttributeError, KeyError, IndexError):
        return []
    values: np.ndarray
    method = "Tree importance"
    signed_values: np.ndarray | None = None
    try:
        if not prefer_shap:
            raise ImportError
        import shap

        target_class = int(target_attack)
        target_probabilities = estimator.predict_proba(scaled)[:, target_class]
        representative_count = max(1, min(len(features), int(np.ceil(len(features) * 0.20)), 50))
        representative_rows = np.argsort(target_probabilities)[-representative_count:]
        explainer = _SHAP_EXPLAINERS.get(id(estimator))
        if explainer is None:
            explainer = shap.TreeExplainer(estimator)
            _SHAP_EXPLAINERS[id(estimator)] = explainer
        shap_values = explainer.shap_values(scaled[representative_rows])
        array = np.asarray(shap_values)
        if array.ndim == 3:
            class_index = min(target_class, array.shape[2] - 1)
            class_values = array[:, :, class_index]
        elif isinstance(shap_values, list):
            class_values = np.asarray(shap_values[min(target_class, len(shap_values) - 1)])
        else:
            class_values = array
        if class_values.ndim != 2 or class_values.shape[1] != len(features.columns):
            raise ValueError("Unexpected SHAP output shape.")

        signed_values = class_values.mean(axis=0)
        values = np.abs(signed_values)
        method = f"Window SHAP ({'Attack' if target_attack else 'Normal'})"
    except (ImportError, ValueError, TypeError, AttributeError):
        global_importance = np.asarray(getattr(estimator, "feature_importances_", []))
        current_variation = np.asarray(features.std(axis=0, ddof=0), dtype=float)
        values = global_importance * (current_variation + 1e-9)
        method = "Window-weighted tree importance"
    if values.size != len(features.columns):
        return []
    total = float(values.sum()) or 1.0
    rows = [
        {
            "feature": FEATURE_LABELS.get(column, column),
            "raw_feature": column,
            "importance": float(value / total),
            "method": method,
            "direction": (
                "Supports final class"
                if signed_values is not None and float(signed_values[index]) >= 0
                else "Opposes final class"
                if signed_values is not None
                else "Window activity"
            ),
            "signed_contribution": (
                float(signed_values[index]) if signed_values is not None else None
            ),
        }
        for index, (column, value) in enumerate(zip(features.columns, values))
    ]
    return sorted(rows, key=lambda row: float(row["importance"]), reverse=True)[:5]


def xai_summary(event: DetectionEvent) -> list[dict[str, object]]:
    """Return model-independent feature evidence suitable for XAI dashboards."""
    return event.top_features or []


def xai_markdown(event: DetectionEvent) -> str:
    rows = xai_summary(event)
    if not rows:
        return "No feature attribution is available for this window."
    method = str(rows[0].get("method", "Feature attribution"))
    lines = [
        f"**Prediction:** {event.category}  \n"
        f"**Decision support:** {event.confidence:.1%}  \n"
        f"**Explanation method:** {method}",
        "",
        "Top contributing traffic features:",
    ]
    lines.extend(f"- {row['feature']}: {float(row['importance']):.1%}" for row in rows)
    return "\n".join(lines)
