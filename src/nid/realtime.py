from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from .classification import classify_window
from .features import FeatureBuilder
from .paths import project_path
from .scapy_capture import capture_packets
from .traffic_scope import classify_flow, window_scope
from .xai import model_feature_evidence


@dataclass
class DetectionEvent:
    timestamp: float
    rows: int
    attack_probability: float
    predicted_attack: bool
    category: str = "Normal"
    confidence: float = 0.0
    severity: str = "Low"
    reasons: list[str] | None = None
    statistics: dict[str, float | int] | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    traffic_scope: str = "Unknown"
    source_country: str = "Unknown"
    threat_score: float = 0.0
    threat_labels: list[str] | None = None
    top_features: list[dict[str, object]] | None = None
    blocked: bool = False

    @property
    def model_threat_score(self) -> float:
        """Window-level model score; attack_probability is retained for storage compatibility."""
        return self.attack_probability

    def endpoint_display(self, value: str | None) -> str:
        if self.rows == 0 or self.traffic_scope == "No Traffic":
            return "No packets captured"
        return value or "Unknown"

    @property
    def source_display(self) -> str:
        return self.endpoint_display(self.source_ip)

    @property
    def destination_display(self) -> str:
        return self.endpoint_display(self.destination_ip)


class RealTimeDetector:
    def __init__(self, model_path: str | Path, threshold: float = 0.75, min_packets: int = 10) -> None:
        self.pipeline = None
        self.calibrator = None
        self.feature_builder = FeatureBuilder()
        self.last_features = pd.DataFrame()
        self.fallback_reason: str | None = None
        self.threshold = threshold
        self.min_packets = min_packets
        try:
            from .model import load_model

            artifact = load_model(model_path)
            self.pipeline = artifact["pipeline"]
            self.calibrator = artifact.get("calibrator")
            self.feature_builder = artifact["feature_builder"]
        except (ImportError, OSError) as error:
            self.fallback_reason = str(error)

    def detect_frame(self, data: pd.DataFrame, xai_mode: str = "shap") -> DetectionEvent:
        if data.empty:
            return DetectionEvent(
                time.time(),
                0,
                0.0,
                False,
                reasons=["No packets captured in this window"],
                statistics={
                    "packet_count": 0,
                    "decision_confidence": 0.0,
                    "decision_uncertainty": 1.0,
                    "evidence_state": "No packets captured",
                },
                source_ip=None,
                destination_ip=None,
                traffic_scope="No Traffic",
            )

        features = self.feature_builder.transform(data)
        self.last_features = features
        if self.pipeline is not None:
            raw_probabilities = self.pipeline.predict_proba(features)[:, 1]
            probabilities = (
                self.calibrator.transform(raw_probabilities)
                if self.calibrator is not None
                else raw_probabilities
            )
            median_probability = float(np.median(probabilities))
            p90_probability = float(np.quantile(probabilities, 0.90))
            raw_median_probability = float(np.median(raw_probabilities))
            raw_p90_probability = float(np.quantile(raw_probabilities, 0.90))
            model_threat_score = (0.70 * median_probability) + (0.30 * p90_probability)
        else:
            model_threat_score = self._heuristic_probability(features)
            median_probability = model_threat_score
            p90_probability = model_threat_score
            raw_median_probability = model_threat_score
            raw_p90_probability = model_threat_score
        classification = classify_window(data, features, model_threat_score, attack_threshold=self.threshold)
        source_ip, destination_ip = self._top_flow(data)
        dominant_scope, traffic_rates = window_scope(data, source_ip, destination_ip)
        traffic_scope = classify_flow(source_ip, destination_ip)
        statistics = classification.statistics
        protocol_counts = self._protocol_counts(data)
        statistics.update(
            {
                "model_probability_median": round(median_probability, 4),
                "model_probability_p90": round(p90_probability, 4),
                "raw_model_probability_median": round(raw_median_probability, 4),
                "raw_model_probability_p90": round(raw_p90_probability, 4),
                "calibration_method": getattr(self.calibrator, "method", "none") if self.pipeline is not None else "heuristic",
                "feature_order_valid": self._feature_order_valid(features),
                "dominant_traffic_scope": dominant_scope,
                "protocol_summary": ", ".join(f"{name}: {count}" for name, count in protocol_counts.items()) or "Unknown",
                **traffic_rates,
            }
        )
        prefer_shap = xai_mode == "shap" or (xai_mode == "adaptive" and classification.category != "Normal")
        top_features = (
            model_feature_evidence(
                self.pipeline,
                features,
                prefer_shap=prefer_shap,
                target_attack=classification.category != "Normal",
            )
            if self.pipeline is not None
            else self._feature_evidence(classification.statistics)
        )
        event = DetectionEvent(
            timestamp=time.time(),
            rows=len(data),
            attack_probability=model_threat_score,
            predicted_attack=classification.category != "Normal",
            category=classification.category,
            confidence=classification.confidence,
            severity=classification.severity,
            reasons=classification.reasons,
            statistics=statistics,
            source_ip=source_ip,
            destination_ip=destination_ip,
            traffic_scope=traffic_scope,
            top_features=top_features,
        )
        if len(data) < self.min_packets:
            event.predicted_attack = False
            event.category = "Normal"
            event.confidence = 0.0
            event.severity = "Low"
            event.reasons = [f"Insufficient packet sample ({len(data)}/{self.min_packets}) for reliable classification"]
            event.statistics["decision_confidence"] = 0.0
            event.statistics["decision_uncertainty"] = 1.0
            event.statistics["evidence_state"] = "Insufficient sample"
        return event

    def detect_file(self, csv_path: str | Path) -> DetectionEvent:
        input_path = project_path(csv_path)
        if not input_path.is_file():
            raise FileNotFoundError(f"Packet CSV not found: {input_path}")
        return self.detect_frame(pd.read_csv(input_path))

    def detect_live_window(
        self,
        interface: str | None,
        window_seconds: float,
        xai_mode: str = "adaptive",
        packet_limit: int = 500,
        debug_packets: bool = False,
    ) -> DetectionEvent:
        capture_started = time.perf_counter()
        packets = capture_packets(
            interface=interface,
            seconds=window_seconds,
            packet_limit=packet_limit,
            debug_packets=debug_packets,
        )
        capture_ms = (time.perf_counter() - capture_started) * 1000
        analysis_started = time.perf_counter()
        event = self.detect_frame(packets, xai_mode=xai_mode)
        statistics = event.statistics or {}
        statistics["capture_latency_ms"] = round(capture_ms, 1)
        statistics["analysis_latency_ms"] = round((time.perf_counter() - analysis_started) * 1000, 1)
        event.statistics = statistics
        return event

    @staticmethod
    def _heuristic_probability(features: pd.DataFrame) -> float:
        suspicious_ports = {21, 22, 23, 25, 110, 445, 1433, 3389, 4444}
        port_score = features["dst_port"].isin(suspicious_ports).mean()
        syn_score = features["tcp_flags"].isin([2, 18]).mean()
        small_packet_score = features["packet_length"].between(1, 80).mean()
        repeated_source_score = min(float(features["packets_per_src"].max()) / 100.0, 1.0)
        score = 0.15 + (0.35 * port_score) + (0.2 * syn_score) + (0.15 * small_packet_score)
        score += 0.15 * repeated_source_score
        return min(float(score), 0.99)

    @staticmethod
    def _top_value(data: pd.DataFrame, column: str) -> str:
        if column not in data:
            return ""
        values = data[column].dropna().astype(str)
        values = values[values.str.len().gt(0)]
        return values.value_counts().index[0] if not values.empty else ""

    @classmethod
    def _top_flow(cls, data: pd.DataFrame) -> tuple[str, str]:
        if "ip.src" not in data or "ip.dst" not in data:
            return cls._top_value(data, "eth.src"), cls._top_value(data, "eth.dst")
        flows = data[["ip.src", "ip.dst"]].fillna("").astype(str)
        flows = flows[flows["ip.src"].str.len().gt(0) & flows["ip.dst"].str.len().gt(0)]
        if flows.empty and "eth.src" in data and "eth.dst" in data:
            eth_flows = data[["eth.src", "eth.dst"]].fillna("").astype(str)
            eth_flows = eth_flows[eth_flows["eth.src"].str.len().gt(0) & eth_flows["eth.dst"].str.len().gt(0)]
            if not eth_flows.empty:
                selected = eth_flows.value_counts().index[0]
                return str(selected[0]), str(selected[1])
        if flows.empty:
            return "", ""
        non_self = flows[flows["ip.src"].ne(flows["ip.dst"])]
        selected = (non_self if not non_self.empty else flows).value_counts().index[0]
        return str(selected[0]), str(selected[1])

    @staticmethod
    def _protocol_counts(data: pd.DataFrame) -> dict[str, int]:
        if "frame.protocol" in data:
            values = data["frame.protocol"].fillna("Unknown").astype(str)
            values = values.where(values.str.len().gt(0), "Unknown")
            return values.value_counts().head(5).astype(int).to_dict()
        protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 2054: "ARP"}
        values = pd.to_numeric(data.get("ip.proto", pd.Series(0, index=data.index)), errors="coerce").fillna(0)
        names = values.map(lambda value: protocol_names.get(int(value), f"Proto {int(value)}" if value else "Unknown"))
        return names.value_counts().head(5).astype(int).to_dict()

    def _feature_order_valid(self, features: pd.DataFrame) -> bool:
        if self.pipeline is None:
            return True
        expected = list(getattr(self.pipeline, "feature_names_in_", features.columns))
        return list(features.columns) == expected

    @staticmethod
    def _feature_evidence(statistics: dict[str, float | int]) -> list[dict[str, object]]:
        labels = {
            "syn_rate": "SYN packet rate",
            "unique_port_rate": "Destination-port diversity",
            "suspicious_login_rate": "Administrative-port traffic",
            "tiny_packet_rate": "Small-packet rate",
            "unique_sources": "Unique source count",
            "unique_destinations": "Unique destination count",
        }
        evidence = [
            {
                "feature": labels[key],
                "raw_feature": key,
                "importance": min(
                    float(value) / max(float(statistics.get("packet_count", 1)), 1)
                    if key in {"unique_sources", "unique_destinations"}
                    else float(value),
                    1.0,
                ),
                "method": "Behavioral evidence",
                "direction": "Window activity",
                "signed_contribution": None,
            }
            for key, value in statistics.items()
            if key in labels
        ]
        return sorted(evidence, key=lambda item: float(item["importance"]), reverse=True)[:5]
