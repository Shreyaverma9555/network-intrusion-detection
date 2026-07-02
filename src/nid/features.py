from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import numpy as np
import pandas as pd


NORMAL_LABELS = {"0", "normal", "benign", "clean", "legitimate"}
FEATURE_COLUMNS = [
    "time_delta",
    "protocol",
    "src_port",
    "dst_port",
    "packet_length",
    "tcp_flags",
    "src_private",
    "dst_private",
    "bytes_per_second",
    "packets_per_src",
    "packets_per_dst",
]


@dataclass
class FeatureBuilder:
    label_column: str = "label"

    def transform(self, frame: pd.DataFrame, include_label: bool = False) -> pd.DataFrame:
        data = frame.copy()
        features = pd.DataFrame(index=data.index)

        timestamps = self._numeric(data, "frame.time_epoch")
        features["time_delta"] = timestamps.diff().fillna(0).clip(lower=0)
        features["protocol"] = self._numeric(data, "ip.proto")
        features["src_port"] = self._first_numeric(data, ["tcp.srcport", "udp.srcport"])
        features["dst_port"] = self._first_numeric(data, ["tcp.dstport", "udp.dstport"])
        features["packet_length"] = self._numeric(data, "frame.len")
        features["tcp_flags"] = self._parse_tcp_flags(data.get("tcp.flags"))
        features["src_private"] = self._is_private_ip(data.get("ip.src"))
        features["dst_private"] = self._is_private_ip(data.get("ip.dst"))

        elapsed = timestamps - timestamps.min()
        elapsed = elapsed.replace(0, np.nan).fillna(1)
        features["bytes_per_second"] = features["packet_length"].cumsum() / elapsed
        features["packets_per_src"] = data.get("ip.src", pd.Series("", index=data.index)).map(
            data.get("ip.src", pd.Series("", index=data.index)).value_counts()
        )
        features["packets_per_dst"] = data.get("ip.dst", pd.Series("", index=data.index)).map(
            data.get("ip.dst", pd.Series("", index=data.index)).value_counts()
        )

        features = features.replace([np.inf, -np.inf], 0).fillna(0)
        features = features.reindex(columns=FEATURE_COLUMNS, fill_value=0)

        if include_label:
            features["target"] = self._target(data[self.label_column])

        return features

    def split_xy(self, frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
        if self.label_column not in frame.columns:
            raise ValueError(f"Missing required label column: {self.label_column}")

        transformed = self.transform(frame, include_label=True)
        return transformed[FEATURE_COLUMNS], transformed["target"]

    @staticmethod
    def _numeric(frame: pd.DataFrame, column: str) -> pd.Series:
        if column not in frame:
            return pd.Series(0, index=frame.index, dtype="float64")
        return pd.to_numeric(frame[column], errors="coerce").fillna(0)

    @classmethod
    def _first_numeric(cls, frame: pd.DataFrame, columns: list[str]) -> pd.Series:
        result = pd.Series(0, index=frame.index, dtype="float64")
        for column in columns:
            if column in frame:
                result = result.mask(result.eq(0), cls._numeric(frame, column))
        return result

    @staticmethod
    def _parse_tcp_flags(series: pd.Series | None) -> pd.Series:
        if series is None:
            return pd.Series(0, dtype="float64")

        def parse(value: object) -> int:
            first_value = str(value).split(",", maxsplit=1)[0].strip().lower()
            try:
                return int(first_value, 16) if first_value else 0
            except ValueError:
                return 0

        return series.fillna("0").apply(parse)

    @staticmethod
    def _is_private_ip(series: pd.Series | None) -> pd.Series:
        if series is None:
            return pd.Series(0, dtype="int64")

        def check(value: object) -> int:
            try:
                return int(ipaddress.ip_address(str(value)).is_private)
            except ValueError:
                return 0

        return series.fillna("").apply(check)

    @staticmethod
    def _target(labels: pd.Series) -> pd.Series:
        normalized = labels.fillna("").astype(str).str.strip().str.lower()
        return (~normalized.isin(NORMAL_LABELS)).astype(int)
