from __future__ import annotations

from src.nid.features import FeatureBuilder


class FeatureExtractor(FeatureBuilder):
    """Deployment-facing alias for the shared training/inference feature builder."""


__all__ = ["FeatureExtractor"]
