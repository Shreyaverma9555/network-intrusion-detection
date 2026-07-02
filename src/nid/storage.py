from __future__ import annotations

import os
from dataclasses import asdict

from .realtime import DetectionEvent


def save_external(event: DetectionEvent) -> list[str]:
    """Mirror events to optional non-primary databases."""
    mongo_uri = os.getenv("NID_MONGODB_URI")
    if not mongo_uri:
        return []
    try:
        from pymongo import MongoClient
    except ImportError as error:
        raise RuntimeError("Install pymongo to use NID_MONGODB_URI.") from error
    MongoClient(mongo_uri).nid.detections.insert_one(asdict(event))
    return ["MongoDB"]
