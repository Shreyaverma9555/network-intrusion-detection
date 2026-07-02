from __future__ import annotations

import argparse
from dataclasses import asdict
import os
from pathlib import Path
import sys
import time

from dotenv import load_dotenv
import requests

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detector.packet_capture import list_interfaces
from src.nid.logging_config import configure_logging
from src.nid.paths import project_path
from src.nid.realtime import RealTimeDetector


logger = configure_logging("nid.detector", "detector.log")


def deliver(api_url: str, api_key: str, event, timeout: float = 15) -> int:
    response = requests.post(
        f"{api_url.rstrip('/')}/api/detections",
        json=asdict(event),
        headers={"X-Sensor-Key": api_key},
        timeout=timeout,
    )
    response.raise_for_status()
    return int(response.json()["event_id"])


def main() -> None:
    load_dotenv(project_path(".env"))
    parser = argparse.ArgumentParser(description="Standalone NID packet detector and API forwarder.")
    parser.add_argument("--api-url", default=os.getenv("API_URL", os.getenv("NID_API_URL", "")))
    parser.add_argument("--api-key", default=os.getenv("NID_SENSOR_API_KEY", ""))
    parser.add_argument("--interface", default=os.getenv("DETECTOR_INTERFACE") or None)
    parser.add_argument("--model", default=os.getenv("MODEL_PATH", "ml/model.pkl"))
    parser.add_argument("--window-seconds", type=float, default=float(os.getenv("NID_WINDOW_SECONDS", "2")))
    parser.add_argument("--packet-limit", type=int, default=int(os.getenv("NID_PACKET_LIMIT", "500")))
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--list-interfaces", action="store_true")
    args = parser.parse_args()

    if args.list_interfaces:
        for interface in list_interfaces():
            print(interface)
        return
    if not args.api_url:
        parser.error("Set API_URL to the deployed backend.")
    if not args.api_key:
        parser.error("Set NID_SENSOR_API_KEY to the backend sensor secret.")

    detector = RealTimeDetector(args.model)
    logger.info("detector_started interface=%s api=%s", args.interface or "default", args.api_url)
    while True:
        event = detector.detect_live_window(
            args.interface,
            args.window_seconds,
            xai_mode="adaptive",
            packet_limit=args.packet_limit,
        )
        if event.rows == 0:
            logger.info("capture_empty interface=%s", args.interface or "default")
        else:
            try:
                event_id = deliver(args.api_url, args.api_key, event)
                logger.info(
                    "event_delivered id=%s packets=%s category=%s severity=%s",
                    event_id,
                    event.rows,
                    event.category,
                    event.severity,
                )
            except requests.RequestException as error:
                logger.error("delivery_failed error=%s", error)
        if args.once:
            return
        time.sleep(0.05)


if __name__ == "__main__":
    main()
