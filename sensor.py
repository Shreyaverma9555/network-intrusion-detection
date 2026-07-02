from __future__ import annotations

import argparse
from dataclasses import asdict
import os
import time

import requests
from dotenv import load_dotenv

from src.nid.paths import project_path
from src.nid.processor import ProcessingPolicy, RealTimeProcessor


def send_event(api_url: str, api_key: str, event, timeout: float, retries: int = 3) -> int:
    last_error: requests.RequestException | None = None
    for attempt in range(retries + 1):
        try:
            response = requests.post(
                f"{api_url.rstrip('/')}/sensor/events",
                json=asdict(event),
                headers={"X-Sensor-Key": api_key},
                timeout=timeout,
            )
            response.raise_for_status()
            return int(response.json()["event_id"])
        except requests.RequestException as error:
            last_error = error
            if attempt < retries:
                time.sleep(min(2 ** attempt, 8))
    assert last_error is not None
    raise last_error


def main() -> None:
    load_dotenv(project_path(".env"))
    parser = argparse.ArgumentParser(description="Capture local traffic and send detections to the SOC API.")
    parser.add_argument("--api-url", default=os.getenv("NID_API_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--api-key", default=os.getenv("NID_SENSOR_API_KEY", ""))
    parser.add_argument("--interface", default=os.getenv("NID_SENSOR_INTERFACE") or None)
    parser.add_argument("--model", default=os.getenv("NID_MODEL_PATH", "models/sample_ensemble.joblib"))
    parser.add_argument("--window-seconds", type=float, default=float(os.getenv("NID_WINDOW_SECONDS", "2")))
    parser.add_argument("--packet-limit", type=int, default=int(os.getenv("NID_PACKET_LIMIT", "500")))
    parser.add_argument("--request-timeout", type=float, default=15)
    parser.add_argument("--delivery-retries", type=int, default=3)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    if not args.api_key:
        parser.error("Set NID_SENSOR_API_KEY or pass --api-key.")
    if not args.api_url.lower().startswith(("http://", "https://")):
        parser.error("--api-url must start with http:// or https://")

    processor = RealTimeProcessor(
        model_path=args.model,
        live_xai_mode="adaptive",
        policy=ProcessingPolicy(
            use_external_threat_intel=False,
            save_events=False,
            save_external=False,
            send_notifications=False,
        ),
    )

    print(f"Sensor started: interface={args.interface or 'default'}, backend={args.api_url}")
    while True:
        result = processor.process_live_window(
            args.interface,
            args.window_seconds,
            packet_limit=args.packet_limit,
        )
        event = result.event
        if event.rows == 0:
            print("No packets captured; nothing sent.")
        else:
            try:
                event_id = send_event(
                    args.api_url,
                    args.api_key,
                    event,
                    args.request_timeout,
                    retries=max(args.delivery_retries, 0),
                )
                print(
                    f"Sent event #{event_id}: packets={event.rows}, "
                    f"category={event.category}, severity={event.severity}"
                )
            except requests.RequestException as error:
                print(f"Backend delivery failed: {error}")
        if args.once:
            break
        time.sleep(0.05)


if __name__ == "__main__":
    main()
