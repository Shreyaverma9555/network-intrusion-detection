from __future__ import annotations

from api import SensorEventRequest, SensorEventResponse, ingest_sensor_event


async def persist_detection(payload: SensorEventRequest) -> SensorEventResponse:
    """Persist, alert, and broadcast one detector event."""
    return await ingest_sensor_event(payload, None)
