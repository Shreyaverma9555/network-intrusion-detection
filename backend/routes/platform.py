from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api import SensorEventRequest, SensorEventResponse, current_user, require_permission, require_sensor_key
from backend.services.dashboard_service import alerts_view, dashboard_view, history_view, statistics_view
from backend.services.detection_service import persist_detection


router = APIRouter(prefix="/api", tags=["SOC Platform"])


@router.post("/detections", response_model=SensorEventResponse, status_code=201)
async def create_detection(
    payload: SensorEventRequest,
    _: None = Depends(require_sensor_key),
) -> SensorEventResponse:
    return await persist_detection(payload)


@router.get("/dashboard")
def dashboard(
    user: dict[str, str] = Depends(require_permission("read:analytics")),
) -> dict[str, object]:
    return dashboard_view()


@router.get("/history")
def history(
    limit: int = Query(100, ge=1, le=1000),
    attacks_only: bool = False,
    category: str = "",
    severity: str = "",
    user: dict[str, str] = Depends(require_permission("read:events")),
) -> list[dict[str, object]]:
    return history_view(limit, attacks_only, category, severity)


@router.get("/alerts")
def alerts(
    limit: int = Query(100, ge=1, le=500),
    user: dict[str, str] = Depends(require_permission("read:events")),
) -> list[dict[str, object]]:
    return alerts_view(limit)


@router.get("/statistics")
def statistics(
    user: dict[str, str] = Depends(require_permission("read:analytics")),
) -> dict[str, object]:
    return statistics_view()


@router.get("/session")
def session(user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
    return user
