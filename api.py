from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hmac
from io import BytesIO
import json
import os
from typing import Any

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from src.nid.auth import authenticate_api_user, normalize_role, permissions_for_role, role_has_permission
from src.nid.attack_generators import SCENARIOS
from src.nid.attack_validation import run_attack_validation
from src.nid.alerts import send_alerts_with_status
from src.nid.event_bus import event_bus
from src.nid.incident_report import incident_report
from src.nid.logging_config import configure_logging
from src.nid.observability import RateLimitMiddleware, RequestMetricsMiddleware, prometheus_metrics
from src.nid.paths import project_path
from src.nid.postgres import PostgresRepository
from src.nid.processor import ProcessingPolicy, RealTimeProcessor
from src.nid.pdf_report import build_incident_pdf
from src.nid.realtime import DetectionEvent
from src.nid.security_analyst import security_analyst_report
from src.nid.threat_intel import lookup_ip
from src.nid.visualization import geo_attack_table


app = FastAPI(
    title="Network Intrusion Detection SOC API",
    version="2.0",
    description="Authenticated backend for IDS events, analytics, threat intelligence, validation, and demo detection.",
)
logger = configure_logging("nid.backend", "app.log")
oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")
VALIDATION_REPORT = project_path("reports/attack_validation.json")

cors_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", os.getenv("NID_API_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestMetricsMiddleware, logger=logger)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[host.strip() for host in os.getenv("ALLOWED_HOSTS", "*").split(",") if host.strip()],
)
if os.getenv("FORCE_HTTPS", "0") == "1":
    app.add_middleware(HTTPSRedirectMiddleware)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    username: str
    role: str
    permissions: list[str] = []


class ManagedUser(BaseModel):
    id: int | None = None
    username: str
    role: str
    active: bool = True


class UserUpsertRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    role: str = Field(default="analyst", pattern="^(admin|analyst|viewer)$")
    active: bool = True


class ApiStatus(BaseModel):
    status: str
    api_version: str
    authenticated_user: str
    postgres_ready: bool
    postgres_error: str = ""


class SimulateResponse(BaseModel):
    scenario: str
    category: str
    severity: str
    predicted_attack: bool
    decision_support: float = Field(ge=0, le=1)
    model_threat_score: float = Field(ge=0, le=1)
    threat_score: float = Field(ge=0)
    source_ip: str
    destination_ip: str
    source_country: str
    mitre_tactics: str = "None"
    mitre_technique_ids: str = "None"
    reasons: list[str]
    actions: list[str]
    errors: list[str]
    statistics: dict[str, Any]


class AnalystReportResponse(BaseModel):
    report: str
    source: str = "local-or-llm"


class SensorEventRequest(BaseModel):
    timestamp: float
    rows: int = Field(ge=1)
    attack_probability: float = Field(ge=0, le=1)
    predicted_attack: bool
    category: str = "Normal"
    confidence: float = Field(default=0, ge=0, le=1)
    severity: str = "Low"
    reasons: list[str] | None = None
    statistics: dict[str, Any] | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    traffic_scope: str = "Unknown"
    source_country: str = "Unknown"
    threat_score: float = Field(default=0, ge=0)
    threat_labels: list[str] | None = None
    top_features: list[dict[str, Any]] | None = None
    blocked: bool = False


class SensorEventResponse(BaseModel):
    event_id: int
    accepted: bool = True
    alerts_sent: list[str] = []
    alert_errors: list[str] = []


def jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET") or os.getenv("SECRET_KEY") or os.getenv("NID_JWT_SECRET")
    if not secret:
        raise HTTPException(status_code=500, detail="NID_JWT_SECRET is not configured")
    return secret


def current_user(token: str = Depends(oauth2)) -> dict[str, str]:
    try:
        payload = jwt.decode(token, jwt_secret(), algorithms=["HS256"])
    except jwt.PyJWTError as error:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from error
    role = normalize_role(str(payload.get("role", "viewer")))
    return {
        "username": str(payload.get("sub", "")),
        "role": role,
        "permissions": permissions_for_role(role),
    }


def require_permission(permission: str):
    def dependency(user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
        if not role_has_permission(str(user.get("role", "viewer")), permission):
            raise HTTPException(status_code=403, detail=f"Permission required: {permission}")
        return user

    return dependency


def require_admin(user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
    if normalize_role(str(user.get("role", "viewer"))) != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def repository() -> PostgresRepository:
    try:
        return PostgresRepository()
    except Exception as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


def require_sensor_key(x_sensor_key: str = Header(default="")) -> None:
    expected = os.getenv("NID_SENSOR_API_KEY", "")
    if not expected:
        raise HTTPException(status_code=503, detail="Sensor ingestion is not configured")
    if not hmac.compare_digest(x_sensor_key, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid sensor API key")


def parse_event(row: dict[str, Any]) -> DetectionEvent:
    data = {key: value for key, value in row.items() if key in DetectionEvent.__dataclass_fields__}
    if isinstance(data.get("statistics"), str):
        data["statistics"] = json.loads(str(data["statistics"]))
    return DetectionEvent(**data)


def load_history(limit: int = 500, attacks_only: bool = False) -> list[dict[str, Any]]:
    try:
        return repository().recent(limit, attacks_only=attacks_only)
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"PostgreSQL unavailable: {error}") from error


def load_event(event_id: int) -> dict[str, Any]:
    try:
        event = repository().event_by_id(event_id)
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"PostgreSQL unavailable: {error}") from error
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.post("/auth/login", response_model=TokenResponse, tags=["Auth"])
def login(form: OAuth2PasswordRequestForm = Depends()) -> TokenResponse:
    authenticated = authenticate_api_user(form.username, form.password)
    if not authenticated:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    expires = datetime.now(timezone.utc) + timedelta(minutes=int(os.getenv("NID_JWT_MINUTES", "60")))
    token = jwt.encode(
        {"sub": authenticated["username"], "role": authenticated["role"], "permissions": authenticated["permissions"], "exp": expires},
        jwt_secret(),
        algorithm="HS256",
    )
    return TokenResponse(access_token=token)


@app.get("/health", tags=["System"])
@app.get("/healthz", tags=["System"])
def healthz() -> dict[str, str]:
    """Unauthenticated process-level health check for Render and load balancers."""
    return {"status": "ok", "version": app.version}


@app.get("/", tags=["System"])
def root() -> dict[str, str]:
    return {
        "service": "Sentinel Network Intrusion Detection SOC API",
        "status": "online",
        "version": app.version,
        "health": "/health",
        "metrics": "/metrics",
        "documentation": "/docs",
    }


@app.get("/metrics", response_class=PlainTextResponse, tags=["System"])
def metrics() -> str:
    return prometheus_metrics()


@app.post("/sensor/events", response_model=SensorEventResponse, tags=["Sensor"])
async def ingest_sensor_event(
    payload: SensorEventRequest,
    _: None = Depends(require_sensor_key),
) -> SensorEventResponse:
    """Accept an already-classified event from a remote Scapy sensor."""
    event = DetectionEvent(**payload.model_dump())
    try:
        event_id = repository().save(event)
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"Event storage failed: {error}") from error
    alert_delivery = None
    if event.predicted_attack and os.getenv("NID_SERVER_ALERTS", "0") == "1":
        alert_delivery = await asyncio.to_thread(send_alerts_with_status, event)
    live_event = payload.model_dump()
    live_event.update({"id": event_id, "created_at": datetime.now(timezone.utc).isoformat()})
    await event_bus.publish({"type": "detection", "event": live_event})
    return SensorEventResponse(
        event_id=event_id,
        alerts_sent=alert_delivery.sent if alert_delivery else [],
        alert_errors=alert_delivery.errors if alert_delivery else [],
    )


@app.websocket("/ws/events")
async def event_stream(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        auth = await asyncio.wait_for(websocket.receive_json(), timeout=10)
        token = str(auth.get("token", ""))
        payload = jwt.decode(token, jwt_secret(), algorithms=["HS256"])
        role = normalize_role(str(payload.get("role", "viewer")))
        if not role_has_permission(role, "read:events"):
            await websocket.close(code=4403)
            return
    except (asyncio.TimeoutError, jwt.PyJWTError, ValueError, TypeError):
        await websocket.close(code=4401)
        return

    await websocket.send_json({"type": "ready", "subscribers": event_bus.subscriber_count + 1})
    try:
        async with event_bus.subscribe() as queue:
            while True:
                event_task = asyncio.create_task(queue.get())
                client_task = asyncio.create_task(websocket.receive())
                done, pending = await asyncio.wait(
                    {event_task, client_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                if client_task in done:
                    packet = client_task.result()
                    if packet.get("type") == "websocket.disconnect":
                        return
                if event_task in done:
                    await websocket.send_json(event_task.result())
    except WebSocketDisconnect:
        return


@app.get("/me", response_model=UserResponse, tags=["Auth"])
def me(user: dict[str, str] = Depends(current_user)) -> UserResponse:
    return UserResponse(**user)


@app.get("/api/system/health", response_model=ApiStatus, tags=["System"])
def health(user: dict[str, str] = Depends(require_permission("read:health"))) -> dict[str, object]:
    try:
        database = PostgresRepository().health()
        return {
            "status": "ok",
            "api_version": app.version,
            "authenticated_user": user["username"],
            "postgres_ready": bool(database.get("ready")),
            "postgres_error": "",
        }
    except Exception as error:
        return {
            "status": "degraded",
            "api_version": app.version,
            "authenticated_user": user["username"],
            "postgres_ready": False,
            "postgres_error": str(error),
        }


@app.get("/database/health", tags=["System"])
def database_health(user: dict[str, str] = Depends(require_permission("read:health"))) -> dict[str, object]:
    try:
        return PostgresRepository().health()
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"PostgreSQL unavailable: {error}") from error


@app.get("/analytics/summary", tags=["Analytics"])
def analytics_summary(user: dict[str, str] = Depends(require_permission("read:analytics"))) -> dict[str, object]:
    try:
        return repository().summary()
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"PostgreSQL unavailable: {error}") from error


@app.get("/analytics/geo", tags=["Analytics"])
def geo_analytics(limit: int = 500, user: dict[str, str] = Depends(require_permission("read:analytics"))) -> list[dict[str, object]]:
    history = load_history(min(max(limit, 1), 1000), attacks_only=True)
    if not history:
        return []
    try:
        import pandas as pd

        frame = pd.DataFrame(history)
        frame["statistics_parsed"] = frame["statistics"].map(json.loads)
        return geo_attack_table(frame).to_dict(orient="records")
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Geo analytics failed: {error}") from error


@app.get("/events", tags=["Events"])
def events(
    limit: int = Query(100, ge=1, le=1000),
    attacks_only: bool = False,
    category: str = "",
    severity: str = "",
    source_ip: str = "",
    user: dict[str, str] = Depends(require_permission("read:events")),
) -> list[dict[str, object]]:
    rows = load_history(limit, attacks_only=attacks_only)
    if category:
        rows = [row for row in rows if str(row.get("category", "")).lower() == category.lower()]
    if severity:
        rows = [row for row in rows if str(row.get("severity", "")).lower() == severity.lower()]
    if source_ip:
        rows = [row for row in rows if str(row.get("source_ip", "")) == source_ip]
    return rows


@app.get("/events/{event_id}", tags=["Events"])
def event_detail(event_id: int, user: dict[str, str] = Depends(require_permission("read:events"))) -> dict[str, object]:
    return load_event(event_id)


@app.get("/siem/logs", tags=["SIEM"])
def siem_logs(
    limit: int = Query(250, ge=1, le=1000),
    query: str = "",
    severity: str = "",
    attacks_only: bool = False,
    user: dict[str, str] = Depends(require_permission("read:events")),
) -> list[dict[str, object]]:
    """Return normalized, searchable events in a SIEM-friendly schema."""
    rows = load_history(limit, attacks_only=attacks_only)
    normalized: list[dict[str, object]] = []
    needle = query.strip().lower()
    for row in rows:
        if severity and str(row.get("severity", "")).lower() != severity.lower():
            continue
        haystack = " ".join(
            str(row.get(field, ""))
            for field in ("source_ip", "destination_ip", "category", "severity", "traffic_scope")
        ).lower()
        if needle and needle not in haystack:
            continue
        normalized.append(
            {
                "@timestamp": row.get("created_at"),
                "event.id": row.get("id"),
                "event.kind": "alert" if row.get("predicted_attack") else "event",
                "event.category": row.get("category", "Normal"),
                "event.severity": row.get("severity", "Low"),
                "source.ip": row.get("source_ip") or None,
                "destination.ip": row.get("destination_ip") or None,
                "network.scope": row.get("traffic_scope", "Unknown"),
                "network.packets": row.get("packet_count", row.get("rows", 0)),
                "threat.score": row.get("threat_score", 0),
                "ml.confidence": row.get("confidence", 0),
                "message": (
                    f"{row.get('severity', 'Low')} {row.get('category', 'Normal')} "
                    f"from {row.get('source_ip') or 'unknown'} to {row.get('destination_ip') or 'unknown'}"
                ),
            }
        )
    return normalized


@app.get("/events/{event_id}/explain", response_model=AnalystReportResponse, tags=["AI Security Analyst"])
def explain_event(
    event_id: int,
    use_llm: bool = False,
    user: dict[str, str] = Depends(require_permission("read:incidents")),
) -> AnalystReportResponse:
    event = parse_event(load_event(event_id))
    return AnalystReportResponse(
        report=security_analyst_report(event, use_llm=use_llm),
        source="openai" if use_llm and os.getenv("OPENAI_API_KEY") else "local-xai",
    )


@app.get("/events/{event_id}/report.pdf", tags=["Incidents"])
def event_pdf(
    event_id: int,
    user: dict[str, str] = Depends(require_permission("read:incidents")),
) -> StreamingResponse:
    event = parse_event(load_event(event_id))
    pdf = build_incident_pdf(event)
    filename = f"soc-incident-{event_id}.pdf"
    return StreamingResponse(
        BytesIO(pdf),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/events/{event_id}/notify", tags=["Alerts"])
def notify_event(
    event_id: int,
    user: dict[str, str] = Depends(require_permission("run:detection")),
) -> dict[str, list[str]]:
    event = parse_event(load_event(event_id))
    if not event.predicted_attack:
        raise HTTPException(status_code=409, detail="Only confirmed attack events can trigger alerts")
    delivery = send_alerts_with_status(event)
    return {"sent": delivery.sent, "errors": delivery.errors}


@app.get("/responses", tags=["Response"])
def responses(limit: int = Query(100, ge=1, le=500), user: dict[str, str] = Depends(require_permission("read:responses"))) -> list[dict[str, object]]:
    try:
        return repository().recent_responses(limit)
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"PostgreSQL unavailable: {error}") from error


@app.get("/threat-intel/{ip}", tags=["Threat Intelligence"])
def threat_intel(ip: str, port: int = 0, external: bool = False, user: dict[str, str] = Depends(require_permission("read:threat-intel"))) -> dict[str, object]:
    intel = lookup_ip(ip, use_external=external, port=port)
    return {
        "ip": intel.ip,
        "score": intel.score,
        "labels": intel.labels or [],
        "country": intel.country,
        "latitude": intel.latitude,
        "longitude": intel.longitude,
        "status": intel.status,
        "provider": intel.provider,
        "asn": intel.asn,
        "isp": intel.isp,
        "organization": intel.organization,
        "port": intel.port,
        "port_service": intel.port_service,
        "port_risk": intel.port_risk,
    }


@app.get("/incidents/latest-report", tags=["Incidents"])
def latest_report(user: dict[str, str] = Depends(require_permission("read:incidents"))) -> dict[str, str]:
    events = load_history(1)
    if not events:
        raise HTTPException(status_code=404, detail="No events available")
    event = parse_event(events[0])
    return {"report": incident_report(event, use_llm=False)}


@app.get("/analyst/latest-report", response_model=AnalystReportResponse, tags=["AI Security Analyst"])
def latest_analyst_report(
    use_llm: bool = False,
    user: dict[str, str] = Depends(require_permission("read:incidents")),
) -> AnalystReportResponse:
    events = load_history(1)
    if not events:
        raise HTTPException(status_code=404, detail="No events available")
    event = parse_event(events[0])
    return AnalystReportResponse(report=security_analyst_report(event, use_llm=use_llm))


@app.post("/detect/simulate", response_model=SimulateResponse, tags=["Detection"])
def simulate_detection(
    scenario: str = Query("port-scan", enum=sorted(SCENARIOS)),
    save_event: bool = False,
    user: dict[str, str] = Depends(require_permission("run:detection")),
) -> SimulateResponse:
    if save_event and normalize_role(str(user.get("role", "viewer"))) != "admin":
        raise HTTPException(status_code=403, detail="Admin role required to save simulated events")
    frame = SCENARIOS[scenario]()
    processor = RealTimeProcessor(policy=ProcessingPolicy(save_events=save_event, save_external=False))
    event = processor.detector.detect_frame(frame, xai_mode="adaptive")
    result = processor.process_event(event)
    return SimulateResponse(
        scenario=scenario,
        category=result.event.category,
        severity=result.event.severity,
        predicted_attack=bool(result.event.predicted_attack),
        decision_support=float(result.event.confidence),
        model_threat_score=float(result.event.attack_probability),
        threat_score=float(result.event.threat_score),
        source_ip=result.event.source_ip,
        destination_ip=result.event.destination_ip,
        source_country=result.event.source_country,
        mitre_tactics=str((result.event.statistics or {}).get("mitre_tactics", "None")),
        mitre_technique_ids=str((result.event.statistics or {}).get("mitre_technique_ids", "None")),
        reasons=result.event.reasons or [],
        actions=result.actions,
        errors=result.errors,
        statistics=result.event.statistics or {},
    )


@app.post("/analyst/simulate", response_model=AnalystReportResponse, tags=["AI Security Analyst"])
def simulate_analyst_report(
    scenario: str = Query("port-scan", enum=sorted(SCENARIOS)),
    use_llm: bool = False,
    user: dict[str, str] = Depends(require_permission("run:detection")),
) -> AnalystReportResponse:
    frame = SCENARIOS[scenario]()
    processor = RealTimeProcessor(policy=ProcessingPolicy(save_events=False, save_external=False))
    event = processor.detector.detect_frame(frame, xai_mode="adaptive")
    result = processor.process_event(event)
    return AnalystReportResponse(report=security_analyst_report(result.event, use_llm=use_llm), source=scenario)


@app.get("/validation/latest", tags=["Validation"])
def latest_validation(user: dict[str, str] = Depends(require_permission("read:validation"))) -> dict[str, object]:
    if not VALIDATION_REPORT.exists():
        raise HTTPException(status_code=404, detail="Attack validation report has not been generated")
    try:
        return json.loads(VALIDATION_REPORT.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=500, detail="Attack validation report is not valid JSON") from error


@app.post("/validation/run", tags=["Validation"])
def run_validation(save_events: bool = False, user: dict[str, str] = Depends(require_permission("run:validation"))) -> dict[str, object]:
    if save_events and normalize_role(str(user.get("role", "viewer"))) != "admin":
        raise HTTPException(status_code=403, detail="Admin role required to save validation events")
    try:
        return run_attack_validation(save_events=save_events)
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Attack validation failed: {error}") from error


@app.get("/users", response_model=list[ManagedUser], tags=["Users"])
def users(user: dict[str, str] = Depends(require_admin)) -> list[dict[str, object]]:
    try:
        return repository().list_users()
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"PostgreSQL unavailable: {error}") from error


@app.post("/users", response_model=ManagedUser, tags=["Users"])
def upsert_user(payload: UserUpsertRequest, user: dict[str, str] = Depends(require_admin)) -> dict[str, object]:
    try:
        user_id = repository().upsert_user(payload.username, payload.role, active=payload.active)
        return {"id": user_id, "username": payload.username, "role": payload.role, "active": payload.active}
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"PostgreSQL unavailable: {error}") from error
