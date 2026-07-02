from __future__ import annotations

from collections import defaultdict, deque
import logging
import os
import threading
import time

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


_lock = threading.Lock()
_requests_total: dict[tuple[str, str, int], int] = defaultdict(int)
_latency_seconds: dict[tuple[str, str], float] = defaultdict(float)
_rate_windows: dict[str, deque[float]] = defaultdict(deque)


class RequestMetricsMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, logger: logging.Logger) -> None:
        super().__init__(app)
        self.logger = logger

    async def dispatch(self, request: Request, call_next):
        started = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - started
        route = request.url.path
        with _lock:
            _requests_total[(request.method, route, response.status_code)] += 1
            _latency_seconds[(request.method, route)] += elapsed
        self.logger.info(
            "request method=%s path=%s status=%s duration_ms=%.1f",
            request.method,
            route,
            response.status_code,
            elapsed * 1000,
        )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in {"/health", "/healthz", "/metrics"}:
            return await call_next(request)
        limit = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        with _lock:
            window = _rate_windows[client]
            while window and now - window[0] >= 60:
                window.popleft()
            if len(window) >= limit:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Retry later."},
                    headers={"Retry-After": "60"},
                )
            window.append(now)
        return await call_next(request)


def prometheus_metrics() -> str:
    lines = [
        "# HELP nid_api_requests_total HTTP requests handled by the SOC API.",
        "# TYPE nid_api_requests_total counter",
    ]
    with _lock:
        for (method, path, status), count in sorted(_requests_total.items()):
            safe_path = path.replace('"', "")
            lines.append(
                f'nid_api_requests_total{{method="{method}",path="{safe_path}",status="{status}"}} {count}'
            )
        lines.extend(
            [
                "# HELP nid_api_request_duration_seconds_total Cumulative request processing time.",
                "# TYPE nid_api_request_duration_seconds_total counter",
            ]
        )
        for (method, path), duration in sorted(_latency_seconds.items()):
            safe_path = path.replace('"', "")
            lines.append(
                f'nid_api_request_duration_seconds_total{{method="{method}",path="{safe_path}"}} {duration:.6f}'
            )
    return "\n".join(lines) + "\n"
