from __future__ import annotations

from api import app
from backend.routes.platform import router as platform_router


if not any(getattr(route, "path", "") == "/api/dashboard" for route in app.routes):
    app.include_router(platform_router)


__all__ = ["app"]
