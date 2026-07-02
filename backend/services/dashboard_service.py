from __future__ import annotations

from typing import Any

from api import load_history, repository


def dashboard_view() -> dict[str, object]:
    summary = repository().summary()
    return {
        "summary": summary,
        "recent_events": load_history(25),
        "active_alerts": load_history(10, attacks_only=True),
    }


def history_view(
    limit: int,
    attacks_only: bool,
    category: str = "",
    severity: str = "",
) -> list[dict[str, Any]]:
    rows = load_history(limit, attacks_only=attacks_only)
    if category:
        rows = [row for row in rows if str(row.get("category", "")).lower() == category.lower()]
    if severity:
        rows = [row for row in rows if str(row.get("severity", "")).lower() == severity.lower()]
    return rows


def alerts_view(limit: int) -> list[dict[str, Any]]:
    return load_history(limit, attacks_only=True)


def statistics_view() -> dict[str, Any]:
    return repository().summary()
