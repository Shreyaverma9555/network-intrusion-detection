from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import asdict
from typing import Any

from .realtime import DetectionEvent


class PostgresRepository:
    REQUIRED_TABLES = {"nid_events", "nid_users", "nid_audit_logs"}

    def __init__(self, dsn: str | None = None) -> None:
        self.dsn = dsn or os.getenv("DATABASE_URL") or os.getenv("NID_POSTGRES_DSN", "")
        if not self.dsn:
            raise ValueError("DATABASE_URL is not configured.")

    def _connect(self):
        try:
            import psycopg
        except ImportError as error:
            raise RuntimeError("Install psycopg[binary] for PostgreSQL logging.") from error
        return psycopg.connect(self.dsn)

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS nid_users (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    role TEXT NOT NULL DEFAULT 'analyst',
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS nid_events (
                    id BIGSERIAL PRIMARY KEY,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    source_ip INET, destination_ip INET, category TEXT NOT NULL,
                    severity TEXT NOT NULL, confidence DOUBLE PRECISION NOT NULL,
                    attack_probability DOUBLE PRECISION NOT NULL, threat_score DOUBLE PRECISION,
                    packet_count INTEGER NOT NULL, predicted_attack BOOLEAN NOT NULL,
                    blocked BOOLEAN NOT NULL DEFAULT FALSE, payload JSONB NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS nid_audit_logs (
                    id BIGSERIAL PRIMARY KEY,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    actor TEXT NOT NULL, action TEXT NOT NULL,
                    target TEXT, details JSONB NOT NULL DEFAULT '{}'::jsonb
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_nid_events_created_at ON nid_events(created_at DESC)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_nid_events_source_ip ON nid_events(source_ip)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_nid_events_category ON nid_events(category)")

    def health(self) -> dict[str, Any]:
        """Verify the configured database connection and required SOC schema."""
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT current_database(), current_user, version(),
                       (SELECT COUNT(*) FROM nid_events)
                """
            ).fetchone()
            table_rows = connection.execute(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_name IN ('nid_events', 'nid_users', 'nid_audit_logs')
                ORDER BY table_name
                """
            ).fetchall()
        tables = {str(table_row[0]) for table_row in table_rows}
        missing = sorted(self.REQUIRED_TABLES - tables)
        return {
            "database": row[0],
            "user": row[1],
            "version": str(row[2]).split(",")[0],
            "tables": sorted(tables),
            "missing_tables": missing,
            "event_count": int(row[3] or 0),
            "ready": not missing,
        }

    def save_event(self, event: DetectionEvent) -> int:
        if event.rows == 0:
            raise ValueError("Cannot store an empty capture window.")
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                INSERT INTO nid_events (
                    source_ip, destination_ip, category, severity, confidence,
                    attack_probability, threat_score, packet_count, predicted_attack,
                    blocked, payload
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    self._valid_ip_or_none(event.source_ip),
                    self._valid_ip_or_none(event.destination_ip),
                    event.category,
                    event.severity,
                    event.confidence,
                    event.attack_probability,
                    event.threat_score,
                    event.rows,
                    event.predicted_attack,
                    event.blocked,
                    json.dumps(asdict(event)),
                ),
            ).fetchone()
        return int(row[0])

    @staticmethod
    def _valid_ip_or_none(value: str | None) -> str | None:
        """Return a canonical IP address, or NULL for missing/non-IP endpoints."""
        if not value:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    def save(self, event: DetectionEvent) -> int:
        """Store a detection event in PostgreSQL."""
        return self.save_event(event)

    def audit(self, actor: str, action: str, target: str = "", details: dict[str, Any] | None = None) -> int:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "INSERT INTO nid_audit_logs (actor, action, target, details) VALUES (%s, %s, %s, %s) RETURNING id",
                (actor, action, target, json.dumps(details or {})),
            ).fetchone()
        return int(row[0])

    def upsert_user(self, username: str, role: str = "analyst", active: bool = True) -> int:
        if role not in {"admin", "analyst", "viewer"}:
            raise ValueError("Role must be admin, analyst, or viewer.")
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                INSERT INTO nid_users (username, role, active)
                VALUES (%s, %s, %s)
                ON CONFLICT (username) DO UPDATE SET role = EXCLUDED.role, active = EXCLUDED.active
                RETURNING id
                """,
                (username, role, active),
            ).fetchone()
            connection.execute(
                "INSERT INTO nid_audit_logs (actor, action, target, details) VALUES (%s, %s, %s, %s)",
                ("database-admin", "upsert_user", username, json.dumps({"role": role, "active": active})),
            )
        return int(row[0])

    def list_users(self) -> list[dict[str, Any]]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, username, role, active, created_at
                FROM nid_users ORDER BY username
                """
            ).fetchall()
        return [
            {
                "id": int(row[0]),
                "username": row[1],
                "role": row[2],
                "active": bool(row[3]),
                "created_at": row[4].isoformat(),
            }
            for row in rows
        ]

    def analytics(self) -> dict[str, Any]:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_events,
                    COUNT(*) FILTER (WHERE predicted_attack) AS total_attacks,
                    COUNT(*) FILTER (WHERE predicted_attack AND created_at::date = CURRENT_DATE) AS attacks_today,
                    COUNT(*) FILTER (WHERE severity IN ('High', 'Critical') AND created_at::date = CURRENT_DATE) AS high_severity,
                    (SELECT category FROM nid_events WHERE predicted_attack GROUP BY category ORDER BY COUNT(*) DESC LIMIT 1),
                    (SELECT source_ip::text FROM nid_events WHERE predicted_attack AND source_ip IS NOT NULL
                     GROUP BY source_ip ORDER BY MAX(threat_score) DESC NULLS LAST LIMIT 1),
                    (SELECT source_ip::text FROM nid_events WHERE predicted_attack AND source_ip IS NOT NULL
                     GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 1),
                    (SELECT destination_ip::text FROM nid_events WHERE predicted_attack AND destination_ip IS NOT NULL
                     GROUP BY destination_ip ORDER BY COUNT(*) DESC LIMIT 1)
                FROM nid_events
                """
            ).fetchone()
        return {
            "total_events": int(row[0] or 0),
            "total_attacks": int(row[1] or 0),
            "attacks_today": int(row[2] or 0),
            "high_severity": int(row[3] or 0),
            "top_attack_type": row[4] or "None",
            "most_dangerous_ip": row[5] or "None",
            "top_source_ip": row[6] or "None",
            "most_targeted_host": row[7] or "None",
        }

    def summary(self) -> dict[str, Any]:
        return self.analytics()

    def recent_events(self, limit: int = 500, attacks_only: bool = False) -> list[dict[str, Any]]:
        self.initialize()
        where = "WHERE predicted_attack" if attacks_only else ""
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT id, created_at, source_ip::text, destination_ip::text, category,
                       severity, confidence, attack_probability, threat_score,
                       packet_count, predicted_attack, blocked, payload
                FROM nid_events {where} ORDER BY id DESC LIMIT %s
                """,
                (limit,),
            ).fetchall()
        events: list[dict[str, Any]] = []
        for row in rows:
            payload = row[12] if isinstance(row[12], dict) else json.loads(row[12])
            payload.update(
                {
                    "id": int(row[0]),
                    "created_at": row[1].isoformat(),
                    "source_ip": row[2] or "",
                    "destination_ip": row[3] or "",
                    "category": row[4],
                    "severity": row[5],
                    "confidence": row[6],
                    "attack_probability": row[7],
                    "threat_score": row[8] or 0,
                    "packet_count": row[9],
                    "predicted_attack": int(row[10]),
                    "blocked": int(row[11]),
                    "statistics": json.dumps(payload.get("statistics") or {}),
                }
            )
            events.append(payload)
        return events

    def recent(self, limit: int = 500, attacks_only: bool = False) -> list[dict[str, Any]]:
        return self.recent_events(limit, attacks_only=attacks_only)

    def event_by_id(self, event_id: int) -> dict[str, Any] | None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, created_at, source_ip::text, destination_ip::text, category,
                       severity, confidence, attack_probability, threat_score,
                       packet_count, predicted_attack, blocked, payload
                FROM nid_events WHERE id = %s
                """,
                (event_id,),
            ).fetchone()
        if row is None:
            return None
        payload = row[12] if isinstance(row[12], dict) else json.loads(row[12])
        payload.update(
            {
                "id": int(row[0]),
                "created_at": row[1].isoformat(),
                "source_ip": row[2] or "",
                "destination_ip": row[3] or "",
                "category": row[4],
                "severity": row[5],
                "confidence": row[6],
                "attack_probability": row[7],
                "threat_score": row[8] or 0,
                "packet_count": row[9],
                "predicted_attack": int(row[10]),
                "blocked": int(row[11]),
                "statistics": json.dumps(payload.get("statistics") or {}),
            }
        )
        return payload

    def record_response(self, source_ip: str, action: str, details: str) -> int:
        self.initialize()
        with self._connect() as connection:
            if action == "block":
                connection.execute(
                    """
                    UPDATE nid_events SET blocked = TRUE
                    WHERE id = (
                        SELECT id FROM nid_events WHERE source_ip = %s::inet ORDER BY id DESC LIMIT 1
                    )
                    """,
                    (source_ip,),
                )
            row = connection.execute(
                """
                INSERT INTO nid_audit_logs (actor, action, target, details)
                VALUES (%s, %s, %s, %s) RETURNING id
                """,
                ("real-time-processor", action, source_ip, json.dumps({"result": details})),
            ).fetchone()
        return int(row[0])

    def recent_responses(self, limit: int = 100) -> list[dict[str, Any]]:
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, created_at, actor, action, target, details
                FROM nid_audit_logs ORDER BY id DESC LIMIT %s
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "id": row[0],
                "created_at": row[1].isoformat(),
                "actor": row[2],
                "action": row[3],
                "source_ip": row[4] or "",
                "details": row[5] if isinstance(row[5], dict) else json.loads(row[5]),
            }
            for row in rows
        ]
