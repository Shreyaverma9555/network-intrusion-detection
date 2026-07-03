from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from api import app


class FakeRepository:
    saved_event = None

    def health(self) -> dict[str, object]:
        return {
            "database": "nid",
            "user": "nid_user",
            "version": "PostgreSQL test",
            "tables": ["nid_audit_logs", "nid_events", "nid_users"],
            "missing_tables": [],
            "event_count": 1,
            "ready": True,
        }

    def summary(self) -> dict[str, object]:
        return {
            "total_attacks": 1,
            "attacks_today": 1,
            "high_severity": 1,
            "top_attack_type": "Port Scan",
            "most_dangerous_ip": "203.0.113.66",
            "top_source_ip": "203.0.113.66",
            "most_targeted_host": "192.168.31.178",
        }

    def recent(self, limit: int = 500, attacks_only: bool = False) -> list[dict[str, object]]:
        event = sample_event()
        return [event] if not attacks_only or event["predicted_attack"] else []

    def event_by_id(self, event_id: int) -> dict[str, object] | None:
        event = sample_event()
        return event if event_id == event["id"] else None

    def recent_responses(self, limit: int = 100) -> list[dict[str, object]]:
        return [{"id": 7, "actor": "test", "action": "block", "source_ip": "203.0.113.66", "details": {}}]

    def list_users(self) -> list[dict[str, object]]:
        return [
            {"id": 1, "username": "admin", "role": "admin", "active": True},
            {"id": 2, "username": "analyst", "role": "analyst", "active": True},
            {"id": 3, "username": "viewer", "role": "viewer", "active": True},
        ]

    def upsert_user(self, username: str, role: str = "analyst", active: bool = True) -> int:
        return 99

    def save(self, event) -> int:
        type(self).saved_event = event
        return 321


def sample_event() -> dict[str, object]:
    return {
        "id": 123,
        "created_at": "2026-06-16T20:00:00+05:30",
        "timestamp": 1.0,
        "rows": 40,
        "attack_probability": 0.93,
        "predicted_attack": 1,
        "category": "Port Scan",
        "confidence": 0.99,
        "severity": "Critical",
        "reasons": ["Rule signature Port Scan matched"],
        "statistics": json.dumps({"source_latitude": 37.0902, "source_longitude": -95.7129}),
        "source_ip": "203.0.113.66",
        "destination_ip": "192.168.31.178",
        "traffic_scope": "Inbound",
        "source_country": "United States",
        "threat_score": 92,
        "threat_labels": ["Known malware host"],
        "top_features": [],
        "blocked": 0,
    }


class ApiBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = patch.dict(
            "os.environ",
            {
                "NID_API_USERNAME": "admin",
                "NID_API_PASSWORD": "secret",
                "NID_API_PASSWORD_SHA256": "",
                "NID_API_ROLE": "admin",
                "NID_API_USERS_JSON": json.dumps(
                    {
                        "analyst": {"password": "analyst-secret", "role": "analyst"},
                        "viewer": {"password": "viewer-secret", "role": "viewer"},
                    }
                ),
                "NID_JWT_SECRET": "0123456789abcdef0123456789abcdef",
                "NID_SENSOR_API_KEY": "sensor-secret",
            },
            clear=False,
        )
        self.env.start()
        self.client = TestClient(app)
        login = self.client.post("/auth/login", data={"username": "admin", "password": "secret"})
        self.assertEqual(login.status_code, 200, login.text)
        self.token = login.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self) -> None:
        self.env.stop()

    def test_auth_and_me_endpoint(self) -> None:
        response = self.client.get("/me", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["username"], "admin")
        self.assertEqual(response.json()["role"], "admin")

    def test_public_liveness_endpoint(self) -> None:
        response = self.client.get("/healthz")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertEqual(self.client.get("/").json()["status"], "online")
        self.assertEqual(self.client.get("/health").status_code, 200)
        self.assertIn("nid_api_requests_total", self.client.get("/metrics").text)

    def test_authenticated_websocket_stream_connects(self) -> None:
        with self.client.websocket_connect("/ws/events") as websocket:
            websocket.send_json({"token": self.token})
            ready = websocket.receive_json()

        self.assertEqual(ready["type"], "ready")
        self.assertGreaterEqual(ready["subscribers"], 1)

    def test_sensor_ingestion_uses_independent_api_key(self) -> None:
        payload = {key: value for key, value in sample_event().items() if key not in {"id", "created_at"}}
        payload["statistics"] = {"packet_count": 40}
        with patch("api.PostgresRepository", FakeRepository):
            denied = self.client.post("/sensor/events", json=payload)
            accepted = self.client.post(
                "/sensor/events",
                json=payload,
                headers={"X-Sensor-Key": "sensor-secret"},
            )

        self.assertEqual(denied.status_code, 401)
        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertEqual(accepted.json()["event_id"], 321)
        self.assertEqual(FakeRepository.saved_event.source_ip, "203.0.113.66")

    def test_threat_intel_endpoint_returns_geoip(self) -> None:
        response = self.client.get("/threat-intel/203.0.113.66?port=22", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["country"], "United States")
        self.assertEqual(payload["port_service"], "SSH")
        self.assertIsNotNone(payload["latitude"])
        self.assertIsNotNone(payload["longitude"])

    def test_simulate_detection_endpoint_runs_without_database(self) -> None:
        response = self.client.post("/detect/simulate?scenario=udp-flood", headers=self.headers)

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["category"], "UDP Flood")
        self.assertTrue(payload["predicted_attack"])
        self.assertIn("T1498", payload["mitre_technique_ids"])

    def test_ai_security_analyst_simulation_endpoint(self) -> None:
        response = self.client.post("/analyst/simulate?scenario=dns-tunnel", headers=self.headers)

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertIn("AI Security Analyst Assessment", payload["report"])
        self.assertIn("T1048", payload["report"])

    def test_database_backed_endpoints(self) -> None:
        with patch("api.PostgresRepository", FakeRepository):
            self.assertEqual(self.client.get("/api/system/health", headers=self.headers).json()["postgres_ready"], True)
            self.assertEqual(self.client.get("/analytics/summary", headers=self.headers).json()["top_attack_type"], "Port Scan")
            self.assertEqual(len(self.client.get("/events", headers=self.headers).json()), 1)
            self.assertEqual(self.client.get("/events/123", headers=self.headers).json()["category"], "Port Scan")
            self.assertEqual(len(self.client.get("/responses", headers=self.headers).json()), 1)
            self.assertIn("AI Incident Report", self.client.get("/incidents/latest-report", headers=self.headers).json()["report"])
            self.assertIn("AI Security Analyst Assessment", self.client.get("/analyst/latest-report", headers=self.headers).json()["report"])

    def test_siem_ai_and_pdf_endpoints(self) -> None:
        with patch("api.PostgresRepository", FakeRepository):
            logs = self.client.get("/siem/logs?query=port&severity=Critical", headers=self.headers)
            explanation = self.client.get("/events/123/explain", headers=self.headers)
            report = self.client.get("/events/123/report.pdf", headers=self.headers)

        self.assertEqual(logs.status_code, 200, logs.text)
        self.assertEqual(logs.json()[0]["event.kind"], "alert")
        self.assertIn("AI Security Analyst Assessment", explanation.json()["report"])
        self.assertEqual(report.headers["content-type"], "application/pdf")
        self.assertTrue(report.content.startswith(b"%PDF-"))

    def test_manual_alert_dispatch_endpoint(self) -> None:
        delivery = type("Delivery", (), {"sent": ["email", "whatsapp"], "errors": []})()
        with patch("api.PostgresRepository", FakeRepository), patch(
            "api.send_alerts_with_status", return_value=delivery
        ):
            response = self.client.post("/events/123/notify", headers=self.headers)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["sent"], ["email", "whatsapp"])

    def test_rbac_viewer_can_read_but_cannot_run_detection_or_manage_users(self) -> None:
        viewer_headers = self._login("viewer", "viewer-secret")
        with patch("api.PostgresRepository", FakeRepository):
            self.assertEqual(self.client.get("/events", headers=viewer_headers).status_code, 200)
            self.assertEqual(self.client.post("/detect/simulate?scenario=port-scan", headers=viewer_headers).status_code, 403)
            self.assertEqual(self.client.get("/users", headers=viewer_headers).status_code, 403)

    def test_rbac_analyst_can_simulate_but_cannot_save_or_manage_users(self) -> None:
        analyst_headers = self._login("analyst", "analyst-secret")
        self.assertEqual(self.client.post("/detect/simulate?scenario=port-scan", headers=analyst_headers).status_code, 200)
        self.assertEqual(
            self.client.post("/detect/simulate?scenario=port-scan&save_event=true", headers=analyst_headers).status_code,
            403,
        )
        with patch("api.PostgresRepository", FakeRepository):
            self.assertEqual(self.client.get("/users", headers=analyst_headers).status_code, 403)

    def test_rbac_admin_can_manage_users(self) -> None:
        with patch("api.PostgresRepository", FakeRepository):
            users = self.client.get("/users", headers=self.headers)
            created = self.client.post(
                "/users",
                headers=self.headers,
                json={"username": "new_analyst", "role": "analyst", "active": True},
            )

        self.assertEqual(users.status_code, 200, users.text)
        self.assertEqual(created.status_code, 200, created.text)
        self.assertEqual(created.json()["username"], "new_analyst")

    def _login(self, username: str, password: str) -> dict[str, str]:
        login = self.client.post("/auth/login", data={"username": username, "password": password})
        self.assertEqual(login.status_code, 200, login.text)
        return {"Authorization": f"Bearer {login.json()['access_token']}"}


if __name__ == "__main__":
    unittest.main()
