from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app import app
from src.nid.auth import hash_password, password_matches
from test_api_backend import FakeRepository, sample_event


class DeploymentApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = patch.dict(
            os.environ,
            {
                "JWT_SECRET": "deployment-jwt-secret-with-enough-length",
                "NID_SENSOR_API_KEY": "detector-key",
                "NID_API_USERNAME": "admin",
                "NID_API_PASSWORD": "secret",
                "NID_API_USERS_JSON": "",
                "RATE_LIMIT_PER_MINUTE": "500",
            },
            clear=False,
        )
        self.environment.start()
        self.client = TestClient(app)
        login = self.client.post("/auth/login", data={"username": "admin", "password": "secret"})
        self.headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    def tearDown(self) -> None:
        self.environment.stop()

    def test_platform_read_endpoints(self) -> None:
        with patch("api.PostgresRepository", FakeRepository):
            dashboard = self.client.get("/api/dashboard", headers=self.headers)
            history = self.client.get("/api/history", headers=self.headers)
            alerts = self.client.get("/api/alerts", headers=self.headers)
            statistics = self.client.get("/api/statistics", headers=self.headers)

        self.assertEqual(dashboard.status_code, 200, dashboard.text)
        self.assertIn("recent_events", dashboard.json())
        self.assertEqual(len(history.json()), 1)
        self.assertEqual(len(alerts.json()), 1)
        self.assertEqual(statistics.json()["top_attack_type"], "Port Scan")

    def test_detector_posts_without_database_credentials(self) -> None:
        payload = {key: value for key, value in sample_event().items() if key not in {"id", "created_at"}}
        payload["statistics"] = {"packet_count": 40}
        with patch("api.PostgresRepository", FakeRepository):
            response = self.client.post(
                "/api/detections",
                headers={"X-Sensor-Key": "detector-key"},
                json=payload,
            )

        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["event_id"], 321)

    def test_pbkdf2_password_hashing(self) -> None:
        encoded = hash_password("correct-horse")

        self.assertTrue(encoded.startswith("pbkdf2_sha256$"))
        self.assertTrue(password_matches("correct-horse", expected_hash=encoded))
        self.assertFalse(password_matches("wrong", expected_hash=encoded))
        self.assertFalse(password_matches("anything"))


if __name__ == "__main__":
    unittest.main()
