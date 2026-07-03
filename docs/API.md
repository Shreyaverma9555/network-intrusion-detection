# API Reference

Interactive OpenAPI documentation is available at `/docs`; the machine-readable schema is at `/openapi.json`.

## Authentication

### Analyst login

`POST /auth/login` with form fields `username` and `password` returns:

```json
{"access_token":"<jwt>","token_type":"bearer"}
```

Send `Authorization: Bearer <jwt>` on protected routes.

### Sensor ingestion

Send `X-Sensor-Key: <NID_SENSOR_API_KEY>` to `POST /api/detections`. Sensor keys cannot access analyst endpoints.

## Core endpoints

| Method | Route | Purpose | Access |
| --- | --- | --- | --- |
| POST | `/auth/login` | Obtain JWT | Public, rate-limited |
| POST | `/api/detections` | Validate, enrich, persist, broadcast | Sensor key |
| GET | `/api/dashboard` | Summary, recent events, active alerts | Analyst |
| GET | `/api/history` | Filtered event history | Analyst |
| GET | `/api/alerts` | Confirmed attack events | Analyst |
| GET | `/api/statistics` | Aggregated SOC statistics | Analyst |
| GET | `/siem/logs` | SIEM-normalized records | Analyst |
| GET | `/threat-intel/{ip}` | Local/external IP enrichment | Analyst |
| GET | `/events/{id}/explain` | Evidence-based analyst explanation | Analyst |
| GET | `/events/{id}/report.pdf` | Download incident PDF | Analyst |
| POST | `/events/{id}/notify` | Send configured alerts | Admin/authorized |
| GET | `/health` | Process liveness | Public |
| GET | `/metrics` | Prometheus text metrics | Public |

## Detection example

```json
{
  "source_ip": "203.0.113.20",
  "destination_ip": "10.0.0.8",
  "source_port": 51515,
  "destination_port": 443,
  "protocol": "TCP",
  "packet_count": 40,
  "category": "Port Scan",
  "severity": "High",
  "confidence": 0.94,
  "predicted_attack": true
}
```

`source_ip` and `destination_ip` may be `null`; values such as “Unknown” or “No packets captured” are rejected/normalized. When `packet_count` is zero, the detector should skip ingestion.

## WebSocket

Connect to `/ws/events`, then immediately send:

```json
{"token":"<jwt>"}
```

The server responds with `{"type":"ready"}`. New events arrive as `{"type":"detection","event":{...}}`. Reconnect with backoff after a network interruption and obtain a new JWT after expiration.

## Errors and limits

The API uses standard status codes: `401` invalid/expired credentials, `403` insufficient role, `404` missing event, `409` invalid incident action, `422` validation failure, `429` rate limit, and `503` dependency failure. Pagination limits are documented in OpenAPI.
