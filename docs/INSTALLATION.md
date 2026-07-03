# Installation and Deployment Guide

## Prerequisites

- Git, Python 3.11+, and Node.js 20+
- Docker Desktop for the container workflow
- A PostgreSQL 14+ database (Supabase is recommended for cloud deployment)
- Administrator/root packet-capture permission on the detector host

## Local development

1. Clone the repository and create a virtual environment:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
```

2. Copy `backend/.env.example` to `.env`. Set at minimum:

```dotenv
DATABASE_URL=postgresql://user:password@host:5432/database
NID_API_USERNAME=admin
NID_API_PASSWORD=<long-unique-password>
JWT_SECRET=<at-least-32-random-bytes>
SECRET_KEY=<different-random-value>
NID_SENSOR_API_KEY=<different-random-value>
CORS_ORIGINS=http://localhost:5173
ALLOWED_HOSTS=localhost,127.0.0.1
```

Generate secrets with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Do not copy the same value between secret fields.

3. Start the API:

```powershell
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

4. In another terminal, start the frontend:

```powershell
cd frontend
Copy-Item .env.example .env.local
npm ci
npm run dev
```

Set `VITE_API_URL=http://localhost:8000` in `frontend/.env.local`.

## Docker Compose

Copy the root `.env.example` to `.env`, fill all required values, then run:

```bash
docker compose up -d --build
docker compose ps
```

This starts PostgreSQL, FastAPI, and Vite. Production should use managed PostgreSQL and a statically built frontend instead of the development Vite container.

## Supabase

1. Create a Supabase project.
2. Open **Project Settings > Database > Connection string**.
3. Copy the transaction pooler URI and replace its password placeholder.
4. Set the complete URI as Render's `DATABASE_URL`. Percent-encode special password characters.
5. Deploy the API; application startup creates the required `nid_users`, `nid_events`, and `nid_audit_logs` tables.

Do not paste database credentials into source files. If a credential has been shared publicly, rotate the database password before deployment.

## Render backend

1. Push the repository to GitHub.
2. In Render choose **New > Blueprint** and select the repository. Render reads `render.yaml`.
3. Enter secret values for `DATABASE_URL` and `NID_API_PASSWORD`. Generated fields in the blueprint create the JWT, application, and sensor secrets.
4. Optionally add threat intelligence and notification variables.
5. Deploy and verify:

```text
https://<service>.onrender.com/health
https://<service>.onrender.com/docs
```

Important Render variables:

| Key | Value |
| --- | --- |
| `DATABASE_URL` | Supabase pooler URI |
| `NID_API_USERNAME` | `admin` or a non-obvious operator name |
| `NID_API_PASSWORD` | Strong unique password |
| `CORS_ORIGINS` | Exact Vercel URL after first frontend deploy |
| `CORS_ORIGIN_REGEX` | `https://.*\.vercel\.app` during previews |
| `ALLOWED_HOSTS` | `*.onrender.com` |
| `NID_ENRICH_SENSOR_EVENTS` | `1` |
| `NID_EXTERNAL_THREAT_INTEL` | `1` when provider keys exist |
| `NID_SERVER_ALERTS` | `1` when notification channels are configured |

## Vercel frontend

1. Import the same GitHub repository in Vercel.
2. Set **Root Directory** to `frontend`.
3. Set `VITE_API_URL=https://<service>.onrender.com`.
4. Deploy.
5. Copy the final Vercel hostname into Render's `CORS_ORIGINS` and redeploy the backend.

## Detector

On the monitored host, install dependencies and set:

```dotenv
API_URL=https://<service>.onrender.com
NID_SENSOR_API_KEY=<same-generated-Render-sensor-key>
MODEL_PATH=ml/model.pkl
DETECTOR_INTERFACE=<optional-interface-name>
```

Run an elevated terminal:

```powershell
py -3.11 detector\realtime_detect.py
```

The detector skips zero-packet windows and sends `null` for unavailable IPs. It never connects directly to PostgreSQL.

## Threat intelligence and alerts

Set `ABUSEIPDB_API_KEY` and/or `VIRUSTOTAL_API_KEY`. For email, set `NID_EMAIL_TO`, `NID_SMTP_HOST`, `NID_SMTP_PORT`, `NID_SMTP_USERNAME`, and `NID_SMTP_PASSWORD`. For WhatsApp/SMS, set `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM`, and `TWILIO_TO`. Webhook options are `NID_ALERT_WEBHOOK`, `NID_DISCORD_WEBHOOK`, `NID_TELEGRAM_BOT_TOKEN`, and `NID_TELEGRAM_CHAT_ID`.

## Operational checks

- `GET /health` returns `200`.
- Login succeeds at `POST /auth/login`.
- `GET /api/dashboard` succeeds with a bearer token.
- The detector receives `201` from `POST /api/detections`.
- Browser developer tools show an authenticated `wss://.../ws/events` connection.
- A test incident can generate a PDF and a notification delivery result.
