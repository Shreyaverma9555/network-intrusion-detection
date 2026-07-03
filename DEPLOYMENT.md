# Cloud Deployment

## Before deploying

You need a GitHub repository plus accounts for Supabase, Render (or AWS), and
Vercel. Never paste provider tokens into source files. Store them in the
provider environment-variable panels.

Render generates independent 'SECRET_KEY', 'JWT_SECRET', and
'NID_SENSOR_API_KEY' values automatically. The Blueprint only asks you to
choose a strong 'NID_API_PASSWORD' for the default 'admin' login.

The application has three independently deployable parts:

1. 'frontend/': React/Vite SOC dashboard on Vercel.
2. 'backend/app.py': FastAPI on Render or EC2, connected to PostgreSQL.
3. 'detector/realtime_detect.py': Scapy sensor on the monitored network.

The sensor must stay on the monitored machine or gateway. Vercel and Render
cannot observe packets from your local network.

## Managed PostgreSQL

Create a Supabase project (or another managed PostgreSQL instance) and copy its
connection string. Retain the provider's required SSL parameter:

~~~text
postgresql://USER:PASSWORD@HOST:6543/postgres?sslmode=require
~~~

Set it as 'DATABASE_URL' only on the backend.

The backend initializes the schema automatically. For manual Supabase setup,
open **SQL Editor -> New Query**, paste
'deploy/supabase/schema.sql', and click **Run**. The script is idempotent.

## Backend on Render

Push the repository to GitHub, create a Render Blueprint, and select
'render.yaml'. Configure:

- 'DATABASE_URL': managed PostgreSQL connection string.
- 'NID_API_PASSWORD': strong password for the default 'admin' account.

The Blueprint supplies 'CORS_ORIGINS', 'ALLOWED_HOSTS', and all generated
secrets. Replace 'CORS_ORIGINS' with the exact Vercel URL after frontend
deployment.

The container initializes the schema before starting. Verify the public
liveness path at 'https://YOUR-SERVICE.onrender.com/health'.

For a manual Render service use 'backend/Dockerfile' and health path '/health'.

Render terminates public HTTPS at its managed proxy, so keep 'FORCE_HTTPS=0'
there. Enable application-level HTTPS redirects only when proxy forwarding is
configured and trusted explicitly.

## Frontend on Vercel

Import this repository and set the Vercel **Root Directory** to 'frontend'.
Set 'VITE_API_URL' to the HTTPS backend origin before building. This URL is
public configuration, not a secret. The React app calls '/api/dashboard' and
opens the authenticated '/ws/events' stream.

Set 'NID_API_CORS_ORIGINS' on Render to the stable Vercel production domain.

## Scapy sensor

On the machine connected to the monitored network:

~~~powershell
py -3.11 -m pip install -r requirements.txt
$env:NID_API_URL="https://YOUR-SERVICE.onrender.com"
$env:NID_SENSOR_API_KEY="THE_SAME_SENSOR_SECRET"
python sensor.py --interface "Wi-Fi"
~~~

Npcap is required on Windows. Packet capture may require an Administrator
terminal. Test one window with:

~~~powershell
python sensor.py --interface "Wi-Fi" --once
~~~

The sensor discards empty windows locally and sends other classified events to
'POST /sensor/events'.

## AWS EC2 backend

~~~bash
docker build -f Dockerfile.api -t nid-soc-api .
docker run -d --restart unless-stopped -p 8000:8000 --env-file .env nid-soc-api
~~~

Put an HTTPS reverse proxy or Application Load Balancer in front of port 8000.
Restrict SSH to trusted administrator IPs. Keep PostgreSQL managed and private.

## Docker and Kubernetes

For a local three-service stack, copy '.env.production.example' to '.env' and
run 'docker compose -f docker-compose.soc.yml up --build'. The frontend is
served on port 8080 and the API on port 8000.

Kubernetes manifests and instructions are in 'deploy/kubernetes'. The API uses
one replica because live events currently use an in-process WebSocket bus; use
Redis Pub/Sub before horizontally scaling the API.

## Production checklist

- Use HTTPS for every public API URL.
- Use different random JWT and sensor secrets.
- Never commit '.env', passwords, or sensor keys.
- Restrict CORS to the exact Vercel origin.
- Rotate the sensor key if an endpoint is lost.
- Enable backend logs and managed database backups.
- Keep automatic IP blocking on the sensor host, not the cloud backend.
