# Real-Time Network Intrusion Detection

## Production Architecture

~~~text
Monitored host / gateway
  detector/realtime_detect.py
  Capture -> Features -> Model -> HTTPS POST /api/detections
                              |
                              v
React/Vite on Vercel <-> FastAPI on Render or AWS EC2 <-> Supabase PostgreSQL
          live WebSocket / JWT / role-based access
~~~

The detector never receives PostgreSQL credentials. Only the backend can access
the database. Browser users authenticate with JWTs; detector ingestion uses an
independent sensor key.

## Deployment-ready Structure

~~~text
frontend/                 React/Vite dashboard for Vercel
backend/                  FastAPI routes, services, models and container
detector/                 Standalone Scapy capture and API forwarding agent
ml/                       Model, scaler and label encoder artifacts
logs/                     Rotating backend and detector logs
deploy/aws/               AWS EC2 instructions
deploy/kubernetes/        Kubernetes manifests
docker-compose.yml        Local production-style stack
render.yaml               Render Blueprint
~~~

## Local Docker Start

1. Copy '.env.example' to '.env'.
2. Replace every placeholder secret.
3. Start the stack:

~~~powershell
docker compose up -d --build
~~~

4. Open 'http://localhost:5173'.
5. Enter 'http://localhost:8000' only when using a custom frontend build; the
   Vite environment normally supplies the API URL.
6. Verify 'http://localhost:8000/health' and
   'http://localhost:8000/metrics'.

## Production API

- 'POST /api/detections' - detector event ingestion using 'X-Sensor-Key'
- 'GET /api/dashboard' - dashboard summary, recent events and active alerts
- 'GET /api/history' - filtered authenticated event history
- 'GET /api/alerts' - confirmed attack events
- 'GET /api/statistics' - aggregate SOC statistics
- 'GET /health' - public liveness endpoint
- 'GET /metrics' - Prometheus-compatible request metrics
- 'WS /ws/events' - authenticated real-time event stream

## Cloud Deployment Order

1. Create Supabase PostgreSQL and copy its pooled connection string with
   'sslmode=require' into backend 'DATABASE_URL'.
2. Deploy the backend from 'render.yaml' or 'backend/Dockerfile'. Configure
   'JWT_SECRET', 'SECRET_KEY', 'NID_SENSOR_API_KEY',
   'NID_API_USERS_JSON', 'CORS_ORIGINS', and 'ALLOWED_HOSTS'.
3. Deploy 'frontend/' to Vercel with
   'VITE_API_URL=https://YOUR-BACKEND-DOMAIN'.
4. Set backend 'CORS_ORIGINS' to the exact Vercel production URL.
5. Run the detector on the monitored machine:

~~~powershell
$env:API_URL="https://YOUR-BACKEND-DOMAIN"
$env:NID_SENSOR_API_KEY="YOUR_SENSOR_SECRET"
python detector/realtime_detect.py --interface "Wi-Fi"
~~~

Full account-side instructions are in [DEPLOYMENT.md](DEPLOYMENT.md).

This project detects suspicious network activity in near real time using Scapy
packet capture, ensemble learning, attack-category analytics, and a Streamlit
SOC dashboard.

It is designed for a college/minor project, prototype SOC demo, or research
baseline. The system can train on labeled flow features and then monitor a live
network interface, raising alerts when the ensemble model predicts malicious
traffic.

For Vercel + Render/AWS + managed PostgreSQL deployment and remote Scapy sensor
setup, see [DEPLOYMENT.md](DEPLOYMENT.md).

For a complete local containerized SOC:

~~~powershell
Copy-Item .env.production.example .env
docker compose -f docker-compose.soc.yml up --build
~~~

Open the frontend at 'http://localhost:8080' and use
'http://localhost:8000' as the API URL.

## Features

- Live packet capture directly with Scapy
- Local traffic classification: host-local, LAN, inbound, outbound, external,
  and multicast/broadcast
- CSV export from `.pcap`/`.pcapng` files
- Flow-inspired feature engineering from packet-level fields
- Ensemble models:
  - Random Forest
  - Extra Trees
  - Gradient Boosting
  - Soft-voting ensemble
- Model evaluation with accuracy, precision, recall, F1 score, and confusion
  matrix
- Ten-category detection: Normal, DoS, Probe, R2L, U2R, Botnet, DDoS,
  Port Scan, Brute Force, and Malware
- Rule-based detection engine with signatures for Port Scan, SYN Flood,
  UDP Flood, ICMP Flood, Brute Force, ARP Spoofing, and DNS Tunneling
- Streamlit dashboard with packet count, threat graph, alert history, attack
  statistics, and current-window analytics
- AI-powered explanations using OpenAI when `OPENAI_API_KEY` is configured,
  with a local evidence-based explanation fallback
- PostgreSQL event history, analytics, users, and response audit logs
- Optional email and webhook alerts
- Email, Telegram, and Discord operational alert channels
- Threat intelligence using a local blacklist and optional AbuseIPDB
- Geo-IP attack map with offline demo coordinates, country statistics, and
  optional external public-IP geolocation
- MITRE ATT&CK mapping for detected categories and rule signatures, including
  tactics, techniques, and technique IDs
- AI Security Analyst assessment with objective, risk, MITRE context, triage
  checklist, recommended response, and false-positive checks
- Explainable AI using SHAP when installed, with tree-importance and behavioral
  evidence fallbacks
- Analyst-controlled Windows Firewall and Linux iptables blocking
- Telegram and optional Twilio SMS/WhatsApp alerts
- Live NetworkX/Plotly host and attack-path visualization
- Optional TensorFlow LSTM multiclass training path
- Modular Python package for extension
- Authenticated WebSocket event streaming for live browser dashboards
- SIEM-style normalized log search and analyst incident workbench
- Downloadable PDF incident reports
- Docker Compose and Kubernetes deployment manifests

## Project Structure

```text
network-intrusion-detection/
  configs/
    fields.json
    sample_config.json
  data/
    README.md
  models/
    README.md
  reports/
    README.md
  src/
    nid/
      capture.py
      features.py
      model.py
      realtime.py
      utils.py
  requirements.txt
  run_capture.py
  train_model.py
  realtime_detect.py
  README.md
```

## Requirements

1. Python 3.10+
2. Npcap installed on Windows for live Scapy packet capture
3. A labeled dataset such as CICIDS2017, UNSW-NB15, NSL-KDD after conversion,
   or your own labeled capture features

Install dependencies:

```powershell
cd "C:\Users\shrey\Documents\New project\network-intrusion-detection"
py -3.11 -m pip install -r requirements.txt
```

Create `.env` from `.env.example`, add PostgreSQL and SMTP credentials, then
check integration readiness:

```powershell
python check_setup.py
```

The CLI and Streamlit dashboard automatically load the project-local `.env`.

Use the unified launcher:

```powershell
python soc.py check
python soc.py live
python soc.py dashboard
python soc.py init-postgres
python soc.py test-postgres
python soc.py validate-attacks
python soc.py test-email
```

`test-email` deliberately sends one test message and is never run automatically.

Install Npcap from the official Npcap installer and enable WinPcap API
compatibility. Live capture may require an Administrator PowerShell window.

## Workflow

### 1. Capture Packets

List interfaces:

```powershell
& "C:\Program Files\Wireshark\tshark.exe" -D
```

Capture 60 seconds of traffic and export packet fields to CSV:

```powershell
python run_capture.py --interface Wi-Fi --seconds 60 --output data/live_packets.csv
```

You can also convert an existing capture:

```powershell
python run_capture.py --pcap data/sample.pcapng --output data/sample_packets.csv
```

### 2. Prepare Training Data

Your training CSV should include packet/flow columns plus a `label` column.
Common accepted packet fields are:

- `frame.time_epoch`
- `ip.src`
- `ip.dst`
- `ip.proto`
- `tcp.srcport`
- `tcp.dstport`
- `udp.srcport`
- `udp.dstport`
- `frame.len`
- `tcp.flags`
- `label`

For binary detection, labels such as `benign`, `normal`, `0`, or `clean` are
treated as normal. Other labels are treated as attacks.

### 3. Train the Ensemble Model

```powershell
python train_model.py --input data/training.csv --model-out models/ensemble.joblib --report reports/metrics.json
```

Running `python train_model.py` without arguments trains the included sample
dataset, which also makes VS Code's **Run Python File** button work directly.

For a quick smoke test, the project includes a tiny demonstration file:

```powershell
python train_model.py --input data/sample_training.csv --model-out models/sample_ensemble.joblib --report reports/sample_metrics.json
```

### 4. Run Real-Time Detection

Run live Scapy capture directly (this also works with VS Code's **Run Python
File** button):

```powershell
python realtime_detect.py
```

Run the included CSV demo explicitly:

```powershell
python realtime_detect.py --demo
```

Analyze any previously captured packet CSV:

```powershell
python realtime_detect.py --input-csv data/live_packets.csv
```

For live Scapy capture, list available interfaces:

```powershell
python realtime_detect.py --list-interfaces
```

Then run a single live window or keep monitoring:

```powershell
python realtime_detect.py --interface "Wi-Fi" --window-seconds 10 --once --explain
python realtime_detect.py --interface "Wi-Fi" --window-seconds 10
python realtime_detect.py --interface "Wi-Fi" --once --threat-intel --notify
python realtime_detect.py --interface "Wi-Fi" --threat-intel --notify --auto-block
python realtime_detect.py --interface "Wi-Fi" --threat-intel --auto-response
```

Fast live monitoring is now the default:

```powershell
python realtime_detect.py --interface "Wi-Fi" --window-seconds 0.5
python realtime_detect.py --fast-live
```

The dashboard and CLI use adaptive explanations by default: Normal windows use
fast window-weighted attribution, while detected threats receive full Window
SHAP. Set `NID_FULL_SHAP_LIVE=1` or use `--full-shap-live` to force SHAP on
every window at higher latency.

Alerts require the Model Threat Score to cross the configured threshold and the
traffic-behavior score to cross its category-specific evidence threshold.
Use the interface number reported by the interface-list command. Add `--once`
to capture one window and exit. Live capture may require an Administrator
PowerShell window depending on the selected interface and Npcap configuration.

Detections and response audits are stored in PostgreSQL when `NID_POSTGRES_DSN`
is configured. Without credentials, the CLI continues in monitoring-only mode;
automatic blocking and auto-response remain disabled because they require an
auditable PostgreSQL event record.
Add `--notify` to send configured alerts. All relative input and output paths are resolved from this project folder, so
the scripts also work when launched from another working directory or an IDE.

`--auto-block` enables real Windows Firewall blocking only for high-support
public-IP threats. Run it only in an Administrator terminal and only on networks
you administer. The dashboard provides a dry-run preview by default.

`--auto-response` enables the guarded High/Critical workflow:

```text
Detect -> log to PostgreSQL -> send configured alerts -> block public source IP
```

The firewall block still requires Administrator/root privileges and either the
configured minimum decision-support or threat-reputation score.

Every live packet window now runs through one real-time processor:

```text
Scapy capture -> multi-class model -> SHAP -> threat intelligence ->
PostgreSQL -> email/Telegram alerts -> automatic response policy
```

An unavailable PostgreSQL server or alert channel is reported as an integration
warning without stopping packet monitoring.
Duplicate source/category alerts are suppressed for five minutes by default;
configure `NID_ALERT_COOLDOWN_SECONDS` or `--alert-cooldown-seconds` as needed.
Windows with fewer than ten packets are treated as insufficient evidence and
cannot trigger alerts or automatic blocking.

### 5. Launch the SOC Dashboard

```powershell
streamlit run dashboard.py
python run_dashboard.py
```

The dashboard starts with the included demo capture. Choose **Live Scapy
capture**, select an interface, and enable **Continuous live monitoring** for
automatic capture, classification, storage, graphs, and alerts.
It remains usable in monitoring mode before PostgreSQL is configured. Adaptive
explanations keep Normal-window analysis fast and automatically use SHAP for
detected threats. PostgreSQL analytics and automatic response activate after a
successful database connection.

Set `NID_DASHBOARD_PASSWORD` or `NID_DASHBOARD_PASSWORD_SHA256` to require a SOC
login before the dashboard opens. The dashboard also includes an **Incident
Report** tab that generates a downloadable analyst report from the current
event.

For false-positive investigation, use:

```powershell
python realtime_detect.py --once --debug-packets --debug-features --explain
```

The detector validates model feature order, prints Scapy packet summaries,
shows SHAP contributors and threat-intelligence results, and tracks the running
Normal/attack-category distribution. Window decisions use a robust median/P90
aggregation of packet-level model outputs rather than the maximum score of one
packet.

Live capture keeps a persistent Scapy sniffer running, so only the first window
pays the Npcap startup cost. The dashboard reports capture, analysis, and
end-to-end latency separately; the default `0.5` second window can be adjusted
with `NID_WINDOW_SECONDS`.
`Model Threat Score` is the robust window-level model signal and is not
presented as a calibrated attack probability. `Decision Support` measures
support for the final class after model and behavioral gates, with uncertainty
shown separately. `Threat Intel` is an independent IP-reputation score.
SHAP explanations are calculated from representative packets in each current
window and show whether each contribution supports or opposes the final class;
they are not static global feature importances.

Run the complete reproducible project audit with:

```powershell
python soc.py verify
```

It verifies decision-support math, changing Window SHAP explanations, dashboard
rendering, PostgreSQL status, and same-source/same-destination traffic
investigation. Results are written to `reports/project_verification.json`.

Run known synthetic attack validation before a demonstration:

```powershell
python soc.py validate-attacks
```

This replays a benign baseline plus Port Scan, SYN Flood, Brute Force, and DNS
Tunneling windows through the real detector, checks category, severity,
decision support, threat intelligence, and PostgreSQL logging, then writes
`reports/attack_validation.json`. Use `--no-postgres` for a fast model-only
validation run.

### 6. Configure AI, Database, and Alerts

Set `NID_POSTGRES_DSN` in `.env` to activate persistent PostgreSQL analytics,
response auditing, and automatic response. Without it, detection and the
dashboard continue in monitoring mode.
`OPENAI_API_KEY` enables LLM-generated SOC explanations;
otherwise the application produces a local explanation from observed evidence.
`NID_MONGODB_URI` optionally mirrors events from the PostgreSQL-first system.
`NID_ALERT_WEBHOOK` and the `NID_SMTP_*` variables enable notifications.
`ABUSEIPDB_API_KEY` enables IP reputation checks. Local Geo-IP coordinates in
`configs/geoip_locations.json` power the dashboard attack map without internet
access. Set `NID_ENABLE_GEOIP=1` to query external public-IP map coordinates and
`NID_ENABLE_RDAP=1` to add ownership/ASN lookup. Local feeds in
`configs/ip_blacklist.json`, `configs/threat_feeds.json`,
`configs/geoip_locations.json`, and `configs/port_intel.json` work without
internet access. Telegram uses
`NID_TELEGRAM_*`; Twilio SMS or WhatsApp uses `TWILIO_*`. Copy only the required
values from `.env.example` into your environment.

PostgreSQL example:

```powershell
$env:NID_POSTGRES_DSN="postgresql://nid_user:password@localhost:5432/nid"
python soc.py init-postgres
```

On Windows with PostgreSQL already installed, use the secure interactive setup:

```powershell
python soc.py setup-postgres
```

It prompts for the existing `postgres` administrator password and a new
`nid_user` password, creates the database and role, writes `.env`, and
initializes the schema.

Manual PostgreSQL example:

```powershell
$env:NID_POSTGRES_DSN="postgresql://nid_user:password@localhost:5432/nid"
python realtime_detect.py --interface "Wi-Fi" --once
```

The processor automatically creates and migrates the PostgreSQL SOC schema.
Use `NID_BLOCK_MIN_CONFIDENCE` and `NID_BLOCK_MIN_THREAT_SCORE` to tune the
automatic response policy. Blocking is never enabled by configuration alone;
it still requires `--auto-block`, `--auto-response`, or an explicit dashboard checkbox.

### FastAPI Backend

The FastAPI backend exposes authenticated SOC endpoints for dashboards,
integrations, and placement demos:

```powershell
python soc.py api
uvicorn api:app --host 127.0.0.1 --port 8000
```

Configure `NID_API_USERNAME`, `NID_API_PASSWORD` or
`NID_API_PASSWORD_SHA256`, and `NID_JWT_SECRET`. Set
`NID_API_CORS_ORIGINS` to allow browser dashboards from other origins.
RBAC roles are `admin`, `analyst`, and `viewer`:

- `viewer`: read-only health, events, analytics, threat intelligence,
  incidents, and validation reports
- `analyst`: viewer permissions plus simulation and validation runs
- `admin`: full access, including user management and saving simulated or
  validation events

For multiple API users, set `NID_API_USERS_JSON`:

```powershell
$env:NID_API_USERS_JSON='{"analyst":{"password":"analyst-pass","role":"analyst"},"viewer":{"password":"viewer-pass","role":"viewer"}}'
```

Dashboard login uses `NID_DASHBOARD_ROLE`; viewer dashboards are read-only for
response controls.
Available endpoints include:

- `POST /auth/login`
- `GET /me`
- `GET /users` admin only
- `POST /users` admin only
- `GET /health`
- `GET /database/health`
- `GET /events`
- `GET /events/{event_id}`
- `GET /analytics/summary`
- `GET /analytics/geo`
- `GET /responses`
- `GET /threat-intel/{ip}`
- `GET /incidents/latest-report`
- `GET /analyst/latest-report`
- `POST /analyst/simulate?scenario=dns-tunnel`
- `POST /detect/simulate?scenario=port-scan`
- `GET /validation/latest`
- `POST /validation/run`

Interactive API docs are available at `http://127.0.0.1:8000/docs` after the
backend starts.

### Protocol And Rule Coverage

Real-time Scapy capture now enriches packet rows with IPv6, ARP, ICMP, DNS,
DHCP, Ethernet, and protocol metadata. Rule gates support Port Scan, SYN Flood,
UDP Flood, ICMP Flood, Brute Force, ARP Spoofing, and DNS Tunneling detections
even when the model score alone is not strong enough.

### MITRE ATT&CK Mapping

Detected attacks are mapped through `configs/mitre_attack_mapping.json`.
Mappings appear in the Streamlit **Threat Intelligence** tab, FastAPI simulation
responses, validation reports, PostgreSQL event payloads, and AI incident
reports. Examples:

- Port Scan -> `T1046 Network Service Discovery`
- SYN/UDP/ICMP Flood -> `T1498 Network Denial of Service`
- Brute Force -> `T1110 Brute Force`
- ARP Spoofing -> `T1557.002 ARP Cache Poisoning`
- DNS Tunneling -> `T1048 Exfiltration Over Alternative Protocol` and
  `T1071.004 Application Layer Protocol: DNS`

### AI Security Analyst

The **AI Security Analyst** dashboard tab and FastAPI analyst endpoints generate
a SOC-style assessment from the current event. The local analyst works without
internet access; when `OPENAI_API_KEY` is configured and `use_llm=true`, the
report can be rewritten by the configured LLM without inventing evidence.

The assessment includes:

- Executive summary and risk rating
- Likely attacker objective
- MITRE ATT&CK context
- Key evidence and rule signatures
- Triage checklist
- Recommended response
- False-positive checks

Replay safe synthetic attack windows and store the resulting event in
PostgreSQL:

```powershell
python simulate_attack.py --type port-scan
python simulate_attack.py --type syn-flood
python simulate_attack.py --type udp-flood
python simulate_attack.py --type icmp-flood
python simulate_attack.py --type brute-force
python simulate_attack.py --type arp-spoofing
python simulate_attack.py --type dns-tunnel
```

Validate all supported synthetic scenarios at once:

```powershell
python validate_attacks.py
python validate_attacks.py --no-postgres
```

### Deploy On AWS

Use the EC2 and Docker Compose deployment in
[`deploy/aws/DEPLOY_AWS.md`](deploy/aws/DEPLOY_AWS.md). EC2 is required because
Scapy needs raw-packet and host-network access. The cloud detector observes the
EC2 instance's traffic; use VPC Traffic Mirroring to inspect traffic from other
EC2 instances.

Initialize the placement-ready PostgreSQL schema and create an analyst:

```powershell
python manage_postgres.py --init --user analyst1 --role analyst
```

PostgreSQL uses normalized `nid_events`, `nid_users`, and `nid_audit_logs`
tables. Automatic response actions are written to the audit log.

Set `NID_DISCORD_WEBHOOK` to enable Discord alerts. Email, Telegram, Discord,
and generic webhook delivery are isolated, so one unavailable channel does not
stop the others or packet monitoring.
External alerts default to High and Critical severity. Configure
`NID_ALERT_MIN_SEVERITY` or `--alert-min-severity` to change that policy.

### 7. Train an Optional Deep Learning Model

The LSTM trainer supports binary or multiclass labeled datasets:

```powershell
python train_deep_model.py --input data/multiclass_training.csv --epochs 20
```

Deep learning does not automatically guarantee better accuracy. Compare it
against the ensemble using a sufficiently large held-out test set before
deploying it. On managed Windows systems, TensorFlow DLLs may be blocked by
Application Control policy; the ensemble and all dashboard features continue to
work without TensorFlow.

## Major Project Architecture

```text
Scapy Packet Capture
        |
Feature Extraction and Threat Analytics
        |
Random Forest / Extra Trees / Gradient Boosting Ensemble
        |
Hybrid Attack Classification: Normal / DoS / Probe / R2L / U2R /
Botnet / DDoS / Port Scan / Brute Force / Malware
        |
Threat Intelligence + XAI + AI Security Assistant
        |
PostgreSQL + optional MongoDB mirror
        |
Email / Telegram / Webhook / Twilio Alerting
        |
Analyst-Approved Windows Firewall / Linux iptables Blocking
```

The included training sample is binary, so the current ten-category engine combines
ensemble threat scoring with explainable traffic-behavior rules. For a
production multiclass model, train with a sufficiently large, balanced dataset
whose labels contain every category you intend to detect. Reputation and
behavior rules are useful supporting signals, but they are not a substitute for
validated multiclass training data.

## How It Works

1. Scapy captures packets directly from a live network interface.
2. The feature pipeline normalizes missing values and builds numeric features:
   packet length, protocol, source/destination ports, TCP flag encodings, and
   rolling aggregate statistics.
3. Several tree-based learners are trained and combined with soft voting.
4. During live detection, the same feature pipeline transforms each capture
   window, and the model predicts whether traffic is benign or malicious.

## Suggested Datasets

- CICIDS2017
- CSE-CIC-IDS2018
- UNSW-NB15
- Bot-IoT
- TON_IoT

Use only networks and datasets you are authorized to monitor. Packet capture on
networks you do not own or administer may violate law, policy, or privacy rules.

## Possible Enhancements

- Add XGBoost or LightGBM for stronger boosted ensembles
- Add flow generation with CICFlowMeter
- Train a calibrated multiclass XGBoost model on NSL-KDD or UNSW-NB15
- Add role-based access control and analyst case management
- Add IP reputation, GeoIP, MITRE ATT&CK mapping, and threat-intelligence feeds
- Add model-drift monitoring and scheduled retraining
- Stream alerts to Slack, email, or a SIEM
- Add SHAP baseline monitoring to detect feature-attribution drift
- Build a Flask/FastAPI dashboard
- Add PostgreSQL retention policies and scheduled backups
