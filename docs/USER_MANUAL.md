# SOC Analyst User Manual

## Sign in

Open the Vercel frontend and sign in with the API username and password configured in Render. A successful login creates a session token in browser session storage; closing the tab or selecting **Log out** ends access.

If the UI says **Failed to fetch**, verify `VITE_API_URL`, Render health, and CORS. If it reports an expired token, sign in again.

## Read the dashboard

- **Total events** is all stored telemetry.
- **Detected attacks** counts events classified as malicious.
- **High severity** highlights events requiring rapid investigation.
- **Top source** is the most active observed origin.
- **Detection categories** compares the current event types.
- **Severity posture** shows Critical, High, Medium, and Low proportions.
- **Live telemetry** confirms that the authenticated WebSocket is connected.

“No traffic” or “Not captured” is a display state, not a database IP value. Start the detector on the monitored network to populate the dashboard.

## Investigate an incident

Select any row in **Security event stream** to open the incident workbench.

1. Confirm source, destination, confidence, severity, and MITRE mapping.
2. Select **Enrich IP** to request current local and external reputation data.
3. Select **AI explain** for an analyst-oriented explanation backed by model evidence.
4. Validate the result against packet context and threat intelligence. ML confidence is evidence, not proof.
5. Select **Notify team** only for a confirmed attack. The response lists successful channels and delivery errors.
6. Select **PDF report** to download the incident record for escalation or assessment evidence.

## Threat intelligence

Reputation scores combine configured sources such as AbuseIPDB, VirusTotal, RDAP/GeoIP, and the local blacklist. Private, loopback, reserved, and documentation IP ranges should not be submitted to external providers. Provider failures do not prevent local detection; the event records available enrichment and notification errors.

## Incident report contents

The PDF includes event identity and timestamp, classification and severity, packet endpoints, protocol/service, location/organization, provider and labels, notification status, MITRE ATT&CK context, model evidence, and analyst recommendations. Store reports according to your organization's evidence-retention policy.

## Notifications

Automatic server alerts run when `NID_SERVER_ALERTS=1` and a confirmed attack is ingested. Manual notifications are available in the workbench. Supported channels are SMTP email, Twilio WhatsApp/SMS, Telegram, Discord, and generic webhooks.

Before enabling automatic delivery:

1. Use test recipients/channels.
2. Trigger a simulated event.
3. Confirm message contents and timestamps.
4. Check Render logs for delivery errors.
5. Move to production recipients only after approval.

## SIEM and audit use

`/siem/logs` exposes normalized fields such as `@timestamp`, `event.kind`, `source.ip`, `destination.ip`, `network.scope`, `threat.score`, and `ml.confidence`. Use the API documentation to integrate a downstream SIEM. Administrative and detection actions are written to audit logs.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Stream offline | API URL, JWT expiry, WebSocket proxy, Render availability |
| Failed to fetch | Vercel environment variable, HTTPS, CORS origin |
| No events | Detector privileges, interface, sensor key, API URL |
| Sensor gets 401/403 | `NID_SENSOR_API_KEY` must exactly match Render |
| Threat lookup is local only | Provider keys, quota, routable IP, external enrichment switch |
| No email/WhatsApp | Channel variables, provider verification, Render delivery logs |
| PDF fails | Event exists and current role has incident-read permission |
| Database unavailable | Supabase project status, pooler URI, encoded password, SSL/network |

## Safe response practice

Do not block an IP solely because of one model prediction. Confirm ownership and reputation, check allowlists, preserve evidence, obtain authorization, and ensure out-of-band recovery access. This application supports analysis; the operator remains responsible for containment decisions.
