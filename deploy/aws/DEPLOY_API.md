# Deploy the SOC API on AWS EC2

1. Launch Ubuntu 24.04 on EC2 and allow inbound 22 from your IP plus 80/443.
2. Attach an IAM role or use Systems Manager instead of placing AWS keys on disk.
3. Install Docker Engine and the Compose plugin.
4. Clone this repository into '/opt/network-intrusion-detection'.
5. Copy '.env.example' to '.env' and configure the Supabase 'DATABASE_URL',
   JWT/application secrets, API users, sensor key, CORS origin, and allowed host.
6. Run:

   ~~~bash
   docker compose up -d --build backend
   ~~~

7. Put Caddy, Nginx, or an Application Load Balancer in front of port 8000 and
   terminate TLS there. Set 'FORCE_HTTPS=1' only after proxy headers and HTTPS
   forwarding are configured.
8. Verify '/health' and scrape '/metrics'.

The Scapy detector should run on the monitored machine and send events to the
public HTTPS API. It should not share database credentials.
