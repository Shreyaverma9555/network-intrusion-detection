#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${1:-$(pwd)}"
cd "$PROJECT_DIR"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl docker.io docker-compose-v2 openssl
systemctl enable --now docker

if [[ ! -f .env.aws ]]; then
  password="$(openssl rand -hex 24)"
  umask 077
  {
    printf 'POSTGRES_PASSWORD=%s\n' "$password"
    printf 'NID_WINDOW_SECONDS=0.5\n'
    printf 'NID_PACKET_LIMIT=500\n'
    printf 'NID_MIN_PACKETS=10\n'
    printf 'NID_ALERT_THRESHOLD=0.75\n'
    printf 'NID_FULL_SHAP_LIVE=0\n'
    printf 'NID_AUTO_RESPONSE=0\n'
  } > .env.aws
fi

docker compose --env-file .env.aws -f docker-compose.aws.yml up -d --build
docker compose --env-file .env.aws -f docker-compose.aws.yml ps
