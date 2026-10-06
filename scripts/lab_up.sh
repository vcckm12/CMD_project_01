#!/bin/sh
# Start the LAB stack (D-21): separate compose project, database, secrets and port (8443).
# Synthetic data only. Usage: LAB_ADMIN_PASSWORD='...' sh scripts/lab_up.sh
set -eu
cd "$(dirname "$0")/.."
: "${LAB_ADMIN_EMAIL:=lab-admin@example.invalid}"
: "${LAB_ADMIN_PASSWORD:?set LAB_ADMIN_PASSWORD (12+ chars)}"
if [ ! -f .env.lab ]; then
  python scripts/gen_env.py .env.lab
  sed -i \
    -e 's/^COMPOSE_PROJECT_NAME=.*/COMPOSE_PROJECT_NAME=ag_lab/' \
    -e 's/^APP_ENV=.*/APP_ENV=lab/' \
    -e 's/^HTTPS_PORT=.*/HTTPS_PORT=8443/' \
    -e 's#^SHOP_ORIGIN=.*#SHOP_ORIGIN=https://shop.example.internal:8443#' \
    -e 's#^OPS_ORIGIN=.*#OPS_ORIGIN=https://ops.example.internal:8443#' .env.lab
  echo "JWT_KEY_FILE=./secrets/lab/jwt_private.pem" >> .env.lab
fi
if [ ! -f secrets/lab/jwt_private.pem ]; then
  MSYS_NO_PATHCONV=1 docker run --rm -u 0 -v "$(pwd -W 2>/dev/null || pwd):/w" -w /w ag_prod-db-test python scripts/gen_jwt_key.py secrets/lab/jwt_private.pem
fi
C="docker compose --env-file .env.lab"
$C build -q
$C up -d --wait postgres
$C run --rm migrate
$C run --rm migrate python -m app.cli.seed  # synthetic catalog and coupons (idempotent)
# The API reports not-ready until a ruleset is published, so publish before waiting on health.
$C up -d api
printf '%s\n%s\n' "$LAB_ADMIN_PASSWORD" "$LAB_ADMIN_PASSWORD" | \
  $C exec -T api python -m app.cli.create_user --email "$LAB_ADMIN_EMAIL" --role admin 2>/dev/null || true
$C exec -T api python -m app.cli.rules bootstrap --actor-email "$LAB_ADMIN_EMAIL" --label lab-v1
$C up -d --wait api audit-worker scheduler streamlit nginx
echo "LAB ready: https://ops.example.internal:8443 (admin $LAB_ADMIN_EMAIL). Stop: $C down"
