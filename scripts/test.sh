#!/bin/sh
# Run the integration tests against a throwaway database, isolated from the dev stack (ag_prod).
# Usage: sh scripts/test.sh [pytest args]   e.g. sh scripts/test.sh -k chat
set -eu
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME=ag_test
trap 'docker compose --profile test down -v >/dev/null 2>&1' EXIT
docker compose --profile test build -q db-test migrate
docker compose up -d --wait postgres >/dev/null
docker compose run --rm migrate >/dev/null
docker compose --profile test run --rm --no-deps db-test sh -c "ruff check . && pytest -q ${*:-tests}"
