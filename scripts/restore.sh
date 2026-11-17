#!/usr/bin/env bash
set -euo pipefail
: "${DATABASE_URL:?}"
psql "$DATABASE_URL" < "${1:-/tmp/ghostfence-backup.sql}"
echo "restore complete"