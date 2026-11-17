#!/usr/bin/env bash
set -euo pipefail
: "${DATABASE_URL:?}"
pg_dump "$DATABASE_URL" > "${1:-/tmp/ghostfence-backup.sql}"
echo "backup written"