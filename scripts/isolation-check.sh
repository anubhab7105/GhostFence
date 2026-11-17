#!/usr/bin/env bash
set -u
fail=0
check_blocked() {
  if curl -s --max-time 3 "$1" >/dev/null 2>&1; then echo "FAIL: reachable $1"; fail=1; else echo "OK: blocked $1"; fi
}
check_allowed() {
  if curl -s --max-time 3 "$1" >/dev/null 2>&1; then echo "OK: reachable $1"; else echo "FAIL: unreachable $1"; fail=1; fi
}
check_blocked "http://sink:8080/"
check_blocked "http://vendor-site:8080/"
check_blocked "http://postgres:5432/"
check_blocked "https://api.anthropic.com/"
check_blocked "https://example.com/"
check_allowed "${GHOSTFENCE_GATEWAY_URL:-http://gateway:8000}/health"
exit $fail