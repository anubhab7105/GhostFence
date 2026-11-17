# API

Base URL: http://localhost:8000

Authentication: `X-API-Key` for operators/agents, `X-Run-Token` for runs.

Endpoints:
- POST /v1/runs
- POST /v1/runs/{id}/close
- GET /v1/runs/{id}
- POST /v1/execute
- POST /v1/inspect
- GET /v1/policies
- GET /v1/approvals
- POST /v1/approvals/{id}/decide
- GET /v1/audit
- POST /v1/audit/verify
- POST /v1/audit/tamper-demo (demo mode only)
- POST /v1/attacks/run
- GET /v1/attacks/{id}/replay
- POST /v1/llm
- GET /v1/stream