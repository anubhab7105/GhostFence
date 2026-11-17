# Invariant Audit

a. Agent container env/code: `docker-compose.yml` agent service env only `GHOSTFENCE_GATEWAY_URL` and `GHOSTFENCE_AGENT_API_KEY`; no provider key or tool credentials. `sdk/python/ghostfence` contains no secrets.

b. Agent-facing denials: `backend/app/gateway/pipeline.py` returns `ExecuteResponse` with `response_model_exclude_none=True` (`backend/app/main.py`); block responses set `risk_score`, `policy_version`, `result`, `approval_id` to `None`, so only `request_id`, `decision`, `reason_code` are serialized.

c. Enforcement mode: `backend/app/api/runs.py` `create_run_endpoint` allows `mode` only when role is admin/approver; agents are forced to `enforce`.

d. No floats in audit payloads: `backend/app/audit/service.py` `append_entry` uses integer `risk_score` and RFC3339 string timestamps; tests scan for floats.

e. Dashboard: `frontend/app/*.tsx` uses `JSON.stringify` in `<pre>`, no `dangerouslySetInnerHTML`.

f. No raw sensitive content/arguments in audit: `backend/app/audit/service.py` stores `evidence_hashes` (HMAC) and redacted excerpts; raw arguments are not persisted (only matched rules/provenance).

g. Tamper demo: `backend/app/main.py` `/v1/audit/tamper-demo` requires `settings.demo_mode` (default false) and `TAMPER_ADMIN_DATABASE_URL`; compose gateway env does not include tamper admin credentials.