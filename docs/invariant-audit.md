# Invariant Audit

| Item | Pass/Fail | File:line references |
|---|---|---|
| a Agent has no provider/tool/operator keys | Pass | docker-compose.yml agent service env; sdk/python/ghostfence contains no secrets |
| b Denial bodies only decision/reason/request ID | Pass | backend/app/main.py:75 (response_model_exclude_none=True); backend/app/gateway/pipeline.py block responses set optional fields to None |
| c Enforcement mode operator-only | Pass | backend/app/api/runs.py:16 |
| d No floats in audit payloads | Pass | backend/app/audit/service.py append_entry uses int risk_score and string timestamps |
| e Dashboard no raw HTML/markdown | Pass | frontend/app/*.tsx use JSON.stringify in pre |
| f No raw sensitive content/arguments | Pass | backend/app/audit/service.py evidence_hash/redacted_excerpt; pipeline payload excludes raw arguments |
| g Tamper demo disabled unless DEMO_MODE | Pass | backend/app/core/settings.py:23; backend/app/main.py:109; docker-compose.yml gateway env has no tamper admin creds |