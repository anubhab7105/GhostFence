# Incident Runbook (FR-70)

1. Verify audit chain: `POST /v1/audit/verify`.
2. Identify first bad sequence and affected run.
3. Revoke run token by closing the run: `POST /v1/runs/{id}/close`.
4. Review approvals and tainted sessions.
5. Restore database from backup and re-verify chain.
6. If tampering suspected, disable demo mode and rotate credentials.