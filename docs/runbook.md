# Incident Runbook

1. Verify audit chain: POST /v1/audit/verify.
2. Identify first bad sequence and affected run.
3. Revoke run token by closing the run.
4. Review approvals and tainted sessions.
5. Restore database from backup and re-verify chain.