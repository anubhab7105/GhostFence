# Architecture

GhostFence is a runtime security gateway between an AI agent and its tools. The agent holds only a run token; the gateway holds credentials, evaluates every tool call, executes allowed tools, and writes decisions to a hash-chained audit log.

See `docs/PRD.md` for requirements and `docs/audit-spec.md` for the audit hash specification.