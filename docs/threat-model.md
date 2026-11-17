# Threat Model

In scope: indirect prompt injection, unauthorised tool use, privilege escalation, data exfiltration through tools, silent tampering with logs.

Limitations: prompt-injection detection is heuristic and advisory; GhostFence only governs tools routed through it; hash chains make tampering detectable, not impossible; users can still approve harmful actions. See PRD section 13.