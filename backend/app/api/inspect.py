"""Context inspector endpoint (basic Phase 1/3 hook)."""

import hashlib

from fastapi import APIRouter, Depends

from ..api.deps import api_key_role, run_token_payload
from ..gateway.runs import set_tainted
from ..schemas.api import InspectRequest, InspectResponse

router = APIRouter(prefix="/v1", tags=["inspect"])


@router.post("/inspect")
def inspect_content(req: InspectRequest, role: str = Depends(api_key_role), token: dict = Depends(run_token_payload)):
    # Basic heuristic severity.
    lowered = req.content.lower()
    findings = []
    severity = 0
    for marker in ["ignore previous", "exfiltrate", "send to", "override", "system prompt"]:
        if marker in lowered:
            findings.append(marker)
            severity += 25
    severity = min(100, severity)
    evidence = hashlib.sha256(req.content.encode("utf-8")).hexdigest()
    tainted = severity >= 25
    if tainted:
        set_tainted(token["session_id"], True, findings)
    return InspectResponse(severity=severity, findings=findings, evidence_hash=evidence, tainted=tainted)