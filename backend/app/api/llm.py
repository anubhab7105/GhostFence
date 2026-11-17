"""Gateway-controlled provider adapter (FR-62, FR-73, D1)."""

from fastapi import APIRouter, Depends, HTTPException

from ..api.deps import api_key_role, run_token_payload
from ..core.settings import settings


router = APIRouter(prefix="/v1", tags=["llm"])


@router.post("/llm")
def llm_adapter(payload: dict, role: str = Depends(api_key_role), token: dict = Depends(run_token_payload)):
    from ..app.main import app_state

    prompt = payload.get("prompt", "")
    classification = payload.get("classification", "public")
    # Fail closed: restricted data and secrets never sent to provider.
    if classification in {"restricted"}:
        raise HTTPException(status_code=403, detail="restricted data cannot be sent to provider")
    approved_up_to = "confidential"
    destinations = app_state.get("destinations")
    provider_dest = None
    if destinations:
        for d in destinations.destinations:
            if "anthropic" in d.host:
                provider_dest = d
    if provider_dest is not None:
        order = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
        if order.get(classification, 0) > order.get(provider_dest.approved_up_to.value if hasattr(provider_dest.approved_up_to, "value") else str(provider_dest.approved_up_to), 0):
            raise HTTPException(status_code=403, detail="classification exceeds provider approval")
    # Redaction / minimisation: drop obvious emails
    import re
    redacted = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED_EMAIL]", prompt)
    # No actual provider call in Phase 3 scaffold; return metadata.
    return {
        "provider": "anthropic",
        "model": settings.anthropic_model if hasattr(settings, "anthropic_model") else "claude",
        "retention": provider_dest.retention if provider_dest else "",
        "training": provider_dest.training if provider_dest else False,
        "redacted_prompt": redacted,
        "status": "not_sent_demo",
    }