"""Policy endpoints (read-only for dashboard)."""

from fastapi import APIRouter, Depends

from ..api.deps import api_key_role
from ..app.main import app_state

router = APIRouter(prefix="/v1/policies", tags=["policies"])


@router.get("")
def list_policies(role: str = Depends(api_key_role)):
    engine = app_state["policy_engine"]
    return {"version": engine.version, "policy": engine.policy.model_dump()}