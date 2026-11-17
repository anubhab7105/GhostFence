"""Attack Lab endpoints (Phase 4)."""

from fastapi import APIRouter, Depends

from ..api.deps import api_key_role
from ..attack_lab.runner import run_scenario

router = APIRouter(prefix="/v1/attacks", tags=["attacks"])


@router.post("/run")
async def run_attack(payload: dict, role: str = Depends(api_key_role)):
    scenario_id = payload.get("scenario_id", "s1")
    mode = payload.get("mode", "protected")
    return await run_scenario(scenario_id, mode)


@router.get("/{attack_id}/replay")
def replay(attack_id: str, role: str = Depends(api_key_role)):
    from ..core.db import get_session
    from sqlalchemy import text
    with get_session() as session:
        row = session.execute(text("SELECT scenario, mode, summary FROM attack_runs WHERE id = :id"), {"id": attack_id}).mappings().first()
    if row is None:
        return {"error": "not found"}
    return {"attack_id": attack_id, "scenario": row["scenario"], "mode": row["mode"], "summary": row["summary"]}