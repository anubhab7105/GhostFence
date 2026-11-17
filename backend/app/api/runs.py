"""Run lifecycle endpoints."""

from fastapi import APIRouter, Depends, HTTPException

from ..api.deps import api_key_role
from ..gateway.runs import close_run, create_run, get_run
from ..schemas.api import RunCloseRequest, RunCreateRequest

router = APIRouter(prefix="/v1/runs", tags=["runs"])


@router.post("")
def create_run_endpoint(req: RunCreateRequest, role: str = Depends(api_key_role)):
    if role not in {"agent", "admin", "approver"}:
        raise HTTPException(status_code=403, detail="auth required")
    mode = req.mode if role in {"admin", "approver"} else "enforce"
    from ..core.settings import settings
    result = create_run(req.agent_id, req.task, {"scenario_id": req.scenario_id, "mode": mode}, ttl=settings.run_ttl_seconds)
    return result


@router.post("/{run_id}/close")
def close_run_endpoint(run_id: str, req: RunCloseRequest, role: str = Depends(api_key_role)):
    ok = close_run(run_id, req.status)
    if not ok:
        raise HTTPException(status_code=404, detail="run not found")
    return {"status": req.status}


@router.get("/{run_id}")
def get_run_endpoint(run_id: str, role: str = Depends(api_key_role)):
    run = get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    return run