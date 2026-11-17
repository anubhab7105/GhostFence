"""Run lifecycle endpoints."""

from fastapi import APIRouter, Depends, HTTPException

from ..gateway.runs import close_run, create_run, get_run
from ..schemas.api import RunCloseRequest, RunCreateRequest

router = APIRouter(prefix="/v1/runs", tags=["runs"])


@router.post("")
def create_run_endpoint(req: RunCreateRequest, role: str = Depends(__import__("fastapi").Depends if False else None) if False else None):
    pass
```

Oops accidental. Let's write cleanly.<|end|><|start|>assist to=tool<|channel|>analysis <|constrain|>xml<|message|><rfl:parameter name="command">
cat > /home/babai/Desktop/codeing/GhostFence/backend/app/api/runs.py <<'PY'
"""Run lifecycle endpoints."""

from fastapi import APIRouter, Depends, HTTPException

from ..api.deps import api_key_role
from ..gateway.runs import close_run, create_run, get_run
from ..schemas.api import RunCloseRequest, RunCreateRequest

router = APIRouter(prefix="/v1/runs", tags=["runs"])


@router.post("")
def create_run_endpoint(req: RunCreateRequest, role: str = Depends(api_key_role)):
    if role not in {"agent", "admin"}:
        raise HTTPException(status_code=403, detail="agent required")
    from ..core.settings import settings
    result = create_run(req.agent_id, req.task, {"scenario_id": req.scenario_id, "mode": req.mode}, ttl=settings.run_ttl_seconds)
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
PY