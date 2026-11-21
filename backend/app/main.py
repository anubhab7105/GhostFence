"""GhostFence gateway application."""

import json
from contextlib import asynccontextmanager
from pathlib import Path

import yaml
import asyncio

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse

from .api.deps import run_token_payload
from .core.security import role_for_api_key
from .api.attacks import router as attacks_router
from .api.inspect import router as inspect_router
from .api.llm import router as llm_router
from .api.policies import router as policies_router
from .api.runs import router as runs_router
from .audit.recovery import recover_pending_outcomes
from .audit.service import append_entry, verify_chain
from .core.db import ping
from .core.settings import settings
from .gateway.egress import EgressClient
from .gateway.executor import execute_tool
from .gateway.pipeline import execute_request
from .gateway.runs import get_run, is_tainted
from .schemas.api import ExecuteRequest
from .policy_engine.engine import PolicyEngine
from .policy_engine.loaders import load_destinations, load_policy, load_registry, load_resources

app_state = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    registry = load_registry(settings.tool_registry_path)
    policy = load_policy(settings.policy_path)
    resources = load_resources(settings.resources_path)
    destinations = load_destinations(settings.destinations_path)
    engine = PolicyEngine(policy, registry, resources, destinations)
    engine.validate_startup()
    app_state["registry"] = registry
    app_state["policy_engine"] = engine
    app_state["resources"] = resources
    app_state["destinations"] = destinations
    app_state["egress"] = EgressClient(allowed_hosts={d.host for d in destinations.destinations})
    try:
        recover_pending_outcomes()
    except Exception:
        pass
    yield


app = FastAPI(title="GhostFence", version="0.1.0", lifespan=lifespan)


@app.get("/health")
def health():
    try:
        ping()
        db_ok = True
    except Exception:
        db_ok = False
    return {"status": "ok", "service": "ghostfence", "db": db_ok}


app.include_router(attacks_router)
app.include_router(policies_router)
app.include_router(runs_router)
app.include_router(inspect_router)
app.include_router(llm_router)


@app.post("/v1/execute", response_model_exclude_none=True)
async def execute_endpoint(req: ExecuteRequest, token: dict = Depends(run_token_payload)):
    from .schemas.api import ExecuteRequest

    return await execute_request(req, token)


@app.get("/v1/audit")
def audit_list():
    return {"entries": []}


@app.get("/v1/stream")
async def stream():
    async def event_generator():
        while True:
            yield "data: {\"status\":\"ok\"}\n\n"
            await asyncio.sleep(15)
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/v1/audit/verify")
def audit_verify():
    return verify_chain()


@app.post("/v1/audit/tamper-demo")
def tamper_demo(sequence: int, new_reason: str, x_api_key: str | None = Header(default=None)):
    import os
    from sqlalchemy import create_engine, text

    if x_api_key is None or role_for_api_key(x_api_key) != "admin":
        raise HTTPException(status_code=403, detail="admin required")
    from .core.settings import settings
    if not settings.demo_mode:
        raise HTTPException(status_code=404, detail="demo mode disabled")
    url = os.getenv("TAMPER_ADMIN_DATABASE_URL")
    if not url:
        raise HTTPException(status_code=404, detail="tamper admin not configured")
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("UPDATE audit_entries SET reason_code = :r WHERE sequence = :s"), {"r": new_reason, "s": sequence})
    engine.dispose()
    return {"tampered": True, "sequence": sequence}
