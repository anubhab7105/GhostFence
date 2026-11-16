"""GhostFence gateway application (Phase 0 scaffold)."""

from fastapi import FastAPI

app = FastAPI(title="GhostFence", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "ghostfence"}