"""Attacker sink mock (Phase 0 scaffold)."""

from fastapi import FastAPI, Request

app = FastAPI(title="GhostFence sink")
REQUESTS: list[dict] = []


@app.get("/requests")
def requests():
    return REQUESTS


@app.post("/reset")
def reset():
    REQUESTS.clear()
    return {"reset": True}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def capture(path: str, request: Request):
    body = await request.body()
    record = {
        "method": request.method,
        "path": "/" + path,
        "headers": dict(request.headers),
        "body": body.decode("utf-8", "replace"),
    }
    REQUESTS.append(record)
    return {"received": True, "count": len(REQUESTS)}