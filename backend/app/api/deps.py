"""FastAPI dependencies."""

from fastapi import Header, HTTPException

from ..core.security import role_for_api_key, verify_run_token


def api_key_role(x_api_key: str | None = Header(default=None)) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="missing api key")
    role = role_for_api_key(x_api_key)
    if role is None:
        raise HTTPException(status_code=401, detail="invalid api key")
    return role


def require_operator(x_api_key: str | None = Header(default=None)) -> str:
    role = api_key_role(x_api_key)
    if role not in {"admin", "approver"}:
        raise HTTPException(status_code=403, detail="operator required")
    return role


def run_token_payload(x_run_token: str | None = Header(default=None)) -> dict:
    if not x_run_token:
        raise HTTPException(status_code=401, detail="missing run token")
    payload = verify_run_token(x_run_token)
    if payload is None:
        raise HTTPException(status_code=401, detail="invalid run token")
    return payload