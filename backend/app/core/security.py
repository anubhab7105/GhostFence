"""API keys, operator keys, and signed run tokens."""

import base64
import hashlib
import hmac
import json
import time

from .settings import settings


def hash_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def verify_api_key(provided: str, expected: str) -> bool:
    return hmac.compare_digest(hash_key(provided), hash_key(expected))


ROLE_KEYS = {
    "admin": settings.admin_api_key,
    "approver": settings.approver_api_key,
    "agent": settings.agent_api_key,
}


def role_for_api_key(provided: str) -> str | None:
    for role, expected in ROLE_KEYS.items():
        if verify_api_key(provided, expected):
            return role
    return None


def issue_run_token(run_id: str, agent_id: str, session_id: str, expires_at: int) -> str:
    payload = {
        "run_id": run_id,
        "agent_id": agent_id,
        "session_id": session_id,
        "exp": expires_at,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    sig = hmac.new(settings.run_token_secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_run_token(token: str) -> dict | None:
    try:
        body, sig = token.split(".", 1)
    except ValueError:
        return None
    expected = hmac.new(settings.run_token_secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    padded = body + "=" * (-len(body) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except Exception:
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload