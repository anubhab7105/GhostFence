"""Checkpointer service (Phase 6, D10)."""

import base64
import json
import os
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from ..core.db import get_session, session_scope

KEY_PATH = os.getenv("CHECKPOINTER_KEY_PATH", "/var/lib/ghostfence/checkpoints/key.pem")
POLL_SECONDS = int(os.getenv("CHECKPOINTER_POLL_SECONDS", "30"))


def _load_or_create_key():
    from cryptography.hazmat.primitives import serialization

    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = Ed25519PrivateKey.generate()
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    with open(KEY_PATH, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key


def _checkpoint_once(key):
    with get_session() as session:
        row = session.execute(text("SELECT last_sequence, encode(last_hash, 'hex') AS last_hash FROM audit_chain_head WHERE id = 1")).mappings().first()
    if row is None:
        return
    payload = {"sequence": int(row["last_sequence"]), "last_hash": row["last_hash"], "ts": int(time.time())}
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    sig = key.sign(raw)
    signed = base64.b64encode(raw + b"." + sig).decode("ascii")
    import uuid
    with session_scope() as session:
        session.execute(
            text("INSERT INTO checkpoints (id, sequence, signed_checkpoint) VALUES (:id, :seq, decode(:cp, 'base64'))"),
            {"id": str(uuid.uuid4()), "seq": payload["sequence"], "cp": base64.b64encode(signed.encode()).decode()},
        )


def main():
    key = _load_or_create_key()
    while True:
        try:
            _checkpoint_once(key)
        except Exception:
            pass
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()