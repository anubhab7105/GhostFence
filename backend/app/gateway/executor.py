"""Gateway-side tool executor (FR-1, D5)."""

import os
from pathlib import Path

from ..core.settings import settings


DATA_ROOT = Path(os.environ.get("GHOSTFENCE_DATA_ROOT", "/tmp/ghostfence-data"))


async def execute_tool(tool_name: str, arguments: dict, egress) -> dict:
    if tool_name == "read_file":
        path = arguments.get("path", "")
        # Prevent traversal; resolve under DATA_ROOT.
        target = (DATA_ROOT / path.lstrip("/")).resolve()
        if DATA_ROOT.resolve() not in target.parents and target != DATA_ROOT.resolve():
            raise ValueError("path traversal")
        if not target.is_file():
            raise FileNotFoundError(str(target))
        return {"content": target.read_text(errors="replace"), "path": path}

    if tool_name == "fetch_document":
        url = arguments.get("url", "")
        response = await egress.request("GET", url)
        return {"status_code": response.status_code, "content": response.text}

    if tool_name == "http_request":
        method = arguments.get("method", "GET")
        url = arguments.get("url", "")
        response = await egress.request(method, url)
        return {"status_code": response.status_code, "content": response.text, "headers": dict(response.headers)}

    if tool_name == "send_email":
        # Deliver to mock mailbox: store in sink-like endpoint if URL provided, else record.
        return {"delivered": True, "to": arguments.get("to"), "subject": arguments.get("subject")}

    if tool_name == "delete_record":
        return {"deleted": arguments.get("record_id")}

    if tool_name in {"transfer_money", "export_customers"}:
        raise PermissionError("denied by policy")

    raise ValueError(f"no executor for {tool_name}")