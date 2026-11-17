"""Outbound payload scanning and exfiltration checks (FR-19, FR-20)."""

import re

PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "api_key": re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*[A-Za-z0-9_\-]{8,}"),
    "card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
}

MARKDOWN_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)]+)\)")
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
HTML_IMAGE = re.compile(r"<img[^>]+src=[\"']([^\"']+)[\"']", re.I)
HTML_LINK = re.compile(r"<a[^>]+href=[\"']([^\"']+)[\"']", re.I)


def _shingle_overlap(payload: str, sensitive_markers: list[str]) -> bool:
    # Keyed shingle overlap: block if any sensitive marker appears as a shingle in payload.
    lowered = payload.lower()
    for marker in sensitive_markers:
        if marker and marker.lower() in lowered:
            return True
    return False


def scan_outbound(payload: str, destination_host: str, allowed_hosts: set[str], sensitive_markers=None, query_cap: int = 100) -> dict:
    findings = []
    # Pattern detectors
    for name, pattern in PATTERNS.items():
        if pattern.search(payload):
            findings.append(name)
    # Keyed shingle overlap
    if sensitive_markers and _shingle_overlap(payload, sensitive_markers):
        findings.append("shingle_overlap")
    # Query length cap
    if "?" in payload:
        query = payload.split("?", 1)[1]
        if len(query) > query_cap:
            findings.append("query_too_long")
    # Markdown/HTML URL blocking
    urls = []
    urls += MARKDOWN_IMAGE.findall(payload)
    urls += MARKDOWN_LINK.findall(payload)
    urls += HTML_IMAGE.findall(payload)
    urls += HTML_LINK.findall(payload)
    for url in urls:
        # Extract host best-effort
        host = url.split("//", 1)[-1].split("/", 1)[0].split("?", 1)[0]
        if host and host not in allowed_hosts:
            findings.append("blocked_url_host")
            break
    if findings:
        return {"ok": False, "reason": "outbound_scan_failed", "findings": findings}
    return {"ok": True, "reason": "clean", "findings": []}