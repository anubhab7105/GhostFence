"""Normalisation helpers for policy evaluation (Phase 1)."""

import ipaddress
import unicodedata
from fnmatch import fnmatch
from urllib.parse import urlsplit


def normalize_text(value: str) -> str:
    if "\x00" in value:
        raise ValueError("null byte in text")
    return unicodedata.normalize("NFC", value)


def normalize_path(value: str) -> str:
    if "\x00" in value:
        raise ValueError("null byte in path")
    value = unicodedata.normalize("NFC", value)
    # Collapse traversal segments without touching the filesystem.
    parts = []
    for part in value.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    normalized = "/" + "/".join(parts)
    return normalized


def normalize_domain(value: str) -> str:
    value = normalize_text(value).strip().lower().rstrip(".")
    # Convert IDNA/Unicode domains to punycode for stable comparison.
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError:
        return value


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def ip_is_blocked(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return True
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return True
    # RFC1918 / private ranges
    if addr.is_private:
        return True
    # Cloud metadata (explicit)
    if str(addr) == "169.254.169.254":
        return True
    return False


def normalize_url(value: str) -> dict:
    if "\x00" in value:
        raise ValueError("null byte in url")
    value = unicodedata.normalize("NFC", value)
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("invalid url")
    if parsed.username or parsed.password:
        raise ValueError("userinfo not allowed")
    host = parsed.hostname
    if not host:
        raise ValueError("missing host")
    host = normalize_domain(host)
    port = parsed.port
    if is_ip_literal(host) and ip_is_blocked(host):
        raise ValueError("blocked ip literal")
    return {
        "scheme": parsed.scheme.lower(),
        "host": host,
        "port": port,
        "path": parsed.path or "/",
        "query": parsed.query,
    }


def suffix_domain_match(host: str, allowed: str) -> bool:
    host = normalize_domain(host)
    allowed = normalize_domain(allowed)
    return host == allowed or host.endswith("." + allowed)


def glob_match(value: str, pattern: str) -> bool:
    return fnmatch(value, pattern)