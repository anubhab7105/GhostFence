"""Egress HTTP client with DNS pinning and address validation (FR-21, Phase 1)."""

import ipaddress
import json
import os
import socket
from typing import Callable
from urllib.parse import urlunsplit

import httpx

from ..core.settings import settings
from ..policy_engine.normalization import ip_is_blocked, is_ip_literal, normalize_domain


class EgressBlocked(Exception):
    pass


class EgressClient:
    def __init__(self, resolver: Callable[[str], list[str]] | None = None, transport=None, demo_allow: bool | None = None):
        env_map = os.getenv("GHOSTFENCE_EGRESS_RESOLVER_JSON")
        if resolver is None and env_map:
            import json as _json
            mapping = _json.loads(env_map)
            def _resolver(host):
                if host in mapping:
                    return mapping[host]
                return [r[4][0] for r in socket.getaddrinfo(host, None)]
            resolver = _resolver
        self.resolver = resolver or (lambda host: [r[4][0] for r in socket.getaddrinfo(host, None)])
        self.transport = transport
        self.demo_allow = settings.demo_allow_evil_test if demo_allow is None else demo_allow
        self.demo_hosts = {"evil.test", "reports.internal.test", "reports.internal.test.evil.test"}

    def _validate_host(self, host: str) -> list[str]:
        host = normalize_domain(host)
        if host in self.demo_hosts and self.demo_allow:
            # Demo-only allow rule: still resolve and pin, but do not block these exact hosts.
            pass
        if is_ip_literal(host) and ip_is_blocked(host) and host not in self.demo_hosts:
            # IP literal blocked unless demo host (demo hosts are names, not IPs)
            raise EgressBlocked(f"blocked address: {host}")
        try:
            ipaddress.ip_address(host)
            ips = [host]
        except ValueError:
            ips = self.resolver(host)
        if not ips:
            raise EgressBlocked("dns resolution failed")
        for ip in ips:
            if ip_is_blocked(ip):
                if not (host in self.demo_hosts and self.demo_allow):
                    raise EgressBlocked(f"blocked resolved address: {ip}")
        return ips

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        from urllib.parse import urlsplit

        parsed = urlsplit(url)
        host = parsed.hostname
        if not host:
            raise EgressBlocked("missing host")
        ips = self._validate_host(host)
        ip = ips[0]
        port = parsed.port
        # Build pinned URL
        netloc = ip
        if port:
            netloc = f"{ip}:{port}"
        pinned_url = urlunsplit((parsed.scheme, netloc, parsed.path or "/", parsed.query, ""))
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.setdefault("Host", host if not port or port in (80, 443) else f"{host}:{port}")
        extensions = dict(kwargs.pop("extensions", {}) or {})
        if parsed.scheme == "https":
            extensions["sni_hostname"] = host
        client_kwargs = {}
        if self.transport is not None:
            client_kwargs["transport"] = self.transport
        async with httpx.AsyncClient(follow_redirects=False, **client_kwargs) as client:
            response = await client.request(method, pinned_url, headers=headers, extensions=extensions, **kwargs)
        return response