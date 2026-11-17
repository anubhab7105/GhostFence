"""SSRF, DNS rebinding and redirect tests against fakes (Phase 1 gate)."""

import httpx
import pytest

from app.gateway.egress import EgressBlocked, EgressClient


@pytest.mark.asyncio
async def test_ssrf_private_ip_blocked():
    client = EgressClient(resolver=lambda host: ["127.0.0.1"], demo_allow=False)
    with pytest.raises(EgressBlocked):
        await client.request("GET", "http://example.com/secret")


@pytest.mark.asyncio
async def test_ssrf_metadata_ip_blocked():
    client = EgressClient(resolver=lambda host: ["169.254.169.254"], demo_allow=False)
    with pytest.raises(EgressBlocked):
        await client.request("GET", "http://example.com/latest/meta-data")


@pytest.mark.asyncio
async def test_dns_rebinding_single_resolution_pins_address():
    # Resolver returns a private address; request must be blocked before any transport use.
    calls = {"n": 0}

    def resolver(host):
        calls["n"] += 1
        return ["10.0.0.5"]

    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="ok"))
    client = EgressClient(resolver=resolver, transport=transport, demo_allow=False)
    with pytest.raises(EgressBlocked):
        await client.request("GET", "http://example.com/")
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_redirect_not_followed():
    def handler(request):
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data"})

    transport = httpx.MockTransport(handler)
    client = EgressClient(resolver=lambda host: ["93.184.216.34"], transport=transport, demo_allow=False)
    response = await client.request("GET", "http://example.com/redirect")
    assert response.status_code == 302
    assert "Location" in response.headers


@pytest.mark.asyncio
async def test_demo_host_allowed():
    def handler(request):
        return httpx.Response(200, text="sink")

    transport = httpx.MockTransport(handler)
    client = EgressClient(resolver=lambda host: ["127.0.0.1"], transport=transport, demo_allow=True)
    response = await client.request("GET", "http://evil.test/exfil")
    assert response.status_code == 200