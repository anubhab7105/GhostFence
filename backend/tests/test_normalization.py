"""Hypothesis property tests for normalisation (Phase 1 gate)."""

from hypothesis import given, strategies as st

from app.policy_engine.normalization import (
    ip_is_blocked,
    normalize_domain,
    normalize_path,
    normalize_text,
    suffix_domain_match,
)


@given(st.text())
def test_normalize_text_never_contains_null(value):
    try:
        out = normalize_text(value)
    except ValueError:
        assert "\x00" in value
        return
    assert "\x00" not in out


@given(st.text())
def test_normalize_path_no_traversal_escapes(value):
    try:
        out = normalize_path(value)
    except ValueError:
        assert "\x00" in value
        return
    assert ".." not in out.split("/")


@given(st.text(), st.text())
def test_suffix_domain_match_is_not_suffix_only(host, allowed):
    # A host must equal the allowed domain or be a proper subdomain, never a bare suffix.
    if host and allowed and host.endswith(allowed) and not host.endswith("." + allowed) and host != allowed:
        assert not suffix_domain_match(host, allowed)


@given(st.sampled_from(["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.1", "::1"]))
def test_blocked_ips(ip):
    assert ip_is_blocked(ip)


@given(st.sampled_from(["8.8.8.8", "1.1.1.1"]))
def test_public_ips_not_blocked(ip):
    assert not ip_is_blocked(ip)


def test_punycode_normalization():
    assert normalize_domain("ExAmPlE.com") == "example.com"
    assert normalize_domain("münchen.de").startswith("xn--")