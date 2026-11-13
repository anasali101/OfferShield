"""Tests for domain intelligence and SSRF protection (Feature C)."""

from __future__ import annotations

import pytest

from detection.domain_checker import (
    UnsafeURLError,
    analyze_domain,
    brand_similarity_findings,
    url_pattern_findings,
    validate_public_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/admin",
        "http://10.0.0.5/",
        "http://192.168.1.10/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://localhost/",
        "http://metadata.google.internal/",
    ],
)
def test_private_and_metadata_targets_are_blocked(url):
    with pytest.raises(UnsafeURLError):
        validate_public_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/file",
        "file:///etc/passwd",
        "http://user:pass@example.com/",
        "http://example.com:22/",
        "javascript:alert(1)",
    ],
)
def test_disallowed_schemes_credentials_and_ports_are_blocked(url):
    with pytest.raises(UnsafeURLError):
        validate_public_url(url)


def test_plain_https_url_is_normalised_and_accepted():
    normalized, host = validate_public_url("https://careers.example.com/apply?src=x#frag")
    assert host == "careers.example.com"
    assert normalized.startswith("https://careers.example.com/apply")
    assert "#frag" not in normalized


def test_ip_literal_pattern_finding():
    findings = url_pattern_findings("http://203.0.113.10/apply", "203.0.113.10")
    assert any(f["id"] == "DOM_IP_LITERAL" for f in findings)


def test_punycode_pattern_finding():
    findings = url_pattern_findings("https://xn--80ak6aa92e.com/", "xn--80ak6aa92e.com")
    assert any(f["id"] == "DOM_PUNYCODE" for f in findings)


def test_brand_impersonation_domain_flagged():
    findings, matches = brand_similarity_findings("infosys-careers.com")
    assert any(f["id"] in {"DOM_SIMILAR_BRAND", "DOM_LOOKALIKE_SUBDOMAIN"} for f in findings)
    assert matches and matches[0]["brand"] == "Infosys"


def test_official_brand_domain_is_clean_not_warning():
    findings, matches = brand_similarity_findings("infosys.com")
    assert any(f["id"] == "DOM_OFFICIAL_BRAND_DOMAIN" and f["severity"] == "clean" for f in findings)
    assert all(f["severity"] != "high" for f in findings)
    assert matches[0]["match"] == "official"


def test_unrelated_domain_has_no_brand_match():
    findings, matches = brand_similarity_findings("totally-unrelated-company.com")
    assert matches == []
    assert all(f["id"] not in {"DOM_SIMILAR_BRAND", "DOM_LOOKALIKE_SUBDOMAIN"} for f in findings)


def test_network_disabled_reports_checks_as_unknown_not_clean(config):
    result = analyze_domain("https://careers.example.com/", config)
    assert result["blocked"] is False
    assert result["network_enabled"] is False
    statuses = {c["key"]: c["status"] for c in result["checks"]}
    assert statuses.get("dns") == "unknown"
    assert statuses.get("ssl") == "unknown"
    assert statuses.get("domain_registration") == "unknown"


def test_blocked_url_is_reported_not_contacted(config):
    result = analyze_domain("http://127.0.0.1/", config)
    assert result["blocked"] is True
    safety = next(c for c in result["checks"] if c["key"] == "url_safety")
    assert safety["status"] == "fail"
