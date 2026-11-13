"""Tests for the deterministic risk engine (Feature G)."""

from __future__ import annotations

from detection.findings import make_finding
from detection.risk_engine import CATEGORY_LIMITS, classify, score_findings


def _payment(points, fid="PAY_X"):
    return make_finding(fid, "payment", "Payment indicator", "critical", points)


def test_classification_thresholds():
    assert classify(0)["key"] == "low"
    assert classify(24)["key"] == "low"
    assert classify(25)["key"] == "moderate"
    assert classify(49)["key"] == "moderate"
    assert classify(50)["key"] == "high"
    assert classify(74)["key"] == "high"
    assert classify(75)["key"] == "critical"
    assert classify(100)["key"] == "critical"


def test_category_cap_limits_repeated_indicators():
    findings = [_payment(18, fid=f"PAY_{i}") for i in range(5)]
    score = score_findings(findings, {"coverage": 1.0, "completed_checks": 5, "total_checks": 5})
    payment_row = next(r for r in score["breakdown"] if r["key"] == "payment")
    assert payment_row["raw_points"] == 90
    assert payment_row["points"] == CATEGORY_LIMITS["payment"] == 25


def test_duplicate_findings_are_not_double_counted():
    findings = [_payment(18, fid="PAY_DUP"), _payment(18, fid="PAY_DUP")]
    score = score_findings(findings, {"coverage": 1.0, "completed_checks": 3, "total_checks": 3})
    payment_row = next(r for r in score["breakdown"] if r["key"] == "payment")
    assert payment_row["points"] == 18
    assert payment_row["indicator_count"] == 1


def test_low_score_with_low_coverage_is_insufficient_evidence():
    score = score_findings([], {"coverage": 0.1, "completed_checks": 1, "total_checks": 10})
    assert score["score"] == 0
    assert score["evidence_status"] == "insufficient"
    assert score["headline"] == "Insufficient evidence"


def test_low_score_with_good_coverage_is_not_insufficient():
    score = score_findings([], {"coverage": 0.9, "completed_checks": 9, "total_checks": 10})
    assert score["evidence_status"] == "adequate"
    assert score["headline"] == "Low detected risk"


def test_payment_indicator_produces_stop_payment_recommendation():
    score = score_findings(
        [_payment(18, fid="PAY_REGISTRATION_FEE")],
        {"coverage": 1.0, "completed_checks": 5, "total_checks": 5},
    )
    titles = {r["title"] for r in score["recommendations"]}
    assert "Do not pay any money" in titles
    priorities = {r["priority"] for r in score["recommendations"]}
    assert "critical" in priorities


def test_score_is_never_a_probability_and_breakdown_covers_all_categories():
    score = score_findings([], {"coverage": 0.0})
    keys = [row["key"] for row in score["breakdown"]]
    assert keys == ["payment", "domain", "company", "document", "osint", "message"]
    assert 0 <= score["score"] <= 100
