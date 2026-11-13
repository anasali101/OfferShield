"""Common finding model used by every detector.

A finding is a single, explainable piece of evidence. Points are assigned by
the detector but are always capped and summed by the deterministic risk engine.
"""

from __future__ import annotations

from detection.utils import safe_text

SEVERITIES = {"critical", "high", "medium", "low", "info", "clean", "unknown"}
WARNING_SEVERITIES = {"critical", "high", "medium", "low"}


def make_finding(
    finding_id: str,
    category: str,
    title: str,
    severity: str,
    points: int = 0,
    evidence: str = "",
    why: str = "",
    source: str = "",
    verified: bool = False,
) -> dict:
    if severity not in SEVERITIES:
        severity = "info"
    return {
        "id": finding_id,
        "category": category,
        "title": safe_text(title, 140),
        "severity": severity,
        "points": max(0, int(points)) if severity in WARNING_SEVERITIES else 0,
        "evidence": safe_text(evidence, 400),
        "why": safe_text(why, 600),
        "source": safe_text(source, 40),
        "verified": bool(verified),
    }


def merge_findings(findings: list[dict]) -> list[dict]:
    """Deduplicate by id so the same indicator is never double-counted."""
    merged: dict[str, dict] = {}
    for finding in findings:
        fid = finding.get("id")
        if not fid:
            continue
        if fid not in merged:
            merged[fid] = dict(finding)
            continue
        existing = merged[fid]
        # Keep the higher point value but never add points twice.
        if finding.get("points", 0) > existing.get("points", 0):
            existing["points"] = finding["points"]
        if finding.get("severity") == "critical":
            existing["severity"] = "critical"
        new_evidence = finding.get("evidence", "")
        if new_evidence and new_evidence not in existing.get("evidence", ""):
            combined = (existing.get("evidence", "") + " | " + new_evidence).strip(" |")
            existing["evidence"] = combined[:400]
    return list(merged.values())
