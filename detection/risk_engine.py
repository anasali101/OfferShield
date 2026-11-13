"""Feature G: transparent, deterministic risk scoring.

The score is a capped sum of detected indicators. It is NOT a probability of
fraud and never depends on the AI layer.
"""

from __future__ import annotations

from detection.findings import WARNING_SEVERITIES, merge_findings

CATEGORY_LIMITS = {
    "payment": 25,
    "domain": 20,
    "company": 20,
    "document": 15,
    "osint": 10,
    "message": 10,
}

CATEGORY_LABELS = {
    "payment": "Payment fraud indicators",
    "domain": "Domain & website intelligence",
    "company": "Company verification",
    "document": "Offer letter analysis",
    "osint": "OSINT & reputation",
    "message": "Recruitment message patterns",
}

CATEGORY_ORDER = ["payment", "domain", "company", "document", "osint", "message"]

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "clean": 5,
    "unknown": 6,
}


def classify(score: int) -> dict:
    if score >= 75:
        return {"key": "critical", "label": "Critical risk", "level": 4}
    if score >= 50:
        return {"key": "high", "label": "High risk", "level": 3}
    if score >= 25:
        return {"key": "moderate", "label": "Moderate warning signs", "level": 2}
    return {"key": "low", "label": "Low detected risk", "level": 1}


def score_findings(findings: list[dict], context: dict | None = None) -> dict:
    """Score findings and return a complete, explainable breakdown."""
    context = context or {}
    merged = merge_findings(findings)

    breakdown = []
    total = 0
    for category in CATEGORY_ORDER:
        cap = CATEGORY_LIMITS[category]
        category_findings = [
            f for f in merged
            if f.get("category") == category and f.get("severity") in WARNING_SEVERITIES
        ]
        raw_points = sum(int(f.get("points", 0)) for f in category_findings)
        capped = min(raw_points, cap)
        total += capped
        breakdown.append(
            {
                "key": category,
                "label": CATEGORY_LABELS[category],
                "points": capped,
                "raw_points": raw_points,
                "cap": cap,
                "indicator_count": len(category_findings),
                "indicators": [
                    {"id": f["id"], "title": f["title"], "points": f.get("points", 0)}
                    for f in category_findings
                ],
                "note": (
                    f"Cap of {cap} prevents repeated {CATEGORY_LABELS[category].lower()} "
                    "from dominating the score."
                ),
            }
        )

    total = max(0, min(100, total))
    classification = classify(total)

    coverage = float(context.get("coverage", 0.0) or 0.0)
    completed = int(context.get("completed_checks", 0) or 0)
    total_checks = int(context.get("total_checks", 0) or 0)

    if total < 25 and coverage < 0.50:
        evidence_status = "insufficient"
        evidence_label = "Insufficient evidence"
        evidence_detail = (
            "The detected risk is low, but too many verification checks could not be "
            "completed to draw a meaningful conclusion. Treat the offer as unverified."
        )
    elif coverage < 0.60:
        evidence_status = "partial"
        evidence_label = "Partially verified"
        evidence_detail = (
            "Some checks completed, but important evidence is missing. Review the "
            "checks that could not be completed before trusting this offer."
        )
    else:
        evidence_status = "adequate"
        evidence_label = "Evidence reviewed"
        evidence_detail = (
            "The main automated checks completed. A low score still does not prove "
            "legitimacy; it means no indicators were detected by these checks."
        )

    warnings = [f for f in merged if f.get("severity") in WARNING_SEVERITIES]
    warnings.sort(key=lambda f: (SEVERITY_ORDER.get(f.get("severity"), 9), -f.get("points", 0)))

    positives = [f for f in merged if f.get("severity") in {"clean", "info"}]
    unknowns = [f for f in merged if f.get("severity") == "unknown"]

    return {
        "score": total,
        "classification": classification,
        "headline": (
            "Insufficient evidence" if evidence_status == "insufficient" else classification["label"]
        ),
        "evidence_status": evidence_status,
        "evidence_label": evidence_label,
        "evidence_detail": evidence_detail,
        "coverage": round(coverage, 3),
        "completed_checks": completed,
        "total_checks": total_checks,
        "breakdown": breakdown,
        "warnings": warnings,
        "positives": positives,
        "unknowns": unknowns,
        "recommendations": build_recommendations(merged, total, classification, context),
        "disclaimer": (
            "This score is a transparent count of detected warning indicators, not a "
            "mathematically established probability of fraud. A low score is not a "
            "guarantee of legitimacy."
        ),
    }


def build_recommendations(
    findings: list[dict],
    total: int,
    classification: dict,
    context: dict,
) -> list[dict]:
    ids = {f.get("id") for f in findings}
    recs: list[dict] = []

    payment_ids = {
        "PAY_REGISTRATION_FEE", "PAY_TRAINING_KIT", "PAY_SECURITY_DEPOSIT",
        "PAY_PLACEMENT_CONFIRMATION", "PAY_INTERVIEW_FEE", "PAY_PROCESSING_FEE",
        "PAY_EQUIPMENT_DEPOSIT", "PAY_COURIER_CHARGE", "PAY_PERSONAL_UPI",
        "PAY_PERSONAL_BANK_TRANSFER", "PAY_CRYPTO_GIFT_CARD",
    }
    if ids & payment_ids:
        recs.append(
            {
                "priority": "critical",
                "title": "Do not pay any money",
                "detail": (
                    "Stop all payments. No legitimate employer charges candidates for "
                    "registration, training, equipment, deposits or placement confirmation. "
                    "Do not send UPI, bank transfers, gift cards or cryptocurrency."
                ),
            }
        )

    if ids & {"MSG_SENSITIVE_DOCUMENTS", "PAY_PERSONAL_UPI", "PAY_PERSONAL_BANK_TRANSFER"}:
        recs.append(
            {
                "priority": "high",
                "title": "Protect your identity and banking details",
                "detail": (
                    "Never share OTPs, CVV, bank passwords or full identity documents with "
                    "an unverified recruiter. If you already shared financial details, contact "
                    "your bank immediately."
                ),
            }
        )

    recs.append(
        {
            "priority": "high",
            "title": "Verify through the company's official channels",
            "detail": (
                "Open the company's official website by typing its domain manually. Use the "
                "careers portal or a published switchboard number to confirm the vacancy and "
                "the recruiter. Do not rely on links or numbers supplied in the offer."
            ),
        }
    )

    if context.get("company_status") == "unverified" or "CO_VERIFICATION_INCOMPLETE" in ids:
        recs.append(
            {
                "priority": "medium",
                "title": "Company identity remains unverified",
                "detail": (
                    "OfferShield could not independently confirm the employer or the "
                    "recruiter. For Indian companies, you can search the MCA master data "
                    "portal manually (mca.gov.in); automated MCA confirmation is not "
                    "available in this MVP."
                ),
            }
        )

    if ids & {"DOM_NEW_DOMAIN", "DOM_SIMILAR_BRAND", "DOM_LOOKALIKE_SUBDOMAIN", "DOM_PUNYCODE"}:
        recs.append(
            {
                "priority": "high",
                "title": "Treat the website as untrusted",
                "detail": (
                    "A young or lookalike domain is a warning sign, not proof of fraud. "
                    "Do not log in or enter personal details. Compare the domain character "
                    "by character with the official domain published on the company's "
                    "verified social or regulatory profiles."
                ),
            }
        )

    if classification["level"] >= 3 or total >= 50:
        recs.append(
            {
                "priority": "critical",
                "title": "Report the offer",
                "detail": (
                    "In India, report cyber fraud at cybercrime.gov.in or call 1930. Report "
                    "the message to the platform where you received it, and warn classmates "
                    "or colleagues who may receive the same offer."
                ),
            }
        )

    if context.get("coverage", 0) < 0.6:
        recs.append(
            {
                "priority": "medium",
                "title": "Complete the missing checks manually",
                "detail": (
                    "Review the 'Checks not completed' section. Missing information is not "
                    "evidence of fraud, but it means the automated assessment is incomplete."
                ),
            }
        )

    if total < 25:
        recs.append(
            {
                "priority": "low",
                "title": "No indicators found is not a guarantee",
                "detail": (
                    "No strong warning indicators were detected by the checks that ran. "
                    "Still confirm the vacancy independently and never pay to secure a job."
                ),
            }
        )

    return recs
