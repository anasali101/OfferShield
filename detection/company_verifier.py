"""Feature E: company and recruiter verification.

This module only reports what can actually be checked. A recognised brand name
or matching email domain is NOT treated as proof that a vacancy or recruiter is
genuine. MCA (India) confirmation requires a manual CAPTCHA-based search, so it
is reported as unverified rather than fabricated.
"""

from __future__ import annotations

import re

from detection.brands import FREE_EMAIL_DOMAINS, KNOWN_BRANDS
from detection.findings import make_finding
from detection.utils import registrable_domain

MCA_PORTAL = "https://www.mca.gov.in/content/mca/global/en/mca/master-data/MDS.html"


def verify_company(text: str, entities: dict, domain_result: dict | None = None) -> dict:
    text = text or ""
    companies = entities.get("companies", []) if entities else []
    emails = entities.get("emails", []) if entities else []
    recruiters = entities.get("recruiters", []) if entities else []
    email_domains = _unique([email.split("@", 1)[1].lower() for email in emails if "@" in email])

    claimed_brand = _detect_brand_claim(text, companies, domain_result)
    official_domains = KNOWN_BRANDS[claimed_brand]["domains"] if claimed_brand else []
    display = KNOWN_BRANDS[claimed_brand]["display"] if claimed_brand else None

    findings: list[dict] = []
    checks: list[dict] = []
    matched_official_email = None
    matched_site_email = None
    status = "unverified"

    if claimed_brand:
        findings.append(
            make_finding(
                "CO_BRAND_RECOGNIZED", "company",
                f"Message references the known brand {display}",
                "info", 0,
                evidence=_brand_evidence(text, companies, claimed_brand),
                why="Recognising a brand name does not verify the sender. Scammers frequently use well-known company names.",
                source="company_verifier",
            )
        )
        matched_official_email = next(
            (domain for domain in email_domains if _domain_matches_any(domain, official_domains)),
            None,
        )
        if matched_official_email:
            status = "partially_verified"
            findings.append(
                make_finding(
                    "CO_EMAIL_MATCHES_OFFICIAL", "company",
                    f"Recruiter email uses the official {display} domain",
                    "clean", 0,
                    evidence=f"{matched_official_email} matches {', '.join(official_domains)}",
                    why="A matching corporate domain is a positive signal, but email display names and accounts can still be compromised or spoofed. It does not verify the vacancy or the individual recruiter.",
                    source="company_verifier", verified=True,
                )
            )
        elif email_domains:
            primary = email_domains[0]
            free_note = " The domain is also a free consumer email provider." if primary in FREE_EMAIL_DOMAINS else ""
            findings.append(
                make_finding(
                    "CO_BRAND_EMAIL_MISMATCH", "company",
                    f"Recruiter email domain does not match {display}'s official domain",
                    "high", 14,
                    evidence=f"{', '.join(email_domains[:3])} vs official {', '.join(official_domains)}",
                    why=(
                        "The message claims a well-known brand but the sender uses an unrelated email domain. "
                        "This is a common impersonation pattern. It is strong evidence to investigate, not absolute proof."
                        + free_note
                    ),
                    source="company_verifier",
                )
            )
        else:
            findings.append(
                make_finding(
                    "CO_NO_EMAIL_FOR_BRAND", "company",
                    f"{display} is named but no recruiter email was found",
                    "unknown", 0,
                    evidence=_brand_evidence(text, companies, claimed_brand),
                    why="Without an email domain, domain consistency cannot be checked. This is missing information, not evidence of fraud.",
                    source="company_verifier",
                )
            )
    else:
        if email_domains and any(domain in FREE_EMAIL_DOMAINS for domain in email_domains):
            free = [d for d in email_domains if d in FREE_EMAIL_DOMAINS]
            findings.append(
                make_finding(
                    "CO_FREE_EMAIL", "company",
                    "Recruiter uses a free consumer email service",
                    "medium", 8,
                    evidence=", ".join(free),
                    why="Small businesses sometimes use free email, so this is not proof of fraud. Established companies and placement agencies normally use corporate domains.",
                    source="company_verifier",
                )
            )
        if email_domains and domain_result and not domain_result.get("blocked"):
            site_reg = domain_result.get("registrable_domain")
            email_regs = [registrable_domain(domain) for domain in email_domains]
            if site_reg and site_reg in email_regs:
                matched_site_email = site_reg
                findings.append(
                    make_finding(
                        "CO_EMAIL_MATCHES_SITE", "company",
                        "Recruiter email domain matches the submitted website",
                        "clean", 0,
                        evidence=f"{site_reg}",
                        why="The email and website share a domain. This is a weak consistency signal only: the website itself may still be fraudulent.",
                        source="company_verifier",
                    )
                )
            elif site_reg and all(domain in FREE_EMAIL_DOMAINS for domain in email_domains):
                pass
            elif site_reg:
                findings.append(
                    make_finding(
                        "CO_EMAIL_SITE_MISMATCH", "company",
                        "Recruiter email domain does not match the submitted website",
                        "medium", 8,
                        evidence=f"Email: {', '.join(email_domains[:3])}; site: {site_reg}",
                        why="Mismatched contact domains are worth explaining. Recruiters at agencies may legitimately use a different domain, so this is not conclusive.",
                        source="company_verifier",
                    )
                )
        if not companies and not email_domains and not recruiters:
            findings.append(
                make_finding(
                    "CO_IDENTITY_MISSING", "company",
                    "No company, recruiter name or email could be extracted",
                    "unknown", 0,
                    evidence="",
                    why="Without an identity claim, automated verification is not possible. Missing information is not evidence of fraud.",
                    source="company_verifier",
                )
            )

    medium_companies = [c["name"] for c in companies if c.get("confidence") == "medium"]
    if len(medium_companies) >= 2:
        findings.append(
            make_finding(
                "CO_MULTIPLE_COMPANIES", "company",
                "Multiple different company names appear in the offer",
                "low", 4,
                evidence="; ".join(medium_companies[:4]),
                why="Inconsistent company names can indicate a copied template. Offers sometimes legitimately involve a client and a staffing agency, so confirm the contracting entity.",
                source="company_verifier",
            )
        )

    # Always-present, honestly reported checks.
    checks.append(
        _check(
            "company_email_consistency",
            "Email domain consistency",
            "pass" if (matched_official_email or matched_site_email) else ("fail" if _has_company_failure(findings) else "unknown"),
            _email_detail(email_domains, official_domains, display),
        )
    )
    checks.append(
        _check(
            "company_existence",
            "Company existence (registry)",
            "unknown",
            "Automated company registry verification is not available in this MVP. "
            + (f"The brand name {display} was recognised in the built-in reference list, which is not a registry check." if display else "No independent registry check was performed."),
        )
    )
    checks.append(
        _check(
            "recruiter_identity",
            "Recruiter identity",
            "unknown",
            "OfferShield cannot verify that the sender is an authorised employee. Contact the company through its official switchboard or careers portal.",
        )
    )
    checks.append(
        _check(
            "mca_records",
            "MCA records (India)",
            "unknown",
            f"MCA master data requires a manual, CAPTCHA-protected search: {MCA_PORTAL}",
        )
    )

    return {
        "claimed_brand": display,
        "official_domains": official_domains,
        "claimed_companies": companies[:6],
        "recruiter_names": recruiters[:5],
        "email_domains": email_domains,
        "status": status,
        "status_label": "Partially verified (email domain only)" if status == "partially_verified" else "Unverified",
        "scope": (
            "Company-level brand reference and email-domain consistency only. "
            "The recruiter and vacancy are not verified."
            if status == "partially_verified"
            else "No independent verification of the employer, recruiter or vacancy was completed."
        ),
        "findings": findings,
        "checks": checks,
        "mca": {
            "status": "manual",
            "url": MCA_PORTAL,
            "note": "MCA master data search requires manual CAPTCHA entry. No automated result is claimed.",
        },
    }


def _detect_brand_claim(text: str, companies: list[dict], domain_result: dict | None) -> str | None:
    for brand_key, info in KNOWN_BRANDS.items():
        patterns = {brand_key, info["display"].lower()}
        for pattern in patterns:
            if re.search(r"\b" + re.escape(pattern) + r"\b", text, re.IGNORECASE):
                return brand_key
    if domain_result:
        for match in domain_result.get("brand_matches", []) or []:
            official = match.get("official_domain", "")
            for brand_key, info in KNOWN_BRANDS.items():
                if official in info["domains"] and match.get("match") == "official":
                    return brand_key
    for company in companies:
        name = company.get("name", "").lower()
        for brand_key in KNOWN_BRANDS:
            if brand_key in name:
                return brand_key
    return None


def _brand_evidence(text: str, companies: list[dict], brand_key: str) -> str:
    info = KNOWN_BRANDS[brand_key]
    for company in companies:
        if brand_key in company.get("name", "").lower() or info["display"].lower() in company.get("name", "").lower():
            return company.get("snippet", "")[:300]
    match = re.search(r"\b" + re.escape(brand_key) + r"\b", text, re.IGNORECASE)
    if match:
        from detection.utils import make_snippet
        return make_snippet(text, match.start(), match.end(), 80)
    return info["display"]


def _domain_matches_any(domain: str, official_domains: list[str]) -> bool:
    domain = (domain or "").lower()
    return any(domain == official or domain.endswith("." + official) for official in official_domains)


def _has_company_failure(findings: list[dict]) -> bool:
    return any(f["severity"] in {"critical", "high"} for f in findings)


def _email_detail(email_domains: list[str], official_domains: list[str], display: str | None) -> str:
    if not email_domains:
        return "No recruiter email was found, so consistency could not be checked."
    if not display:
        return f"Email domain(s): {', '.join(email_domains[:3])}. No official domain to compare against."
    if any(_domain_matches_any(domain, official_domains) for domain in email_domains):
        return f"Email domain matches official {display} domain(s): {', '.join(official_domains)}."
    return f"Email domain(s) {', '.join(email_domains[:3])} do not match {display}'s official domain(s) {', '.join(official_domains)}. Verify independently."


def _check(key: str, label: str, status: str, detail: str) -> dict:
    return {"key": key, "label": label, "status": status, "detail": str(detail or "")[:260], "source": "company"}


def _unique(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
