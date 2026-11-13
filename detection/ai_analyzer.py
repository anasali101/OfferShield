"""Feature F: optional AI explanation.

The AI never computes or modifies the risk score. It receives only the
deterministic findings and structured evidence. If no API key is configured it
returns a disabled status and the rule-based report is unaffected.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

import requests

from detection.utils import clean_text

SYSTEM_PROMPT = (
    "You are a cautious cybersecurity analyst assistant for OfferShield, a "
    "recruitment-fraud detection tool. You receive deterministic findings from a "
    "rule-based engine. Use ONLY the supplied findings and facts. Never invent "
    "domain records, company records, scam reports, registry results or "
    "verification outcomes. Never state or imply a probability of fraud, and do "
    "not output a new risk score. Clearly separate (1) verified facts, (2) "
    "unverified claims, and (3) missing information. Explain in plain English why "
    "the indicators matter and give practical, calm recommendations. If the "
    "evidence is insufficient, say so. Keep the response under 300 words."
)


def generate_explanation(case: dict, message_text: str | None, consent: bool, config: dict) -> dict:
    api_key = (config.get("AI_API_KEY") or "").strip()
    if not api_key:
        return {
            "status": "disabled",
            "text": "",
            "message": (
                "AI explanations are not configured. The deterministic rule-based "
                "analysis above is complete and unaffected."
            ),
        }
    if not consent:
        return {
            "status": "skipped",
            "text": "",
            "message": (
                "AI explanation was not requested. Consent is required before derived "
                "findings are sent to an external AI provider."
            ),
        }

    base_url = (config.get("AI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
    payload = _build_payload(case, message_text)
    body = {
        "model": config.get("AI_MODEL") or "gpt-4o-mini",
        "temperature": 0.2,
        "max_tokens": 800,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Explain the following OfferShield investigation to a job seeker. "
                    "Do not add facts that are not present.\n\n"
                    + json.dumps(payload, ensure_ascii=False, indent=2)
                ),
            },
        ],
    }
    try:
        response = requests.post(
            f"{base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "OfferShield/1.0",
            },
            json=body,
            timeout=int(config.get("AI_TIMEOUT", 30)),
        )
    except requests.RequestException as exc:
        return {
            "status": "unavailable",
            "text": "",
            "message": (
                f"The AI provider could not be reached ({type(exc).__name__}). "
                "The rule-based analysis is complete and unaffected."
            ),
        }

    if response.status_code != 200:
        return {
            "status": "unavailable",
            "text": "",
            "message": (
                f"The AI provider returned HTTP {response.status_code}. "
                "No AI explanation is shown; the rule-based analysis is unaffected."
            ),
        }
    try:
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        if isinstance(content, list):
            content = " ".join(str(part.get("text", "")) if isinstance(part, dict) else str(part) for part in content)
        text = clean_text(str(content), 6000).strip()
    except (KeyError, IndexError, TypeError, ValueError):
        return {
            "status": "unavailable",
            "text": "",
            "message": "The AI response could not be interpreted. No AI explanation is shown.",
        }
    if not text:
        return {"status": "unavailable", "text": "", "message": "The AI returned an empty response."}

    host = urlparse(base_url).netloc or "configured provider"
    return {
        "status": "ok",
        "text": text,
        "model": config.get("AI_MODEL"),
        "provider": host,
        "message": "AI-assisted explanation. It does not affect the risk score.",
    }


def _build_payload(case: dict, message_text: str | None) -> dict:
    score = case.get("score", {})
    findings = [
        {
            "title": f.get("title"),
            "severity": f.get("severity"),
            "category": f.get("category"),
            "evidence": f.get("evidence"),
            "why": f.get("why"),
            "verified": f.get("verified"),
        }
        for f in case.get("findings", [])
        if f.get("severity") in {"critical", "high", "medium", "low", "clean", "unknown"}
    ][:30]
    checks = [
        {"label": c.get("label"), "status": c.get("status"), "detail": c.get("detail")}
        for c in case.get("checks", [])
    ][:30]
    entities = case.get("entities", {})
    safe_entities = {
        "companies": [c.get("name") for c in entities.get("companies", [])][:5],
        "recruiters": entities.get("recruiters", [])[:3],
        "email_domains": sorted({e.split("@", 1)[1] for e in entities.get("emails", []) if "@" in e}),
        "phone_count": len(entities.get("phones", [])),
        "urls": entities.get("urls", [])[:3],
        "amounts": [a.get("raw") for a in entities.get("amounts", [])][:10],
    }
    payload = {
        "scan_type": case.get("kind"),
        "risk_score": score.get("score"),
        "classification": score.get("classification", {}).get("label"),
        "evidence_status": score.get("evidence_label"),
        "findings": findings,
        "checks": checks,
        "entities": safe_entities,
        "company_verification": {
            "status": case.get("company", {}).get("status_label"),
            "scope": case.get("company", {}).get("scope"),
        },
        "domain_summary": {
            "host": case.get("domain", {}).get("host"),
            "registration_age_days": case.get("domain", {}).get("registration", {}).get("age_days"),
            "brand_matches": case.get("domain", {}).get("brand_matches", []),
        },
        "document_summary": {
            "text_extraction": case.get("document", {}).get("text_extraction", {}).get("status"),
            "page_count": case.get("document", {}).get("page_count"),
            "ocr": case.get("document", {}).get("ocr", {}).get("message"),
        },
        "missing_checks": [c.get("label") for c in case.get("checks", []) if c.get("status") == "unknown"][:10],
    }
    if message_text:
        payload["message_excerpt"] = _redact(clean_text(message_text, 2500))
    return payload


def _redact(text: str) -> str:
    from detection.utils import EMAIL_RE, INDIAN_PHONE_RE, UPI_RE

    def mask_email(match):
        local, domain = match.group(0).split("@", 1)
        return f"{local[:1]}***@{domain}"

    text = EMAIL_RE.sub(mask_email, text)
    text = INDIAN_PHONE_RE.sub(lambda m: "******" + m.group(0)[-4:], text)
    text = UPI_RE.sub(lambda m: "***@" + m.group(1), text)
    return text
