"""Analysis orchestration: runs checks, scores findings and stores the report.

Every network/LLM operation is optional and isolated. Failures produce
"unknown/unavailable" results instead of fabricated data.
"""

from __future__ import annotations

import logging
import uuid

from detection.ai_analyzer import generate_explanation
from detection.brands import KNOWN_BRANDS
from detection.company_verifier import verify_company
from detection.domain_checker import UnsafeURLError, analyze_domain, validate_public_url
from detection.findings import merge_findings
from detection.payment_detector import detect_payments
from detection.pdf_analyzer import analyze_pdf
from detection.reputation import check_reputation
from detection.risk_engine import SEVERITY_ORDER, score_findings
from detection.text_analyzer import analyze_text
from detection.utils import clean_text, extract_entities, utc_now_iso
from services import jobs, storage

log = logging.getLogger(__name__)

STEPS = {
    "text": [
        ("input", "Input validation"),
        ("entities", "Entity extraction"),
        ("payment", "Payment fraud analysis"),
        ("patterns", "Recruitment pattern analysis"),
        ("domain", "Domain & website intelligence"),
        ("company", "Company verification"),
        ("reputation", "Reputation checks"),
        ("scoring", "Deterministic risk scoring"),
        ("ai", "AI explanation"),
        ("report", "Report assembly"),
    ],
    "pdf": [
        ("input", "File validation"),
        ("document", "PDF extraction & document analysis"),
        ("payment", "Payment clause detection"),
        ("patterns", "Suspicious clause detection"),
        ("domain", "Domain & website intelligence"),
        ("company", "Company verification"),
        ("reputation", "Reputation checks"),
        ("scoring", "Deterministic risk scoring"),
        ("ai", "AI explanation"),
        ("report", "Report assembly"),
    ],
    "url": [
        ("input", "Input validation"),
        ("safety", "URL safety / SSRF validation"),
        ("domain", "Domain, DNS, TLS & registration"),
        ("company", "Company verification"),
        ("reputation", "Reputation checks"),
        ("scoring", "Deterministic risk scoring"),
        ("ai", "AI explanation"),
        ("report", "Report assembly"),
    ],
}

VERIFICATION_SOURCES = {"domain", "company", "document", "osint"}


def run_text_analysis(job_id: str, text: str, consent: bool, config: dict) -> None:
    jobs.set_job_running(job_id)
    try:
        _step(job_id, "input", "running")
        cleaned = clean_text(text, int(config.get("MAX_TEXT_CHARS", 50_000)))
        if len(cleaned) < 10:
            raise PipelineError("Please provide at least 10 characters of offer text to analyse.")
        _step(job_id, "input", "done", f"{len(cleaned)} characters accepted.")

        case = _base_case("text", {"kind": "text", "text_length": len(cleaned)})

        _step(job_id, "entities", "running")
        entities = extract_entities(cleaned, KNOWN_BRANDS)
        case["entities"] = entities
        _step(job_id, "entities", "done", _entity_detail(entities))

        _step(job_id, "payment", "running")
        payment = detect_payments(cleaned)
        _step(job_id, "payment", "done", f"{len(payment['contexts'])} payment context(s) found.")

        _step(job_id, "patterns", "running")
        text_result = analyze_text(cleaned, entities)
        _step(job_id, "patterns", "done", f"{len(text_result['findings'])} pattern finding(s).")

        _step(job_id, "domain", "running")
        domain_result = _analyse_first_link(entities.get("urls", []), config)
        _step(job_id, "domain", "done" if domain_result else "skipped", _domain_step_detail(domain_result))

        _step(job_id, "company", "running")
        company = verify_company(cleaned, entities, domain_result)
        _step(job_id, "company", "done", company["status_label"] + ".")

        _step(job_id, "reputation", "running")
        reputation = _reputation_stage(domain_result, config)
        _step(job_id, "reputation", _reputation_step_status(reputation, config), _reputation_detail(reputation, config))

        checks = _build_checks(payment, text_result, domain_result, company, reputation, kind="text")
        findings = _collect_findings(payment, text_result, domain_result, company, reputation)
        _step(job_id, "scoring", "running")
        score = _score(findings, checks, company)
        _step(job_id, "scoring", "done", f"Score {score['score']}/100 - {score['headline']}.")

        _finish_case(
            job_id, case, findings, checks, score, config,
            message_text=cleaned, consent=consent,
            domain_result=domain_result, company=company, document=None,
            input_meta=case["input"],
        )
    except PipelineError as exc:
        jobs.fail_job(job_id, str(exc))
    except Exception:
        log.exception("Text analysis job failed")
        jobs.fail_job(job_id, "The analysis could not be completed due to an internal error. No file data was retained.")


def run_pdf_analysis(job_id: str, data: bytes, filename: str, consent: bool, config: dict) -> None:
    jobs.set_job_running(job_id)
    try:
        _step(job_id, "input", "running")
        if not data:
            raise PipelineError("The uploaded file is empty.")
        if not data.startswith(b"%PDF-"):
            raise PipelineError("The uploaded file is not a valid PDF (missing PDF signature).")
        _step(job_id, "input", "done", f"Validated PDF, {len(data) / 1024:.0f} KB.")

        _step(job_id, "document", "running")
        document = analyze_pdf(data, filename, config)
        extraction = document.get("text_extraction", {})
        _step(job_id, "document", "done", f"{extraction.get('status')}: {extraction.get('message', '')}")
        text = document.pop("text", "") or ""
        document.pop("shingles", None)
        document["ocr"].pop("text", None)
        case = _base_case(
            "pdf",
            {
                "kind": "pdf",
                "filename": filename[:120],
                "size_bytes": len(data),
                "page_count": document.get("page_count"),
                "fingerprint": document.get("fingerprint"),
                "text_extraction": document.get("text_extraction", {}).get("status"),
                "ocr_used": document.get("text_extraction", {}).get("status") == "ocr_done",
            },
        )

        _step(job_id, "payment", "running")
        payment = detect_payments(text) if text else {"findings": [], "contexts": [], "amounts": [], "upi_ids": []}
        _step(job_id, "payment", "done", f"{len(payment['contexts'])} payment context(s) found.")

        _step(job_id, "patterns", "running")
        entities = extract_entities(text, KNOWN_BRANDS) if text else extract_entities("", KNOWN_BRANDS)
        text_result = analyze_text(text, entities) if text else {"findings": [], "signals": [], "entities": entities}
        _step(job_id, "patterns", "done", f"{len(text_result['findings'])} clause finding(s).")

        _step(job_id, "domain", "running")
        domain_result = _analyse_first_link(entities.get("urls", []), config)
        _step(job_id, "domain", "done" if domain_result else "skipped", _domain_step_detail(domain_result))

        _step(job_id, "company", "running")
        company = verify_company(text, entities, domain_result)
        _step(job_id, "company", "done", company["status_label"] + ".")

        _step(job_id, "reputation", "running")
        reputation = _reputation_stage(domain_result, config)
        _step(job_id, "reputation", _reputation_step_status(reputation, config), _reputation_detail(reputation, config))

        checks = _build_checks(payment, text_result, domain_result, company, reputation, kind="pdf", document=document)
        findings = _collect_findings(payment, text_result, domain_result, company, reputation, document)
        _step(job_id, "scoring", "running")
        score = _score(findings, checks, company)
        _step(job_id, "scoring", "done", f"Score {score['score']}/100 - {score['headline']}.")

        case["entities"] = entities
        _finish_case(
            job_id, case, findings, checks, score, config,
            message_text=None, consent=consent,
            domain_result=domain_result, company=company, document=document,
            input_meta=case["input"],
            document_text_missing=not text,
        )
    except PipelineError as exc:
        jobs.fail_job(job_id, str(exc))
    except Exception:
        log.exception("PDF analysis job failed")
        jobs.fail_job(job_id, "The PDF could not be analysed due to an internal error. No file data was retained.")


def run_url_analysis(job_id: str, url: str, consent: bool, config: dict) -> None:
    jobs.set_job_running(job_id)
    try:
        _step(job_id, "input", "running")
        _step(job_id, "safety", "running")
        try:
            normalized, host = validate_public_url(url)
        except UnsafeURLError as exc:
            _step(job_id, "safety", "failed", str(exc))
            raise PipelineError(f"URL blocked by safety validation: {exc}") from exc
        _step(job_id, "input", "done", f"Website URL accepted: {host}")
        _step(job_id, "safety", "done", "Scheme, port, hostname and resolved addresses passed SSRF checks.")

        case = _base_case("url", {"kind": "url", "url": normalized, "host": host})

        _step(job_id, "domain", "running")
        domain_result = analyze_domain(normalized, config)
        _step(job_id, "domain", "done", _domain_step_detail(domain_result))

        entities = extract_entities(normalized, KNOWN_BRANDS)
        case["entities"] = entities
        _step(job_id, "company", "running")
        company = verify_company("", entities, domain_result)
        _step(job_id, "company", "done", company["status_label"] + ".")

        _step(job_id, "reputation", "running")
        reputation = _reputation_stage(domain_result, config)
        _step(job_id, "reputation", _reputation_step_status(reputation, config), _reputation_detail(reputation, config))

        payment = {"findings": [], "contexts": [], "amounts": [], "upi_ids": []}
        text_result = {"findings": [], "signals": [], "entities": entities}
        checks = _build_checks(payment, text_result, domain_result, company, reputation, kind="url")
        findings = _collect_findings(payment, text_result, domain_result, company, reputation)
        _step(job_id, "scoring", "running")
        score = _score(findings, checks, company)
        _step(job_id, "scoring", "done", f"Score {score['score']}/100 - {score['headline']}.")

        _finish_case(
            job_id, case, findings, checks, score, config,
            message_text=None, consent=consent,
            domain_result=domain_result, company=company, document=None,
            input_meta=case["input"],
        )
    except PipelineError as exc:
        jobs.fail_job(job_id, str(exc))
    except Exception:
        log.exception("URL analysis job failed")
        jobs.fail_job(job_id, "The website could not be analysed due to an internal error.")


# ---------------------------------------------------------------------------
# Shared stages
# ---------------------------------------------------------------------------

class PipelineError(Exception):
    """A safe, user-facing analysis error."""


def _step(job_id: str, key: str, status: str, detail: str = "") -> None:
    jobs.set_step(job_id, key, status, detail)


def _base_case(kind: str, input_meta: dict) -> dict:
    return {
        "id": uuid.uuid4().hex,
        "kind": kind,
        "created_at": utc_now_iso(),
        "input": input_meta,
        "entities": {},
        "findings": [],
        "checks": [],
        "score": {},
        "domain": {},
        "company": {},
        "document": {},
        "ai": {},
        "limitations": [],
        "disclaimer": (
            "OfferShield is an automated screening tool. It can miss scams and it cannot "
            "certify that an offer is genuine. Never pay money to obtain a job."
        ),
    }


def _analyse_first_link(urls: list[str], config: dict) -> dict | None:
    for url in urls or []:
        if not url.lower().startswith(("http://", "https://")):
            continue
        try:
            return analyze_domain(url, config)
        except UnsafeURLError:
            return {
                "url": url,
                "host": "",
                "registrable_domain": "",
                "findings": [],
                "checks": [
                    {
                        "key": "url_safety",
                        "label": "URL safety validation",
                        "status": "fail",
                        "detail": "A link in the offer was blocked by SSRF protection. No request was sent to it.",
                        "source": "domain",
                    }
                ],
                "registration": {"available": False, "note": "Link blocked."},
                "dns": {},
                "ssl": {},
                "http": {},
                "brand_matches": [],
                "blocked": True,
                "network_enabled": bool(config.get("NETWORK_CHECKS_ENABLED", True)),
                "error": "Link blocked by SSRF protection.",
            }
        except Exception:
            log.exception("Domain analysis failed")
            return None
    return None


def _reputation_stage(domain_result: dict | None, config: dict) -> dict:
    if not domain_result or domain_result.get("blocked"):
        return check_reputation("", config)
    return check_reputation(domain_result.get("url", ""), config)


def _reputation_step_status(reputation: dict, config: dict) -> str:
    has_key = bool((config.get("VIRUSTOTAL_API_KEY") or "").strip() or (config.get("SAFE_BROWSING_API_KEY") or "").strip())
    if not config.get("NETWORK_CHECKS_ENABLED", True):
        return "skipped"
    if not has_key:
        return "skipped"
    return "done"


def _reputation_detail(reputation: dict, config: dict) -> str:
    providers = reputation.get("providers") or []
    if not config.get("NETWORK_CHECKS_ENABLED", True):
        return "Network checks disabled; no reputation lookup performed."
    if not providers:
        return "No reputation API keys configured; no result claimed."
    return "Queried: " + ", ".join(providers)


def _domain_step_detail(domain_result: dict | None) -> str:
    if not domain_result:
        return "No website link available; domain checks skipped."
    if domain_result.get("blocked"):
        return "Link blocked by SSRF protection; no network request was made."
    if not domain_result.get("network_enabled", True):
        return "Network disabled; only offline URL pattern checks were performed."
    return f"{domain_result.get('host')}: registration, DNS, TLS, HTTP and pattern checks completed."


def _build_checks(payment, text_result, domain_result, company, reputation, kind: str, document: dict | None = None) -> list[dict]:
    checks: list[dict] = []

    payment_warnings = [f for f in payment.get("findings", []) if f.get("severity") in {"critical", "high", "medium", "low"}]
    document_readable = bool(document) and (document.get("text_extraction", {}).get("status") in {"done", "ocr_done"})
    if kind == "url":
        checks.append(_check("payment_analysis", "Payment requests", "unknown", "No recruitment message was supplied, so payment language cannot be assessed.", "payment"))
    elif kind == "pdf" and not document_readable:
        checks.append(_check("payment_analysis", "Payment requests", "unknown", "The PDF text could not be read, so payment language could not be assessed.", "payment"))
    else:
        if any(f["severity"] in {"critical", "high"} for f in payment_warnings):
            status = "fail"
        elif payment_warnings:
            status = "warn"
        else:
            status = "pass"
        checks.append(
            _check(
                "payment_analysis", "Payment requests", status,
                f"{len(payment_warnings)} payment indicator(s) detected." if payment_warnings
                else "No candidate-facing fee, deposit or transfer request was detected.",
                "payment",
            )
        )

    if kind == "url":
        checks.append(_check("message_patterns", "Recruitment message patterns", "unknown", "Not applicable to a website-only scan.", "message"))
    elif kind == "pdf" and not document_readable:
        checks.append(_check("message_patterns", "Suspicious clauses", "unknown", "The PDF text could not be read, so clauses could not be assessed.", "message"))
    else:
        warnings = [f for f in text_result.get("findings", []) if f.get("severity") in {"critical", "high", "medium", "low"}]
        if any(f["severity"] in {"critical", "high"} for f in warnings):
            status = "fail"
        elif warnings:
            status = "warn"
        else:
            status = "pass"
        checks.append(
            _check(
                "message_patterns", "Recruitment message patterns", status,
                f"{len(warnings)} recruitment pattern indicator(s)." if warnings
                else "No known recruitment-scam language patterns were detected.",
                "message",
            )
        )

    if document:
        checks.extend(document.get("checks", []))

    if domain_result:
        checks.extend(domain_result.get("checks", []))
        if domain_result.get("blocked"):
            for key, label in (
                ("domain_registration", "Domain registration age"),
                ("dns", "DNS records"),
                ("ssl", "TLS certificate"),
                ("http", "Website reachability"),
            ):
                checks.append(_check(key, label, "unknown", "Blocked URL was not contacted.", "domain"))
    else:
        checks.append(_check("domain_registration", "Domain registration age", "unknown", "No website URL was supplied.", "domain"))
        checks.append(_check("dns", "DNS records", "unknown", "No website URL was supplied.", "domain"))
        checks.append(_check("ssl", "TLS certificate", "unknown", "No website URL was supplied.", "domain"))
        checks.append(_check("http", "Website reachability", "unknown", "No website URL was supplied.", "domain"))

    checks.extend(company.get("checks", []))
    checks.extend(reputation.get("checks", []))
    return _dedupe_checks(checks)


def _collect_findings(payment, text_result, domain_result, company, reputation, document: dict | None = None) -> list[dict]:
    findings = []
    findings.extend(payment.get("findings", []))
    findings.extend(text_result.get("findings", []))
    for signal in text_result.get("signals", []):
        findings.append(
            {
                "id": signal["id"],
                "category": "message",
                "title": signal["title"],
                "severity": signal.get("status", "info"),
                "points": 0,
                "evidence": "",
                "why": signal.get("detail", ""),
                "source": "text_analyzer",
                "verified": False,
            }
        )
    if domain_result:
        findings.extend(domain_result.get("findings", []))
    findings.extend(company.get("findings", []))
    findings.extend(reputation.get("findings", []))
    if document:
        findings.extend(document.get("findings", []))
    merged = merge_findings(findings)
    merged.sort(key=lambda f: (SEVERITY_ORDER.get(f.get("severity"), 9), -int(f.get("points", 0)), f.get("title", "")))
    return merged


def _score(findings: list[dict], checks: list[dict], company: dict) -> dict:
    verification = [c for c in checks if c.get("source") in VERIFICATION_SOURCES]
    completed = [c for c in verification if c.get("status") in {"pass", "warn", "fail"}]
    coverage = (len(completed) / len(verification)) if verification else 0.0
    context = {
        "coverage": coverage,
        "completed_checks": len(completed),
        "total_checks": len(verification),
        "company_status": company.get("status"),
    }
    return score_findings(findings, context)


def _finish_case(
    job_id, case, findings, checks, score, config,
    message_text, consent, domain_result, company, document,
    input_meta, document_text_missing: bool = False,
) -> None:
    _step(job_id, "ai", "running")
    case.update(
        {
            "input": input_meta,
            "entities": _sanitise_entities(case.get("entities") or {}),
            "findings": findings,
            "checks": checks,
            "score": score,
            "domain": _sanitise_domain(domain_result),
            "company": _sanitise_company(company),
            "document": _sanitise_document(document),
            "limitations": _limitations(config, case["kind"], checks, document, document_text_missing),
        }
    )
    try:
        ai = generate_explanation(case, message_text, consent, config)
    except Exception:
        log.exception("AI explanation failed")
        ai = {
            "status": "unavailable",
            "text": "",
            "message": "The AI explanation failed unexpectedly. The rule-based report is unaffected.",
        }
    case["ai"] = ai
    if ai.get("status") == "ok":
        _step(job_id, "ai", "done", "Explanation generated. The score was not changed.")
    elif ai.get("status") == "disabled":
        _step(job_id, "ai", "skipped", "No AI API key configured; rule-based report only.")
    elif ai.get("status") == "skipped":
        _step(job_id, "ai", "skipped", "AI consent not given; no content sent to an AI provider.")
    else:
        _step(job_id, "ai", "skipped", ai.get("message", "AI unavailable."))

    _step(job_id, "report", "running")
    storage.save_case(config["DB_PATH"], case, int(config.get("CASE_TTL_HOURS", 24)))
    _step(job_id, "report", "done", "Investigation report saved temporarily and ready to view.")
    jobs.finish_job(job_id, f"/results/{case['id']}")



def _sanitise_entities(entities: dict) -> dict:
    amounts = []
    for amount in (entities.get("amounts") or [])[:15]:
        amounts.append(
            {
                "raw": amount.get("raw"),
                "value": amount.get("value"),
                "currency": amount.get("currency"),
                "context": amount.get("context"),
            }
        )
    return {
        "emails": (entities.get("emails") or [])[:10],
        "phones": (entities.get("phones") or [])[:10],
        "urls": (entities.get("urls") or [])[:10],
        "upi_ids": (entities.get("upi_ids") or [])[:10],
        "amounts": amounts,
        "companies": (entities.get("companies") or [])[:8],
        "recruiters": (entities.get("recruiters") or [])[:6],
    }


def _sanitise_domain(domain_result: dict | None) -> dict:
    if not domain_result:
        return {}
    keep = ("url", "host", "registrable_domain", "blocked", "error", "network_enabled")
    result = {key: domain_result.get(key) for key in keep}
    result["registration"] = domain_result.get("registration", {})
    result["dns"] = domain_result.get("dns", {})
    result["ssl"] = domain_result.get("ssl", {})
    result["http"] = domain_result.get("http", {})
    result["brand_matches"] = domain_result.get("brand_matches", [])
    return result


def _sanitise_company(company: dict | None) -> dict:
    if not company:
        return {}
    keep = (
        "claimed_brand", "official_domains", "claimed_companies", "recruiter_names",
        "email_domains", "status", "status_label", "scope", "mca",
    )
    return {key: company.get(key) for key in keep}


def _sanitise_document(document: dict | None) -> dict:
    if not document:
        return {}
    keep = (
        "filename", "size_bytes", "page_count", "fingerprint", "metadata",
        "metadata_anomalies", "text_extraction", "duplicate", "active_content",
        "embedded_files", "encrypted",
    )
    result = {key: document.get(key) for key in keep}
    ocr = dict(document.get("ocr") or {})
    ocr.pop("text", None)
    result["ocr"] = ocr
    result["similar_documents"] = [
        {"score": s.get("score"), "jaccard": s.get("jaccard"), "fuzzy": s.get("fuzzy"), "created_at": s.get("created_at")}
        for s in (document.get("similar_documents") or [])
    ]
    return result


def _limitations(config: dict, kind: str, checks: list[dict], document: dict | None, document_text_missing: bool) -> list[str]:
    items = [
        "OfferShield is an automated screening tool. It can miss fraud and cannot certify that an offer is genuine.",
        "Company registry verification (MCA, India) requires a manual CAPTCHA-based search and was not automated.",
        "A low score means no indicators were detected by the checks that ran; it is not a guarantee of legitimacy.",
    ]
    if not config.get("NETWORK_CHECKS_ENABLED", True):
        items.append("Network checks were disabled in this deployment, so domain, DNS, TLS and reputation checks did not run.")
    if not (config.get("AI_API_KEY") or "").strip():
        items.append("AI explanations are not configured. All findings and the risk score come from the deterministic engine.")
    if kind == "pdf":
        items.append("PDF metadata and formatting are weak evidence only. They are never used to claim that a document is forged.")
        if document_text_missing:
            items.append("The PDF had no readable text layer. Its contents were NOT analysed unless OCR succeeded; see the document section.")
        ocr = (document or {}).get("ocr", {})
        if ocr.get("attempted") and not ocr.get("available"):
            items.append("OCR was attempted but Tesseract is unavailable on this server. The scanned document could not be read.")
    if kind == "text":
        items.append("Message scans cannot verify the sender's identity or the existence of the vacancy. Confirm through official channels.")
    if kind == "url":
        items.append("Domain age and HTTPS do not establish legitimacy. A website can be new, validly encrypted and still fraudulent.")
    missing = [c["label"] for c in checks if c.get("status") == "unknown"]
    if missing:
        items.append("Checks that could not be completed: " + ", ".join(missing[:8]) + ".")
    return items


def _check(key: str, label: str, status: str, detail: str, source: str) -> dict:
    return {"key": key, "label": label, "status": status, "detail": str(detail or "")[:280], "source": source}


def _dedupe_checks(checks: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for check in checks:
        key = (check.get("key"), check.get("source"))
        if key in seen:
            continue
        seen.add(key)
        out.append(check)
    return out


def _entity_detail(entities: dict) -> str:
    return (
        f"{len(entities.get('emails', []))} email(s), {len(entities.get('phones', []))} phone(s), "
        f"{len(entities.get('urls', []))} URL(s), {len(entities.get('companies', []))} company candidate(s)."
    )
