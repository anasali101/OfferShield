"""Shared helpers: sanitisation, entity extraction and domain utilities."""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone
from urllib.parse import urlparse

MAX_SNIPPET = 280

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE = re.compile(r"[ \t\u00a0]+")
_MULTI_NEWLINE = re.compile(r"\n{3,}")

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"https?://[^\s<>\"')\]}]+", re.IGNORECASE)
WWW_RE = re.compile(r"\bwww\.[^\s<>\"')\]}]+", re.IGNORECASE)

INDIAN_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s\-]?)?[6-9]\d{9}(?!\d)")
INTL_PHONE_RE = re.compile(r"(?<!\d)\+\d{1,3}[\s\-]?\d{5,14}(?!\d)")

MONEY_RE = re.compile(
    r"(?:(?:₹|Rs\.?|INR|\$|USD|€|EUR)\s?[\d,]+(?:\.\d{1,2})?(?:\s?(?:k|lakh|lac|crore|cr))?"
    r"|[\d,]+(?:\.\d{1,2})?\s?(?:₹|Rs\.?|INR|USD|rupees|dollars)"
    r"|[\d,]+\s?(?:k|K)\s?(?:per\s+month|/month|pm)?)",
    re.IGNORECASE,
)

UPI_HANDLES = {
    "ybl", "paytm", "upi", "apl", "ibl", "axl", "okhdfcbank", "okicici",
    "oksbi", "okaxis", "barodampay", "jupiteraxis", "sliceaxis", "fam",
    "naviaxis", "superyes", "timecosmos", "waaxis", "yesg", "airtel",
    "freecharge", "postpe", "amazonpay", "bhim", "digibank", "indus",
}
UPI_RE = re.compile(r"\b[A-Za-z0-9._\-]{2,64}@([A-Za-z][A-Za-z0-9]{1,30})\b")

MULTI_PART_SUFFIXES = {
    "co.in", "co.uk", "com.au", "co.nz", "co.za", "com.br", "com.mx",
    "com.sg", "com.my", "co.jp", "co.kr", "com.cn", "com.hk", "com.tr",
    "org.in", "net.in", "ac.in", "gov.in", "nic.in", "edu.in", "firm.in",
    "gen.in", "ind.in", "res.in", "org.uk", "me.uk", "ac.uk", "gov.uk",
    "com.pk", "com.bd", "com.np", "com.lk",
}

COMPANY_SUFFIX_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9&.'\-]*(?:\s+[A-Z][A-Za-z0-9&.'\-]*){0,5}\s+"
    r"(?:Pvt\.?\s*Ltd\.?|Private\s+Limited|Limited|Ltd\.?|LLP|Inc\.?|Corporation|"
    r"Corp\.?|Technologies|Technology|Solutions|Services|Systems|Infotech|"
    r"Software|Consulting|Enterprises|Industries|Group))\b"
)
COMPANY_LABEL_RE = re.compile(
    r"(?:Company|Organi[sz]ation|Employer)\s*[:\-]\s*([A-Za-z0-9&.,'\- ]{2,80})",
    re.IGNORECASE,
)
RECRUITER_LABEL_RE = re.compile(
    r"(?:Recruiter|Contact\s+Person|HR\s+Manager|Hiring\s+Manager|Talent\s+Acquisition)"
    r"\s*[:\-]\s*([A-Za-z][A-Za-z .'\-]{2,50})",
    re.IGNORECASE,
)
SIGNATURE_RE = re.compile(
    r"(?:Regards|Sincerely|Thanks(?:\s+and\s+regards)?|Warm\s+regards)\s*[,:.\-]?\s*\n+\s*"
    r"([A-Z][A-Za-z .'\-]{2,48})",
    re.IGNORECASE,
)


def clean_text(text: str, max_chars: int = 50_000) -> str:
    """Normalise untrusted text for analysis without destroying meaning."""
    if not isinstance(text, str):
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = _CONTROL_CHARS.sub(" ", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _WHITESPACE.sub(" ", text)
    text = _MULTI_NEWLINE.sub("\n\n", text).strip()
    return text[:max_chars]


def normalise_for_compare(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "").lower()
    return re.sub(r"[^a-z0-9\s]", " ", text)


def make_snippet(text: str, start: int, end: int, radius: int = 90) -> str:
    """Return a compact evidence snippet around a match."""
    if not text:
        return ""
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    piece = text[left:right]
    piece = re.sub(r"\s+", " ", piece).strip()
    if left > 0:
        piece = "… " + piece
    if right < len(text):
        piece = piece + " …"
    return piece[:MAX_SNIPPET]


def extract_emails(text: str) -> list[str]:
    return _dedupe([m.group(0).strip(" .,;:") for m in EMAIL_RE.finditer(text or "")])


def extract_upi_ids(text: str, emails: list[str] | None = None) -> list[str]:
    emails_lower = {e.lower() for e in (emails or [])}
    found = []
    for match in UPI_RE.finditer(text or ""):
        handle = match.group(1).lower()
        token = match.group(0)
        if token.lower() in emails_lower:
            continue
        if handle in UPI_HANDLES:
            found.append(token)
    return _dedupe(found)


def extract_phones(text: str) -> list[str]:
    found = []
    for match in INDIAN_PHONE_RE.finditer(text or ""):
        digits = re.sub(r"\D", "", match.group(0))
        if len(digits) >= 10:
            found.append(match.group(0).strip())
    for match in INTL_PHONE_RE.finditer(text or ""):
        digits = re.sub(r"\D", "", match.group(0))
        if 10 <= len(digits) <= 15:
            found.append(match.group(0).strip())
    return _dedupe(found)


def extract_urls(text: str) -> list[str]:
    urls = [m.group(0) for m in URL_RE.finditer(text or "")]
    urls += ["http://" + m.group(0) for m in WWW_RE.finditer(text or "")]
    cleaned = []
    for url in urls:
        url = url.rstrip(".,;:!?)]}'\"")
        if url not in cleaned:
            cleaned.append(url)
    return cleaned


def extract_amounts(text: str) -> list[dict]:
    """Extract monetary mentions with their location and a local snippet."""
    results = []
    for match in MONEY_RE.finditer(text or ""):
        raw = match.group(0).strip()
        value = _parse_amount(raw)
        if value is None:
            continue
        results.append(
            {
                "raw": raw,
                "value": value,
                "currency": _currency_of(raw),
                "start": match.start(),
                "end": match.end(),
                "context": make_snippet(text, match.start(), match.end(), 70),
            }
        )
    return results


def _parse_amount(raw: str) -> float | None:
    cleaned = raw.lower().replace(",", "")
    multiplier = 1
    if "lakh" in cleaned or "lac" in cleaned:
        multiplier = 100_000
    elif "crore" in cleaned or re.search(r"\bcr\b", cleaned):
        multiplier = 10_000_000
    elif re.search(r"\d\s?k\b", cleaned) or re.search(r"\d+k", cleaned):
        multiplier = 1_000
    number = re.search(r"\d+(?:\.\d+)?", cleaned)
    if not number:
        return None
    try:
        return float(number.group(0)) * multiplier
    except ValueError:
        return None


def _currency_of(raw: str) -> str:
    lowered = raw.lower()
    if "₹" in raw or "rs" in lowered or "inr" in lowered or "rupee" in lowered:
        return "INR"
    if "$" in raw or "usd" in lowered or "dollar" in lowered:
        return "USD"
    if "€" in raw or "eur" in lowered:
        return "EUR"
    return "UNKNOWN"


def extract_company_names(text: str, known_brands: dict[str, list[str]] | None = None) -> list[dict]:
    """Heuristically extract claimed company names with a confidence label."""
    text = text or ""
    results: list[dict] = []
    seen: set[str] = set()

    if known_brands:
        for brand in known_brands:
            pattern = re.compile(r"\b" + re.escape(brand) + r"\b", re.IGNORECASE)
            match = pattern.search(text)
            if match:
                display = match.group(0)
                key = display.lower()
                if key not in seen:
                    seen.add(key)
                    results.append(
                        {"name": display, "confidence": "high", "snippet": make_snippet(text, match.start(), match.end(), 60)}
                    )

    for match in COMPANY_SUFFIX_RE.finditer(text):
        name = re.sub(r"\s+", " ", match.group(1)).strip(" .,")
        key = name.lower()
        if key not in seen:
            seen.add(key)
            results.append(
                {"name": name, "confidence": "medium", "snippet": make_snippet(text, match.start(), match.end(), 60)}
            )

    for match in COMPANY_LABEL_RE.finditer(text):
        name = re.sub(r"\s+", " ", match.group(1)).strip(" .,")
        if len(name) < 3:
            continue
        key = name.lower()
        if key not in seen:
            seen.add(key)
            results.append(
                {"name": name, "confidence": "medium", "snippet": make_snippet(text, match.start(), match.end(), 60)}
            )

    return results[:8]


def extract_recruiter_names(text: str) -> list[str]:
    text = text or ""
    names: list[str] = []
    for regex in (RECRUITER_LABEL_RE, SIGNATURE_RE):
        for match in regex.finditer(text):
            candidate = re.sub(r"\s+", " ", match.group(1)).strip(" .,-")
            candidate = re.split(
                r"\b(?:HR|Human Resources|Recruiter|Manager|Team|Department|Mobile|Phone|Email)\b",
                candidate,
                maxsplit=1,
                flags=re.IGNORECASE,
            )[0].strip(" .,-")
            if 2 <= len(candidate) <= 48 and not candidate.lower() in {"team", "hr team"}:
                if candidate.lower() not in {n.lower() for n in names}:
                    names.append(candidate)
    return names[:5]


def extract_entities(text: str, known_brands: dict[str, list[str]] | None = None) -> dict:
    emails = extract_emails(text)
    urls = extract_urls(text)
    return {
        "emails": emails,
        "phones": extract_phones(text),
        "urls": urls,
        "upi_ids": extract_upi_ids(text, emails),
        "amounts": extract_amounts(text),
        "companies": extract_company_names(text, known_brands),
        "recruiters": extract_recruiter_names(text),
    }


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain (eTLD+1) without an external PSL library."""
    host = (host or "").strip().lower().strip(".")
    if not host or host.replace(".", "").isdigit():
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def host_from_url(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.lower()
        if key and key not in seen:
            seen.add(key)
            out.append(item)
    return out


def safe_text(value, limit: int = 500) -> str:
    """Coerce untrusted values to bounded plain strings for reports."""
    if value is None:
        return ""
    return str(value)[:limit]
