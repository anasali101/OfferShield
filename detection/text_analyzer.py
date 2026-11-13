"""Feature A: recruitment message pattern analysis."""

from __future__ import annotations

import re

from detection.brands import KNOWN_BRANDS
from detection.findings import make_finding
from detection.utils import (
    extract_amounts,
    extract_entities,
    make_snippet,
    normalise_for_compare,
)

PATTERNS = [
    {
        "id": "MSG_GUARANTEED_PLACEMENT",
        "title": "Guaranteed placement claimed",
        "severity": "high",
        "points": 8,
        "regex": r"\b(?:guaranteed?|assured|100\s*%)\s+(?:job|placement|position|employment)\b|\bjob\s+guarantee\b|\b100\s*%\s+placement\b",
        "why": "No genuine employer can guarantee a job before an interview and selection process. Guarantees are a strong scam indicator.",
    },
    {
        "id": "MSG_NO_INTERVIEW",
        "title": "Job offered with no interview",
        "severity": "high",
        "points": 7,
        "regex": r"\b(?:no|without\s+(?:any\s+)?)\s*(?:technical\s+)?interview\b|\bdirect\s+(?:joining|offer)\b|\boffer\s+letter\s+without\s+(?:an?\s+)?interview\b|\bselected\s+based\s+(?:only\s+)?on\s+(?:your\s+)?(?:resume|cv)\b",
        "why": "Legitimate technical roles require assessment. Offers without any interview are commonly used to create false urgency.",
    },
    {
        "id": "MSG_URGENCY",
        "title": "Urgent payment or response demanded",
        "severity": "medium",
        "points": 5,
        "regex": r"\b(?:pay|deposit|transfer|confirm|respond|reply)\b[^.\n]{0,40}\b(?:within|before|in)\s+\d+\s*(?:hours?|hrs?|minutes?|days?)\b|\b(?:urgent(?:ly)?|immediately|last\s+date\s+today|limited\s+(?:seats|slots|time)|only\s+\d+\s+(?:seats|slots)|act\s+(?:fast|now)|expires\s+today|hurry)\b",
        "why": "Artificial deadlines pressure victims into paying before they can verify the offer.",
    },
    {
        "id": "MSG_NO_SKILLS",
        "title": "No skills or experience required",
        "severity": "medium",
        "points": 5,
        "regex": r"\bno\s+(?:skills?|experience)\s+(?:required|needed)\b|\bany\s+graduate\s+can\s+apply\b|\b(?:any\s+)?freshers?\s+(?:welcome|can\s+apply),\s*no\s+experience\b",
        "why": "Unskilled high-paying roles are frequently used as bait. Genuine roles describe real requirements.",
    },
    {
        "id": "MSG_SENSITIVE_DOCUMENTS",
        "title": "Sensitive documents or OTP requested early",
        "severity": "medium",
        "points": 4,
        "regex": r"\b(?:send|share|provide|submit)\b[^.\n]{0,40}\b(?:aadhaar|aadhar|pan\s+card|passport|otp|one[\s-]?time\s+password|bank\s+(?:details|account|password)|cvv)\b",
        "why": "OTPs and financial credentials should never be shared during recruitment. Identity documents should only be handled through verified official channels.",
    },
    {
        "id": "MSG_TASK_SCAM",
        "title": "Task-based / engagement farming job pattern",
        "severity": "high",
        "points": 6,
        "regex": r"\b(?:like\s+and\s+subscribe|complete\s+(?:simple\s+)?tasks?|daily\s+(?:payout|income|tasks?)|earn\s+(?:money\s+)?per\s+task|part[\s-]?time\s+job\b[^.\n]{0,60}\b(?:earn|income|payout))\b",
        "why": "Task-based 'jobs' that require an initial deposit or fee are a well-known fraud pattern.",
    },
    {
        "id": "MSG_PERSONAL_CHANNEL",
        "title": "Recruitment conducted only via WhatsApp/Telegram",
        "severity": "low",
        "points": 3,
        "regex": r"\b(?:whatsapp|telegram)\s*(?:only|number|me|us)\b|\b(?:dm|message|contact)\s+(?:me|us)?\s*(?:only\s+)?(?:on|via)\s+(?:whatsapp|telegram)\b|\bcontact\s+(?:on|via)\s+(?:whatsapp|telegram)\b",
        "why": "Informal-only channels are not proof of fraud, but legitimate employers normally use corporate email and an official careers portal.",
    },
    {
        "id": "MSG_GENERIC_MNC",
        "title": "Vague 'top MNC' claim without a company name",
        "severity": "low",
        "points": 3,
        "regex": r"\b(?:top|reputed|leading|prestigious|fortune\s*500)\s+(?:mnc|company|multinational)\b",
        "why": "Scam messages often avoid naming the employer so that the claim cannot be checked.",
    },
]

_INTERVIEW_SIGNAL = re.compile(
    r"\b(?:technical\s+interview|hr\s+round|interview\s+(?:is\s+)?scheduled|"
    r"schedule\s+(?:an?\s+)?interview|panel\s+interview|online\s+assessment|"
    r"coding\s+test|aptitude\s+test)\b",
    re.IGNORECASE,
)
_FORMAL_SIGNAL = re.compile(
    r"\b(?:employment\s+contract|offer\s+letter|background\s+verification|"
    r"official\s+careers?\s+(?:page|portal)|employee\s+id|reporting\s+manager)\b",
    re.IGNORECASE,
)
_FREE_EMAIL_HINT = re.compile(
    r"\b(?:gmail|yahoo|hotmail|outlook|rediffmail)\b", re.IGNORECASE
)


def analyze_text(text: str, entities: dict | None = None) -> dict:
    """Analyse a recruitment message for fraud patterns and trust signals."""
    text = text or ""
    entities = entities or extract_entities(text, KNOWN_BRANDS)
    findings: list[dict] = []
    signals: list[dict] = []
    matched_ids: set[str] = set()

    for pattern in PATTERNS:
        for match in re.finditer(pattern["regex"], text, re.IGNORECASE):
            if pattern["id"] in matched_ids:
                continue
            # Social-channel mentions are not suspicious when a full interview
            # process and corporate email are also present.
            if pattern["id"] == "MSG_PERSONAL_CHANNEL" and _has_formal_process(text):
                continue
            matched_ids.add(pattern["id"])
            findings.append(
                make_finding(
                    pattern["id"],
                    "message",
                    pattern["title"],
                    pattern["severity"],
                    pattern["points"],
                    evidence=make_snippet(text, match.start(), match.end(), 110),
                    why=pattern["why"],
                    source="text_analyzer",
                )
            )
            break

    salary_finding = _detect_unrealistic_salary(text)
    if salary_finding:
        findings.append(salary_finding)

    if _INTERVIEW_SIGNAL.search(text):
        signals.append(
            {
                "id": "SIG_INTERVIEW_PROCESS",
                "title": "A structured interview or assessment is mentioned",
                "status": "clean",
                "detail": "This is a positive process signal, but the message itself cannot confirm that the process is genuine.",
            }
        )
    if _FORMAL_SIGNAL.search(text):
        signals.append(
            {
                "id": "SIG_FORMAL_PROCESS",
                "title": "Formal hiring language detected",
                "status": "clean",
                "detail": "References to contracts or official careers pages are indicators only and can be copied by scammers.",
            }
        )

    return {
        "findings": findings,
        "signals": signals,
        "entities": entities,
        "matched_patterns": sorted(matched_ids),
        "normalised": normalise_for_compare(text)[:4000],
    }


def _has_formal_process(text: str) -> bool:
    return bool(_INTERVIEW_SIGNAL.search(text)) and not _FREE_EMAIL_HINT.search(text)


def _detect_unrealistic_salary(text: str) -> dict | None:
    amounts = extract_amounts(text)
    lowered = text.lower()
    fresher_context = bool(
        re.search(r"\b(?:fresher|no\s+experience|any\s+graduate|no\s+skills?)\b", lowered)
    )
    for amount in amounts:
        context = amount["context"].lower()
        value = amount["value"] or 0
        monthly = bool(re.search(r"\b(?:per\s+month|/month|monthly|\bpm\b)\b", context))
        daily = bool(re.search(r"\b(?:per\s+day|/day|daily)\b", context))
        if amount["currency"] != "INR":
            continue
        threshold_monthly = 150_000 if fresher_context else 300_000
        if (monthly and value >= threshold_monthly) or (daily and value >= 5_000):
            return make_finding(
                "MSG_UNREALISTIC_SALARY",
                "message",
                "Unrealistically high pay offered",
                "medium",
                5,
                evidence=amount["context"],
                why="Extremely high monthly or daily pay combined with minimal requirements is a common bait technique. Salary figures alone are not proof of fraud.",
                source="text_analyzer",
            )
    return None
