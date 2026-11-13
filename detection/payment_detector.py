"""Feature B/D: payment fraud indicators.

Detects requests for money from the candidate. Salary, stipend and CTC
mentions are deliberately not treated as payment demands.
"""

from __future__ import annotations

import re

from detection.findings import make_finding
from detection.utils import extract_amounts, extract_upi_ids, extract_emails, make_snippet

PAYMENT_PATTERNS = [
    {
        "id": "PAY_REGISTRATION_FEE",
        "title": "Registration / application fee requested",
        "regex": r"\b(?:registration|enrol{1,2}ment|enrollment|application|joining)\s*(?:fee|fees|charge|charges|amount|payment|money)\b",
        "severity": "critical",
        "points": 18,
        "why": "Legitimate employers do not charge candidates to apply, register or confirm a job.",
    },
    {
        "id": "PAY_TRAINING_KIT",
        "title": "Training kit / training fee requested",
        "regex": r"\b(?:training\s*(?:kit|kits|material|materials|program(?:me)?|course|fee|fees|charge|charges)|kit\s*(?:fee|fees|charge|charges|cost))\b",
        "severity": "critical",
        "points": 18,
        "why": "Charging candidates for mandatory training or a kit before joining is a common recruitment scam.",
    },
    {
        "id": "PAY_SECURITY_DEPOSIT",
        "title": "Security / refundable deposit requested",
        "regex": r"\b(?:security\s+deposit|refundable\s+deposit|caution\s+deposit|deposit\s+(?:amount|money))\b",
        "severity": "critical",
        "points": 18,
        "why": "A refundable deposit is a classic advance-fee scam pattern. 'Refundable' promises are not protection.",
    },
    {
        "id": "PAY_PLACEMENT_CONFIRMATION",
        "title": "Payment demanded to confirm placement",
        "regex": r"\b(?:placement|seat|offer|joining)\s*(?:confirmation|booking)\s*(?:fee|fees|charge|charges|amount|payment)\b|\b(?:pay|deposit)\b[^.\n]{0,60}\b(?:confirm|confirmation)\s+(?:your\s+)?(?:placement|seat|offer)\b",
        "severity": "critical",
        "points": 18,
        "why": "A genuine offer is confirmed by an employment contract, not by a payment.",
    },
    {
        "id": "PAY_INTERVIEW_FEE",
        "title": "Interview fee requested",
        "regex": r"\b(?:interview|screening|assessment)\s*(?:fee|fees|charge|charges|amount|payment)\b",
        "severity": "high",
        "points": 15,
        "why": "Employers and their legitimate vendors do not charge candidates for interviews or assessments.",
    },
    {
        "id": "PAY_PROCESSING_FEE",
        "title": "Processing / documentation fee requested",
        "regex": r"\b(?:processing|documentation|document|verification|onboarding|administrative)\s*(?:fee|fees|charge|charges|amount|payment)\b",
        "severity": "high",
        "points": 12,
        "why": "Onboarding paperwork is an employer cost. Requests for processing fees are high-risk.",
    },
    {
        "id": "PAY_EQUIPMENT_DEPOSIT",
        "title": "Equipment / laptop deposit requested",
        "regex": r"\b(?:laptop|equipment|device|system)\s*(?:deposit|fee|fees|charge|charges|amount|payment)\b",
        "severity": "high",
        "points": 14,
        "why": "Employers provide work equipment. Asking a candidate to pay for it is a known scam pattern.",
    },
    {
        "id": "PAY_COURIER_CHARGE",
        "title": "Courier / delivery charge requested",
        "regex": r"\b(?:courier|shipping|delivery|dispatch)\s*(?:fee|fees|charge|charges|amount|payment)\b",
        "severity": "medium",
        "points": 10,
        "why": "Small delivery charges are often used to test a victim's willingness to pay before larger demands.",
    },
]

_NEGATION_BEFORE = re.compile(
    r"\b(?:no|never|without|zero|not\s+any|free\s+of)\b[^.\n]{0,40}$", re.IGNORECASE
)
_NEGATION_AFTER = re.compile(
    r"^[^.\n]{0,45}\b(?:not\s+required|not\s+applicable|is\s+free|are\s+free|free\s+of\s+cost|no\s+fee)\b",
    re.IGNORECASE,
)
_PAYMENT_CUE = re.compile(
    r"\b(?:pay|paid|payment|deposit|transfer|remit|send\s+(?:money|amount|rs|inr)|"
    r"scan\s+(?:the\s+)?qr|upi|bank\s+transfer|account\s+(?:number|no)|a/c|ifsc|"
    r"amount|charges|fee|fees|cost)\b",
    re.IGNORECASE,
)
_CRYPTO_GIFT = re.compile(
    r"\b(?:gift\s?card|google\s+play\s+(?:card|code)|amazon\s+(?:gift\s+)?card|"
    r"bitcoin|btc|usdt|crypto(?:currency)?|binance|wallet\s+address)\b",
    re.IGNORECASE,
)
_BANK_ACCOUNT = re.compile(
    r"\b(?:account\s*(?:number|no\.?|details)|a/c\s*(?:number|no\.?)?|ifsc\s*(?:code)?)\b",
    re.IGNORECASE,
)
_PERSONAL_PAYMENT = re.compile(
    r"\b(?:send|transfer|deposit|pay)\b[^.\n]{0,80}\b(?:to|into)\s+(?:my|this|the\s+following)\b",
    re.IGNORECASE,
)


def detect_payments(text: str) -> dict:
    """Return payment findings plus structured payment contexts."""
    text = text or ""
    findings: list[dict] = []
    contexts: list[dict] = []
    amounts = extract_amounts(text)
    emails = extract_emails(text)
    upi_ids = extract_upi_ids(text, emails)

    negated_fee_found = False

    for pattern in PAYMENT_PATTERNS:
        for match in re.finditer(pattern["regex"], text, re.IGNORECASE):
            window_start = max(0, match.start() - 150)
            window_end = min(len(text), match.end() + 150)
            window = text[window_start:window_end]

            before = text[max(0, match.start() - 60):match.start()]
            after = text[match.end():match.end() + 60]
            if _NEGATION_BEFORE.search(before) or _NEGATION_AFTER.search(after):
                negated_fee_found = True
                continue

            nearby_amounts = [
                a for a in amounts
                if window_start <= a["start"] <= window_end
            ]
            has_cue = bool(_PAYMENT_CUE.search(window)) or bool(nearby_amounts)
            if not has_cue:
                continue

            evidence = make_snippet(text, match.start(), match.end(), 100)
            if nearby_amounts:
                evidence += " | Amount(s): " + ", ".join(a["raw"] for a in nearby_amounts[:3])

            findings.append(
                make_finding(
                    pattern["id"],
                    "payment",
                    pattern["title"],
                    pattern["severity"],
                    pattern["points"],
                    evidence=evidence,
                    why=pattern["why"],
                    source="payment_detector",
                )
            )
            contexts.append(
                {
                    "type": pattern["id"],
                    "title": pattern["title"],
                    "severity": pattern["severity"],
                    "amounts": [a["raw"] for a in nearby_amounts[:5]],
                    "snippet": evidence,
                }
            )
            break  # one finding per payment type keeps scoring tidy

    if negated_fee_found:
        findings.append(
            make_finding(
                "PAY_NO_FEE_STATED",
                "payment",
                "Message explicitly states that no fee is required",
                "clean",
                0,
                evidence="A negation such as 'no fee' or 'free of cost' was found.",
                why="This is a positive signal but cannot by itself prove legitimacy.",
                source="payment_detector",
                verified=True,
            )
        )

    combined_low = text.lower()

    if upi_ids:
        payment_context_present = bool(contexts) or bool(_PAYMENT_CUE.search(combined_low))
        if payment_context_present:
            findings.append(
                make_finding(
                    "PAY_PERSONAL_UPI",
                    "payment",
                    "Personal UPI ID provided for payment",
                    "high",
                    12,
                    evidence="UPI ID(s): " + ", ".join(upi_ids[:3]),
                    why="Personal UPI transfers are difficult to reverse and are commonly used in recruitment scams. Verify the recipient independently.",
                    source="payment_detector",
                )
            )

    if _BANK_ACCOUNT.search(text) and _PERSONAL_PAYMENT.search(text):
        findings.append(
            make_finding(
                "PAY_PERSONAL_BANK_TRANSFER",
                "payment",
                "Bank transfer requested to a personal-looking account",
                "high",
                12,
                evidence=make_snippet(text, _BANK_ACCOUNT.search(text).start(), _BANK_ACCOUNT.search(text).end(), 100),
                why="Requests to transfer money to an individual account rather than a corporate account are a strong warning sign.",
                source="payment_detector",
            )
        )

    crypto_match = _CRYPTO_GIFT.search(text)
    if crypto_match:
        findings.append(
            make_finding(
                "PAY_CRYPTO_GIFT_CARD",
                "payment",
                "Crypto or gift-card payment requested",
                "critical",
                16,
                evidence=make_snippet(text, crypto_match.start(), crypto_match.end(), 100),
                why="No legitimate employer asks a candidate to pay in gift cards or cryptocurrency. These transfers are effectively untraceable.",
                source="payment_detector",
            )
        )

    return {
        "findings": findings,
        "contexts": contexts,
        "amounts": amounts,
        "upi_ids": upi_ids,
    }
