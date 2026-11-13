"""Optional OSINT / URL reputation providers.

Both providers are optional. If no API key is configured, OfferShield reports
the check as unavailable. It never invents reputation results.
"""

from __future__ import annotations

import base64

import requests

from detection.findings import make_finding

USER_AGENT = "OfferShield/1.0"
VT_ENDPOINT = "https://www.virustotal.com/api/v3/urls/{url_id}"
SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_reputation(url: str, config: dict) -> dict:
    findings: list[dict] = []
    checks: list[dict] = []

    if not url:
        checks.append(
            _check("url_reputation", "URL reputation", "unknown", "No website URL was available for reputation lookup.")
        )
        findings.append(
            make_finding(
                "OSINT_NO_URL", "osint", "No URL available for reputation lookup",
                "unknown", 0, evidence="",
                why="Reputation services need a URL. This is missing information, not evidence of fraud.",
                source="reputation",
            )
        )
        return {"findings": findings, "checks": checks, "providers": []}

    if not config.get("NETWORK_CHECKS_ENABLED", True):
        checks.append(_check("url_reputation", "URL reputation", "unknown", "Network checks are disabled by configuration."))
        findings.append(
            make_finding(
                "OSINT_SKIPPED", "osint", "Reputation check skipped",
                "unknown", 0, evidence=url,
                why="Network checks are disabled. No reputation result is claimed.",
                source="reputation",
            )
        )
        return {"findings": findings, "checks": checks, "providers": []}

    providers = []
    vt_key = (config.get("VIRUSTOTAL_API_KEY") or "").strip()
    sb_key = (config.get("SAFE_BROWSING_API_KEY") or "").strip()

    if vt_key:
        providers.append("VirusTotal")
        vt = _virustotal(url, vt_key, int(config.get("DOMAIN_TIMEOUT", 6)))
        findings.extend(vt["findings"])
        checks.append(_check("virustotal", "VirusTotal URL reputation", vt["status"], vt["detail"]))
    else:
        checks.append(_check("virustotal", "VirusTotal URL reputation", "unknown", "No VIRUSTOTAL_API_KEY configured."))

    if sb_key:
        providers.append("Google Safe Browsing")
        sb = _safe_browsing(url, sb_key, int(config.get("DOMAIN_TIMEOUT", 6)))
        findings.extend(sb["findings"])
        checks.append(_check("safe_browsing", "Google Safe Browsing", sb["status"], sb["detail"]))
    else:
        checks.append(_check("safe_browsing", "Google Safe Browsing", "unknown", "No SAFE_BROWSING_API_KEY configured."))

    if not vt_key and not sb_key:
        findings.append(
            make_finding(
                "OSINT_PROVIDER_UNAVAILABLE", "osint", "No reputation provider configured",
                "unknown", 0, evidence=url,
                why="URL reputation checks are optional and were not performed. This is not evidence of fraud.",
                source="reputation",
            )
        )

    return {"findings": findings, "checks": checks, "providers": providers}


def _virustotal(url: str, api_key: str, timeout: int) -> dict:
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    try:
        response = requests.get(
            VT_ENDPOINT.format(url_id=url_id),
            headers={"x-apikey": api_key, "User-Agent": USER_AGENT},
            timeout=(min(4, timeout), timeout),
        )
    except requests.RequestException as exc:
        return {
            "status": "unknown",
            "detail": f"VirusTotal lookup failed ({type(exc).__name__}). No result claimed.",
            "findings": [
                make_finding(
                    "OSINT_VT_ERROR", "osint", "VirusTotal lookup could not be completed",
                    "unknown", 0, evidence=url,
                    why="The external reputation API was unavailable. This is not evidence of fraud.",
                    source="reputation",
                )
            ],
        }

    if response.status_code == 404:
        return {
            "status": "unknown",
            "detail": "This URL has not been analysed by VirusTotal. Absence of a record is not a clean bill of health.",
            "findings": [],
        }
    if response.status_code != 200:
        return {
            "status": "unknown",
            "detail": f"VirusTotal returned HTTP {response.status_code}. No result claimed.",
            "findings": [],
        }

    try:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, TypeError, ValueError):
        return {
            "status": "unknown",
            "detail": "VirusTotal response could not be interpreted. No result claimed.",
            "findings": [],
        }

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    detail = (
        f"{malicious} malicious, {suspicious} suspicious, {harmless} harmless engine verdicts. "
        "Reputation data can lag behind new scam sites."
    )
    findings = []
    if malicious > 0:
        findings.append(
            make_finding(
                "OSINT_URL_MALICIOUS", "osint", "URL flagged as malicious by reputation engines",
                "critical", 10, evidence=f"{malicious} engine(s) flagged this URL",
                why="Multiple independent security engines have associated this URL with malicious activity. Treat it as dangerous.",
                source="reputation", verified=True,
            )
        )
        status = "fail"
    elif suspicious > 0:
        findings.append(
            make_finding(
                "OSINT_URL_SUSPICIOUS", "osint", "URL flagged as suspicious by reputation engines",
                "high", 8, evidence=f"{suspicious} engine(s) flagged this URL as suspicious",
                why="Reputation engines see suspicious characteristics. Avoid entering credentials or payments.",
                source="reputation", verified=True,
            )
        )
        status = "warn"
    else:
        findings.append(
            make_finding(
                "OSINT_VT_NO_DETECTIONS", "osint", "No VirusTotal engine detections",
                "clean", 0, evidence=f"{harmless} harmless verdicts",
                why="No detections is a weak positive signal only. New phishing sites often have no reputation history.",
                source="reputation", verified=True,
            )
        )
        status = "pass"
    return {"status": status, "detail": detail, "findings": findings}


def _safe_browsing(url: str, api_key: str, timeout: int) -> dict:
    payload = {
        "client": {"clientId": "offershield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(
            SAFE_BROWSING_ENDPOINT,
            params={"key": api_key},
            json=payload,
            headers={"User-Agent": USER_AGENT},
            timeout=(min(4, timeout), timeout),
        )
    except requests.RequestException as exc:
        return {
            "status": "unknown",
            "detail": f"Safe Browsing lookup failed ({type(exc).__name__}). No result claimed.",
            "findings": [],
        }
    if response.status_code != 200:
        return {
            "status": "unknown",
            "detail": f"Safe Browsing returned HTTP {response.status_code}. No result claimed.",
            "findings": [],
        }
    try:
        matches = response.json().get("matches", [])
    except (ValueError, AttributeError):
        return {"status": "unknown", "detail": "Safe Browsing response could not be interpreted.", "findings": []}

    if matches:
        types = sorted({m.get("threatType", "THREAT") for m in matches})
        return {
            "status": "fail",
            "detail": "Safe Browsing threat types: " + ", ".join(types),
            "findings": [
                make_finding(
                    "OSINT_SAFE_BROWSING_MATCH", "osint", "Google Safe Browsing flags this URL",
                    "critical", 10, evidence="Threat types: " + ", ".join(types),
                    why="Google Safe Browsing has identified this URL as a threat. Do not visit it or enter information.",
                    source="reputation", verified=True,
                )
            ],
        }
    return {
        "status": "pass",
        "detail": "No Safe Browsing matches. This is not a guarantee; new sites may not be listed yet.",
        "findings": [
            make_finding(
                "OSINT_SAFE_BROWSING_CLEAN", "osint", "No Google Safe Browsing match",
                "clean", 0, evidence=url,
                why="No match is a weak positive signal only. Reputation lists lag behind newly created scam sites.",
                source="reputation", verified=True,
            )
        ],
    }


def _check(key: str, label: str, status: str, detail: str) -> dict:
    return {"key": key, "label": label, "status": status, "detail": str(detail or "")[:260], "source": "osint"}
