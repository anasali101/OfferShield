"""Feature C: domain, DNS, TLS and registration intelligence.

Security model:
- Only http/https URLs are accepted.
- Userinfo (user:pass@host) is rejected.
- Hostnames are resolved; every resolved address must be globally routable.
- Loopback, private, link-local, multicast, reserved and metadata addresses are
  blocked (SSRF protection).
- Redirects are followed manually, one hop at a time, re-validating each URL.
- Requests never download response bodies; only headers/status are inspected.
- Fixed timeouts are applied to DNS, TCP, TLS and HTTP operations.

Residual risk: a hostile DNS server could change answers between our validation
and the HTTP client's own lookup (DNS rebinding). Re-validation on every request
plus no automatic redirects reduces, but does not eliminate, that risk. This is
documented in the README.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlunparse

import dns.exception
import dns.resolver
import requests
from rapidfuzz import fuzz

from detection.brands import (
    FREE_HOSTING_DOMAINS,
    KNOWN_BRANDS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)
from detection.findings import make_finding
from detection.utils import make_snippet, registrable_domain

USER_AGENT = "OfferShield/1.0 (defensive recruitment-fraud checks; non-intrusive)"
ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {None, 80, 443, 8080, 8443}
BLOCKED_HOSTNAMES = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal", "metadata", "instance-data",
}
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa", ".lan", ".intranet")
MAX_REDIRECTS = 3
MAX_URL_LENGTH = 2048


class UnsafeURLError(ValueError):
    """Raised when a URL fails SSRF or scheme validation."""


def normalize_url(raw: str) -> tuple[str, str]:
    raw = (raw or "").strip()
    if not raw:
        raise UnsafeURLError("Please enter a website URL.")
    if len(raw) > MAX_URL_LENGTH:
        raise UnsafeURLError("URL is too long.")
    if any(ord(ch) < 32 for ch in raw):
        raise UnsafeURLError("URL contains invalid control characters.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeURLError("Only http and https URLs are supported.")
    if parsed.username or parsed.password:
        raise UnsafeURLError("URLs containing embedded credentials are not allowed.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsafeURLError("URL contains an invalid port.") from exc
    if port not in ALLOWED_PORTS:
        raise UnsafeURLError("Only standard web ports (80, 443, 8080, 8443) are allowed.")
    host = (parsed.hostname or "").strip().rstrip(".").lower()
    if not host:
        raise UnsafeURLError("URL does not contain a valid hostname.")
    if len(host) > 253:
        raise UnsafeURLError("Hostname is too long.")
    if host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_SUFFIXES):
        raise UnsafeURLError("Local, internal and metadata hostnames are blocked.")
    try:
        host_ascii = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UnsafeURLError("Hostname is not valid IDNA.") from exc

    ip = _parse_ip(host_ascii)
    if ip is not None:
        if not is_public_ip(ip):
            raise UnsafeURLError("Private, loopback and reserved IP addresses are blocked.")
    else:
        ips, _error = resolve_host(host_ascii, timeout=5)
        if ips and not all(is_public_ip(_parse_ip(value)) for value in ips):
            raise UnsafeURLError("This hostname resolves to a private or reserved address.")

    netloc = host_ascii
    if port:
        netloc = f"{host_ascii}:{port}"
    clean = urlunparse((scheme, netloc, parsed.path or "/", parsed.params, parsed.query, ""))
    return clean, host_ascii


def validate_public_url(raw: str) -> tuple[str, str]:
    return normalize_url(raw)


def _parse_ip(value: str | None):
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value.split("%")[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def is_public_ip(ip) -> bool:
    if ip is None:
        return False
    return bool(
        ip.is_global
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_unspecified
    )


def resolve_host(host: str, timeout: int = 5) -> tuple[list[str], str | None]:
    """Resolve A/AAAA records securely with a bounded timeout."""
    ips: list[str] = []
    errors: list[str] = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = max(2, timeout)
    resolver.timeout = max(1, timeout - 1)
    for rtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(host, rtype, raise_on_no_answer=False)
            if answers.rrset:
                ips.extend(str(rdata) for rdata in answers)
        except dns.resolver.NXDOMAIN:
            errors.append("domain does not exist (NXDOMAIN)")
            break
        except dns.resolver.NoNameservers:
            errors.append("no nameservers answered")
            break
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            errors.append("DNS lookup timed out")
            break
        except Exception as exc:  # defensive: DNS libraries vary by version
            errors.append(f"DNS error: {type(exc).__name__}")
            break

    if not ips:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            ips = [info[4][0] for info in infos]
        except OSError:
            pass
    return _unique(ips), (errors[0] if errors and not ips else None)


def analyze_domain(url: str, config: dict) -> dict:
    network_enabled = bool(config.get("NETWORK_CHECKS_ENABLED", True))
    timeout = max(3, min(15, int(config.get("DOMAIN_TIMEOUT", 6))))
    result = {
        "url": url,
        "host": "",
        "registrable_domain": "",
        "findings": [],
        "checks": [],
        "registration": {"available": False, "note": "Not checked."},
        "dns": {},
        "ssl": {},
        "http": {},
        "brand_matches": [],
        "blocked": False,
        "network_enabled": network_enabled,
    }

    try:
        normalized, host = validate_public_url(url)
    except UnsafeURLError as exc:
        result["blocked"] = True
        result["error"] = str(exc)
        result["checks"].append(_check("url_safety", "URL safety validation", "fail", str(exc)))
        return result

    result["url"] = normalized
    result["host"] = host
    result["registrable_domain"] = registrable_domain(host)

    pattern_findings = url_pattern_findings(normalized, host)
    result["findings"].extend(pattern_findings)

    brand_findings, matches = brand_similarity_findings(host)
    result["findings"].extend(brand_findings)
    result["brand_matches"] = matches

    if not network_enabled:
        detail = "Network checks are disabled by configuration (NETWORK_CHECKS_ENABLED=0)."
        for key, label in (
            ("domain_registration", "Domain registration age"),
            ("dns", "DNS records"),
            ("ssl", "TLS certificate"),
            ("http", "Website reachability"),
        ):
            result["checks"].append(_check(key, label, "unknown", detail))
        result["checks"].append(_check("url_patterns", "URL pattern analysis", _pattern_status(pattern_findings), "Analysed offline."))
        result["checks"].append(_check("brand_similarity", "Brand similarity", _brand_status(brand_findings), _brand_detail(matches)))
        result["registration"] = {"available": False, "note": "Network checks disabled."}
        return result

    dns_info = _dns_info(host, timeout)
    result["dns"] = dns_info
    result["findings"].extend(_dns_findings(dns_info))

    registration = rdap_lookup(host, timeout, config)
    result["registration"] = registration
    result["findings"].extend(_registration_findings(registration))

    ssl_info = ssl_probe(host, timeout)
    result["ssl"] = ssl_info
    result["findings"].extend(_ssl_findings(ssl_info, normalized))

    http_info = http_probe(normalized, timeout)
    result["http"] = http_info
    result["findings"].extend(_http_findings(http_info))

    result["checks"].append(
        _check("domain_registration", "Domain registration age", _registration_status(registration),
               _registration_detail(registration))
    )
    result["checks"].append(_check("dns", "DNS records", _dns_status(dns_info), _dns_detail(dns_info)))
    result["checks"].append(_check("ssl", "TLS certificate", _ssl_status(ssl_info), _ssl_detail(ssl_info)))
    result["checks"].append(_check("http", "Website reachability", _http_status(http_info), _http_detail(http_info)))
    result["checks"].append(
        _check("url_patterns", "URL pattern analysis", _pattern_status(pattern_findings),
               "Pattern checks look for IP-literal hosts, punycode, shorteners and high-risk TLDs.")
    )
    result["checks"].append(
        _check("brand_similarity", "Brand similarity", _brand_status(brand_findings), _brand_detail(matches))
    )
    return result


# ---------------------------------------------------------------------------
# Offline URL / brand analysis
# ---------------------------------------------------------------------------

def url_pattern_findings(url: str, host: str) -> list[dict]:
    findings: list[dict] = []
    parsed = urlparse(url)
    ip = _parse_ip(host)
    reg = registrable_domain(host)
    tld = reg.rsplit(".", 1)[-1] if "." in reg else ""

    if ip is not None:
        findings.append(
            make_finding(
                "DOM_IP_LITERAL", "domain", "Website uses a raw IP address instead of a domain",
                "high", 8, evidence=host,
                why="Legitimate companies publish branded domains. Raw IP hosts are harder to verify and common in short-lived scam sites.",
                source="domain_checker",
            )
        )

    if host.startswith("xn--") or ".xn--" in host:
        findings.append(
            make_finding(
                "DOM_PUNYCODE", "domain", "Punycode (internationalised) domain name",
                "medium", 6, evidence=host,
                why="Punycode can be used for homograph attacks that visually imitate well-known brands. It also has legitimate uses, so this is a warning only.",
                source="domain_checker",
            )
        )

    if tld in SUSPICIOUS_TLDS:
        findings.append(
            make_finding(
                "DOM_SUSPICIOUS_TLD", "domain", f"High-abuse top-level domain (.{tld})",
                "low", 3, evidence=host,
                why="Some TLDs are disproportionately used for short-lived scam sites. Many legitimate sites also use them, so this is weak evidence on its own.",
                source="domain_checker",
            )
        )

    if reg in URL_SHORTENERS:
        findings.append(
            make_finding(
                "DOM_URL_SHORTENER", "domain", "Link shortener hides the destination",
                "medium", 5, evidence=url[:200],
                why="Shortened links prevent you from seeing the real destination before clicking. Expand the link using a trusted service or ask for the full URL.",
                source="domain_checker",
            )
        )

    if reg in FREE_HOSTING_DOMAINS:
        findings.append(
            make_finding(
                "DOM_FREE_HOSTING", "domain", "Website hosted on a free subdomain platform",
                "low", 4, evidence=reg,
                why="Free hosting is not inherently fraudulent, but established employers normally use their own corporate domain for recruitment.",
                source="domain_checker",
            )
        )

    if parsed.scheme == "http":
        findings.append(
            make_finding(
                "DOM_NO_HTTPS", "domain", "Website submitted over plain HTTP",
                "low", 4, evidence=url[:200],
                why="HTTP is not encrypted. Note that HTTPS alone does not establish legitimacy, and many phishing sites use valid certificates.",
                source="domain_checker",
            )
        )

    labels = host.split(".")
    if len(host) > 45 or labels.count("") > 0 or (host.count("-") >= 4):
        findings.append(
            make_finding(
                "DOM_OBFUSCATED_HOST", "domain", "Unusually long or obfuscated hostname",
                "low", 3, evidence=host,
                why="Excessively complex hostnames are sometimes used to hide the real registrable domain. Read the domain from right to left.",
                source="domain_checker",
            )
        )

    if "xn--" in url or re.search(r"%[0-9a-f]{2}", parsed.netloc, re.IGNORECASE):
        pass  # netloc is normalised; encoded-host tricks are rejected upstream.

    return findings


def brand_similarity_findings(host: str) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    matches: list[dict] = []
    reg = registrable_domain(host)

    for brand_key, info in KNOWN_BRANDS.items():
        domains = info["domains"]
        for official in domains:
            if host == official or host.endswith("." + official):
                findings.append(
                    make_finding(
                        "DOM_OFFICIAL_BRAND_DOMAIN", "domain",
                        f"Domain matches the known official domain for {info['display']}",
                        "clean", 0,
                        evidence=host,
                        why="This confirms the domain belongs to the brand. It does not confirm that the recruiter or vacancy is genuine.",
                        source="domain_checker", verified=True,
                    )
                )
                matches.append(
                    {"brand": info["display"], "official_domain": official, "match": "official", "evidence": host}
                )
                return findings, matches

    reg_sld = reg.split(".")[0] if reg else ""
    host_labels = host.split(".")
    reg_labels = reg.split(".") if reg else []
    subdomain_labels = host_labels[: max(0, len(host_labels) - len(reg_labels))]

    best = None
    for brand_key, info in KNOWN_BRANDS.items():
        for official in info["domains"]:
            brand_sld = official.split(".")[0].replace("-", "")
            if len(brand_sld) < 4:
                continue
            normalized_sld = _deobfuscate(reg_sld).replace("-", "").replace("_", "")
            if not normalized_sld:
                continue

            reason = None
            if _contains_brand_token(normalized_sld, brand_sld):
                reason = "contains"
            elif any(_contains_brand_token(_deobfuscate(label), brand_sld) for label in subdomain_labels):
                reason = "subdomain"
            else:
                ratio = fuzz.ratio(normalized_sld, brand_sld)
                if ratio >= 88:
                    reason = f"similar ({round(ratio)}%)"

            if reason:
                score = 12 if reason in {"contains", "subdomain"} else 10
                best = (info, official, reason, score)
                break
        if best:
            break

    if best:
        info, official, reason, score = best
        finding_id = "DOM_LOOKALIKE_SUBDOMAIN" if reason == "subdomain" else "DOM_SIMILAR_BRAND"
        findings.append(
            make_finding(
                finding_id, "domain",
                f"Domain resembles the official domain of {info['display']}",
                "high", score,
                evidence=f"{host} ↔ {official}",
                why=(
                    "The domain is similar to, or embeds, a known brand but is not the official "
                    "domain. This is a common typosquatting/impersonation pattern. A similarity "
                    "match is evidence to investigate, not proof of fraud."
                ),
                source="domain_checker",
            )
        )
        matches.append(
            {
                "brand": info["display"],
                "official_domain": official,
                "match": reason,
                "evidence": host,
            }
        )

    return findings, matches


def _contains_brand_token(value: str, brand: str) -> bool:
    if not value or not brand:
        return False
    if value == brand:
        return False
    tokens = re.split(r"[^a-z0-9]+", value)
    if brand in tokens:
        return True
    if len(brand) >= 5 and (value.startswith(brand) or value.endswith(brand)):
        return True
    return False


def _deobfuscate(value: str) -> str:
    value = (value or "").lower()
    replacements = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"}
    value = "".join(replacements.get(ch, ch) for ch in value)
    value = value.replace("vv", "w").replace("rn", "m").replace("cl", "d")
    return value


# ---------------------------------------------------------------------------
# Live checks
# ---------------------------------------------------------------------------

def _dns_info(host: str, timeout: int) -> dict:
    info = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], "cname": [], "error": None}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = max(2, timeout)
    resolver.timeout = max(1, timeout - 1)
    for record_type, key in (("A", "a"), ("AAAA", "aaaa"), ("MX", "mx"), ("NS", "ns"), ("TXT", "txt"), ("CNAME", "cname")):
        try:
            answers = resolver.resolve(host, record_type, raise_on_no_answer=False)
            if not answers.rrset:
                continue
            if record_type == "MX":
                info[key] = [f"{r.preference} {str(r.exchange).rstrip('.')}" for r in answers][:5]
            elif record_type == "TXT":
                info[key] = ["".join(part.decode("utf-8", "replace") for part in r.strings)[:200] for r in answers][:5]
            else:
                info[key] = [str(r).rstrip(".") for r in answers][:8]
        except dns.resolver.NXDOMAIN:
            info["error"] = "NXDOMAIN - the domain does not currently exist in DNS"
            break
        except dns.resolver.NoNameservers:
            info["error"] = "No nameservers answered the DNS query"
            break
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            info["error"] = "DNS query timed out"
            break
        except Exception as exc:
            info["error"] = f"DNS query failed ({type(exc).__name__})"
            break
    return info


def rdap_lookup(host: str, timeout: int, config: dict) -> dict:
    if _parse_ip(host) is not None:
        return {"available": False, "note": "Registration lookup is not applicable to IP-address URLs."}
    domain = registrable_domain(host)
    template = config.get("RDAP_URL_TEMPLATE") or "https://rdap.org/domain/{domain}"
    url = template.format(domain=domain)
    session = requests.Session()
    session.trust_env = False
    try:
        response = session.get(
            url,
            timeout=(min(4, timeout), timeout),
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"},
        )
        if response.status_code == 200:
            data = response.json()
            registration = _rdap_registration(data)
            if registration:
                registration["source"] = "RDAP"
                registration["registrar_url"] = url
                return registration
    except (requests.RequestException, ValueError, KeyError, TypeError):
        pass

    whois_result = _whois_fallback(domain, timeout)
    if whois_result:
        whois_result["source"] = "WHOIS"
        return whois_result
    return {"available": False, "note": "Registration data could not be retrieved from RDAP or WHOIS."}


def _whois_fallback(domain: str, timeout: int) -> dict | None:
    """python-whois fallback with a bounded wait (the library has no timeout)."""
    import threading

    holder: dict = {}

    def worker():
        try:
            import whois  # python-whois
            data = whois.whois(domain)
            created = getattr(data, "creation_date", None)
            if isinstance(created, list):
                created = created[0] if created else None
            registrar = getattr(data, "registrar", None)
            if isinstance(registrar, list):
                registrar = registrar[0] if registrar else None
            holder["data"] = {"created": created, "registrar": registrar}
        except Exception:
            holder["data"] = None

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout=max(2, timeout))
    data = holder.get("data")
    if not data or not data.get("created"):
        return None
    created = _coerce_datetime(data["created"])
    if not created:
        return None
    age_days = (datetime.now(timezone.utc) - created).days
    return {
        "available": True,
        "registration_date": created.date().isoformat(),
        "age_days": age_days,
        "registrar": str(data.get("registrar") or "Unknown"),
        "status": [],
        "note": "Obtained via WHOIS fallback; details may be less complete than RDAP.",
    }


def _rdap_registration(data: dict) -> dict | None:
    if not isinstance(data, dict):
        return None
    created = None
    expires = None
    for event in data.get("events", []) or []:
        action = str(event.get("eventAction", "")).lower()
        date = _coerce_datetime(event.get("eventDate"))
        if action == "registration" and date:
            created = date
        elif action == "expiration" and date:
            expires = date
    if not created:
        return None
    age_days = (datetime.now(timezone.utc) - created).days
    registrar = None
    for entity in data.get("entities", []) or []:
        roles = [str(r).lower() for r in entity.get("roles", [])]
        if "registrar" in roles:
            registrar = _vcard_name(entity.get("vcardArray"))
            if registrar:
                break
    return {
        "available": True,
        "registration_date": created.date().isoformat(),
        "expiration_date": expires.date().isoformat() if expires else None,
        "age_days": age_days,
        "registrar": registrar or "Not disclosed",
        "status": [str(s) for s in (data.get("status") or [])][:6],
        "note": "Registration dates can be privacy-protected or inaccurate.",
    }


def _vcard_name(vcard) -> str | None:
    try:
        if isinstance(vcard, list) and len(vcard) > 1:
            for entry in vcard[1]:
                if entry and entry[0] == "fn":
                    return str(entry[3])[:100]
    except (IndexError, TypeError):
        return None
    return None


def ssl_probe(host: str, timeout: int) -> dict:
    info = {"available": False, "verified": False, "error": None}
    if _parse_ip(host) is not None:
        info["error"] = "TLS hostname verification is not meaningful for an IP-address URL."
        return info

    # Validate resolution immediately before opening the socket.
    ips, _ = resolve_host(host, timeout)
    if ips and not all(is_public_ip(_parse_ip(value)) for value in ips):
        info["error"] = "Blocked: hostname resolved to a non-public address during TLS check."
        return info

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
                info.update(
                    {
                        "available": True,
                        "verified": True,
                        "protocol": tls.version(),
                        "cipher": cipher[0] if cipher else None,
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "subject": _name_dict(cert.get("subject")),
                        "issuer": _name_dict(cert.get("issuer")),
                        "san": [value for key, value in cert.get("subjectAltName", []) if key == "DNS"][:8],
                    }
                )
                expires = ssl.cert_time_to_seconds(cert.get("notAfter", ""))
                info["days_remaining"] = int((datetime.fromtimestamp(expires, timezone.utc) - datetime.now(timezone.utc)).days)
                info["self_signed"] = info["subject"] == info["issuer"]
    except ssl.SSLCertVerificationError as exc:
        info.update({"available": True, "verified": False, "error": f"Certificate verification failed: {exc.verify_message or exc.reason}"})
    except (socket.timeout, TimeoutError):
        info["error"] = "TLS connection timed out."
    except ConnectionRefusedError:
        info["error"] = "TLS connection refused on port 443."
    except OSError as exc:
        info["error"] = f"TLS connection failed ({type(exc).__name__})."
    return info


def http_probe(url: str, timeout: int) -> dict:
    session = requests.Session()
    session.trust_env = False
    info = {"reachable": False, "status_code": None, "original_url": url, "final_url": url, "redirects": [], "error": None, "server": None}
    current = url
    try:
        for _ in range(MAX_REDIRECTS + 1):
            current, _host = validate_public_url(current)
            response = session.get(
                current,
                timeout=(min(4, timeout), timeout),
                allow_redirects=False,
                stream=True,
                headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.1"},
            )
            info["status_code"] = response.status_code
            info["server"] = (response.headers.get("Server") or "")[:80] or None
            info["final_url"] = current
            location = response.headers.get("Location")
            response.close()
            if response.is_redirect and location:
                nxt = urljoin(current, location)
                validate_public_url(nxt)
                info["redirects"].append(nxt)
                current = nxt
                continue
            info["reachable"] = True
            break
    except UnsafeURLError as exc:
        info["error"] = f"Redirect blocked: {exc}"
    except requests.exceptions.SSLError:
        info["error"] = "TLS verification failed while loading the page."
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        info["error"] = "Website did not respond within the timeout."
    except requests.RequestException as exc:
        info["error"] = f"HTTP check failed ({type(exc).__name__})."
    finally:
        session.close()
    return info


# ---------------------------------------------------------------------------
# Finding builders
# ---------------------------------------------------------------------------

def _registration_findings(reg: dict) -> list[dict]:
    if not reg.get("available"):
        return [
            make_finding(
                "DOM_REG_UNAVAILABLE", "domain", "Domain registration data unavailable",
                "unknown", 0, evidence=reg.get("note", ""),
                why="Missing registration data is not evidence of fraud. It only means this check could not be completed.",
                source="domain_checker",
            )
        ]
    age = int(reg.get("age_days") or 0)
    evidence = (
        f"Registered {reg.get('registration_date')} "
        f"({age} days ago); registrar: {reg.get('registrar')}; source: {reg.get('source')}"
    )
    common_why = "Domain age is one indicator only. Many legitimate new businesses exist, so age alone is never conclusive."
    if age < 0:
        return [make_finding("DOM_FUTURE_REGISTRATION", "domain", "Registration date is in the future", "low", 3, evidence, "Future dates usually indicate a data error, but they reduce confidence in the record.", source="domain_checker")]
    if age <= 30:
        return [make_finding("DOM_NEW_DOMAIN", "domain", "Domain registered in the last 30 days", "high", 12, evidence, common_why, "domain_checker")]
    if age <= 90:
        return [make_finding("DOM_NEW_DOMAIN", "domain", "Domain registered within the last 90 days", "high", 10, evidence, common_why, "domain_checker")]
    if age <= 180:
        return [make_finding("DOM_YOUNG_DOMAIN", "domain", "Domain is less than 6 months old", "medium", 6, evidence, common_why, "domain_checker")]
    if age <= 365:
        return [make_finding("DOM_YOUNG_DOMAIN", "domain", "Domain is less than 1 year old", "low", 4, evidence, common_why, "domain_checker")]
    return [make_finding("DOM_ESTABLISHED", "domain", "Domain registration is more than one year old", "clean", 0, evidence, "An older registration is a weak positive signal only. Domains can change ownership and older domains can be compromised.", "domain_checker", verified=True)]


def _dns_findings(dns_info: dict) -> list[dict]:
    if dns_info.get("error") and not (dns_info.get("a") or dns_info.get("aaaa")):
        return [
            make_finding(
                "DOM_DNS_FAILURE", "domain", "Domain does not resolve in DNS",
                "low", 3, evidence=dns_info["error"],
                why="A claimed active recruitment website that does not resolve is worth investigating, but DNS outages and typos also happen. This is not proof of fraud.",
                source="domain_checker",
            )
        ]
    return []


def _ssl_findings(ssl_info: dict, url: str) -> list[dict]:
    findings: list[dict] = []
    if not ssl_info.get("available"):
        findings.append(
            make_finding(
                "DOM_SSL_UNAVAILABLE", "domain", "TLS certificate could not be inspected",
                "unknown", 0, evidence=ssl_info.get("error", ""),
                why="No certificate was retrieved. This may be a network issue, an HTTP-only site or a blocked connection. It is not evidence of fraud by itself.",
                source="domain_checker",
            )
        )
        return findings

    if not ssl_info.get("verified"):
        findings.append(
            make_finding(
                "DOM_SSL_INVALID", "domain", "TLS certificate failed validation",
                "high", 8, evidence=ssl_info.get("error", ""),
                why="An invalid certificate prevents secure, authenticated communication. However, HTTPS and valid certificates do not prove a site is legitimate.",
                source="domain_checker",
            )
        )
        return findings

    if ssl_info.get("self_signed"):
        findings.append(
            make_finding(
                "DOM_SSL_SELF_SIGNED", "domain", "Self-signed TLS certificate",
                "medium", 6, evidence=str(ssl_info.get("issuer")),
                why="Self-signed certificates are not trusted by browsers and are unusual for corporate recruitment sites.",
                source="domain_checker",
            )
        )
    days = ssl_info.get("days_remaining")
    if isinstance(days, int) and days < 0:
        findings.append(
            make_finding(
                "DOM_SSL_EXPIRED", "domain", "TLS certificate has expired",
                "high", 8, evidence=f"Expired {abs(days)} days ago",
                why="An expired certificate suggests neglected infrastructure. It does not prove fraud, but it lowers trust in the website.",
                source="domain_checker",
            )
        )
    elif isinstance(days, int) and days <= 14:
        findings.append(
            make_finding(
                "DOM_SSL_EXPIRING", "domain", "TLS certificate expires soon",
                "low", 3, evidence=f"{days} days remaining",
                why="Short-lived certificates are common with free certificate authorities, so this is weak evidence.",
                source="domain_checker",
            )
        )
    if ssl_info.get("verified") and not findings:
        issuer = (ssl_info.get("issuer") or {}).get("organizationName") or (ssl_info.get("issuer") or {}).get("commonName") or "unknown issuer"
        findings.append(
            make_finding(
                "DOM_SSL_VALID", "domain", "TLS certificate is valid",
                "clean", 0, evidence=f"Issuer: {issuer}; expires: {ssl_info.get('not_after')}",
                why="A valid certificate encrypts traffic and confirms domain control at issuance. It does not establish that the company or recruiter is genuine.",
                source="domain_checker", verified=True,
            )
        )
    if urlparse(url).scheme == "http":
        findings.append(
            make_finding(
                "DOM_HTTP_NOT_ENCRYPTED", "domain", "Page was submitted over HTTP",
                "low", 3, evidence=url[:200],
                why="Data sent over HTTP is unencrypted. Use the official HTTPS domain after independent verification.",
                source="domain_checker",
            )
        )
    return findings


def _http_findings(http_info: dict) -> list[dict]:
    findings = []
    if not http_info.get("reachable"):
        findings.append(
            make_finding(
                "DOM_HTTP_UNREACHABLE", "domain", "Website could not be reached",
                "unknown", 0, evidence=http_info.get("error", ""),
                why="A connection failure can be caused by timeouts, blocking or an offline site. It is not proof of fraud.",
                source="domain_checker",
            )
        )
        return findings
    if http_info.get("redirects"):
        original_host = urlparse(http_info.get("original_url") or "").hostname or ""
        final_host = urlparse(http_info.get("final_url") or "").hostname or ""
        if registrable_domain(final_host) != registrable_domain(original_host):
            findings.append(
                make_finding(
                    "DOM_REDIRECT_DIFFERENT", "domain", "Website redirects to a different domain",
                    "low", 4, evidence=f"→ {http_info.get('final_url', '')[:200]}",
                    why="Cross-domain redirects are common in analytics and link tracking, but can also hide the true destination. Verify the final domain carefully.",
                    source="domain_checker",
                )
            )
    code = http_info.get("status_code")
    if isinstance(code, int) and code >= 400:
        findings.append(
            make_finding(
                "DOM_HTTP_ERROR", "domain", f"Website returned HTTP {code}",
                "low", 2, evidence=f"HTTP {code}",
                why="Error responses can be temporary or caused by bot protection. They do not prove fraud.",
                source="domain_checker",
            )
        )
    elif isinstance(code, int) and 200 <= code < 400:
        findings.append(
            make_finding(
                "DOM_HTTP_OK", "domain", "Website responded successfully",
                "clean", 0, evidence=f"HTTP {code}; server: {http_info.get('server') or 'not disclosed'}",
                why="A working website is basic infrastructure. Scam sites can be fully functional.",
                source="domain_checker", verified=True,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Check helpers
# ---------------------------------------------------------------------------

def _check(key: str, label: str, status: str, detail: str) -> dict:
    return {"key": key, "label": label, "status": status, "detail": str(detail or "")[:240], "source": "domain"}


def _registration_status(reg: dict) -> str:
    if not reg.get("available"):
        return "unknown"
    age = int(reg.get("age_days") or 0)
    if age < 0:
        return "warn"
    if age <= 90:
        return "fail"
    if age <= 180:
        return "warn"
    return "pass"


def _registration_detail(reg: dict) -> str:
    if not reg.get("available"):
        return reg.get("note", "Registration data unavailable.")
    return (
        f"Registered {reg.get('registration_date')} ({reg.get('age_days')} days ago); "
        f"registrar: {reg.get('registrar')}; source: {reg.get('source')}. "
        "Age alone never determines fraud."
    )


def _dns_status(info: dict) -> str:
    if info.get("a") or info.get("aaaa"):
        return "pass"
    if info.get("error"):
        return "warn"
    return "unknown"


def _dns_detail(info: dict) -> str:
    if info.get("a") or info.get("aaaa"):
        parts = [
            f"A: {', '.join(info['a'][:3])}" if info.get("a") else "",
            f"AAAA: {', '.join(info['aaaa'][:2])}" if info.get("aaaa") else "",
            f"MX: {len(info.get('mx', []))}" if info.get("mx") else "",
            f"NS: {', '.join(info['ns'][:2])}" if info.get("ns") else "",
        ]
        return "; ".join(p for p in parts if p) + "."
    return info.get("error") or "No A/AAAA records found."


def _ssl_status(info: dict) -> str:
    if not info.get("available"):
        return "unknown"
    if not info.get("verified"):
        return "fail"
    days = info.get("days_remaining")
    if isinstance(days, int) and days < 0:
        return "fail"
    if isinstance(days, int) and days <= 14:
        return "warn"
    return "pass"


def _ssl_detail(info: dict) -> str:
    if not info.get("available"):
        return info.get("error") or "TLS not available."
    if not info.get("verified"):
        return info.get("error") or "Certificate failed validation."
    issuer = (info.get("issuer") or {}).get("organizationName") or (info.get("issuer") or {}).get("commonName") or "unknown"
    return (
        f"Valid certificate from {issuer}; expires {info.get('not_after')} "
        f"({info.get('days_remaining')} days). HTTPS is not proof of legitimacy."
    )


def _http_status(info: dict) -> str:
    if not info.get("reachable"):
        return "unknown"
    code = info.get("status_code")
    if isinstance(code, int) and code < 400:
        return "pass"
    return "warn"


def _http_detail(info: dict) -> str:
    if not info.get("reachable"):
        return info.get("error") or "Unreachable."
    return (
        f"HTTP {info.get('status_code')}; final URL {info.get('final_url')}; "
        f"redirects: {len(info.get('redirects') or [])}."
    )


def _pattern_status(findings: list[dict]) -> str:
    if any(f["severity"] in {"critical", "high"} for f in findings):
        return "fail"
    if any(f["severity"] in {"medium", "low"} for f in findings):
        return "warn"
    return "pass"


def _brand_status(findings: list[dict]) -> str:
    if any(f["id"] in {"DOM_SIMILAR_BRAND", "DOM_LOOKALIKE_SUBDOMAIN"} for f in findings):
        return "fail"
    if any(f["id"] == "DOM_OFFICIAL_BRAND_DOMAIN" for f in findings):
        return "pass"
    return "unknown"


def _brand_detail(matches: list[dict]) -> str:
    if not matches:
        return "No resemblance to the built-in brand list. This does not verify the website."
    match = matches[0]
    if match["match"] == "official":
        return f"Matches official {match['brand']} domain {match['official_domain']}. Domain only; recruiter not verified."
    return f"Resembles {match['brand']} ({match['official_domain']}): {match['match']}."


def _name_dict(name) -> dict:
    result = {}
    for item in name or []:
        try:
            result[item[0][0]] = item[0][1]
        except (IndexError, TypeError):
            continue
    return result


def _coerce_datetime(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        cleaned = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(cleaned)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        try:
            from email.utils import parsedate_to_datetime
            parsed = parsedate_to_datetime(value)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return None
    return None


def _unique(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
