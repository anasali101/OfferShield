# OfferShield

**Know Before You Trust.** OfferShield is an AI-assisted recruitment-fraud
screening tool. It investigates job messages, PDF offer letters and recruitment
websites and produces a transparent, evidence-based risk report.

- Deterministic rule engine produces the score. The optional AI layer only
  explains findings and **never** changes the score.
- Missing information is reported as **Unknown** — never as fraud.
- Works fully offline with **no paid API keys**. Domain age and HTTPS are weak
  signals and are never treated as verdicts on their own.
- Uploaded PDFs are processed **in memory** and never written to disk.

> OfferShield is a screening aid, not a background-check service and not a fraud
> determination. It can miss scams and cannot certify that an offer is genuine.
> Never pay money to obtain a job.

---

## Table of contents

1. [Features](#features)
2. [Project structure](#project-structure)
3. [Requirements](#requirements)
4. [Windows setup (VS Code)](#windows-setup-vs-code)
5. [Linux / macOS setup](#linux--macos-setup)
6. [Configuration](#configuration)
7. [Running the app](#running-the-app)
8. [Running the tests](#running-the-tests)
9. [Scoring model](#scoring-model)
10. [HTTP API](#http-api)
11. [Privacy and data handling](#privacy-and-data-handling)
12. [Security controls](#security-controls)
13. [Known limitations](#known-limitations)
14. [Troubleshooting](#troubleshooting)

---

## Features

| Area | What it does |
| --- | --- |
| **Message analysis** | Detects candidate-facing fees, training-kit charges, deposits, placement-confirmation payments, guaranteed placement, no-interview offers, urgency pressure, sensitive-document/OTP requests, personal UPI/bank transfers, gift cards and crypto. |
| **PDF offer letters** | PyMuPDF text extraction, SHA-256 fingerprinting, exact-duplicate detection, hashed-shingle similarity against previously seen documents, metadata anomalies, embedded-file and active-content markers. Scanned PDFs use OCR **only** if Tesseract is installed; otherwise the report states the document was not analysed. |
| **Domain intelligence** | RDAP/WHOIS registration age, DNS records, TLS certificate details, HTTP reachability, redirect analysis, URL-pattern checks (IP literal, punycode, shorteners, risky TLDs) and lookalike-brand similarity with homoglyph normalisation. |
| **Company verification** | Claimed-brand vs. recruiter-email-domain consistency, free-email detection, email/site mismatch. MCA (India) registry search is disclosed as **manual** — no automated result is claimed. |
| **OSINT (optional)** | VirusTotal and Google Safe Browsing lookups when API keys are configured; otherwise the check is reported as unavailable. |
| **AI explanation (optional)** | Any OpenAI-compatible chat endpoint. Requires explicit consent. Receives derived findings — never the uploaded PDF. Does not affect scoring. |
| **Reporting** | Interactive HTML report with score breakdown, findings, uncompleted checks, next actions and a downloadable PDF investigation report. |

---

## Project structure

```
offershield/
├─ app.py                     # Flask app factory, security headers, error handlers
├─ config.py                  # Environment-driven configuration + snapshot()
├─ requirements.txt
├─ .env.example
├─ detection/                 # Deterministic detection & scoring modules
│  ├─ payment_detector.py     # Fee / deposit / UPI / crypto detection
│  ├─ text_analyzer.py        # Recruitment message patterns
│  ├─ risk_engine.py          # Capped scoring, classification, recommendations
│  ├─ domain_checker.py       # SSRF-safe domain, DNS, TLS, RDAP checks
│  ├─ company_verifier.py     # Brand / email consistency, MCA disclosure
│  ├─ pdf_analyzer.py         # PDF extraction + document analysis
│  ├─ document_similarity.py  # Fingerprints + hashed-shingle similarity
│  ├─ reputation.py           # Optional URL reputation providers
│  ├─ ai_analyzer.py          # Optional AI explanation (redacted input)
│  ├─ report_generator.py     # PDF report (ReportLab)
│  ├─ brands.py, findings.py, utils.py
├─ services/
│  ├─ pipeline.py             # Orchestrates scans, steps, coverage, case assembly
│  ├─ jobs.py                 # In-process job registry with live progress
│  └─ storage.py              # SQLite cases + hashed document index (TTL)
├─ routes/
│  ├─ main.py                 # Pages, results, report download, health
│  └─ analysis.py             # /api/analyze and /api/job/<id>
├─ templates/                 # base, index, dashboard, about, results, error
├─ static/css/style.css       # Dark cybersecurity SaaS theme
├─ static/js/app.js           # Tabs, dropzone, submission, polling, filters
└─ tests/                     # Offline pytest suite
```

---

## Requirements

- **Python 3.11+** (developed against 3.12/3.14).
- All core Python dependencies are in `requirements.txt`.
- **Optional:** the Tesseract OCR binary (only for scanned/image-only PDFs).
  Without it, scanned PDFs are reported as *not analysed* rather than guessed.

---

## Windows setup (VS Code)

Open a **PowerShell** terminal in VS Code (`Ctrl` + `` ` ``) at the project
folder.

```powershell
# 1. Create and activate a virtual environment
py -m venv .venv
.\.venv\Scripts\Activate.ps1

# If activation is blocked, allow it for this session only:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 2. Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 3. Create your environment file
Copy-Item .env.example .env
#    then edit .env as needed (optional)

# 4. Run the tests
python -m pytest tests/ -q

# 5. Start the development server
python app.py
# Open http://127.0.0.1:5000
```

Production-style run on Windows (no debug server):

```powershell
waitress-serve --host 127.0.0.1 --port 5000 app:app
```

Optional OCR on Windows: install the Tesseract binary (e.g. from the UB-Mannheim
build), then add its folder (usually `C:\Program Files\Tesseract-OCR`) to `PATH`.

---

## Linux / macOS setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
python -m pytest tests/ -q
python app.py
```

Production-style run:

```bash
waitress-serve --host 127.0.0.1 --port 5000 app:app
# or, with a WSGI server you prefer (gunicorn, uwsgi, etc.)
```

---

## Configuration

All configuration is environment driven; copy `.env.example` to `.env`. Every
value is optional — OfferShield runs with none of them set.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | random per start | Flask session secret. Set a fixed value in production. |
| `MAX_UPLOAD_MB` | `5` | Maximum PDF upload size. |
| `MAX_TEXT_CHARS` | `50000` | Maximum pasted text length. |
| `CASE_TTL_HOURS` | `24` | How long a finished report is retained. |
| `DOC_INDEX_TTL_DAYS` | `90` | Retention of hashed document signatures. |
| `NETWORK_CHECKS_ENABLED` | `1` | Set to `0` for a fully offline demo. |
| `DOMAIN_TIMEOUT` | `6` | DNS/TCP/TLS/HTTP timeout (seconds). |
| `AI_API_KEY` | *(empty)* | Enables the optional AI explanation. |
| `AI_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible base URL. |
| `AI_MODEL` | `gpt-4o-mini` | Model name for explanations. |
| `AI_TIMEOUT` | `30` | AI request timeout (seconds). |
| `VIRUSTOTAL_API_KEY` | *(empty)* | Enables VirusTotal URL reputation. |
| `SAFE_BROWSING_API_KEY` | *(empty)* | Enables Google Safe Browsing. |
| `RDAP_URL_TEMPLATE` | `https://rdap.org/domain/{domain}` | RDAP endpoint override. |

**Never commit a real `.env` file.** `.gitignore` already excludes it.

---

## Running the app

- Development: `python app.py` → http://127.0.0.1:5000
- The app binds to `127.0.0.1` by default. To expose it, use a production WSGI
  server (Waitress) behind a reverse proxy with request limits.

---

## Running the tests

The test suite is fully offline (network checks disabled, no API keys) and
covers the deterministic engine end to end.

```bash
python -m pytest tests/ -q
```

Test files:

- `test_payment_detector.py` — fees, deposits, UPI, crypto, salary false-positives.
- `test_text_analyzer.py` — recruitment patterns and positive signals.
- `test_risk_engine.py` — caps, classification thresholds, evidence status.
- `test_pdf_analyzer.py` — extraction, duplicates, similarity, unreadable PDFs.
- `test_domain_checker.py` — SSRF blocking, URL patterns, brand similarity.
- `test_api.py` — pages, scans, polling, SSRF rejection, PDF upload, 404s.

---

## Scoring model

Points are assigned only to **detected** indicators and are capped per category.
Duplicate indicator IDs are counted once. The AI never influences the score.

| Category | Cap | Typical evidence |
| --- | --- | --- |
| Payment fraud indicators | 25 | Registration/training/deposit requests, personal UPI, bank transfer, gift cards |
| Domain & website intelligence | 20 | New domain, lookalike brand, punycode, TLS failure, shortener |
| Company verification | 20 | Brand/email mismatch, free email, email/site mismatch |
| Offer letter analysis | 15 | Exact duplicate, high similarity, active content, metadata anomaly |
| OSINT & reputation | 10 | Optional VirusTotal / Google Safe Browsing verdicts |
| Recruitment message patterns | 10 | Guaranteed placement, no interview, urgency, unrealistic pay |

**Classification:** `0–24` low · `25–49` moderate · `50–74` high · `75–100` critical.

An additional **Insufficient evidence** status is shown when the score is low
(< 25) but fewer than half of the verification checks could be completed. The
score is a count of detected indicators, **not** a probability of fraud.

---

## HTTP API

### `POST /api/analyze`

Start a scan. Same-origin submissions only.

**Text / URL** — JSON body:

```json
{ "type": "text", "text": "…offer message…", "consent": false }
{ "type": "url",  "url":  "https://careers.example.com/apply", "consent": false }
```

**PDF** — `multipart/form-data` with a `file` field (`.pdf`, valid `%PDF-`
signature, within the size limit) and an optional `consent` field.

Response (`202`):

```json
{ "job_id": "…", "steps": [ { "key": "input", "label": "Input validation", "status": "pending", "detail": "" } ] }
```

Errors return `{ "error": "…" }` with `400`, `403` (cross-origin), or `413`.

### `GET /api/job/<job_id>`

Poll progress. Returns the job with `status` (`queued` | `running` | `done` |
`error`), per-step `steps`, `result_url` (when done) and `error` (when failed).

### `GET /api/health`

```json
{ "status": "ok", "version": "1.0.0", "ai_configured": false, "network_checks": true, "reputation_configured": false }
```

### Pages

- `GET /` — landing page
- `GET /dashboard` — investigation dashboard
- `GET /about` — methodology, security and limitations
- `GET /results/<case_id>` — HTML report
- `GET /results/<case_id>/report.pdf` — PDF report

---

## Privacy and data handling

- **Uploaded PDFs** are processed in memory, never written to disk, never
  executed and never retained permanently.
- **Reports** are stored in SQLite for a short period (`CASE_TTL_HOURS`,
  default 24 h) so they can be viewed and downloaded, then deleted automatically.
- **Similarity index** stores only SHA-256 hashes of normalised word 5-grams —
  never the document text.
- **AI** is disabled unless an API key is configured *and* the consent box is
  ticked. Uploaded PDFs are never sent to the AI provider; only derived findings
  and summaries are sent. For pasted messages, a redacted excerpt may be
  included (emails, phone numbers and UPI IDs are masked).
- **Analysis submissions** are restricted to the same origin; no API secrets are
  hardcoded.

---

## Security controls

- Upload validation: extension, `%PDF-` signature and size limit; safe filename
  handling; uploads are never executed.
- SSRF protection: only `http`/`https`; credentials-in-URL rejected;
  loopback/private/link-local/reserved/metadata addresses blocked; restricted
  ports (`80, 443, 8080, 8443`); redirects followed manually and re-validated
  (max 3 hops); bounded timeouts; response bodies are **not** downloaded.
- Strict `Content-Security-Policy` (`script-src 'self'`), `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.
- Cross-origin API submissions rejected; safe error handling that never exposes
  stack traces or user content.
- **Residual risk:** a hostile DNS server could change answers between our
  validation and the HTTP client's own lookup (DNS rebinding). Re-validation on
  every request plus disabled automatic redirects reduces, but does not
  eliminate, this risk.

---

## Known limitations

- **No registry verification.** MCA and similar registries require manual,
  CAPTCHA-protected searches. OfferShield reports *Unverified*, not a fabricated
  result.
- **No vacancy confirmation.** It cannot confirm that a vacancy exists or that a
  sender is an authorised employee.
- **Finite brand list.** The built-in reference list cannot cover every company;
  absence of a similarity match is not a positive signal.
- **Reputation lag.** New scam domains often have no reputation history; a clean
  result is not proof of legitimacy.
- **Weak signals stay weak.** Domain age and HTTPS never determine fraud on
  their own.
- **OCR depends on Tesseract.** If the binary is missing, scanned documents are
  explicitly reported as not analysed.
- **AI can be wrong.** The explanation is advisory and is never used for scoring.
- **No built-in rate limiting.** Put OfferShield behind a reverse proxy with
  request limits for public deployments.

---

## Troubleshooting

- **`.\.venv\Scripts\Activate.ps1` is blocked** — run
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal.
- **`pymupdf`/`fitz` import warning** — harmless; the code prefers the
  `pymupdf` import name and falls back to `fitz`.
- **Scanned PDF says "not analysed"** — install Tesseract and ensure it is on
  `PATH`, then re-scan.
- **Domain checks show Unknown** — set `NETWORK_CHECKS_ENABLED=1` and ensure the
  host has outbound DNS/HTTP access.
- **AI explanation empty** — set `AI_API_KEY` and tick the consent box; the
  rule-based report is unaffected either way.
