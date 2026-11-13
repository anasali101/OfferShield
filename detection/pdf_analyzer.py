"""Feature B: PDF offer-letter analysis.

Extraction is performed with PyMuPDF. Image-only PDFs trigger an OCR attempt
only when Tesseract and pytesseract are both available; otherwise the report
clearly states that the document could not be fully read. Image-only documents
are never silently treated as successfully parsed.
"""

from __future__ import annotations

import io
import re
from datetime import datetime, timedelta, timezone

try:  # PyMuPDF >= 1.24 prefers the pymupdf import name
    import pymupdf  # type: ignore
except ImportError:  # pragma: no cover - older installations
    import fitz as pymupdf  # type: ignore

from detection import document_similarity
from detection.findings import make_finding
from detection.utils import clean_text, make_snippet

MIN_TEXT_CHARS = 40
MAX_OCR_PAGES = 5
PDF_DATE_RE = re.compile(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?")
ACTIVE_CONTENT_RE = re.compile(rb"/(?:JavaScript|JS|Launch)\b")


def analyze_pdf(data: bytes, filename: str, config: dict) -> dict:
    result = {
        "filename": filename,
        "size_bytes": len(data),
        "page_count": 0,
        "fingerprint": document_similarity.sha256_bytes(data),
        "metadata": {},
        "metadata_anomalies": [],
        "text_extraction": {
            "status": "error",
            "method": None,
            "chars": 0,
            "message": "",
        },
        "ocr": {"attempted": False, "available": False, "message": "Not required."},
        "duplicate": False,
        "similar_documents": [],
        "active_content": False,
        "embedded_files": 0,
        "encrypted": False,
        "findings": [],
        "checks": [],
        "text": "",
    }

    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:
        result["text_extraction"]["message"] = f"The PDF could not be opened ({type(exc).__name__})."
        result["findings"].append(
            make_finding(
                "DOC_UNREADABLE", "document", "PDF could not be parsed",
                "unknown", 0, evidence=type(exc).__name__,
                why="An unreadable PDF may be corrupt, encrypted or not a real PDF. No conclusions about its content can be drawn.",
                source="pdf_analyzer",
            )
        )
        result["checks"].append(_check("document_text", "Document text extraction", "unknown", result["text_extraction"]["message"]))
        return result

    try:
        result["encrypted"] = bool(doc.needs_pass)
        if doc.needs_pass:
            result["text_extraction"]["message"] = (
                "The PDF is password-protected, so its text cannot be extracted without the password. "
                "The document was not analysed."
            )
            result["findings"].append(
                make_finding(
                    "DOC_ENCRYPTED", "document", "Password-protected PDF",
                    "unknown", 0, evidence="Encrypted document",
                    why="Encryption can be legitimate. OfferShield cannot inspect the contents, so no conclusions are drawn.",
                    source="pdf_analyzer",
                )
            )
            result["checks"].append(_check("document_text", "Document text extraction", "unknown", result["text_extraction"]["message"]))
            return result

        result["page_count"] = doc.page_count
        result["metadata"] = _normalise_metadata(doc.metadata or {})
        result["embedded_files"] = _safe_embfile_count(doc)
        result["active_content"] = bool(ACTIVE_CONTENT_RE.search(data))

        raw_text = []
        for page in doc:
            try:
                raw_text.append(page.get_text("text") or "")
            except Exception:
                continue
        text = clean_text("\n".join(raw_text), int(config.get("MAX_TEXT_CHARS", 50_000)))
        result["text"] = text

        if len(text) >= MIN_TEXT_CHARS:
            result["text_extraction"].update(
                {
                    "status": "done",
                    "method": "PyMuPDF text layer",
                    "chars": len(text),
                    "message": "Text was extracted from the PDF text layer.",
                }
            )
        else:
            result["text_extraction"].update(
                {
                    "status": "image_only",
                    "method": None,
                    "chars": len(text),
                    "message": "Very little or no text layer was found. The PDF is probably scanned or image-based.",
                }
            )
            _attempt_ocr(doc, result, config)
            if result["ocr"].get("text"):
                result["text"] = result["ocr"]["text"]
                text = result["text"]

        if result["active_content"]:
            result["findings"].append(
                make_finding(
                    "DOC_ACTIVE_CONTENT", "document", "PDF contains active-content markers",
                    "medium", 5, evidence="Found /JavaScript, /JS or /Launch in the file structure",
                    why="Active content can run scripts or launch actions in some PDF viewers. This is a security concern and should be treated cautiously. It is not proof that the offer is fraudulent.",
                    source="pdf_analyzer",
                )
            )
        if result["embedded_files"]:
            result["findings"].append(
                make_finding(
                    "DOC_EMBEDDED_FILES", "document", "PDF contains embedded file attachments",
                    "low", 3, evidence=f"{result['embedded_files']} embedded file(s)",
                    why="Embedded files are unusual in offer letters. Do not open attachments without independent verification.",
                    source="pdf_analyzer",
                )
            )

        result["metadata_anomalies"] = _metadata_anomalies(result["metadata"])
        for anomaly in result["metadata_anomalies"]:
            result["findings"].append(
                make_finding(
                    anomaly["id"], "document", anomaly["title"],
                    anomaly["severity"], anomaly["points"],
                    evidence=anomaly["evidence"],
                    why=anomaly["why"],
                    source="pdf_analyzer",
                )
            )

        if text and len(text) >= MIN_TEXT_CHARS:
            shingles = document_similarity.build_shingles(text)
            result["shingles"] = shingles
            result["duplicate"] = document_similarity.fingerprint_exists(config["DB_PATH"], result["fingerprint"])
            if result["duplicate"]:
                result["findings"].append(
                    make_finding(
                        "DOC_DUPLICATE_FINGERPRINT", "document",
                        "Exact same PDF was previously submitted",
                        "high", 10,
                        evidence=f"Fingerprint {result['fingerprint'][:16]}… already exists in the local index",
                        why="Identical files can be sent to many candidates as part of a mass scam campaign. However, this can also mean the same document was submitted twice by you. This is not proof of forgery.",
                        source="pdf_analyzer",
                    )
                )
            similar = document_similarity.find_similar_documents(
                config["DB_PATH"], shingles, exclude_fingerprint=result["fingerprint"]
            )
            result["similar_documents"] = similar
            if similar:
                best = similar[0]
                if best["score"] >= 0.9:
                    severity, points = "high", 10
                elif best["score"] >= 0.8:
                    severity, points = "medium", 8
                else:
                    severity, points = "low", 5
                result["findings"].append(
                    make_finding(
                        "DOC_HIGH_SIMILARITY", "document",
                        "Highly similar offer letter previously submitted",
                        severity, points,
                        evidence=f"Best similarity {round(best['score'] * 100)}% against a previously indexed document",
                        why="Shared templates are common in mass recruitment scams, but legitimate companies also reuse templates. Similarity is supporting evidence, not proof.",
                        source="pdf_analyzer",
                    )
                )
            document_similarity.index_document(config["DB_PATH"], result["fingerprint"], shingles)

        _finalise_pdf_checks(result)
        return result

    finally:
        try:
            doc.close()
        except Exception:
            pass


def _attempt_ocr(doc, result: dict, config: dict) -> None:
    result["ocr"] = {"attempted": True, "available": False, "message": ""}
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        result["ocr"]["message"] = (
            "OCR is unavailable because pytesseract/Pillow is not installed. "
            "The image-based PDF could not be read, so its content was NOT analysed."
        )
        result["findings"].append(
            make_finding(
                "DOC_OCR_UNAVAILABLE", "document", "Scanned PDF could not be read (OCR unavailable)",
                "unknown", 0, evidence="No text layer; pytesseract/Pillow not installed",
                why="OfferShield will not guess at the contents of an unreadable document. Install Tesseract OCR and pytesseract to enable scanning.",
                source="pdf_analyzer",
            )
        )
        return
    try:
        pytesseract.get_tesseract_version()
    except Exception:
        result["ocr"]["message"] = (
            "OCR is unavailable because the Tesseract binary is not installed or not on PATH. "
            "The image-based PDF could not be read, so its content was NOT analysed."
        )
        result["findings"].append(
            make_finding(
                "DOC_OCR_UNAVAILABLE", "document", "Scanned PDF could not be read (Tesseract missing)",
                "unknown", 0, evidence="No text layer; Tesseract binary unavailable",
                why="OfferShield will not guess at the contents of an unreadable document. Install Tesseract OCR to enable this check.",
                source="pdf_analyzer",
            )
        )
        return

    result["ocr"]["available"] = True
    collected = []
    pages = min(doc.page_count, MAX_OCR_PAGES)
    try:
        for index in range(pages):
            page = doc.load_page(index)
            pixmap = page.get_pixmap(dpi=200)
            image = Image.open(io.BytesIO(pixmap.tobytes("png")))
            collected.append(pytesseract.image_to_string(image))
        text = clean_text("\n".join(collected), int(config.get("MAX_TEXT_CHARS", 50_000)))
        if len(text) >= MIN_TEXT_CHARS:
            result["ocr"]["text"] = text
            result["text_extraction"].update(
                {
                    "status": "ocr_done",
                    "method": f"Tesseract OCR ({pages} page(s), max {MAX_OCR_PAGES})",
                    "chars": len(text),
                    "message": "No text layer was found, so OCR was used. OCR text can contain errors.",
                }
            )
        else:
            result["ocr"]["message"] = "OCR ran but produced too little readable text."
            result["findings"].append(
                make_finding(
                    "DOC_OCR_NO_TEXT", "document", "OCR produced no usable text",
                    "unknown", 0, evidence=f"OCR ran on {pages} page(s)",
                    why="The document may be handwritten, low quality or not an offer letter. No conclusions can be drawn about its content.",
                    source="pdf_analyzer",
                )
            )
    except Exception as exc:
        result["ocr"]["message"] = f"OCR failed ({type(exc).__name__}). The document was not fully analysed."
        result["findings"].append(
            make_finding(
                "DOC_OCR_FAILED", "document", "OCR failed",
                "unknown", 0, evidence=type(exc).__name__,
                why="The document could not be read reliably. No content conclusions are drawn.",
                source="pdf_analyzer",
            )
        )


def _finalise_pdf_checks(result: dict) -> None:
    extraction = result["text_extraction"]
    if extraction["status"] in {"done", "ocr_done"}:
        result["checks"].append(
            _check("document_text", "Document text extraction", "pass",
                   f"{extraction['message']} ({extraction['chars']} characters)")
        )
    elif extraction["status"] == "image_only":
        detail = extraction["message"] + " " + result["ocr"].get("message", "")
        result["checks"].append(_check("document_text", "Document text extraction", "unknown", detail.strip()))
    else:
        result["checks"].append(_check("document_text", "Document text extraction", "unknown", extraction["message"]))

    if result["findings"] and any(f["id"] == "DOC_DUPLICATE_FINGERPRINT" for f in result["findings"]):
        result["checks"].append(_check("document_duplicate", "Document fingerprint", "fail", "This exact PDF is already in the local index."))
    else:
        result["checks"].append(_check("document_duplicate", "Document fingerprint", "pass", f"SHA-256: {result['fingerprint'][:24]}… No exact duplicate found."))

    if result["similar_documents"]:
        best = result["similar_documents"][0]["score"]
        status = "fail" if best >= 0.9 else "warn"
        result["checks"].append(_check("document_similarity", "Similarity to indexed documents", status, f"Best match {round(best * 100)}%."))
    else:
        result["checks"].append(_check("document_similarity", "Similarity to indexed documents", "pass", "No similar indexed document above 60%."))

    result["checks"].append(_check("document_metadata", "PDF metadata examination", "pass" if not result["metadata_anomalies"] else "warn", "Metadata anomalies are weak signals and are never treated as proof of forgery."))


def _normalise_metadata(metadata: dict) -> dict:
    clean = {}
    for key in ("title", "author", "subject", "keywords", "creator", "producer", "creationDate", "modDate", "trapped"):
        value = metadata.get(key)
        if value:
            clean[key] = str(value)[:300]
    return clean


def _safe_embfile_count(doc) -> int:
    try:
        return int(doc.embfile_count())
    except Exception:
        return 0


def _metadata_anomalies(metadata: dict) -> list[dict]:
    anomalies = []
    now = datetime.now(timezone.utc)
    for key, label in (("creationDate", "creation"), ("modDate", "modification")):
        raw = metadata.get(key)
        if not raw:
            continue
        parsed = _parse_pdf_date(raw)
        if parsed and parsed > now + timedelta(days=2):
            anomalies.append(
                {
                    "id": "DOC_FUTURE_METADATA_DATE",
                    "title": f"PDF metadata {label} date is in the future",
                    "severity": "low",
                    "points": 3,
                    "evidence": f"{key}: {raw[:80]}",
                    "why": "Future dates can indicate a manipulated or misconfigured system clock. Many legitimate tools produce incorrect metadata, so this is not proof of forgery.",
                }
            )
    return anomalies


def _parse_pdf_date(value: str) -> datetime | None:
    match = PDF_DATE_RE.search(value or "")
    if not match:
        return None
    parts = [int(p) if p else 0 for p in match.groups()[:6]]
    year, month, day, hour, minute, second = (parts + [0] * 6)[:6]
    try:
        return datetime(max(1970, year), max(1, month or 1), max(1, day or 1), hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None


def _check(key: str, label: str, status: str, detail: str) -> dict:
    return {"key": key, "label": label, "status": status, "detail": str(detail or "")[:280], "source": "document"}
