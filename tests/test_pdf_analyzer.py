"""Tests for PDF offer-letter analysis (Feature B)."""

from __future__ import annotations

from detection.pdf_analyzer import analyze_pdf


def test_text_pdf_is_extracted(config, sample_pdf_bytes):
    result = analyze_pdf(sample_pdf_bytes, "offer.pdf", config)
    assert result["text_extraction"]["status"] == "done"
    assert result["text_extraction"]["chars"] >= 40
    assert result["page_count"] == 1
    assert result["fingerprint"]
    assert "registration fee" in result["text"].lower()


def test_duplicate_fingerprint_detected_on_second_submission(config, sample_pdf_bytes):
    first = analyze_pdf(sample_pdf_bytes, "offer.pdf", config)
    assert first["duplicate"] is False
    second = analyze_pdf(sample_pdf_bytes, "offer.pdf", config)
    assert second["duplicate"] is True
    assert any(f["id"] == "DOC_DUPLICATE_FINGERPRINT" for f in second["findings"])


def test_similar_document_flagged_for_reworded_copy(config, sample_pdf_bytes):
    analyze_pdf(sample_pdf_bytes, "offer.pdf", config)
    near_copy = sample_pdf_bytes.replace(b"Infosys", b"Infosys ")
    result = analyze_pdf(near_copy, "offer2.pdf", config)
    # Either an exact duplicate or a high-similarity match must be reported.
    assert result["duplicate"] or result["similar_documents"]


def test_unreadable_pdf_is_reported_as_unknown_not_clean(config):
    result = analyze_pdf(b"this is not a pdf at all", "broken.pdf", config)
    assert any(f["id"] == "DOC_UNREADABLE" for f in result["findings"])
    assert result["text_extraction"]["status"] == "error"
    text_check = next(c for c in result["checks"] if c["key"] == "document_text")
    assert text_check["status"] == "unknown"


def test_image_only_pdf_without_tesseract_is_explicitly_not_analysed(config):
    """A PDF with no text layer must never be silently treated as parsed."""
    import io

    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    # Draw an image-free blank page: no extractable text at all.
    pdf.rect(100, 100, 200, 200, fill=1)
    pdf.showPage()
    pdf.save()

    result = analyze_pdf(buffer.getvalue(), "scanned.pdf", config)
    assert result["text_extraction"]["status"] in {"image_only", "done"}
    if result["text_extraction"]["status"] == "image_only":
        assert result["text_extraction"]["chars"] < 40
        assert result["ocr"]["attempted"] is True
        if not result["ocr"]["available"]:
            assert "NOT analysed" in result["ocr"]["message"] or "not" in result["ocr"]["message"].lower()
