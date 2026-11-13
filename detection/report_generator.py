"""PDF investigation report generation with ReportLab."""

from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

NAVY = colors.HexColor("#0b1220")
PANEL = colors.HexColor("#111c31")
BORDER = colors.HexColor("#24324d")
TEXT = colors.HexColor("#1a2433")
MUTED = colors.HexColor("#5b6b83")
ACCENT = colors.HexColor("#2563eb")
GREEN = colors.HexColor("#15803d")
AMBER = colors.HexColor("#b45309")
RED = colors.HexColor("#b91c1c")
GREY = colors.HexColor("#6b7280")
CRITICAL = colors.HexColor("#7f1d1d")

SEVERITY_COLORS = {
    "critical": RED,
    "high": colors.HexColor("#c2410c"),
    "medium": AMBER,
    "low": colors.HexColor("#a16207"),
    "info": ACCENT,
    "clean": GREEN,
    "unknown": GREY,
}

STATUS_LABELS = {
    "pass": "No issue detected",
    "warn": "Warning",
    "fail": "Issue detected",
    "unknown": "Not completed",
}

STATUS_COLORS = {"pass": GREEN, "warn": AMBER, "fail": RED, "unknown": GREY}


def generate_report(case: dict) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=14 * mm,
        bottomMargin=16 * mm,
        title=f"OfferShield Investigation Report {case.get('id', '')[:8]}",
        author="OfferShield",
        subject="Recruitment fraud risk assessment",
    )
    styles = _styles()
    story = []

    story.append(_banner(case, styles))
    story.append(Spacer(1, 5 * mm))

    score = case.get("score", {})
    story.append(_score_panel(case, score, styles))
    story.append(Spacer(1, 4 * mm))
    story.append(
        Paragraph(
            escape(score.get("disclaimer", "")),
            styles["muted"],
        )
    )
    story.append(Spacer(1, 4 * mm))

    story.append(_section("1. Investigation summary", styles))
    summary = [
        ["Scan type", _kind_label(case.get("kind"))],
        ["Report created (UTC)", str(case.get("created_at", ""))],
        ["Risk score", f"{score.get('score', 0)} / 100"],
        ["Classification", score.get("headline", "")],
        ["Evidence status", f"{score.get('evidence_label', '')} ({round(float(score.get('coverage', 0)) * 100)}% of verification checks completed)"],
    ]
    if case.get("input", {}).get("filename"):
        summary.append(["Document", str(case["input"]["filename"])])
    if case.get("input", {}).get("host"):
        summary.append(["Website host", str(case["input"]["host"])])
    if case.get("input", {}).get("text_length"):
        summary.append(["Message length", f"{case['input']['text_length']} characters"])
    story.append(_kv_table(summary, styles))
    story.append(Spacer(1, 4 * mm))

    story.append(_section("2. Score contributions", styles))
    story.append(_breakdown_table(score.get("breakdown", []), styles))
    story.append(Spacer(1, 2 * mm))
    story.append(
        Paragraph(
            "Scores are capped per category to prevent repeated findings from dominating. "
            "The AI explanation, if enabled, never changes these points.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 4 * mm))

    story.append(_section("3. Extracted entities", styles))
    story.append(_entities_table(case.get("entities", {}), styles))
    story.append(Spacer(1, 4 * mm))

    warnings = [f for f in case.get("findings", []) if f.get("severity") in {"critical", "high", "medium", "low"}]
    story.append(_section("4. Warning findings and evidence", styles))
    if warnings:
        for finding in warnings[:30]:
            story.append(_finding_block(finding, styles))
    else:
        story.append(Paragraph("No warning indicators were detected by the checks that completed.", styles["body"]))
    story.append(Spacer(1, 3 * mm))

    story.append(_section("5. Checks performed", styles))
    story.append(_checks_table(case.get("checks", []), styles))
    story.append(Spacer(1, 2 * mm))
    story.append(
        Paragraph(
            "Green means only that the specific check found no issue. It is not a guarantee "
            "that the offer, website or document is legitimate.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 4 * mm))

    if case.get("domain"):
        story.append(_section("6. Domain and website intelligence", styles))
        story.append(_domain_block(case["domain"], styles))
        story.append(Spacer(1, 3 * mm))

    if case.get("company"):
        story.append(_section("7. Company verification", styles))
        story.append(_company_block(case["company"], styles))
        story.append(Spacer(1, 3 * mm))

    if case.get("document"):
        story.append(_section("8. Document analysis", styles))
        story.append(_document_block(case["document"], styles))
        story.append(Spacer(1, 3 * mm))

    story.append(_section("9. AI-assisted explanation (optional)", styles))
    ai = case.get("ai", {}) or {}
    if ai.get("status") == "ok":
        story.append(Paragraph(escape(ai.get("text", "")).replace("\n", "<br/>"), styles["body"]))
        story.append(Spacer(1, 1 * mm))
        story.append(
            Paragraph(
                escape(f"Provider: {ai.get('provider', '')}; model: {ai.get('model', '')}. "
                        "This explanation is advisory only and does not affect the risk score."),
                styles["muted"],
            )
        )
    else:
        story.append(Paragraph(escape(ai.get("message", "AI explanation unavailable.")), styles["muted"]))
    story.append(Spacer(1, 4 * mm))

    story.append(_section("10. Recommended next actions", styles))
    for index, rec in enumerate(score.get("recommendations", []), start=1):
        story.append(
            Paragraph(
                f"<b>{index}. {escape(rec.get('title', ''))}</b> "
                f"<font color='#{_hex(SEVERITY_COLORS.get(rec.get('priority'), MUTED))}'>"
                f"[{escape(str(rec.get('priority', '')).upper())}]</font><br/>"
                + escape(rec.get("detail", "")).replace("\n", "<br/>"),
                styles["body"],
            )
        )
        story.append(Spacer(1, 1.5 * mm))
    story.append(Spacer(1, 3 * mm))

    other = [f for f in case.get("findings", []) if f.get("severity") in {"clean", "unknown", "info"}]
    if other:
        story.append(_section("11. Other observations (positive and unavailable)", styles))
        for finding in other[:25]:
            color = _hex(SEVERITY_COLORS.get(finding.get("severity"), GREY))
            story.append(
                Paragraph(
                    f"<font color='#{color}'><b>{escape(str(finding.get('severity', '')).upper())}</b></font> "
                    f"<b>{escape(finding.get('title', ''))}</b> — {escape(finding.get('why', ''))}",
                    styles["small"],
                )
            )
            story.append(Spacer(1, 1 * mm))
        story.append(Spacer(1, 3 * mm))

    story.append(_section("12. Limitations and privacy", styles))
    for item in case.get("limitations", []):
        story.append(Paragraph("• " + escape(item), styles["small"]))
    story.append(Spacer(1, 2 * mm))
    story.append(
        Paragraph(
            "Uploaded PDFs are processed in memory and are not stored permanently. Only this "
            "investigation result is retained temporarily for report access and is deleted "
            "automatically according to the server's retention setting. Document similarity "
            "uses hashed word fingerprints, not document text.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 4 * mm))
    story.append(
        Paragraph(
            escape(case.get("disclaimer", "")),
            styles["disclaimer"],
        )
    )

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("Title", parent=base["Title"], fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=colors.white, alignment=TA_LEFT, spaceAfter=0),
        "tagline": ParagraphStyle("Tagline", parent=base["Normal"], fontName="Helvetica", fontSize=10, leading=13, textColor=colors.HexColor("#b7c6dd")),
        "h1": ParagraphStyle("H1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=NAVY, spaceBefore=2, spaceAfter=4),
        "h2": ParagraphStyle("H2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=10.5, leading=13, textColor=TEXT, spaceBefore=4, spaceAfter=2),
        "body": ParagraphStyle("Body", parent=base["BodyText"], fontName="Helvetica", fontSize=9.2, leading=13, textColor=TEXT, spaceAfter=2),
        "small": ParagraphStyle("Small", parent=base["BodyText"], fontName="Helvetica", fontSize=8.2, leading=11.2, textColor=TEXT),
        "muted": ParagraphStyle("Muted", parent=base["BodyText"], fontName="Helvetica", fontSize=8.2, leading=11.5, textColor=MUTED),
        "disclaimer": ParagraphStyle("Disclaimer", parent=base["BodyText"], fontName="Helvetica-Oblique", fontSize=8, leading=11, textColor=MUTED),
        "score": ParagraphStyle("Score", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=40, leading=44, alignment=TA_LEFT),
        "scorelabel": ParagraphStyle("ScoreLabel", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=11, leading=14),
        "cell": ParagraphStyle("Cell", parent=base["BodyText"], fontName="Helvetica", fontSize=8.2, leading=11, textColor=TEXT),
        "cellbold": ParagraphStyle("CellBold", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=8.2, leading=11, textColor=TEXT),
        "cellwhite": ParagraphStyle("CellWhite", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=8.2, leading=11, textColor=colors.white),
    }


def _banner(case, styles):
    inner = Table(
        [
            [Paragraph("OFFERSHIELD", styles["title"])],
            [Paragraph("Know Before You Trust. — Recruitment fraud investigation report", styles["tagline"])],
        ],
        colWidths=[178 * mm],
    )
    inner.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (0, 0), 10),
                ("BOTTOMPADDING", (0, 1), (0, 1), 10),
                ("TOPPADDING", (0, 1), (0, 1), 0),
            ]
        )
    )
    wrapper = Table([[inner]], colWidths=[178 * mm])
    wrapper.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, NAVY),
            ]
        )
    )
    return wrapper


def _score_panel(case, score, styles):
    classification = score.get("classification", {})
    color = {
        "critical": CRITICAL,
        "high": RED,
        "moderate": AMBER,
        "low": GREEN,
    }.get(classification.get("key"), GREY)
    score_text = Paragraph(f"{score.get('score', 0)}", ParagraphStyle("s", parent=styles["score"], textColor=color))
    detail = Paragraph(
        f"<b>{escape(score.get('headline', ''))}</b><br/>"
        f"<font color='#{_hex(MUTED)}'>{escape(score.get('evidence_detail', ''))}</font>",
        styles["body"],
    )
    table = Table(
        [
            [score_text, Paragraph("<b>RISK SCORE</b><br/><font size=8 color='#5b6b83'>out of 100 (indicator count, not a probability)</font>", styles["body"])],
            ["", detail],
        ],
        colWidths=[35 * mm, 143 * mm],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f7fb")),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("SPAN", (0, 0), (0, 0)),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LINEBELOW", (1, 0), (1, 0), 0, colors.white),
            ]
        )
    )
    return table


def _section(title, styles):
    return KeepTogether([Paragraph(escape(title), styles["h1"]), HRFlowable(width="100%", thickness=0.6, color=BORDER, spaceBefore=1, spaceAfter=4)])


def _kv_table(rows, styles):
    data = [[Paragraph(escape(str(a)), styles["cellbold"]), Paragraph(escape(str(b)), styles["cell"])] for a, b in rows]
    table = Table(data, colWidths=[45 * mm, 133 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2f8")),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _breakdown_table(breakdown, styles):
    data = [[
        Paragraph("Category", styles["cellwhite"]),
        Paragraph("Points", styles["cellwhite"]),
        Paragraph("Cap", styles["cellwhite"]),
        Paragraph("Indicators", styles["cellwhite"]),
    ]]
    for item in breakdown:
        data.append(
            [
                Paragraph(escape(item.get("label", "")), styles["cell"]),
                Paragraph(f"<b>{item.get('points', 0)}</b>", styles["cell"]),
                Paragraph(str(item.get("cap", "")), styles["cell"]),
                Paragraph(str(item.get("indicator_count", 0)), styles["cell"]),
            ]
        )
    table = Table(data, colWidths=[85 * mm, 22 * mm, 20 * mm, 51 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fc")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _entities_table(entities, styles):
    rows = [
        ["Companies claimed", ", ".join(c.get("name", "") for c in entities.get("companies", [])) or "None extracted"],
        ["Recruiter names", ", ".join(entities.get("recruiters", [])) or "None extracted"],
        ["Email addresses", ", ".join(entities.get("emails", [])) or "None extracted"],
        ["Phone numbers", ", ".join(entities.get("phones", [])) or "None extracted"],
        ["UPI IDs", ", ".join(entities.get("upi_ids", [])) or "None extracted"],
        ["URLs", ", ".join(entities.get("urls", [])) or "None extracted"],
        ["Monetary mentions", ", ".join(a.get("raw", "") for a in entities.get("amounts", [])) or "None extracted"],
    ]
    return _kv_table(rows, styles)


def _checks_table(checks, styles):
    data = [[
        Paragraph("Status", styles["cellwhite"]),
        Paragraph("Check", styles["cellwhite"]),
        Paragraph("Detail", styles["cellwhite"]),
    ]]
    for check in checks:
        status = check.get("status", "unknown")
        color = _hex(STATUS_COLORS.get(status, GREY))
        data.append(
            [
                Paragraph(f"<font color='#{color}'><b>{escape(STATUS_LABELS.get(status, 'Unknown'))}</b></font>", styles["cell"]),
                Paragraph(escape(check.get("label", "")), styles["cell"]),
                Paragraph(escape(check.get("detail", "")), styles["cell"]),
            ]
        )
    table = Table(data, colWidths=[30 * mm, 48 * mm, 100 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fc")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _finding_block(finding, styles):
    severity = finding.get("severity", "info")
    color = _hex(SEVERITY_COLORS.get(severity, GREY))
    points = finding.get("points", 0)
    title = (
        f"<font color='#{color}'><b>{escape(str(severity).upper())}</b></font> "
        f"<b>{escape(finding.get('title', ''))}</b>"
        + (f" <font color='#{color}'>+{points} pts</font>" if points else "")
    )
    parts = [Paragraph(title, styles["body"])]
    if finding.get("evidence"):
        parts.append(Paragraph("<i>Evidence:</i> " + escape(finding["evidence"]), styles["small"]))
    if finding.get("why"):
        parts.append(Paragraph("<i>Why it matters:</i> " + escape(finding["why"]), styles["small"]))
    parts.append(Spacer(1, 2 * mm))
    return KeepTogether(parts)


def _domain_block(domain, styles):
    rows = [
        ["Website URL", domain.get("url", "")],
        ["Host", domain.get("host", "")],
        ["Registrable domain", domain.get("registrable_domain", "")],
    ]
    reg = domain.get("registration", {}) or {}
    if reg.get("available"):
        rows.append(["Domain registered", f"{reg.get('registration_date')} ({reg.get('age_days')} days ago); registrar: {reg.get('registrar')}; source: {reg.get('source')}"])
    else:
        rows.append(["Domain registration", reg.get("note", "Unavailable")])
    dns = domain.get("dns", {}) or {}
    rows.append(["DNS A/AAAA", ", ".join((dns.get("a") or []) + (dns.get("aaaa") or [])[:2]) or dns.get("error") or "None"])
    rows.append(["DNS NS/MX", " | ".join(filter(None, [", ".join((dns.get("ns") or [])[:3]), ", ".join((dns.get("mx") or [])[:3])])) or "None"])
    ssl = domain.get("ssl", {}) or {}
    if ssl.get("available"):
        rows.append(["TLS certificate", f"verified: {ssl.get('verified')}; issuer: {(ssl.get('issuer') or {}).get('organizationName') or (ssl.get('issuer') or {}).get('commonName')}; expires: {ssl.get('not_after')}; error: {ssl.get('error') or 'none'}"])
    else:
        rows.append(["TLS certificate", ssl.get("error") or "Unavailable"])
    http = domain.get("http", {}) or {}
    rows.append(["HTTP result", f"reachable: {http.get('reachable')}; status: {http.get('status_code')}; final: {http.get('final_url')}; error: {http.get('error') or 'none'}"])
    if domain.get("brand_matches"):
        rows.append(["Brand similarity", "; ".join(f"{m.get('brand')} ({m.get('match')}) vs {m.get('official_domain')}" for m in domain["brand_matches"])])
    return _kv_table(rows, styles)


def _company_block(company, styles):
    rows = [
        ["Verification status", company.get("status_label", "Unverified")],
        ["Scope", company.get("scope", "")],
        ["Claimed brand", company.get("claimed_brand") or "None recognised"],
        ["Official domain reference", ", ".join(company.get("official_domains", [])) or "None"],
        ["Recruiter email domains", ", ".join(company.get("email_domains", [])) or "None extracted"],
        ["Extracted companies", ", ".join(c.get("name", "") for c in company.get("claimed_companies", [])) or "None"],
        ["Extracted recruiters", ", ".join(company.get("recruiter_names", [])) or "None"],
        ["MCA (India)", company.get("mca", {}).get("note", "Manual verification required")],
    ]
    return _kv_table(rows, styles)


def _document_block(document, styles):
    extraction = document.get("text_extraction", {}) or {}
    rows = [
        ["Filename", document.get("filename", "")],
        ["Pages", str(document.get("page_count", ""))],
        ["Size", f"{round((document.get('size_bytes') or 0) / 1024)} KB"],
        ["SHA-256", document.get("fingerprint", "")],
        ["Text extraction", f"{extraction.get('status')} — {extraction.get('message', '')}"],
        ["OCR", (document.get("ocr", {}) or {}).get("message", "Not required")],
        ["Exact duplicate", "Yes" if document.get("duplicate") else "No"],
        ["Active content", "Detected" if document.get("active_content") else "Not detected"],
        ["Embedded files", str(document.get("embedded_files", 0))],
    ]
    similar = document.get("similar_documents") or []
    if similar:
        rows.append(["Similar documents", "; ".join(f"{round(s.get('score', 0) * 100)}% similarity" for s in similar)])
    metadata = document.get("metadata") or {}
    if metadata:
        rows.append(["Metadata", "; ".join(f"{key}: {value}" for key, value in list(metadata.items())[:6])])
    return _kv_table(rows, styles)


def _kind_label(kind: str) -> str:
    return {"text": "Job message scan", "pdf": "PDF offer letter", "url": "Website URL"}.get(kind, str(kind))


def _hex(color) -> str:
    try:
        return color.hexval()[2:]
    except Exception:
        return "6b7280"


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.4)
    canvas.line(16 * mm, 11 * mm, 194 * mm, 11 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(16 * mm, 7 * mm, "OfferShield — Know Before You Trust. Automated screening, not a fraud determination.")
    canvas.drawRightString(194 * mm, 7 * mm, f"Page {doc.page}")
    canvas.restoreState()
