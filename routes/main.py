"""Page routes: landing, dashboard, results, report download, about."""

from __future__ import annotations

import io

from flask import Blueprint, current_app, jsonify, render_template, send_file

from detection.report_generator import generate_report
from services import storage

main_bp = Blueprint("main", __name__)


@main_bp.get("/")
def index():
    return render_template("index.html")


@main_bp.get("/dashboard")
def dashboard():
    return render_template("dashboard.html", max_upload_mb=current_app.config["MAX_UPLOAD_MB"])


@main_bp.get("/about")
def about():
    return render_template("about.html")


@main_bp.get("/results/<case_id>")
def results(case_id: str):
    if not case_id.isalnum() or len(case_id) != 32:
        return render_template("error.html", code=404, message="That report does not exist."), 404
    case = storage.get_case(current_app.config["DB_PATH"], case_id)
    if not case:
        return (
            render_template(
                "error.html",
                code=404,
                message=(
                    "This investigation report was not found. Reports are deleted "
                    "automatically after the configured retention period."
                ),
            ),
            404,
        )
    return render_template("results.html", case=case)


@main_bp.get("/results/<case_id>/report.pdf")
def download_report(case_id: str):
    if not case_id.isalnum() or len(case_id) != 32:
        return render_template("error.html", code=404, message="That report does not exist."), 404
    case = storage.get_case(current_app.config["DB_PATH"], case_id)
    if not case:
        return render_template("error.html", code=404, message="That report has expired or does not exist."), 404
    pdf_bytes = generate_report(case)
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"offershield-report-{case_id[:8]}.pdf",
        max_age=0,
    )


@main_bp.get("/api/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "version": "1.0.0",
            "ai_configured": bool(current_app.config.get("AI_API_KEY")),
            "network_checks": bool(current_app.config.get("NETWORK_CHECKS_ENABLED")),
            "reputation_configured": bool(
                current_app.config.get("VIRUSTOTAL_API_KEY")
                or current_app.config.get("SAFE_BROWSING_API_KEY")
            ),
        }
    )
