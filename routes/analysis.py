"""JSON API for starting scans and polling progress."""

from __future__ import annotations

import math
import threading
from urllib.parse import urlparse

from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import secure_filename

from config import Config
from detection.domain_checker import UnsafeURLError, validate_public_url
from services import jobs, pipeline

analysis_bp = Blueprint("analysis", __name__)

SNAPSHOT_KEYS = list(Config.snapshot().keys())
MAX_TEXT = 50_000


def _config() -> dict:
    return {key: current_app.config.get(key) for key in SNAPSHOT_KEYS}


def _same_origin() -> bool:
    origin = request.headers.get("Origin")
    if not origin:
        return True
    try:
        return urlparse(origin).netloc == request.host
    except ValueError:
        return False


def _coerce_consent(value) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


@analysis_bp.post("/api/analyze")
def analyze():
    if not _same_origin():
        return jsonify({"error": "Cross-origin submissions are not allowed."}), 403

    config = _config()

    if request.files and "file" in request.files:
        return _handle_pdf(config)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Send JSON with a 'type' field, or upload a PDF as multipart form data."}), 400

    scan_type = str(payload.get("type", "")).lower()
    consent = _coerce_consent(payload.get("consent", False))

    if scan_type == "text":
        text = payload.get("text")
        if not isinstance(text, str):
            return jsonify({"error": "The 'text' field must be a string."}), 400
        if len(text) > int(config.get("MAX_TEXT_CHARS", MAX_TEXT)):
            return jsonify({"error": f"Text exceeds the {config.get('MAX_TEXT_CHARS', MAX_TEXT)} character limit."}), 400
        if len(text.strip()) < 10:
            return jsonify({"error": "Please provide at least 10 characters of offer text."}), 400
        job_id = jobs.create_job("text", pipeline.STEPS["text"])
        thread = threading.Thread(
            target=pipeline.run_text_analysis,
            args=(job_id, text, consent, config),
            daemon=True,
        )
        thread.start()
        return jsonify({"job_id": job_id, "steps": jobs.get_job(job_id)["steps"]}), 202

    if scan_type == "url":
        raw_url = payload.get("url")
        if not isinstance(raw_url, str) or not raw_url.strip():
            return jsonify({"error": "Please provide a website URL."}), 400
        try:
            normalized, host = validate_public_url(raw_url)
        except UnsafeURLError as exc:
            return jsonify({"error": f"URL rejected: {exc}"}), 400
        job_id = jobs.create_job("url", pipeline.STEPS["url"])
        thread = threading.Thread(
            target=pipeline.run_url_analysis,
            args=(job_id, normalized, consent, config),
            daemon=True,
        )
        thread.start()
        return jsonify({"job_id": job_id, "steps": jobs.get_job(job_id)["steps"], "host": host}), 202

    return jsonify({"error": "Unsupported scan type. Use 'text', 'url' or upload a PDF."}), 400


def _handle_pdf(config: dict):
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify({"error": "No PDF file was provided."}), 400

    safe_name = secure_filename(upload.filename)
    if not safe_name:
        safe_name = "offer-letter.pdf"
    safe_name = safe_name[:120]
    if not safe_name.lower().endswith(".pdf"):
        return jsonify({"error": "Only .pdf files are accepted."}), 400

    max_bytes = int(config.get("MAX_UPLOAD_MB", 5)) * 1024 * 1024
    data = upload.read(max_bytes + 1)
    if len(data) > max_bytes:
        return jsonify({"error": f"File exceeds the {config.get('MAX_UPLOAD_MB', 5)} MB limit."}), 413
    if len(data) < 8 or not data.startswith(b"%PDF-"):
        return jsonify({"error": "The uploaded file is not a valid PDF (bad file signature)."}), 400

    consent = _coerce_consent(request.form.get("consent", False))
    job_id = jobs.create_job("pdf", pipeline.STEPS["pdf"])
    thread = threading.Thread(
        target=pipeline.run_pdf_analysis,
        args=(job_id, data, safe_name, consent, config),
        daemon=True,
    )
    thread.start()
    return (
        jsonify(
            {
                "job_id": job_id,
                "steps": jobs.get_job(job_id)["steps"],
                "filename": safe_name,
                "size_kb": math.ceil(len(data) / 1024),
            }
        ),
        202,
    )


@analysis_bp.get("/api/job/<job_id>")
def job_status(job_id: str):
    if not job_id or not job_id.isalnum() or len(job_id) != 32:
        return jsonify({"error": "Invalid job id."}), 400
    job = jobs.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found or expired. Please start a new scan."}), 404
    return jsonify(job)
