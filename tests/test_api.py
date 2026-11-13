"""End-to-end API tests: pages, scans, progress polling and SSRF rejection."""

from __future__ import annotations

import io
import time


def _poll(client, job_id, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        response = client.get(f"/api/job/{job_id}")
        assert response.status_code == 200
        job = response.get_json()
        if job["status"] in {"done", "error"}:
            return job
        time.sleep(0.05)
    raise AssertionError("job did not finish in time")


def test_health_endpoint(client):
    body = client.get("/api/health").get_json()
    assert body["status"] == "ok"
    assert body["network_checks"] is False
    assert body["ai_configured"] is False


def test_static_pages_render(client):
    for path in ("/", "/dashboard", "/about"):
        assert client.get(path).status_code == 200


def test_text_scan_end_to_end(client):
    message = (
        "Congratulations, you are selected for the Data Entry role. Pay a refundable "
        "registration fee of Rs 2000 and a security deposit of Rs 5000 to UPI "
        "hrpayments@okaxis. Send your Aadhaar card and PAN card. This is urgent, reply "
        "within 2 hours. Contact infosys.hr.recruit@gmail.com."
    )
    response = client.post("/api/analyze", json={"type": "text", "text": message, "consent": False})
    assert response.status_code == 202
    payload = response.get_json()
    assert payload["job_id"]

    job = _poll(client, payload["job_id"])
    assert job["status"] == "done"
    assert job["result_url"].startswith("/results/")

    result = client.get(job["result_url"])
    assert result.status_code == 200
    html = result.get_data(as_text=True)
    assert "Score contributions" in html
    assert "Findings &amp; evidence" in html or "Findings & evidence" in html

    pdf = client.get(job["result_url"] + "/report.pdf")
    assert pdf.status_code == 200
    assert pdf.data[:4] == b"%PDF"


def test_text_scan_too_short_is_rejected(client):
    response = client.post("/api/analyze", json={"type": "text", "text": "hi"})
    assert response.status_code == 400
    assert "10 characters" in response.get_json()["error"]


def test_url_scan_rejects_private_address(client):
    response = client.post("/api/analyze", json={"type": "url", "url": "http://127.0.0.1/admin"})
    assert response.status_code == 400
    assert "Private" in response.get_json()["error"] or "blocked" in response.get_json()["error"]


def test_cross_origin_submission_is_rejected(client):
    response = client.post(
        "/api/analyze",
        json={"type": "text", "text": "Pay a registration fee of Rs 1000 now."},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403


def test_pdf_scan_end_to_end_and_duplicate_detection(client, sample_pdf_bytes):
    def upload():
        return client.post(
            "/api/analyze",
            data={"file": (io.BytesIO(sample_pdf_bytes), "offer.pdf"), "consent": "false"},
            content_type="multipart/form-data",
        )

    first = upload()
    assert first.status_code == 202
    job = _poll(client, first.get_json()["job_id"])
    assert job["status"] == "done"

    case_id = job["result_url"].rsplit("/", 1)[-1]
    page = client.get(job["result_url"]).get_data(as_text=True)
    assert "Document analysis" in page

    second = upload()
    job2 = _poll(client, second.get_json()["job_id"])
    assert job2["status"] == "done"
    page2 = client.get(job2["result_url"]).get_data(as_text=True)
    assert "Exact duplicate" in page2
    assert case_id  # sanity: first case id was captured


def test_pdf_upload_rejects_non_pdf(client):
    response = client.post(
        "/api/analyze",
        data={"file": (io.BytesIO(b"not a pdf"), "notes.pdf"), "consent": "false"},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400


def test_unknown_job_returns_404(client):
    response = client.get("/api/job/" + "a" * 32)
    assert response.status_code == 404


def test_missing_case_report_returns_404(client):
    response = client.get("/results/" + "b" * 32)
    assert response.status_code == 404
