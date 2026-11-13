"""Shared pytest fixtures.

All tests run fully offline: network checks are disabled and no optional API
keys are configured, so the deterministic engine is exercised on its own.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ["NETWORK_CHECKS_ENABLED"] = "0"

from app import create_app  # noqa: E402
from services import storage  # noqa: E402


@pytest.fixture()
def app():
    tmpdir = tempfile.mkdtemp(prefix="offershield-test-")
    db_path = Path(tmpdir) / "test.sqlite3"
    application = create_app(
        {
            "TESTING": True,
            "NETWORK_CHECKS_ENABLED": False,
            "DATA_DIR": Path(tmpdir),
            "DB_PATH": db_path,
            "AI_API_KEY": "",
            "VIRUSTOTAL_API_KEY": "",
            "SAFE_BROWSING_API_KEY": "",
            "DOMAIN_TIMEOUT": 2,
            "SECRET_KEY": "test-secret",
        }
    )
    storage.init_db(db_path)
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def config(app):
    return {key: app.config.get(key) for key in app.config}


@pytest.fixture()
def sample_pdf_bytes():
    """Build a small text-based PDF in memory (no disk writes)."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    import io

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    pdf.drawString(
        72,
        760,
        "Congratulations, you are selected for the Data Entry role at Infosys.",
    )
    pdf.drawString(
        72,
        740,
        "Please pay a refundable registration fee of Rs 2000 to confirm your seat.",
    )
    pdf.drawString(
        72,
        720,
        "Contact our HR team at infosys.hr.recruit@gmail.com or WhatsApp +91 9000000000.",
    )
    pdf.drawString(
        72,
        700,
        "Send your Aadhaar card and PAN card for onboarding. This is urgent, reply today.",
    )
    pdf.showPage()
    pdf.save()
    return buffer.getvalue()
