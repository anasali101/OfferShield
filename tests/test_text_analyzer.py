"""Tests for the recruitment message pattern analyser (Feature A)."""

from __future__ import annotations

from detection.text_analyzer import analyze_text
from detection.utils import extract_entities


def _ids(result):
    return {f["id"] for f in result["findings"]}


def test_guaranteed_placement_flagged():
    result = analyze_text("We offer 100% job guarantee with direct joining, no interview needed.")
    ids = _ids(result)
    assert "MSG_GUARANTEED_PLACEMENT" in ids
    assert "MSG_NO_INTERVIEW" in ids


def test_urgency_flagged():
    result = analyze_text("This offer is urgent. Confirm within 2 hours or the seat is cancelled.")
    assert "MSG_URGENCY" in _ids(result)


def test_sensitive_documents_flagged():
    result = analyze_text("Please send your Aadhaar card and PAN card along with your OTP to proceed.")
    assert "MSG_SENSITIVE_DOCUMENTS" in _ids(result)


def test_legitimate_interview_message_has_no_warnings_and_positive_signal():
    message = (
        "Thank you for your application. We would like to schedule a technical interview on "
        "20 November via video call. There is no fee at any stage of our process. "
        "Regards, Talent Acquisition Team."
    )
    result = analyze_text(message, extract_entities(message))
    assert result["findings"] == []
    signal_ids = {s["id"] for s in result["signals"]}
    assert "SIG_INTERVIEW_PROCESS" in signal_ids


def test_formal_process_suppresses_whatsapp_channel_finding():
    message = (
        "We will schedule a technical interview this week. You can contact me on WhatsApp "
        "if you have questions before then."
    )
    result = analyze_text(message, extract_entities(message))
    assert "MSG_PERSONAL_CHANNEL" not in _ids(result)


def test_whatsapp_only_without_process_is_flagged():
    message = "This is a work from home job. Contact me only on WhatsApp to start immediately."
    result = analyze_text(message, extract_entities(message))
    assert "MSG_PERSONAL_CHANNEL" in _ids(result)


def test_task_scam_pattern_flagged():
    message = "Earn money per task. Like and subscribe videos and get daily payout to your account."
    result = analyze_text(message, extract_entities(message))
    assert "MSG_TASK_SCAM" in _ids(result)
