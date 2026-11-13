"""Tests for the payment fraud detector (Feature D)."""

from __future__ import annotations

from detection.payment_detector import detect_payments


def _ids(result):
    return {f["id"] for f in result["findings"]}


def test_registration_fee_is_critical():
    result = detect_payments(
        "To confirm your joining, pay a registration fee of Rs 2000 immediately."
    )
    assert "PAY_REGISTRATION_FEE" in _ids(result)
    finding = next(f for f in result["findings"] if f["id"] == "PAY_REGISTRATION_FEE")
    assert finding["severity"] == "critical"
    assert finding["points"] > 0


def test_security_deposit_detected():
    result = detect_payments("A refundable security deposit of Rs 5000 is required before joining.")
    assert "PAY_SECURITY_DEPOSIT" in _ids(result)


def test_salary_alone_is_not_a_payment_request():
    result = detect_payments("The annual CTC for this role is Rs 12,00,000 per annum.")
    assert result["findings"] == []


def test_negated_fee_is_reported_as_positive_not_warning():
    result = detect_payments(
        "There is no registration fee at any stage of our recruitment process."
    )
    ids = _ids(result)
    assert "PAY_REGISTRATION_FEE" not in ids
    assert "PAY_NO_FEE_STATED" in ids
    clean = next(f for f in result["findings"] if f["id"] == "PAY_NO_FEE_STATED")
    assert clean["severity"] == "clean"
    assert clean["points"] == 0


def test_personal_upi_with_payment_context_flagged():
    text = "Pay the training fee of Rs 2000 to UPI id hrpayments@okaxis to receive your offer."
    result = detect_payments(text)
    assert "PAY_PERSONAL_UPI" in _ids(result)
    assert "hrpayments@okaxis" in result["upi_ids"]


def test_upi_without_payment_context_not_flagged():
    result = detect_payments("Reach out to our team at support@okaxis if you have questions.")
    assert "PAY_PERSONAL_UPI" not in _ids(result)


def test_crypto_gift_card_payment_is_critical():
    result = detect_payments(
        "Purchase an Amazon gift card of Rs 5000 and send the code to confirm your placement."
    )
    assert "PAY_CRYPTO_GIFT_CARD" in _ids(result)
    finding = next(f for f in result["findings"] if f["id"] == "PAY_CRYPTO_GIFT_CARD")
    assert finding["severity"] == "critical"
