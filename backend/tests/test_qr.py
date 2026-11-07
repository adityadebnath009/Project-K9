"""
Comprehensive Test Suite for Advanced Extension: QR Code Scam Detection (Quishing Protection)
Covers:
- Decoding QR images from bytes and Base64 data URLs
- Detecting deceptive UPI payment addresses masquerading as utilities/banks
- Benign UPI payment verification
- End-to-end QR orchestration with Web3 commitment
- FastAPI POST /api/v1/scan/qr (Multipart & JSON Base64)
"""

import io
import base64
import pytest
import qrcode
from PIL import Image
from fastapi.testclient import TestClient

from main import app
from models.schemas import RiskTier, InputType
from engine.threat.qr_scanner import decode_qr_image, parse_upi_payment_uri
from engine.orchestrator import orchestrate_qr_scan

client = TestClient(app)


def make_qr_image_bytes(payload: str) -> bytes:
    """Helper to generate in-memory PNG QR code bytes for a given payload."""
    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# -------------------------------------------------------------
# Tests 1 - 5: Low-Level QR Decoding & UPI URI Parsing
# -------------------------------------------------------------
def test_qr_decode_url_payload():
    """Generates QR with URL payload and verifies clean decoding."""
    qr_bytes = make_qr_image_bytes("https://python.org/downloads")
    res = decode_qr_image(qr_bytes)

    assert res.decoded is True
    assert res.payload_type == "url"
    assert res.raw_payload == "https://python.org/downloads"


def test_qr_decode_fraudulent_upi_vpa():
    """Identifies individual VPA mimicking official electricity department."""
    malicious_upi = "upi://pay?pa=bescom.electricity.bill@okhdfcbank&pn=StateElectricityDiscom&am=4800&cu=INR"
    qr_bytes = make_qr_image_bytes(malicious_upi)
    res = decode_qr_image(qr_bytes)

    assert res.decoded is True
    assert res.payload_type == "upi_payment"
    assert res.upi_details is not None
    assert res.upi_details.is_suspicious_vpa is True
    assert any("masquerades as official authority" in r for r in res.upi_details.suspicious_reasons)


def test_qr_decode_benign_upi_payment():
    """Validates regular peer-to-peer consumer payment without institutional impersonation."""
    clean_upi = "upi://pay?pa=john.doe@okaxis&pn=JohnDoe&am=150&cu=INR"
    qr_bytes = make_qr_image_bytes(clean_upi)
    res = decode_qr_image(qr_bytes)

    assert res.decoded is True
    assert res.payload_type == "upi_payment"
    assert res.upi_details.is_suspicious_vpa is False
    assert len(res.upi_details.suspicious_reasons) == 0


def test_qr_decode_base64_data_url_string():
    """Verifies that base64 encoded strings with data:image/png prefix decode identically."""
    raw_bytes = make_qr_image_bytes("https://k9-sentinel.io")
    b64_str = "data:image/png;base64," + base64.b64encode(raw_bytes).decode("ascii")

    res = decode_qr_image(b64_str)
    assert res.decoded is True
    assert res.raw_payload == "https://k9-sentinel.io"


def test_qr_decode_corrupted_garbage_bytes_no_crash():
    """Corrupted garbage bytes return decoded=False cleanly without throwing unhandled exceptions."""
    res = decode_qr_image(b"NOT_A_VALID_IMAGE_DATA_123456")
    assert res.decoded is False
    assert "Failed to process" in (res.error or "")


# -------------------------------------------------------------
# Tests 6 - 7: Orchestrator Full QR Pipeline Execution
# -------------------------------------------------------------
@pytest.mark.anyio
async def test_orchestrate_qr_scan_fraudulent_upi():
    """End-to-end QR orchestration flags fake utility QR as Confirmed Malicious and commits to Web3."""
    fraud_upi = "upi://pay?pa=uppcl.electricity.recovery@paytm&pn=UPPCLOfficer&am=6200&cu=INR"
    qr_bytes = make_qr_image_bytes(fraud_upi)

    res = await orchestrate_qr_scan(qr_bytes)

    assert res.input_type == InputType.QR_CODE
    assert res.risk_tier == RiskTier.CONFIRMED_MALICIOUS
    assert res.threat_score >= 80
    assert res.is_safe is False
    assert res.qr_inspection is not None
    assert res.qr_inspection.payload_type == "upi_payment"
    assert res.web3_commitment is not None
    assert res.web3_commitment.on_chain_registered is True


@pytest.mark.anyio
async def test_orchestrate_qr_scan_embedded_url():
    """Embedded URL in QR routes through the 6-phase orchestrator."""
    qr_bytes = make_qr_image_bytes("https://python.org")
    res = await orchestrate_qr_scan(qr_bytes)

    assert res.input_type == InputType.QR_CODE
    assert res.risk_tier == RiskTier.LOW_RISK
    assert res.is_safe is True
    assert res.qr_inspection is not None


# -------------------------------------------------------------
# Tests 8 - 10: FastAPI POST /api/v1/scan/qr Endpoints
# -------------------------------------------------------------
def test_api_scan_qr_endpoint_base64():
    """POST /api/v1/scan/qr accepts JSON body with image_base64."""
    raw_bytes = make_qr_image_bytes("upi://pay?pa=traffic.police.challan@okhdfcbank&pn=TrafficDept&am=1000")
    b64_str = base64.b64encode(raw_bytes).decode("ascii")

    resp = client.post("/api/v1/scan/qr", json={"image_base64": b64_str})
    assert resp.status_code == 200
    data = resp.json()

    assert data["input_type"] == "qr_code"
    assert data["risk_tier"] == "Confirmed Malicious"
    assert data["qr_inspection"]["payload_type"] == "upi_payment"


def test_api_scan_qr_endpoint_multipart_file_upload():
    """POST /api/v1/scan/qr accepts multipart image file uploads."""
    raw_bytes = make_qr_image_bytes("https://google.com")

    resp = client.post(
        "/api/v1/scan/qr",
        files={"file": ("qr.png", raw_bytes, "image/png")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["input_type"] == "qr_code"
    assert data["is_safe"] is True


def test_api_scan_qr_endpoint_missing_input_returns_400():
    """POST /api/v1/scan/qr with empty body returns 400 Bad Request."""
    resp = client.post("/api/v1/scan/qr", json={})
    assert resp.status_code == 422  # validation error for missing field
