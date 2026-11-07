"""
Comprehensive 20-Test Suite for Phase 4: AI Threat Analyst & MITRE ATT&CK Briefing Engine.
Covers:
1-5: High-fidelity IOC Extraction (URLs, Indian Phones, UPI Handles, TRAI Sender IDs, Deduplication)
6-14: Deterministic Rule-Based Expert System (KYC, Suspension, Utility, Financial Fraud, Typosquatting, Compound Scams, Benign texts, Hinglish lures)
15-16: Schema Integrity, Range Constraints & JSON Serialization
17-19: Offline Fallback & Network/API Fault Tolerance (Missing Key, Timeout, Model Error)
20: Live End-to-End Briefing Pipeline Execution
"""

import os
import json
import pytest
from unittest.mock import MagicMock
import httpx
import groq

from models.schemas import AIBriefingReport, DomainThreatSchema, UrgencyNlpSchema
from engine.threat.ai_analyst import (
    extract_indicators_of_compromise,
    _deterministic_ai_briefing,
    generate_threat_ai_briefing,
    analyze_with_groq_llm,
    MITRE_DB,
)


# -------------------------------------------------------------
# Tests 1 - 5: High-Fidelity IOC Extraction Mechanics
# -------------------------------------------------------------
def test_ioc_url_extraction():
    """Extracts HTTP and HTTPS URLs with arbitrary paths, ports, and query parameters."""
    text = "Visit http://phish.in/login?ref=123 and backup at https://secure.bank.com:8443/verify"
    iocs = extract_indicators_of_compromise(text)
    assert "http://phish.in/login?ref=123" in iocs["urls"]
    assert "https://secure.bank.com:8443/verify" in iocs["urls"]


def test_ioc_indian_phone_number_extraction():
    """Extracts +91 formatted numbers and raw 10-digit mobile numbers starting with 6, 7, 8, 9."""
    text = "Contact support immediately at +91-9876543210 or 8765432109 for KYC re-activation."
    iocs = extract_indicators_of_compromise(text)
    assert any("9876543210" in p for p in iocs["phones"])
    assert any("8765432109" in p for p in iocs["phones"])


def test_ioc_upi_handle_extraction():
    """Extracts fintech UPI handles while safely ignoring regular corporate email providers."""
    text = "Send penalty fees to payment.dept@okhdfcbank or recovery@upi. Email questions to info@gmail.com."
    iocs = extract_indicators_of_compromise(text)
    assert "payment.dept@okhdfcbank" in iocs["upi_handles"]
    assert "recovery@upi" in iocs["upi_handles"]
    assert "info@gmail.com" not in iocs["upi_handles"]


def test_ioc_sender_id_extraction():
    """Extracts TRAI commercial SMS sender headers (two alpha characters followed by hyphen and six alphanumeric)."""
    text = "Alert received from AD-SBIINB: OTP is 492019. Notification from VK-HDFCBK confirms login."
    iocs = extract_indicators_of_compromise(text)
    assert "AD-SBIINB" in iocs["sender_ids"]
    assert "VK-HDFCBK" in iocs["sender_ids"]


def test_ioc_deduplication_and_multiple_occurrences():
    """Ensures repeated indicators in spam text are deduplicated."""
    text = "Click https://bad.link now! Remember https://bad.link! Call 9876543210 or +919876543210."
    iocs = extract_indicators_of_compromise(text)
    assert len(iocs["urls"]) == 1
    assert len([p for p in iocs["phones"] if "9876543210" in p]) >= 1


# -------------------------------------------------------------
# Tests 6 - 14: Deterministic Expert Fallback & Threat Scenarios
# -------------------------------------------------------------
def test_deterministic_fake_kyc_compliance_lure():
    """Verifies fake KYC pretexting maps to T1598.002, T1566.002, and T1204.001."""
    text = "Dear customer, your mandatory KYC update is pending. Click http://kyc-airtel.in to avoid deactivation."
    iocs = extract_indicators_of_compromise(text)
    nlp = UrgencyNlpSchema(
        is_coercive=True,
        urgency_score=80,
        detected_categories=["fake_kyc_and_compliance"],
        urgency_keywords=["kyc", "mandatory", "deactivation"],
        severity="CRITICAL",
    )
    report = _deterministic_ai_briefing(text, iocs, nlp_report=nlp)

    tech_ids = [t.id for t in report.mitre_attack_techniques]
    assert "T1598.002" in tech_ids
    assert "T1566.002" in tech_ids
    assert "T1204.001" in tech_ids
    assert "Credential & PII Harvesting" in report.threat_category


def test_deterministic_account_suspension_urgency():
    """Verifies account suspension within deadline maps to T1598.002 and T1204.001."""
    text = "Your NetBanking access will be terminated in 24 hours due to non-compliance. http://unlock-sbi.net"
    iocs = extract_indicators_of_compromise(text)
    nlp = UrgencyNlpSchema(
        is_coercive=True,
        urgency_score=75,
        detected_categories=["account_suspension"],
        urgency_keywords=["terminated", "24 hours"],
        severity="HIGH",
    )
    report = _deterministic_ai_briefing(text, iocs, nlp_report=nlp)

    tech_ids = [t.id for t in report.mitre_attack_techniques]
    assert "T1598.002" in tech_ids
    assert "T1204.001" in tech_ids
    assert any("Artificial Time-Pressure" in tr for tr in report.psychological_triggers)


def test_deterministic_utility_power_disconnection_threat():
    """Verifies electricity disconnection lures trigger psychological urgency flags."""
    text = "Dear consumer, your electricity power will be cut tonight at 9:30 PM. Pay via http://bill-pay.org"
    iocs = extract_indicators_of_compromise(text)
    nlp = UrgencyNlpSchema(
        is_coercive=True,
        urgency_score=70,
        detected_categories=["utility_disconnection"],
        urgency_keywords=["power cut", "tonight"],
        severity="HIGH",
    )
    report = _deterministic_ai_briefing(text, iocs, nlp_report=nlp)
    assert report.confidence_score >= 85
    assert len(report.psychological_triggers) > 0


def test_deterministic_financial_upi_fraud_lure():
    """Verifies fake rewards/recharge/UPI lure maps to T1657 (Financial Fraud)."""
    text = "Congratulations! You won INR 50,000 lottery. Approve collect request at claim@okhdfcbank"
    iocs = extract_indicators_of_compromise(text)
    nlp = UrgencyNlpSchema(
        is_coercive=True,
        urgency_score=65,
        detected_categories=["fake_reward_and_recharge"],
        urgency_keywords=["won", "lottery"],
        severity="CRITICAL",
    )
    report = _deterministic_ai_briefing(text, iocs, nlp_report=nlp)

    tech_ids = [t.id for t in report.mitre_attack_techniques]
    assert "T1657" in tech_ids
    assert "Financial Fraud" in report.threat_category


def test_deterministic_infrastructure_typosquat_mapping():
    """Verifies domain typosquatting detection maps to T1584 (Compromise Infrastructure)."""
    text = "Login to your account at http://paypa1-secure.com"
    iocs = extract_indicators_of_compromise(text)
    domain_report = DomainThreatSchema(
        hostname="paypa1-secure.com",
        domain_name="paypa1-secure.com",
        threat_detected=True,
        is_typosquatted=True,
        impersonated_brand="paypal",
        severity="CRITICAL",
    )
    report = _deterministic_ai_briefing(text, iocs, domain_report=domain_report)

    tech_ids = [t.id for t in report.mitre_attack_techniques]
    assert "T1584" in tech_ids
    assert report.targeted_entity == "PAYPAL"


def test_deterministic_combined_compound_threat():
    """Verifies compound attacks with typosquat domain, fake KYC, and suspension urgency coalesce."""
    text = "URGENT: SBI customer, KYC expired! Account blocked in 12h. Visit http://sbi-kyc-fix.top immediately."
    iocs = extract_indicators_of_compromise(text)
    nlp = UrgencyNlpSchema(
        is_coercive=True,
        urgency_score=95,
        detected_categories=["fake_kyc_and_compliance", "account_suspension"],
        urgency_keywords=["urgent", "blocked", "12h", "kyc"],
        severity="CRITICAL",
    )
    domain_report = DomainThreatSchema(
        hostname="sbi-kyc-fix.top",
        domain_name="sbi-kyc-fix.top",
        threat_detected=True,
        is_typosquatted=True,
        impersonated_brand="sbi",
        severity="CRITICAL",
    )
    report = _deterministic_ai_briefing(text, iocs, domain_report=domain_report, nlp_report=nlp)

    tech_ids = [t.id for t in report.mitre_attack_techniques]
    # Check all 4 primary techniques are present
    assert {"T1584", "T1566.002", "T1598.002", "T1204.001"}.issubset(set(tech_ids))
    assert report.targeted_entity == "SBI"


def test_deterministic_benign_conversational_text():
    """Verifies benign educational messages produce zero hostile MITRE techniques."""
    text = "Welcome to K9 Sentinel AI documentation. Read our architecture overview at https://docs.k9.io"
    iocs = extract_indicators_of_compromise(text)
    nlp = UrgencyNlpSchema(
        is_coercive=False,
        urgency_score=0,
        detected_categories=[],
        urgency_keywords=[],
        severity="SAFE",
    )
    report = _deterministic_ai_briefing(text, iocs, nlp_report=nlp)

    assert report.threat_category == "Benign Information"
    assert len(report.mitre_attack_techniques) == 0
    assert report.confidence_score >= 90
    assert "No hostile" in report.executive_summary


def test_deterministic_benign_order_update_clean():
    """Verifies normal e-commerce dispatch notifications are not falsely flagged."""
    text = "Your package #91823 has been shipped via BlueDart. Track delivery at https://bluedart.com/track/91823"
    iocs = extract_indicators_of_compromise(text)
    report = _deterministic_ai_briefing(text, iocs)

    assert report.threat_category == "Benign Information"
    assert len(report.mitre_attack_techniques) == 0
    assert "Exercise standard caution" in report.analyst_recommendation


def test_deterministic_hinglish_slang_threat_detection():
    """Verifies coercive threats in mixed Hindi-English (Hinglish) trigger urgency flags."""
    text = "Aapka SIM card 24 ghante me block ho jayega. Turant KYC update karein http://jio-kyc.in par."
    iocs = extract_indicators_of_compromise(text)
    nlp = UrgencyNlpSchema(
        is_coercive=True,
        urgency_score=75,
        detected_categories=["fake_kyc_and_compliance", "account_suspension"],
        urgency_keywords=["block", "24 ghante", "kyc"],
        severity="CRITICAL",
    )
    report = _deterministic_ai_briefing(text, iocs, nlp_report=nlp)

    assert len(report.mitre_attack_techniques) > 0
    assert "Do NOT click" in report.analyst_recommendation


# -------------------------------------------------------------
# Tests 15 - 16: Pydantic Contract Invariants & Serialization
# -------------------------------------------------------------
def test_ai_briefing_schema_contract_invariants():
    """Verifies that AIBriefingReport enforces confidence score bounds and non-null strings."""
    report = AIBriefingReport(
        executive_summary="Executive summary text here.",
        threat_category="Phishing",
        targeted_entity="Bank",
        psychological_triggers=["Urgency"],
        mitre_attack_techniques=[MITRE_DB["T1566.002"]],
        extracted_indicators=["URL: http://test.com"],
        analyst_recommendation="Block URL immediately.",
        confidence_score=95,
        ai_engine="Deterministic Fallback",
        offline_mode=True,
    )
    assert 0 <= report.confidence_score <= 100
    assert report.offline_mode is True
    assert len(report.extracted_indicators) == 1


def test_ai_briefing_json_roundtrip_serialization():
    """Verifies JSON serialization and deserialization retains identical fields and nested MITRE objects."""
    report = _deterministic_ai_briefing("Scam text alert", {"urls": ["http://evil.com"]})
    json_str = report.model_dump_json()
    data = json.loads(json_str)

    assert "executive_summary" in data
    assert "mitre_attack_techniques" in data
    reconstructed = AIBriefingReport.model_validate_json(json_str)
    assert reconstructed.executive_summary == report.executive_summary
    assert reconstructed.confidence_score == report.confidence_score


# -------------------------------------------------------------
# Tests 17 - 19: Offline Fallback & Fault Tolerance
# -------------------------------------------------------------
def test_groq_missing_api_key_graceful_offline_fallback(monkeypatch):
    """Verifies analyze_with_groq_llm returns None when GROQ_API_KEY is not configured."""
    monkeypatch.setenv("GROQ_API_KEY", "")
    result = analyze_with_groq_llm("Suspicious message text", {})
    assert result is None

    # Entire pipeline still returns valid AIBriefingReport via deterministic fallback
    full_report = generate_threat_ai_briefing("Suspicious message text")
    assert isinstance(full_report, AIBriefingReport)
    assert full_report.offline_mode is True


def test_groq_network_timeout_graceful_fallback(monkeypatch):
    """Verifies that network timeout exceptions during Groq invocation fall back cleanly to deterministic rules."""
    monkeypatch.setenv("GROQ_API_KEY", "gsk_mock_key_for_testing")

    def mock_invoke(*args, **kwargs):
        raise httpx.RequestError("Simulated connection timeout to api.groq.com")

    # Mock ChatGroq.with_structured_output invocation
    mock_runnable = MagicMock()
    mock_runnable.invoke.side_effect = mock_invoke
    mock_chat_groq = MagicMock()
    mock_chat_groq.return_value.with_structured_output.return_value = mock_runnable

    monkeypatch.setattr("langchain_groq.ChatGroq", mock_chat_groq)

    full_report = generate_threat_ai_briefing("Test message with network outage")
    assert isinstance(full_report, AIBriefingReport)
    assert full_report.offline_mode is True
    assert "Deterministic Fallback" in full_report.ai_engine


def test_groq_api_not_found_model_fallback(monkeypatch):
    """Verifies that if a model returns 404 NotFoundError, it attempts candidate models or falls back safely."""
    monkeypatch.setenv("GROQ_API_KEY", "gsk_mock_key_for_testing")

    def mock_invoke(*args, **kwargs):
        raise groq.NotFoundError(
            message="Model does not exist",
            response=httpx.Response(404, request=httpx.Request("POST", "https://api.groq.com")),
            body=None,
        )

    mock_runnable = MagicMock()
    mock_runnable.invoke.side_effect = mock_invoke
    mock_chat_groq = MagicMock()
    mock_chat_groq.return_value.with_structured_output.return_value = mock_runnable

    monkeypatch.setattr("langchain_groq.ChatGroq", mock_chat_groq)

    full_report = generate_threat_ai_briefing("Test message with invalid model")
    assert isinstance(full_report, AIBriefingReport)
    assert full_report.offline_mode is True


# -------------------------------------------------------------
# Test 20: Live End-to-End Briefing Pipeline Execution
# -------------------------------------------------------------
def test_generate_threat_ai_briefing_live_execution():
    """Verifies end-to-end execution on a real threat prompt produces populated intelligence fields."""
    sample = (
        "URGENT: Your SBI account is blocked due to missing PAN verification. "
        "Visit http://sbi-pan-update.in to verify now or call 9876543210."
    )
    report = generate_threat_ai_briefing(sample)

    assert isinstance(report, AIBriefingReport)
    assert len(report.executive_summary) > 20
    assert len(report.analyst_recommendation) > 10
    assert report.confidence_score >= 80
    assert any("http://sbi-pan-update.in" in ind or "9876543210" in ind for ind in report.extracted_indicators)
