"""
End-to-End API & Master Orchestrator Test Suite for K9 Sentinel AI.
Tests:
- Root health check & capabilities
- 6 mandatory benchmark scenarios (3 suspicious + 3 benign)
- POST /api/v1/scan and POST /api/v1/scan/message
- POST /api/v1/web3/verify & GET /api/v1/web3/latest
- GET /api/v1/threats/stix (STIX 2.1 export)
- Input validation & 404/422 error boundaries
"""

import pytest
from fastapi.testclient import TestClient
from main import app
from models.schemas import RiskTier

client = TestClient(app)


# -------------------------------------------------------------
# Tests 1 - 2: System Health & Benchmark Catalog
# -------------------------------------------------------------
def test_root_health_check():
    """GET / returns operational status and all 6 phase engines."""
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "OPERATIONAL"
    assert "phase1_crypto" in data["engine"]
    assert "phase5_web3" in data["engine"]


def test_get_benchmark_scenarios_catalog():
    """GET /api/v1/scenarios returns the benchmark cases."""
    resp = client.get("/api/v1/scenarios")
    assert resp.status_code == 200
    scenarios = resp.json()
    assert len(scenarios) >= 6

    ids = [s["id"] for s in scenarios]
    assert "scenario-1-emudhra-weak-ca" in ids
    assert "scenario-2-paypal-typosquat-harvest" in ids
    assert "scenario-3-sbi-kyc-sms-scam" in ids
    assert "scenario-4-python-foundation-benign" in ids
    assert "scenario-5-airtel-xstream-deep-link" in ids
    assert "scenario-6-google-corporate-official" in ids
    assert "scenario-7-electricity-quishing-upi" in ids


# -------------------------------------------------------------
# Tests 3 - 8: 6 Mandatory Benchmark Scenarios Execution
# -------------------------------------------------------------
def test_run_scenario_1_emudhra_weak_ca():
    """Scenario 1: eMudhra NIST P-384 low-entropy key recovery (Mozilla Bug 2083449)."""
    resp = client.post("/api/v1/scenarios/scenario-1-emudhra-weak-ca/run")
    assert resp.status_code == 200
    data = resp.json()

    assert data["risk_tier"] == "Confirmed Malicious"
    assert data["threat_score"] == 100
    assert data["is_safe"] is False
    assert data["crypto_report"]["emudhra_audit"]["vulnerable"] is True
    assert data["crypto_report"]["emudhra_audit"]["recovered_scalar_d"] == 4
    assert data["web3_commitment"]["on_chain_registered"] is True


def test_run_scenario_2_paypal_typosquat_harvest():
    """Scenario 2: PayPal Typosquat + Cross-Origin Credential Harvesting."""
    resp = client.post("/api/v1/scenarios/scenario-2-paypal-typosquat-harvest/run")
    assert resp.status_code == 200
    data = resp.json()

    assert data["risk_tier"] in ("Confirmed Malicious", "High Risk")
    assert data["is_safe"] is False
    assert data["threat_report"]["domain_threats"]["is_typosquatted"] is True
    assert data["threat_report"]["dom_harvesting"]["cross_origin_submission"] is True


def test_run_scenario_3_sbi_kyc_sms_scam():
    """Scenario 3: Coercive Indian Banking SMS Phishing with 24h deadline."""
    resp = client.post("/api/v1/scenarios/scenario-3-sbi-kyc-sms-scam/run")
    assert resp.status_code == 200
    data = resp.json()

    assert data["risk_tier"] in ("Confirmed Malicious", "High Risk")
    assert data["is_safe"] is False
    assert len(data["ai_briefing"]["mitre_attack_techniques"]) > 0
    assert data["correlation_report"]["has_campaign_match"] is True


def test_run_scenario_4_python_foundation_benign():
    """Scenario 4: Python Software Foundation (Benign Open Source Infrastructure)."""
    resp = client.post("/api/v1/scenarios/scenario-4-python-foundation-benign/run")
    assert resp.status_code == 200
    data = resp.json()

    assert data["risk_tier"] == "Low Risk"
    assert data["is_safe"] is True
    assert data["threat_score"] < 25


def test_run_scenario_5_airtel_xstream_deep_link():
    """Scenario 5: Bharti Airtel Xstream Promotional Deep Link (Benign)."""
    resp = client.post("/api/v1/scenarios/scenario-5-airtel-xstream-deep-link/run")
    assert resp.status_code == 200
    data = resp.json()

    assert data["risk_tier"] in ("Low Risk", "Suspicious")
    assert data["threat_report"]["domain_threats"]["is_typosquatted"] is False


def test_run_scenario_6_google_corporate_official():
    """Scenario 6: Google Official Infrastructure (Benign)."""
    resp = client.post("/api/v1/scenarios/scenario-6-google-corporate-official/run")
    assert resp.status_code == 200
    data = resp.json()

    assert data["risk_tier"] == "Low Risk"
    assert data["is_safe"] is True


def test_run_scenario_7_electricity_quishing_upi():
    """Scenario 7: State Electricity Discom QR Quishing & Malicious UPI Fraud."""
    resp = client.post("/api/v1/scenarios/scenario-7-electricity-quishing-upi/run")
    assert resp.status_code == 200
    data = resp.json()

    assert data["input_type"] == "qr_code"
    assert data["risk_tier"] == "Confirmed Malicious"
    assert data["threat_score"] >= 80
    assert data["qr_inspection"]["payload_type"] == "upi_payment"
    assert data["qr_inspection"]["upi_details"]["is_suspicious_vpa"] is True


# -------------------------------------------------------------
# Tests 9 - 11: General Scan Endpoints
# -------------------------------------------------------------
def test_scan_endpoint_url_input():
    """POST /api/v1/scan executes unified inspection on arbitrary target."""
    resp = client.post("/api/v1/scan", json={"target": "https://python.org"})
    assert resp.status_code == 200
    data = resp.json()
    assert "target" in data
    assert "web3_commitment" in data
    assert data["web3_commitment"]["report_hash"].startswith("0x")


def test_scan_message_endpoint():
    """POST /api/v1/scan/message specializes in SMS / text scanning."""
    sample = "Power will be disconnected tonight at 9:30 PM. Pay bill at http://power-pay.online"
    resp = client.post("/api/v1/scan/message", json={"message": sample})
    assert resp.status_code == 200
    data = resp.json()
    assert data["input_type"] == "message"
    assert data["correlation_report"]["has_campaign_match"] is True


def test_scan_invalid_scenario_id_returns_404():
    """Executing a non-existent scenario returns 404 cleanly."""
    resp = client.post("/api/v1/scenarios/non-existent-scenario-999/run")
    assert resp.status_code == 404


# -------------------------------------------------------------
# Tests 12 - 15: Web3 Verification, Latest Threats & STIX Export
# -------------------------------------------------------------
def test_web3_verify_endpoint_valid_and_tampered():
    """POST /api/v1/web3/verify correctly distinguishes authentic vs tampered reports."""
    # First, run a scan to generate a committed on-chain record
    scan_resp = client.post("/api/v1/scan/message", json={"message": "Urgent alert: SBI KYC expired!"})
    scan_data = scan_resp.json()
    report_hash = scan_data["web3_commitment"]["report_hash"]

    # Verify without payload (check existence on-chain)
    verify_resp = client.post("/api/v1/web3/verify", json={"report_hash": report_hash})
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["is_valid"] is True
    assert v_data["tamper_detected"] is False

    # Verify with tampered payload -> tamper_detected=True
    tampered_payload = {"fake_key": "hacked"}
    tamper_resp = client.post("/api/v1/web3/verify", json={"report_hash": report_hash, "payload": tampered_payload})
    t_data = tamper_resp.json()
    assert t_data["is_valid"] is False
    assert t_data["tamper_detected"] is True


def test_get_latest_web3_threats():
    """GET /api/v1/web3/latest returns the list of decentralized records."""
    resp = client.get("/api/v1/web3/latest?limit=5")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


def test_export_stix_threat_indicators():
    """GET /api/v1/threats/stix returns valid STIX 2.1 JSON bundle."""
    resp = client.get("/api/v1/threats/stix")
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "bundle"
    assert "objects" in data
    assert isinstance(data["objects"], list)


def test_scan_empty_input_rejected_by_validation():
    """POST /api/v1/scan with whitespace is rejected by Pydantic validation (422)."""
    resp = client.post("/api/v1/scan", json={"target": "   "})
    assert resp.status_code == 422


# -------------------------------------------------------------
# Tests 16 - 20: Community Incidents, Voting & Health Aliases
# -------------------------------------------------------------
def test_health_check_endpoint():
    """GET /health returns online status and operational capabilities."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["online"] is True
    assert data["status"] == "OPERATIONAL"
    assert data["version"] == "1.0.0"


def test_scan_endpoint_accepts_url_field():
    """POST /api/v1/scan accepts {'url': '...'} sent by frontend."""
    resp = client.post("/api/v1/scan", json={"url": "https://python.org"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["target"] == "https://python.org"
    assert data["is_safe"] is True


def test_get_community_incidents():
    """GET /api/v1/incidents returns community reports with victim context and votes."""
    resp = client.get("/api/v1/incidents")
    assert resp.status_code == 200
    incidents = resp.json()
    assert isinstance(incidents, list)
    assert len(incidents) >= 4

    first = incidents[0]
    assert "id" in first
    assert "target" in first
    assert "user_experience" in first
    assert "victim_status" in first
    assert "fake_votes" in first
    assert "legit_votes" in first
    assert "countdown_hours_remaining" in first


def test_create_and_vote_community_incident():
    """POST /api/v1/incidents reports incident, POST /vote increments vote count."""
    payload = {
        "target": "https://fake-lottery-gift.xyz",
        "category": "Gift Card Scam",
        "reporter": "tester@test.com",
        "user_experience": "Claimed I won an iPhone, demanded 500 processing fee via UPI.",
        "victim_status": "Blocked in Time",
        "initial_vote": "fake",
    }
    create_resp = client.post("/api/v1/incidents", json=payload)
    assert create_resp.status_code == 201
    created = create_resp.json()
    inc_id = created["id"]
    initial_fake = created["fake_votes"]

    # Vote "fake"
    vote_resp = client.post(f"/api/v1/incidents/{inc_id}/vote", json={"vote": "fake"})
    assert vote_resp.status_code == 200
    updated = vote_resp.json()
    assert updated["fake_votes"] == initial_fake + 1

    # Vote "legit"
    vote_legit_resp = client.post(f"/api/v1/incidents/{inc_id}/vote", json={"vote": "legit"})
    assert vote_legit_resp.status_code == 200
    updated_legit = vote_legit_resp.json()
    assert updated_legit["legit_votes"] == 1


def test_vote_invalid_vote_type_rejected():
    """POST /api/v1/incidents/{id}/vote with invalid vote returns 400."""
    resp = client.post("/api/v1/incidents/inc-001/vote", json={"vote": "maybe"})
    assert resp.status_code == 400
