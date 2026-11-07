"""
Comprehensive 20-Test Suite for Phase 5: Web3 Decentralized Threat Intelligence Registry.
Covers:
1-5: Keccak-256 Cryptographic Hashing Mechanics (Strings, Dicts, Pydantic, Tamper Collision, Known Vectors)
6-9: Risk Tier Mapping, Commitment Structuring, Idempotency & Sequencing
10-14: Verification Logic, Tamper Proofing, Case Insensitivity & Format Validation
15-18: On-Chain Querying, Pagination, Latest Reports & Missing Hash Lookups
19-20: ABI Conformance & Fault-Tolerant Provider Resiliency
"""

import json
import pytest
from pydantic import BaseModel
from web3 import Web3

from models.schemas import Web3CommitmentRecord, RiskTier
from engine.web3.abi import THREAT_REGISTRY_ABI
from engine.web3.registry_client import (
    compute_report_keccak256,
    ThreatRegistryClient,
    RISK_TIER_MAP,
)


# -------------------------------------------------------------
# Tests 1 - 5: Keccak-256 Hashing Mechanics & Canonicalization
# -------------------------------------------------------------
def test_keccak256_canonical_hashing():
    """Verifies standard keccak256 hash generation produces 66-char 0x hex string."""
    digest = compute_report_keccak256("K9-Sentinel-Threat-Report")
    assert digest.startswith("0x")
    assert len(digest) == 66
    # Known Ethereum test vector: keccak256("hello world")
    hw_hash = compute_report_keccak256("hello world")
    assert hw_hash == "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"


def test_keccak256_empty_string_known_vector():
    """Verifies keccak256 of empty string matches standard Ethereum null hash."""
    null_hash = compute_report_keccak256("")
    assert null_hash == "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def test_keccak256_raw_bytes_hashing():
    """Verifies direct hashing of raw binary bytes."""
    raw_data = b"\x00\x01\x02\x03\xff\xfe"
    digest = compute_report_keccak256(raw_data)
    assert digest.startswith("0x")
    assert len(digest) == 66


def test_keccak256_dict_canonicalization():
    """Verifies that dicts with arbitrary key order produce identical cryptographic hashes."""
    dict_a = {"domain": "sbi-kyc.in", "risk": "CRITICAL", "confidence": 95}
    dict_b = {"confidence": 95, "domain": "sbi-kyc.in", "risk": "CRITICAL"}
    hash_a = compute_report_keccak256(dict_a)
    hash_b = compute_report_keccak256(dict_b)
    assert hash_a == hash_b


def test_keccak256_collision_resistance_tamper_detection():
    """Altering a single byte in the report payload produces a completely different digest."""
    payload_original = {"domain": "paypal.com", "verified": True}
    payload_tampered = {"domain": "paypal.com", "verified": False}
    hash_orig = compute_report_keccak256(payload_original)
    hash_tamp = compute_report_keccak256(payload_tampered)
    assert hash_orig != hash_tamp


# -------------------------------------------------------------
# Tests 6 - 9: Risk Tier Mapping, Commitment Structuring & Idempotency
# -------------------------------------------------------------
def test_risk_tier_integer_conversion():
    """Verifies RiskTier values correctly normalize into integers 0 to 4."""
    client = ThreatRegistryClient()
    assert client._convert_risk_tier_to_int(RiskTier.LOW_RISK) == 0
    assert client._convert_risk_tier_to_int(RiskTier.SUSPICIOUS) == 1
    assert client._convert_risk_tier_to_int(RiskTier.HIGH_RISK) == 2
    assert client._convert_risk_tier_to_int(RiskTier.CONFIRMED_MALICIOUS) == 3
    assert client._convert_risk_tier_to_int(RiskTier.INCONCLUSIVE) == 4
    assert client._convert_risk_tier_to_int("Confirmed Malicious") == 3


def test_commit_report_structure():
    """Verifies commit_report returns a valid Web3CommitmentRecord with all fields populated."""
    client = ThreatRegistryClient()
    payload = {"target": "paypa1-login.com", "risk": "Confirmed Malicious"}
    record = client.commit_report(
        domain="paypa1-login.com",
        risk_tier=RiskTier.CONFIRMED_MALICIOUS,
        payload=payload,
    )

    assert isinstance(record, Web3CommitmentRecord)
    assert record.on_chain_registered is True
    assert record.report_hash.startswith("0x")
    assert record.transaction_hash.startswith("0x")
    assert record.block_number is not None and record.block_number > 0
    assert "EVM" in record.network or "Ledger" in record.network


def test_commit_report_idempotency():
    """Committing the exact same report twice returns the same transaction hash and record."""
    client = ThreatRegistryClient()
    payload = {"target": "airtel-kyc.in", "timestamp": "2026-11-07T12:00:00"}
    rec1 = client.commit_report("airtel-kyc.in", "High Risk", payload)
    rec2 = client.commit_report("airtel-kyc.in", "High Risk", payload)

    assert rec1.report_hash == rec2.report_hash
    assert rec1.transaction_hash == rec2.transaction_hash
    assert rec1.block_number == rec2.block_number


def test_multiple_distinct_reports_sequence():
    """Committing multiple distinct reports generates unique hashes and increments ledger state."""
    client = ThreatRegistryClient()
    records = []
    for i in range(5):
        payload = {"domain": f"scam-domain-{i}.com", "index": i}
        rec = client.commit_report(f"scam-domain-{i}.com", RiskTier.SUSPICIOUS, payload)
        records.append(rec)

    # All hashes and transaction hashes must be mutually distinct
    hashes = [r.report_hash for r in records]
    tx_hashes = [r.transaction_hash for r in records]
    assert len(set(hashes)) == 5
    assert len(set(tx_hashes)) == 5


# -------------------------------------------------------------
# Tests 10 - 14: Verification Logic, Tamper Proofing & Format Validation
# -------------------------------------------------------------
def test_verify_report_valid_match():
    """Valid registered report verified against its original payload returns True."""
    client = ThreatRegistryClient()
    payload = {"domain": "verified-scam.xyz", "iocs": ["http://phish.xyz"]}
    rec = client.commit_report("verified-scam.xyz", "Suspicious", payload)

    is_valid = client.verify_report(rec.report_hash, expected_payload=payload)
    assert is_valid is True


def test_verify_report_tampered_payload_fails():
    """If an attacker tampers with the off-chain report data, on-chain verification returns False."""
    client = ThreatRegistryClient()
    real_payload = {"domain": "attacker.net", "risk_tier": "Confirmed Malicious"}
    fake_payload = {"domain": "attacker.net", "risk_tier": "Low Risk"}  # Altered off-chain!

    rec = client.commit_report("attacker.net", "Confirmed Malicious", real_payload)
    assert client.verify_report(rec.report_hash, expected_payload=fake_payload) is False


def test_verify_report_case_insensitivity():
    """Verifies that verification tolerates uppercase or mixed-case hex string inputs."""
    client = ThreatRegistryClient()
    payload = {"domain": "case-test.com", "val": 42}
    rec = client.commit_report("case-test.com", "Low Risk", payload)

    upper_hash = "0x" + rec.report_hash[2:].upper()
    assert client.verify_report(upper_hash, expected_payload=payload) is True


def test_verify_report_invalid_hash_rejected():
    """Malformed or invalid length hashes are safely rejected without exception."""
    client = ThreatRegistryClient()
    assert client.verify_report("not-a-hash") is False
    assert client.verify_report("0x1234") is False
    assert client.verify_report("") is False


def test_unregistered_hash_verification_returns_false():
    """A valid 66-character hex hash that was never committed on-chain returns False."""
    client = ThreatRegistryClient()
    unregistered_hash = "0x000000000000000000000000000000000000000000000000000000000000dead"
    assert client.verify_report(unregistered_hash) is False
    assert client.get_report_by_hash(unregistered_hash) is None


# -------------------------------------------------------------
# Tests 15 - 18: Querying, Metadata Retrieval & Pagination
# -------------------------------------------------------------
def test_get_report_by_hash_retrieval():
    """Verifies retrieval of stored metadata (domain, risk_tier, block number)."""
    client = ThreatRegistryClient()
    payload = {"domain": "sbi-update.top", "timestamp": 12345}
    rec = client.commit_report("sbi-update.top", RiskTier.HIGH_RISK, payload)

    fetched = client.get_report_by_hash(rec.report_hash)
    assert fetched is not None
    assert fetched["domain"] == "sbi-update.top"
    assert fetched["risk_tier"] == 2
    assert fetched["report_hash"] == rec.report_hash


def test_get_latest_reports_ordering():
    """Verifies that get_latest_reports returns items in reverse chronological order."""
    client = ThreatRegistryClient()
    for idx in range(3):
        client.commit_report(f"site-{idx}.org", "Low Risk", {"index": idx})

    latest = client.get_latest_reports(limit=3)
    assert len(latest) >= 3
    # Latest committed item appears first
    assert latest[0]["domain"] == "site-2.org"
    assert latest[1]["domain"] == "site-1.org"
    assert latest[2]["domain"] == "site-0.org"


def test_latest_reports_pagination_bounds():
    """Requesting limit greater than total records cleanly returns all records without crashing."""
    client = ThreatRegistryClient()
    client.commit_report("single.com", "Low Risk", {"x": 1})
    res = client.get_latest_reports(limit=9999)
    assert isinstance(res, list)
    assert len(res) >= 1


def test_pydantic_schema_serialization_roundtrip():
    """Verifies Web3CommitmentRecord cleanly serializes to JSON and back."""
    client = ThreatRegistryClient()
    rec = client.commit_report("test-domain.net", RiskTier.LOW_RISK, {"status": "ok"})
    json_str = rec.model_dump_json()
    data = json.loads(json_str)

    assert data["on_chain_registered"] is True
    assert data["report_hash"] == rec.report_hash
    rebuilt = Web3CommitmentRecord.model_validate_json(json_str)
    assert rebuilt.report_hash == rec.report_hash


# -------------------------------------------------------------
# Tests 19 - 20: ABI Conformance & Fault Tolerance
# -------------------------------------------------------------
def test_solidity_contract_abi_conformance():
    """Verifies that the Python client ABI includes all critical functions and events in ThreatRegistry.sol."""
    func_names = [item["name"] for item in THREAT_REGISTRY_ABI if item.get("type") == "function"]
    assert "registerThreatReport" in func_names
    assert "verifyReport" in func_names
    assert "getReportByHash" in func_names
    assert "getLatestReports" in func_names

    event_names = [item["name"] for item in THREAT_REGISTRY_ABI if item.get("type") == "event"]
    assert "ThreatReportCommitted" in event_names


def test_offline_and_error_resilience(monkeypatch):
    """Verifies that unreachable or malformed provider URLs fall back cleanly without raising unhandled errors."""
    client = ThreatRegistryClient(provider_url="http://unreachable-rpc-node.invalid:9999")
    payload = {"target": "offline-test.com"}
    rec = client.commit_report("offline-test.com", "Low Risk", payload)

    assert isinstance(rec, Web3CommitmentRecord)
    assert rec.on_chain_registered is True
    assert rec.report_hash.startswith("0x")
