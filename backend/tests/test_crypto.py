"""
Comprehensive 20-Test Suite for Cryptographic Trust Auditor & eMudhra Incident (Mozilla Bug 2083449).
Covers small-scalar discrete log recovery, multiple curves, boundary conditions, OneCRL blocklist,
RSA handling, and raw PEM serialization.
"""

import datetime
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from engine.crypto.emudhra_auditor import (
    audit_emudhra_weak_ecc_key,
    audit_pem_certificate,
    KNOWN_REVOKED_EMUDHRA_FINGERPRINTS,
)


def make_cert(private_key, name_suffix="Test", hash_alg=hashes.SHA256()) -> x509.Certificate:
    """Helper to generate an X.509 certificate for a given private key."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"K9-Sentinel-Cert-{name_suffix}"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(private_key, hash_alg)
    )


# -------------------------------------------------------------
# Tests 1 - 7: Parameterized Real-World & Edge-Case Small Scalars (P-384)
# -------------------------------------------------------------
@pytest.mark.parametrize("scalar", [1, 2, 4, 56, 66, 115, 237])
def test_emudhra_p384_known_and_edge_scalars(scalar):
    """Verifies Wayne's discrete log recovery across all Bug 2083449 integers and lower bounds."""
    priv = ec.derive_private_key(scalar, ec.SECP384R1())
    cert = make_cert(priv, name_suffix=f"scalar-{scalar}", hash_alg=hashes.SHA384())
    result = audit_emudhra_weak_ecc_key(cert, max_scalar=500)

    assert result.vulnerable is True
    assert result.severity == "CRITICAL"
    assert result.recovered_scalar_d == scalar
    assert result.curve == "secp384r1"


# -------------------------------------------------------------
# Tests 8 - 10: Parameterized Small Scalars on NIST P-256 Curve
# -------------------------------------------------------------
@pytest.mark.parametrize("scalar", [3, 42, 255])
def test_p256_curve_small_scalars(scalar):
    """Verifies that NIST P-256 curves are also audited for low-entropy generation."""
    priv = ec.derive_private_key(scalar, ec.SECP256R1())
    cert = make_cert(priv, name_suffix=f"p256-{scalar}")
    result = audit_emudhra_weak_ecc_key(cert, max_scalar=300)

    assert result.vulnerable is True
    assert result.recovered_scalar_d == scalar
    assert result.curve == "secp256r1"


# -------------------------------------------------------------
# Test 11: secp256k1 Curve Support
# -------------------------------------------------------------
def test_secp256k1_small_scalar():
    """Verifies secp256k1 (Web3 / Fintech curve) small scalar recovery."""
    priv = ec.derive_private_key(7, ec.SECP256K1())
    cert = make_cert(priv, name_suffix="secp256k1-7")
    result = audit_emudhra_weak_ecc_key(cert, max_scalar=50)

    assert result.vulnerable is True
    assert result.recovered_scalar_d == 7
    assert result.curve == "secp256k1"


# -------------------------------------------------------------
# Test 12: Upper Boundary Check (Exact Threshold match d=1000)
# -------------------------------------------------------------
def test_scalar_exact_upper_threshold():
    """Tests that the loop cleanly identifies scalars at the exact boundary of max_scalar=1000."""
    priv = ec.derive_private_key(1000, ec.SECP256R1())
    cert = make_cert(priv, name_suffix="threshold-1000")
    result = audit_emudhra_weak_ecc_key(cert, max_scalar=1000)

    assert result.vulnerable is True
    assert result.recovered_scalar_d == 1000


# -------------------------------------------------------------
# Test 13: Scalar Beyond Tested Range (d=1001 with max_scalar=1000)
# -------------------------------------------------------------
def test_scalar_beyond_tested_range():
    """A scalar outside the candidate range must return SAFE without false flags."""
    priv = ec.derive_private_key(1001, ec.SECP256R1())
    cert = make_cert(priv, name_suffix="beyond-range")
    result = audit_emudhra_weak_ecc_key(cert, max_scalar=1000)

    assert result.vulnerable is False
    assert result.status == "SAFE"


# -------------------------------------------------------------
# Tests 14 - 15: True High-Entropy Cryptographic Keys (P-256 and P-384)
# -------------------------------------------------------------
def test_high_entropy_p256_safe():
    """A standard randomly generated P-256 key must safely pass."""
    priv = ec.generate_private_key(ec.SECP256R1())
    cert = make_cert(priv, name_suffix="high-entropy-p256")
    result = audit_emudhra_weak_ecc_key(cert, max_scalar=1000)

    assert result.vulnerable is False
    assert result.status == "SAFE"


def test_high_entropy_p384_safe():
    """A standard randomly generated P-384 key must safely pass."""
    priv = ec.generate_private_key(ec.SECP384R1())
    cert = make_cert(priv, name_suffix="high-entropy-p384", hash_alg=hashes.SHA384())
    result = audit_emudhra_weak_ecc_key(cert, max_scalar=1000)

    assert result.vulnerable is False
    assert result.status == "SAFE"


# -------------------------------------------------------------
# Test 16: RSA Certificate Handling (Non-ECC)
# -------------------------------------------------------------
def test_rsa_certificate_safely_distinguished():
    """RSA certificates must be properly distinguished as non-ECC and not trigger ECC attacks."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = make_cert(priv, name_suffix="rsa-2048")
    result = audit_emudhra_weak_ecc_key(cert)

    assert result.vulnerable is False
    assert result.key_type == "RSA/Non-ECC"
    assert result.status == "SAFE_FROM_ECC_SCALAR_ATTACK"


# -------------------------------------------------------------
# Tests 17 - 18: Mozilla OneCRL Blocklist Fingerprint Matching
# -------------------------------------------------------------
def test_onecrl_mock_fingerprint_matching(monkeypatch):
    """Asserts that certificates matching Mozilla OneCRL SHA-256 fingerprints are immediately blocked."""
    priv = ec.generate_private_key(ec.SECP384R1())
    cert = make_cert(priv, name_suffix="onecrl-target")

    # Mock the known fingerprints to include this certificate's hash
    real_fp = cert.fingerprint(hashes.SHA256()).hex().lower()
    monkeypatch.setattr(
        "engine.crypto.emudhra_auditor.KNOWN_REVOKED_EMUDHRA_FINGERPRINTS",
        {real_fp: "Simulated Revoked eMudhra Intermediate Sub-CA"}
    )

    result = audit_emudhra_weak_ecc_key(cert)
    assert result.vulnerable is True
    assert result.severity == "CRITICAL"
    assert result.cve_issue == "Mozilla-Bug-2083449/OneCRL-Revocation"
    assert result.fingerprint == real_fp


def test_onecrl_clean_fingerprint_unaffected():
    """Normal certificates whose fingerprints are not in OneCRL are not falsely flagged."""
    priv = ec.generate_private_key(ec.SECP256R1())
    cert = make_cert(priv, name_suffix="clean-cert")
    result = audit_emudhra_weak_ecc_key(cert)

    assert result.vulnerable is False
    assert result.cve_issue != "Mozilla-Bug-2083449/OneCRL-Revocation"


# -------------------------------------------------------------
# Tests 19 - 20: Raw PEM Parsing Helper & Malformed Byte Handling
# -------------------------------------------------------------
def test_audit_pem_certificate_valid_bytes():
    """Tests the audit_pem_certificate helper with real serialized PEM bytes."""
    priv = ec.derive_private_key(4, ec.SECP384R1())
    cert = make_cert(priv, name_suffix="pem-test", hash_alg=hashes.SHA384())
    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)

    result = audit_pem_certificate(pem_bytes, max_scalar=50)
    assert result.vulnerable is True
    assert result.recovered_scalar_d == 4


def test_audit_pem_certificate_malformed_bytes_no_crash():
    """Malformed garbage bytes must return PARSE_ERROR cleanly without unhandled exception."""
    garbage = b"-----BEGIN CERTIFICATE-----\nNOT_VALID_BASE64_DATA\n-----END CERTIFICATE-----"
    result = audit_pem_certificate(garbage)

    assert result.vulnerable is False
    assert result.status == "PARSE_ERROR"
    assert "Invalid PEM certificate structure" in (result.error or "")


# -------------------------------------------------------------
# Tests 21 - 23: RSA Key Length & Deprecated Signature Algorithms
# -------------------------------------------------------------
from engine.crypto.rsa_auditor import audit_rsa_key_and_signature
from engine.crypto.chain_validator import _parse_certificate_details
from engine.crypto.ct_auditor import query_certificate_transparency_logs


def test_rsa_weak_1024_bit_flagged():
    """1024-bit RSA keys must be flagged as CRITICAL vulnerability."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    cert = make_cert(priv, name_suffix="rsa-1024")
    result = audit_rsa_key_and_signature(cert)

    assert result.is_rsa is True
    assert result.key_size == 1024
    assert result.vulnerable is True
    assert result.severity == "CRITICAL"
    assert any("Weak RSA key size: 1024" in issue for issue in result.issues)


def test_rsa_strong_2048_bit_safe():
    """Standard 2048-bit RSA keys with SHA-256 must pass safely."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = make_cert(priv, name_suffix="rsa-2048-clean", hash_alg=hashes.SHA256())
    result = audit_rsa_key_and_signature(cert)

    assert result.is_rsa is True
    assert result.key_size == 2048
    assert result.vulnerable is False
    assert result.severity == "SAFE"


def test_rsa_deprecated_sha1_signature_flagged():
    """Certificates signed with deprecated SHA-1 must be flagged as HIGH severity."""
    class MockCertWithSHA1:
        class MockOID:
            dotted_string = "1.2.840.113549.1.1.5"
        signature_algorithm_oid = MockOID()
        signature_hash_algorithm = None
        def public_key(self):
            return rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

    mock_cert = MockCertWithSHA1()
    result = audit_rsa_key_and_signature(mock_cert)
    assert result.vulnerable is True
    assert result.severity == "HIGH"
    assert any("sha1WithRSAEncryption" in issue for issue in result.issues)


# -------------------------------------------------------------
# Test 24: Certificate Chain Detail Parsing & SAN Matching
# -------------------------------------------------------------
def test_chain_validator_parsing_logic():
    """Verifies that _parse_certificate_details correctly extracts SANs and validity."""
    priv = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Authority")]))
        .public_key(priv.public_key())
        .serial_number(123456)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("test.example.com"), x509.DNSName("api.example.com")]),
            critical=False,
        )
        .sign(priv, hashes.SHA256())
    )

    parsed = _parse_certificate_details(cert, "test.example.com", ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.3", 128), "TLSv1.3")
    assert parsed.connected is True
    assert parsed.is_expired is False
    assert parsed.hostname_matches is True
    assert "test.example.com" in parsed.sans
    assert "api.example.com" in parsed.sans


# -------------------------------------------------------------
# Test 25: CT Auditor Handles Offline / Timed Out Queries Gracefully
# -------------------------------------------------------------
@pytest.mark.anyio
async def test_ct_auditor_graceful_handling():
    """Ensures CT log auditor fails open gracefully on invalid/non-existent domains without crashing."""
    result = await query_certificate_transparency_logs("this-domain-does-not-exist-at-all-999.invalid", timeout_seconds=1.0)
    assert isinstance(result.available, bool)
    assert result.records_count >= 0

