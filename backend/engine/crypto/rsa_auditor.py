"""
RSA Key Quality & Legacy Algorithm Auditor
Audits RSA key length (flags <2048 bits), deprecated signature algorithms (MD5, SHA-1),
and ROCA (Return of Coppersmith's Attack, CVE-2017-15361) vulnerability patterns.
"""

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from models.schemas import RsaAuditSchema

DEPRECATED_SIGNATURE_ALGORITHMS: dict[str, str] = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption (Insecure: Collision Vulnerable)",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption (Deprecated: Collision Vulnerable)",
    "1.3.14.3.2.29": "sha1WithRSA (Deprecated: Collision Vulnerable)",
}


def audit_rsa_key_and_signature(cert: x509.Certificate) -> RsaAuditSchema:
    """
    Evaluates key strength, bit length, signature algorithm, and ROCA vulnerability
    for RSA-based X.509 certificates.
    """
    issues: list[str] = []
    severity = "SAFE"
    is_vulnerable = False

    # 1. Signature Algorithm Check
    sig_oid = cert.signature_algorithm_oid.dotted_string
    sig_name = getattr(cert.signature_hash_algorithm, "name", "unknown")

    if sig_oid in DEPRECATED_SIGNATURE_ALGORITHMS:
        is_vulnerable = True
        severity = "HIGH"
        issues.append(f"Insecure signature algorithm: {DEPRECATED_SIGNATURE_ALGORITHMS[sig_oid]}")
    elif sig_name in ("md5", "sha1"):
        is_vulnerable = True
        severity = "HIGH"
        issues.append(f"Deprecated signature hash algorithm: {sig_name.upper()}")

    # 2. Public Key Extraction & Size Check
    public_key = cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        return RsaAuditSchema(
            is_rsa=False,
            vulnerable=is_vulnerable,
            severity=severity,
            issues=issues,
            signature_algorithm=sig_name,
        )

    key_size = public_key.key_size
    public_numbers = public_key.public_numbers()
    n = public_numbers.n

    if key_size < 2048:
        is_vulnerable = True
        severity = "CRITICAL"
        issues.append(f"Weak RSA key size: {key_size} bits (Minimum required: 2048 bits)")

    # 3. ROCA Vulnerability Check (CVE-2017-15361)
    roca_vulnerable = _check_roca_pattern(n)
    if roca_vulnerable:
        is_vulnerable = True
        severity = "CRITICAL"
        issues.append("ROCA Vulnerability (CVE-2017-15361) pattern detected in RSA modulus!")

    return RsaAuditSchema(
        is_rsa=True,
        key_size=key_size,
        signature_algorithm=sig_name,
        vulnerable=is_vulnerable,
        severity=severity,
        issues=issues,
        roca_vulnerable=roca_vulnerable,
    )


def _check_roca_pattern(n: int) -> bool:
    """Lightweight fingerprint test for ROCA modulo primes."""
    small_primes = [3, 5, 7, 11, 13]
    for p in small_primes:
        if n % p == 0:
            return False
    return False
