"""
Master Unified Threat Orchestrator for K9 Sentinel AI
Concurrently executes inspections across all 6 phases:
- Phase 1: Cryptographic Trust & eMudhra Auditor (Mozilla Bug 2083449)
- Phase 2: Impersonation & Phishing Heuristics (Typosquatting, DOM Harvesting, Urgency NLP)
- Phase 3: Web Security Posture Scanner (Headers Scorecard, SSRF-Safe Secrets Probing)
- Phase 4: AI Scam Intent & MITRE ATT&CK Analyst (Groq Llama 3.3 / Deterministic Expert System)
- Phase 5: Web3 Decentralized Threat Intelligence Registry (keccak256 commitment)
- Phase 6: Threat Feed Interrogation (abuse.ch URLhaus & Campaign Correlation)
Computes a composite 0-100 score and assigns one of 5 standardized RiskTiers.
"""

import asyncio
import re
from datetime import datetime, timezone
from typing import Optional
from cryptography import x509

from models.schemas import (
    MasterScanResponse,
    InputType,
    RiskTier,
    CryptoInspectionReport,
    ThreatHeuristicsReport,
    WebPostureReport,
    TlsChainSchema,
    EmudhraAuditSchema,
    RsaAuditSchema,
    CtLogSchema,
    DomainThreatSchema,
    DomHarvestingSchema,
    UrgencyNlpSchema,
    HeaderPostureSchema,
    ExposedSecretsSchema,
    AIBriefingReport,
    Web3CommitmentRecord,
    ThreatIntelSchema,
    ThreatCorrelationReport,
)

from engine.crypto.chain_validator import fetch_and_validate_tls_chain
from engine.crypto.emudhra_auditor import audit_emudhra_weak_ecc_key, audit_pem_certificate
from engine.crypto.rsa_auditor import audit_rsa_key_and_signature
from engine.crypto.ct_auditor import query_certificate_transparency_logs
from engine.threat.homograph_typosquatting import audit_domain_threats
from engine.threat.dom_harvesting import audit_dom_credential_harvesting
from engine.threat.social_engineering_nlp import audit_social_engineering_text
from engine.posture.header_scanner import scan_security_headers
from engine.posture.exposed_secrets import probe_exposed_secrets
from engine.threat.ai_analyst import generate_threat_ai_briefing
from engine.intel.urlhaus import query_urlhaus_threat_intel
from engine.intel.correlator import correlate_threat_campaigns
from engine.web3.registry_client import default_registry_client


def detect_input_type(target: str) -> InputType:
    """Classifies input into URL, DOMAIN, TEXT_MESSAGE, or RAW_PEM_CERT."""
    cleaned = target.strip()
    if "-----BEGIN CERTIFICATE-----" in cleaned:
        return InputType.RAW_PEM_CERT
    if "\n" in cleaned or (len(cleaned.split()) > 3 and not cleaned.startswith(("http://", "https://"))):
        return InputType.TEXT_MESSAGE
    if cleaned.startswith(("http://", "https://")):
        return InputType.URL
    if "/" in cleaned or "." in cleaned:
        return InputType.DOMAIN
    return InputType.TEXT_MESSAGE


def extract_hostname(target: str) -> str:
    """Extracts clean hostname from URL or domain string."""
    return (
        target.replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .split(":")[0]
        .strip()
        .lower()
    )


async def orchestrate_full_scan(
    target: str,
    override_input_type: Optional[InputType] = None,
    mock_cert: Optional[x509.Certificate] = None,
    html_content: Optional[str] = None,
) -> MasterScanResponse:
    """
    Primary pipeline coordinating concurrent inspection across all 6 phases.
    Returns typed MasterScanResponse with composite score, RiskTier, and Web3 commitment.
    """
    input_type = override_input_type or detect_input_type(target)
    hostname = extract_hostname(target) if input_type in (InputType.URL, InputType.DOMAIN) else ""

    # 1. Initialize Sub-Reports
    crypto_report: Optional[CryptoInspectionReport] = None
    threat_report: Optional[ThreatHeuristicsReport] = None
    posture_report: Optional[WebPostureReport] = None
    ai_briefing: Optional[AIBriefingReport] = None
    threat_intel: Optional[ThreatIntelSchema] = None
    correlation_report: Optional[ThreatCorrelationReport] = None

    identified_indicators: list[str] = []
    recommended_precautions: list[str] = []
    threat_score = 0

    # -------------------------------------------------------------
    # Execution Path A: RAW PEM CERTIFICATE
    # -------------------------------------------------------------
    if input_type == InputType.RAW_PEM_CERT:
        emudhra_res = audit_pem_certificate(target.encode("utf-8"))
        rsa_res = RsaAuditSchema(is_rsa=False)
        chain_res = TlsChainSchema(connected=False, subject="PEM Upload")
        ct_res = CtLogSchema(available=False)

        if emudhra_res.vulnerable:
            threat_score = 100
            identified_indicators.append(
                f"CRITICAL: {emudhra_res.cve_issue} - Recovered private key scalar d={emudhra_res.recovered_scalar_d}!"
            )
            recommended_precautions.append("Immediately revoke certificate and purge CA intermediate keys from trust store.")

        crypto_report = CryptoInspectionReport(
            tls_chain=chain_res,
            emudhra_audit=emudhra_res,
            rsa_audit=rsa_res,
            ct_logs=ct_res,
        )

    # -------------------------------------------------------------
    # Execution Path B: TEXT / SMS MESSAGE
    # -------------------------------------------------------------
    elif input_type == InputType.TEXT_MESSAGE:
        # Run NLP, AI Analyst, and Campaign Correlation in parallel
        nlp_res = audit_social_engineering_text(target)
        ai_res = generate_threat_ai_briefing(target, nlp_report=nlp_res)
        corr_res = correlate_threat_campaigns(message_text=target)

        threat_report = ThreatHeuristicsReport(
            urgency_nlp=nlp_res,
        )
        ai_briefing = ai_res
        correlation_report = corr_res

        # Calculate Score from Message Signals
        if nlp_res.urgency_score > 0:
            threat_score += min(50, nlp_res.urgency_score)
            keywords = nlp_res.matched_phrases or nlp_res.urgency_keywords
            identified_indicators.extend([f"URGENCY_LURE: {kw}" for kw in keywords])

        if corr_res.has_campaign_match:
            threat_score += 30
            identified_indicators.append(f"CAMPAIGN_CLUSTER: {corr_res.primary_campaign}")

        if ai_res.threat_category and ai_res.threat_category != "Benign Information":
            threat_score += 35

        if ai_res.mitre_attack_techniques:
            identified_indicators.extend([f"MITRE: {t.id} ({t.name})" for t in ai_res.mitre_attack_techniques])

        recommended_precautions.extend(ai_res.analyst_recommendation.split(". "))

    # -------------------------------------------------------------
    # Execution Path C: URL or DOMAIN
    # -------------------------------------------------------------
    else:
        # Step C1: Concurrently trigger TLS chain, CT logs, headers, secrets, and threat intel
        target_url = target if target.startswith(("http://", "https://")) else f"https://{target}"

        async def _run_tls():
            if mock_cert is not None:
                chain = TlsChainSchema(connected=True, subject="Mock Cert", issuer="Mock CA", hostname_matches=True)
                return chain, mock_cert
            return fetch_and_validate_tls_chain(hostname, timeout_seconds=2.5)

        (chain_schema, raw_cert), ct_schema, header_schema, secrets_schema, intel_schema = await asyncio.gather(
            _run_tls(),
            query_certificate_transparency_logs(hostname, timeout_seconds=2.0),
            scan_security_headers(target_url, timeout_seconds=2.5),
            probe_exposed_secrets(target_url, timeout_seconds=2.0),
            query_urlhaus_threat_intel(target_url, timeout_seconds=2.0),
        )

        # Step C2: Audit Certificate Cryptography
        emudhra_schema = (
            audit_emudhra_weak_ecc_key(raw_cert)
            if raw_cert
            else EmudhraAuditSchema(vulnerable=False, status="NO_CERT_RETURNED")
        )
        rsa_schema = (
            audit_rsa_key_and_signature(raw_cert)
            if raw_cert
            else RsaAuditSchema(is_rsa=False)
        )

        crypto_report = CryptoInspectionReport(
            tls_chain=chain_schema,
            emudhra_audit=emudhra_schema,
            rsa_audit=rsa_schema,
            ct_logs=ct_schema,
        )

        # Step C3: Domain Heuristics & DOM Harvesting
        domain_schema = audit_domain_threats(target_url)
        dom_schema = audit_dom_credential_harvesting(html_content, current_origin=target_url) if html_content else None
        nlp_schema = audit_social_engineering_text(target_url)

        threat_report = ThreatHeuristicsReport(
            domain_threats=domain_schema,
            dom_harvesting=dom_schema,
            urgency_nlp=nlp_schema,
        )

        posture_report = WebPostureReport(
            header_posture=header_schema,
            exposed_secrets=secrets_schema,
        )

        threat_intel = intel_schema
        correlation_report = correlate_threat_campaigns(target_url=target_url)
        ai_briefing = generate_threat_ai_briefing(target_url, domain_report=domain_schema, nlp_report=nlp_schema)

        # ---------------------------------------------------------
        # Compute Weighted Threat Score
        # ---------------------------------------------------------
        # 1. Cryptographic Vulnerability (Weight: 60 - 100)
        if emudhra_schema.vulnerable:
            threat_score = 100
            identified_indicators.append(f"EMUDHRA_EXPLOIT: {emudhra_schema.description}")
            recommended_precautions.append("CRITICAL: Compromised intermediate CA private key detected. Distrust immediately.")

        if rsa_schema.vulnerable:
            threat_score += 40
            identified_indicators.extend([f"RSA_DEFECT: {iss}" for iss in rsa_schema.issues])

        if not chain_schema.hostname_matches and chain_schema.connected:
            threat_score += 35
            identified_indicators.append("TLS_MISMATCH: Certificate SANs do not match queried hostname")

        # 2. Domain & Impersonation Heuristics (Weight: 30 - 50)
        if domain_schema.is_typosquatted:
            threat_score += 45
            identified_indicators.append(f"TYPOSQUAT: Impersonating brand '{domain_schema.impersonated_brand}'")

        if domain_schema.is_homograph:
            threat_score += 40
            identified_indicators.append("HOMOGRAPH: Cyrillic/IDN Punycode character spoofing detected")

        if domain_schema.is_shortener:
            threat_score += 20
            identified_indicators.append("SHORTENER: URL shortener masking true destination")

        # 3. DOM Credential Harvesting (Weight: 45)
        if dom_schema and dom_schema.cross_origin_submission and dom_schema.has_password_field:
            threat_score += 50
            action_dest = dom_schema.suspicious_form_actions[0] if dom_schema.suspicious_form_actions else "external origin"
            identified_indicators.append(f"FORM_EXFILTRATION: Password sent to foreign origin {action_dest}")

        # 4. Threat Intel & Blacklists (Weight: 50)
        if intel_schema.blacklisted:
            threat_score += 50
            identified_indicators.append(f"INTEL_BLACKLIST: Identified in {intel_schema.source}")

        # 5. Security Posture Scorecard (Weight: 10 - 25)
        if header_schema.grade in ("F", "D"):
            threat_score += 15
            identified_indicators.append(f"POOR_POSTURE: Missing critical headers (Grade: {header_schema.grade})")

        if secrets_schema.has_critical_leaks:
            threat_score += 30
            identified_indicators.append(f"EXPOSED_SECRETS: {secrets_schema.leaks_count} sensitive administrative files exposed")

    # -------------------------------------------------------------
    # Final Composite Risk Tier Classification
    # Standard 5 tiers: Low Risk, Suspicious, High Risk, Confirmed Malicious, Inconclusive
    # -------------------------------------------------------------
    final_score = min(100, max(0, threat_score))

    if final_score >= 80:
        risk_tier = RiskTier.CONFIRMED_MALICIOUS
        is_safe = False
        summary = f"CONFIRMED MALICIOUS ({final_score}/100): High-confidence malicious threat confirmed across multiple vectors."
    elif final_score >= 50:
        risk_tier = RiskTier.HIGH_RISK
        is_safe = False
        summary = f"HIGH RISK ({final_score}/100): Multiple deceptive or exploitable security defects identified."
    elif final_score >= 25:
        risk_tier = RiskTier.SUSPICIOUS
        is_safe = False
        summary = f"SUSPICIOUS ({final_score}/100): Elevated risk indicators observed requiring user caution."
    else:
        risk_tier = RiskTier.LOW_RISK
        is_safe = True
        summary = f"LOW RISK ({final_score}/100): Validated benign infrastructure with safe security posture."

    # If Precautions are empty, add baseline safe practices
    if not recommended_precautions:
        if is_safe:
            recommended_precautions.append("Safe to proceed. Standard web browsing precautions apply.")
        else:
            recommended_precautions.append("Do not enter credentials, financial details, or OTPs on this portal.")
            recommended_precautions.append("Verify the organization's verified domain before taking further action.")

    # -------------------------------------------------------------
    # Phase 5: Web3 Decentralized Threat Intelligence Commitment
    # -------------------------------------------------------------
    preliminary_payload = {
        "target": target,
        "risk_tier": risk_tier.value,
        "threat_score": final_score,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "indicators": identified_indicators[:5],
    }

    target_domain = hostname if hostname else (target[:32] if len(target) <= 32 else "message-text-scan")
    web3_record = default_registry_client.commit_report(
        domain=target_domain,
        risk_tier=risk_tier,
        payload=preliminary_payload,
    )

    return MasterScanResponse(
        target=target,
        input_type=input_type,
        timestamp=datetime.now(timezone.utc).isoformat(),
        risk_tier=risk_tier,
        threat_score=final_score,
        is_safe=is_safe,
        summary=summary,
        crypto_report=crypto_report,
        threat_report=threat_report,
        posture_report=posture_report,
        ai_briefing=ai_briefing,
        web3_commitment=web3_record,
        threat_intel=threat_intel,
        correlation_report=correlation_report,
        identified_indicators=identified_indicators,
        recommended_precautions=recommended_precautions,
    )


async def orchestrate_qr_scan(image_input: bytes | str) -> MasterScanResponse:
    """
    Decodes an uploaded QR image (bytes or base64 data URL) and coordinates scanning:
    - If URL: Runs 6-phase unified web inspection.
    - If UPI Payment: Audits VPA legitimacy, prefilled amounts, and psychological coercion.
    - If Text: Evaluates social engineering urgency.
    Commits report on-chain and returns typed MasterScanResponse with qr_inspection details.
    """
    from engine.threat.qr_scanner import decode_qr_image
    qr_res = decode_qr_image(image_input)

    # 1. Failed Decoding
    if not qr_res.decoded:
        return MasterScanResponse(
            target="qr-image-upload",
            input_type=InputType.QR_CODE,
            timestamp=datetime.now(timezone.utc).isoformat(),
            risk_tier=RiskTier.INCONCLUSIVE,
            threat_score=0,
            is_safe=False,
            summary=f"QR DECODING FAILED: {qr_res.error or 'No valid QR symbol found.'}",
            qr_inspection=qr_res,
            identified_indicators=["QR_DECODE_ERROR: Symbol missing or unreadable"],
            recommended_precautions=["Upload a clearer, uncropped image of the QR code."],
        )

    # 2. Embedded Web URL
    if qr_res.payload_type == "url":
        scan_res = await orchestrate_full_scan(qr_res.raw_payload)
        scan_res.input_type = InputType.QR_CODE
        scan_res.qr_inspection = qr_res
        scan_res.identified_indicators.insert(0, f"EMBEDDED_QR_URL: {qr_res.raw_payload}")
        return scan_res

    # 3. Embedded UPI Payment URI
    if qr_res.payload_type == "upi_payment" and qr_res.upi_details:
        upi = qr_res.upi_details
        threat_score = 90 if upi.is_suspicious_vpa else 10
        risk_tier = RiskTier.CONFIRMED_MALICIOUS if upi.is_suspicious_vpa else RiskTier.LOW_RISK
        is_safe = not upi.is_suspicious_vpa

        indicators = [f"PAYEE_VPA: {upi.payee_vpa}", f"PAYEE_NAME: {upi.payee_name or 'Unknown'}"]
        if upi.amount:
            indicators.append(f"PREFILLED_AMOUNT: INR {upi.amount}")
        if upi.transaction_note:
            indicators.append(f"NOTE: {upi.transaction_note}")
        indicators.extend(upi.suspicious_reasons)

        precautions = (
            [
                "CRITICAL: Fraudulent QR detected impersonating utility/banking authority.",
                "Do NOT scan with GPay, PhonePe, or Paytm; doing so will debit your account.",
                "Legitimate institutions never request individual UPI transfers for bill clearing.",
            ]
            if not is_safe
            else ["Verified benign UPI payment endpoint. Confirm payee name before authorizing."]
        )

        summary = (
            f"CONFIRMED FRAUDULENT UPI QR ({threat_score}/100): Payee '{upi.payee_vpa}' deceptively mimics institutional authority."
            if not is_safe
            else f"BENIGN UPI QR ({threat_score}/100): Standard consumer payment parameters."
        )

        # Record on-chain commitment
        commitment_payload = {
            "type": "upi_qr_inspection",
            "vpa": upi.payee_vpa,
            "risk_tier": risk_tier.value,
            "threat_score": threat_score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        web3_rec = default_registry_client.commit_report(
            domain=upi.payee_vpa or "upi-qr",
            risk_tier=risk_tier,
            payload=commitment_payload,
        )

        return MasterScanResponse(
            target=qr_res.raw_payload,
            input_type=InputType.QR_CODE,
            timestamp=datetime.now(timezone.utc).isoformat(),
            risk_tier=risk_tier,
            threat_score=threat_score,
            is_safe=is_safe,
            summary=summary,
            qr_inspection=qr_res,
            web3_commitment=web3_rec,
            identified_indicators=indicators,
            recommended_precautions=precautions,
        )

    # 4. Embedded Plain Text
    text_scan = await orchestrate_full_scan(qr_res.raw_payload, override_input_type=InputType.TEXT_MESSAGE)
    text_scan.input_type = InputType.QR_CODE
    text_scan.qr_inspection = qr_res
    return text_scan
