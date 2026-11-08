"""
Pydantic Data Contracts & Schemas for K9-Sentinel
Defines typed request/response identities, validation rules, and the 5 standardized
risk classification tiers mandated by the Hack Matrix 2026 problem statement.
"""

from enum import Enum
from typing import Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator


# ---------------------------------------------------------------------
# Standardized Risk Classification Tiers (Mandated by Section 6 of Guidelines)
# ---------------------------------------------------------------------
class RiskTier(str, Enum):
    LOW_RISK = "Low Risk"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"
    CONFIRMED_MALICIOUS = "Confirmed Malicious"
    INCONCLUSIVE = "Inconclusive"


class InputType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    MESSAGE = "message"  # SMS, Email, WhatsApp text
    TEXT_MESSAGE = "message"
    PEM_CERT = "pem_cert"
    RAW_PEM_CERT = "pem_cert"
    QR_CODE = "qr_code"


# ---------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------
class ScanRequest(BaseModel):
    target: Optional[str] = Field(None, max_length=4096, description="Target URL, domain, or raw SMS/email message text")
    url: Optional[str] = Field(None, max_length=4096, description="Alias for target when scanning web URLs")
    input_type: InputType = Field(default=InputType.URL, description="Type of input: url, domain, or message")

    @model_validator(mode="before")
    @classmethod
    def normalize_target_and_url(cls, data: Any) -> Any:
        if isinstance(data, dict):
            raw_target = data.get("target") or data.get("url")
            if not raw_target or not str(raw_target).strip():
                raise ValueError("Target input cannot be empty or only whitespace")
            data["target"] = str(raw_target).strip()
            data["url"] = data["target"]
        elif isinstance(data, str):
            cleaned = data.strip()
            if not cleaned:
                raise ValueError("Target input cannot be empty or only whitespace")
            return {"target": cleaned, "url": cleaned, "input_type": InputType.URL}
        return data


class CommunityIncident(BaseModel):
    id: str
    target: str
    domain: str
    category: str
    reporter: str
    timestamp: str
    user_experience: str
    victim_status: str = "Blocked in Time"
    fake_votes: int = 0
    legit_votes: int = 0
    consensus_status: str = "Active Verification"
    countdown_hours_remaining: int = 24
    stix_bundle: Optional[dict[str, Any]] = None


class CreateIncidentRequest(BaseModel):
    target: str = Field(..., min_length=1)
    category: str = Field(default="Unclassified Phishing")
    reporter: Optional[str] = "Anonymous Reporter"
    user_experience: str = Field(..., min_length=5, description="Description of user experience / problem encountered")
    victim_status: str = Field(default="Blocked in Time")
    initial_vote: str = Field(default="fake")


class VoteIncidentRequest(BaseModel):
    vote: str = Field(..., description="'fake' (Yes, it's fake) or 'legit' (No, it's not fake)")


# ---------------------------------------------------------------------
# Phase 1: Cryptographic Trust & Certificate Schemas
# ---------------------------------------------------------------------
class EmudhraAuditSchema(BaseModel):
    vulnerable: bool
    severity: str = "SAFE"
    cve_issue: Optional[str] = None
    curve: Optional[str] = None
    recovered_scalar_d: Optional[int] = None
    discovery_method: Optional[str] = None
    fingerprint: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    key_type: Optional[str] = None
    error: Optional[str] = None


class RsaAuditSchema(BaseModel):
    is_rsa: bool
    key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None
    vulnerable: bool = False
    severity: str = "SAFE"
    issues: list[str] = Field(default_factory=list)
    roca_vulnerable: bool = False


class TlsChainSchema(BaseModel):
    connected: bool
    subject: Optional[str] = None
    issuer: Optional[str] = None
    sans: list[str] = Field(default_factory=list)
    is_self_signed: bool = False
    is_expired: bool = False
    is_not_yet_valid: bool = False
    days_until_expiry: Optional[int] = None
    hostname_matches: bool = False
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    error: Optional[str] = None


class CtLogSchema(BaseModel):
    available: bool = False
    records_count: int = 0
    recent_sample_count: int = 0
    issuers_seen: list[str] = Field(default_factory=list)
    reason: Optional[str] = None


class CryptoInspectionReport(BaseModel):
    tls_chain: TlsChainSchema
    emudhra_audit: EmudhraAuditSchema
    rsa_audit: RsaAuditSchema
    ct_logs: CtLogSchema


# ---------------------------------------------------------------------
# Phase 2: Threat & Impersonation Heuristics Schemas
# ---------------------------------------------------------------------
class DomainThreatSchema(BaseModel):
    hostname: str
    domain_name: str
    is_shortener: bool = False
    is_homograph: bool = False
    decoded_punycode: Optional[str] = None
    is_typosquatted: bool = False
    impersonated_brand: Optional[str] = None
    brand_owner: Optional[str] = None
    levenshtein_distance: Optional[int] = None
    deceptive_tokens: list[str] = Field(default_factory=list)
    entropy: float = 0.0
    high_entropy_flag: bool = False
    threat_detected: bool = False
    severity: str = "SAFE"


class DomHarvestingSchema(BaseModel):
    forms_count: int = 0
    has_password_field: bool = False
    sensitive_inputs_found: list[str] = Field(default_factory=list)
    cross_origin_submission: bool = False
    suspicious_form_actions: list[str] = Field(default_factory=list)
    obfuscated_js: bool = False
    obfuscation_indicators: list[str] = Field(default_factory=list)
    hidden_iframes: bool = False
    harvesting_detected: bool = False
    severity: str = "SAFE"


class UrgencyNlpSchema(BaseModel):
    urgency_score: int = Field(ge=0, le=100)
    detected_categories: list[str] = Field(default_factory=list)
    matched_phrases: list[str] = Field(default_factory=list)
    urgency_keywords: list[str] = Field(default_factory=list)
    is_coercive: bool = False
    severity: str = "SAFE"


class ThreatHeuristicsReport(BaseModel):
    domain_threats: Optional[DomainThreatSchema] = None
    dom_harvesting: Optional[DomHarvestingSchema] = None
    urgency_nlp: Optional[UrgencyNlpSchema] = None


# ---------------------------------------------------------------------
# Phase 3: Web Security Posture Schemas
# ---------------------------------------------------------------------
class HeaderFinding(BaseModel):
    header: str
    status: str  # "PASS" or "FAIL"
    value: Optional[str] = None
    impact: str
    remediation: Optional[str] = None


class HeaderPostureSchema(BaseModel):
    posture_score: int = Field(ge=0, le=100)
    grade: str  # "A+", "A", "B", "C", "D", "F"
    passed_headers_count: int
    failed_headers_count: int
    findings: list[HeaderFinding] = Field(default_factory=list)


class ExposedLeakFinding(BaseModel):
    name: str
    path: str
    url: str
    severity: str
    impact: str
    status_code: int


class ExposedSecretsSchema(BaseModel):
    probed: bool
    reason: Optional[str] = None
    leaks_count: int = 0
    has_critical_leaks: bool = False
    leaks: list[ExposedLeakFinding] = Field(default_factory=list)


class WebPostureReport(BaseModel):
    header_posture: HeaderPostureSchema
    exposed_secrets: ExposedSecretsSchema


# ---------------------------------------------------------------------
# Phase 4: AI Threat Briefing Schemas (Groq / LangChain)
# ---------------------------------------------------------------------
class MitreTechnique(BaseModel):
    id: str = Field(description="MITRE ATT&CK technique ID e.g. T1566.002")
    name: str = Field(description="Technique name e.g. Phishing: Spearphishing Link")
    tactic: Optional[str] = None
    description: Optional[str] = None


class AIBriefingReport(BaseModel):
    executive_summary: str
    threat_category: str
    targeted_entity: str
    psychological_triggers: list[str] = Field(default_factory=list)
    mitre_attack_techniques: list[MitreTechnique] = Field(default_factory=list)
    extracted_indicators: list[str] = Field(default_factory=list)
    analyst_recommendation: str
    confidence_score: int = Field(ge=0, le=100)
    ai_engine: str = "Groq Llama 3.3 70B"
    offline_mode: bool = False


# ---------------------------------------------------------------------
# Phase 5: Web3 On-Chain Threat Registry Schemas
# ---------------------------------------------------------------------
class Web3CommitmentRecord(BaseModel):
    report_hash: str = Field(..., description="Keccak-256 / SHA-256 cryptographic digest of the threat report")
    on_chain_registered: bool = False
    contract_address: Optional[str] = None
    transaction_hash: Optional[str] = None
    block_number: Optional[int] = None
    network: str = "Local EVM / Ethereum Testnet"
    verification_url: Optional[str] = None


# ---------------------------------------------------------------------
# Phase 6: Threat Intelligence & Campaign Correlation Schemas
# ---------------------------------------------------------------------
class ThreatFeedFinding(BaseModel):
    source: str = "abuse.ch URLhaus"
    url: str
    url_status: str = "online"  # online, offline, unknown
    threat_type: str = "malware_download"
    tags: list[str] = Field(default_factory=list)
    date_added: Optional[str] = None
    reporter: Optional[str] = None


class ThreatIntelSchema(BaseModel):
    blacklisted: bool = False
    source: str = "URLhaus / Open Threat Intelligence"
    query_target: str
    matches_count: int = 0
    findings: list[ThreatFeedFinding] = Field(default_factory=list)
    offline_fallback: bool = False


class CorrelatedCampaign(BaseModel):
    campaign_name: str
    confidence: int = Field(ge=0, le=100)
    cluster_pattern: str
    shared_indicators: list[str] = Field(default_factory=list)
    associated_mitre: list[str] = Field(default_factory=list)


class ThreatCorrelationReport(BaseModel):
    has_campaign_match: bool = False
    total_correlated_campaigns: int = 0
    primary_campaign: Optional[str] = None
    campaigns: list[CorrelatedCampaign] = Field(default_factory=list)
    correlation_notes: Optional[str] = None


# ---------------------------------------------------------------------
# Advanced Extension: QR Code & UPI Payment Scams
# ---------------------------------------------------------------------
class UpiPaymentDetails(BaseModel):
    is_upi: bool = False
    payee_vpa: Optional[str] = None
    payee_name: Optional[str] = None
    amount: Optional[str] = None
    currency: Optional[str] = "INR"
    transaction_note: Optional[str] = None
    is_suspicious_vpa: bool = False
    suspicious_reasons: list[str] = Field(default_factory=list)


class QrInspectionSchema(BaseModel):
    decoded: bool = False
    raw_payload: str
    payload_type: str = "unknown"  # "upi_payment", "url", "plain_text"
    upi_details: Optional[UpiPaymentDetails] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------
# Master Unified Scan Response (Full Contract)
# ---------------------------------------------------------------------
class MasterScanResponse(BaseModel):
    target: str
    input_type: InputType
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    risk_tier: RiskTier
    threat_score: int = Field(ge=0, le=100, description="Overall Composite Risk Score (0 = Completely Clean, 100 = Confirmed Malicious)")
    is_safe: bool
    summary: str
    
    # Detailed sub-inspections
    crypto_report: Optional[CryptoInspectionReport] = None
    threat_report: Optional[ThreatHeuristicsReport] = None
    posture_report: Optional[WebPostureReport] = None
    ai_briefing: Optional[AIBriefingReport] = None
    web3_commitment: Optional[Web3CommitmentRecord] = None
    threat_intel: Optional[ThreatIntelSchema] = None
    correlation_report: Optional[ThreatCorrelationReport] = None
    qr_inspection: Optional[QrInspectionSchema] = None
    
    # Evidence & Recommended Precautions (Mandated by Section 4 of Guidelines)
    identified_indicators: list[str] = Field(default_factory=list)
    recommended_precautions: list[str] = Field(default_factory=list)
