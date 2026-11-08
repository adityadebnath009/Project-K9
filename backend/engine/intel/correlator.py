"""
Multi-Report Threat Correlation & Cybercrime Campaign Clustering Engine
Cross-references observed threat telemetry against known active threat campaigns
to identify coordinated attacks, infrastructure reuse, and recurring deception playbooks.
"""

from typing import Optional
from models.schemas import ThreatCorrelationReport, CorrelatedCampaign


CAMPAIGN_SIGNATURES = [
    {
        "campaign_name": "Operation BlueKite (Indian Banking KYC Pretexting Campaign)",
        "keywords": ["kyc", "pan", "aadhaar", "netbanking", "deactivated", "unblock", "suspended", "account locked"],
        "target_brands": ["sbi", "hdfc", "icici", "pnb", "axis", "kotak", "bob", "canara", "airtel"],
        "mitre_techniques": ["T1598.002", "T1566.002", "T1204.001"],
        "pattern_description": "Coordinated SMS/WhatsApp phishing campaign targeting Indian retail bank customers using mandatory KYC updates to steal credentials and OTPs.",
        "base_confidence": 85,
    },
    {
        "campaign_name": "Operation VoltCut (State Utility & Electricity Disconnection Scam)",
        "keywords": ["electricity", "power", "bill", "disconnect", "tonight", "power cut", "discom", "officer"],
        "target_brands": ["bescom", "tneb", "mseb", "uppcl", "bses", "dhbvn"],
        "mitre_techniques": ["T1598.002", "T1204.001"],
        "pattern_description": "Social engineering campaign intimidating citizens with immediate nocturnal power cuts to coerce urgent payments into fraudulent UPI accounts.",
        "base_confidence": 90,
    },
    {
        "campaign_name": "Operation QuickLure (Evasive Shortlink Phishing Network)",
        "keywords": ["weurl.co", "bit.ly", "tinyurl", "cutt.ly", "is.gd", "t.co", "rb.gy"],
        "target_brands": ["general_phishing"],
        "mitre_techniques": ["T1584", "T1566.002"],
        "pattern_description": "Adversaries leveraging commercial and ephemeral URL shorteners to mask destination endpoints and bypass static email/SMS gateway filters.",
        "base_confidence": 75,
    },
    {
        "campaign_name": "Operation CryptoDrain (Decentralized Wallet & Airdrop Phishing)",
        "keywords": ["airdrop", "metamask", "phantom", "seed phrase", "claim token", "connect wallet", "drainer"],
        "target_brands": ["ethereum", "solana", "metamask", "phantom", "opensea", "uniswap"],
        "mitre_techniques": ["T1566.002", "T1657"],
        "pattern_description": "Web3 credential harvesting utilizing imitation decentralized app (dApp) interfaces to trigger malicious permit approvals or capture recovery phrases.",
        "base_confidence": 88,
    },
]


def correlate_threat_campaigns(
    target_url: Optional[str] = None,
    message_text: Optional[str] = None,
    extracted_indicators: Optional[list[str]] = None,
) -> ThreatCorrelationReport:
    """
    Correlates target text, URLs, and indicators against known threat campaign signatures.
    Returns a typed ThreatCorrelationReport model.
    """
    combined_corpus = " ".join([
        target_url or "",
        message_text or "",
        " ".join(extracted_indicators or []),
    ]).lower()

    if not combined_corpus.strip():
        return ThreatCorrelationReport(
            has_campaign_match=False,
            total_correlated_campaigns=0,
            primary_campaign=None,
            campaigns=[],
            correlation_notes="No telemetry indicators supplied for cross-campaign correlation.",
        )

    matched_campaigns: list[CorrelatedCampaign] = []

    for sig in CAMPAIGN_SIGNATURES:
        import re
        matched_keywords = [
            kw for kw in sig["keywords"] 
            if re.search(r"\b" + re.escape(kw) + r"\b", combined_corpus)
        ]
        matched_brands = [
            b for b in sig["target_brands"] 
            if re.search(r"\b" + re.escape(b) + r"\b", combined_corpus)
        ]

        # Require at least 2 keyword signals or keyword + brand to prevent spurious false positives
        if len(matched_keywords) >= 2 or (matched_keywords and matched_brands):
            confidence = sig["base_confidence"]
            if matched_brands:
                confidence = min(100, confidence + 10)

            shared_ind = [f"KEYWORD: {k}" for k in matched_keywords[:4]]
            if matched_brands:
                shared_ind.extend([f"BRAND: {b.upper()}" for b in matched_brands[:2]])

            matched_campaigns.append(
                CorrelatedCampaign(
                    campaign_name=sig["campaign_name"],
                    confidence=confidence,
                    cluster_pattern=sig["pattern_description"],
                    shared_indicators=shared_ind,
                    associated_mitre=sig["mitre_techniques"],
                )
            )

    # Sort campaigns by confidence descending
    matched_campaigns.sort(key=lambda c: c.confidence, reverse=True)

    has_match = len(matched_campaigns) > 0
    primary = matched_campaigns[0].campaign_name if has_match else None
    notes = (
        f"Correlated with {len(matched_campaigns)} active threat cluster(s). "
        f"Primary threat vector: {primary}."
        if has_match
        else "No correlation found with active monitored cybercrime campaign playbooks."
    )

    return ThreatCorrelationReport(
        has_campaign_match=has_match,
        total_correlated_campaigns=len(matched_campaigns),
        primary_campaign=primary,
        campaigns=matched_campaigns,
        correlation_notes=notes,
    )
