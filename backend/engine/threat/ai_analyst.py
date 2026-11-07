"""
AI Threat Analyst & Social Engineering Briefing Engine
Extracts indicators of compromise (URLs, phone numbers, UPI handles, sender IDs),
orchestrates LLM reasoning via LangChain + Groq (Llama 3.3), and provides a deterministic
expert rule fallback mapping threats directly to MITRE ATT&CK techniques.
"""

import os
import re
from typing import Optional
from dotenv import load_dotenv
import httpx
import groq

from models.schemas import AIBriefingReport, MitreTechnique, DomainThreatSchema, UrgencyNlpSchema
from engine.threat.social_engineering_nlp import audit_social_engineering_text

load_dotenv()

# Standard MITRE ATT&CK Technique Definitions
MITRE_DB = {
    "T1566.002": MitreTechnique(
        id="T1566.002",
        name="Phishing: Spearphishing Link",
        tactic="Initial Access",
        description="Adversary sends targeted deceptive messages containing malicious links to lure victims into credential harvest or payload delivery.",
    ),
    "T1598.002": MitreTechnique(
        id="T1598.002",
        name="Phishing for Information: Spearphishing Link",
        tactic="Reconnaissance",
        description="Adversary directs victims to spoofed portal to illicitly harvest credentials, Aadhaar/PAN, or banking OTPs.",
    ),
    "T1657": MitreTechnique(
        id="T1657",
        name="Financial Fraud / Wire Fraud",
        tactic="Impact",
        description="Adversary conducts fraudulent financial transactions or coaxes victim into unauthorized UPI transfers or fake recharge payments.",
    ),
    "T1584": MitreTechnique(
        id="T1584",
        name="Compromise Infrastructure: Domains",
        tactic="Resource Development",
        description="Adversary leverages typosquatted, homograph, or shortlink domains to masquerade as trusted organizations.",
    ),
    "T1204.001": MitreTechnique(
        id="T1204.001",
        name="User Execution: Malicious Link",
        tactic="Execution",
        description="Adversary relies on psychological urgency cues to coerce victim into executing an untrusted URL.",
    ),
}

# Regex Patterns for IOC Extraction
REGEX_URL = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
REGEX_PHONE = re.compile(r"(?:\+?91[\-\s]?)?[6-9]\d{9}\b|\+[1-9]\d{7,14}\b")
REGEX_SENDER_ID = re.compile(r"\b[A-Z]{2}-[A-Z0-9]{6}\b")
REGEX_UPI = re.compile(
    r"\b[a-zA-Z0-9.\-_]{2,64}@(?!gmail|yahoo|outlook|hotmail|icloud|proton)[a-zA-Z]{2,32}\b",
    re.IGNORECASE,
)


def extract_indicators_of_compromise(text: str) -> dict[str, list[str]]:
    """
    Extracts high-fidelity indicators (IOCs): URLs, phone numbers, UPI handles, and sender headers.
    """
    raw_urls = REGEX_URL.findall(text)
    # Strip trailing punctuation like exclamation marks, periods, commas, closing brackets
    cleaned_urls = [re.sub(r"[.,!?;:\"')\]}]+$", "", u) for u in raw_urls if u.strip()]

    phones = REGEX_PHONE.findall(text)
    sender_ids = REGEX_SENDER_ID.findall(text)
    upi_handles = REGEX_UPI.findall(text)

    return {
        "urls": list(dict.fromkeys(cleaned_urls)),
        "phones": list(dict.fromkeys(phones)),
        "sender_ids": list(dict.fromkeys(sender_ids)),
        "upi_handles": list(dict.fromkeys(upi_handles)),
    }


def _deterministic_ai_briefing(
    text: str,
    extracted_iocs: dict[str, list[str]],
    domain_report: Optional[DomainThreatSchema] = None,
    nlp_report: Optional[UrgencyNlpSchema] = None,
) -> AIBriefingReport:
    """
    Deterministic rule-based expert system providing evidence-grounded threat briefings
    and MITRE ATT&CK mappings with zero external API dependencies.
    """
    nlp = nlp_report or audit_social_engineering_text(text)
    all_indicators: list[str] = []
    for k, items in extracted_iocs.items():
        all_indicators.extend([f"{k.upper()}: {item}" for item in items])

    mitre_techniques: list[MitreTechnique] = []
    triggers: list[str] = []
    threat_category = "Benign Information"
    targeted_entity = "General Public"
    confidence = 90

    # 1. Evaluate Typosquatting / Infrastructure Compromise
    if domain_report and domain_report.threat_detected:
        mitre_techniques.append(MITRE_DB["T1584"])
        domain_label = getattr(domain_report, "domain_name", None) or getattr(domain_report, "hostname", "unknown")
        all_indicators.append(f"DOMAIN_ANOMALY: {domain_label} ({domain_report.impersonated_brand or 'unknown brand'})")
        targeted_entity = domain_report.impersonated_brand.upper() if domain_report.impersonated_brand else "Targeted Brand"
        threat_category = "Brand Impersonation & Typosquatting"

    # 2. Evaluate Social Engineering & Coercion Categories
    if nlp.is_coercive or nlp.urgency_score > 30:
        mitre_techniques.append(MITRE_DB["T1204.001"])
        if extracted_iocs.get("urls"):
            mitre_techniques.append(MITRE_DB["T1566.002"])

        if "fake_kyc_and_compliance" in nlp.detected_categories:
            mitre_techniques.append(MITRE_DB["T1598.002"])
            triggers.append("Regulatory Compliance / Mandatory KYC Pretexting")
            threat_category = "Credential & PII Harvesting (Phishing)"
            if targeted_entity == "General Public":
                targeted_entity = "Banking / Telecom Customers"

        if "account_suspension" in nlp.detected_categories or "utility_disconnection" in nlp.detected_categories:
            mitre_techniques.append(MITRE_DB["T1598.002"])
            triggers.append("Artificial Time-Pressure / Imminent Loss of Service")
            if threat_category == "Benign Information":
                threat_category = "Account Takeover & Coercive Phishing"

        if "fake_reward_and_recharge" in nlp.detected_categories or extracted_iocs.get("upi_handles"):
            mitre_techniques.append(MITRE_DB["T1657"])
            triggers.append("Unearned Financial Incentive / Free Recharge Lure")
            threat_category = "Financial Fraud & Deceptive Payment Trap"

    # Deduplicate MITRE techniques
    unique_mitre = list({t.id: t for t in mitre_techniques}.values())

    if not triggers and threat_category == "Benign Information":
        executive_summary = (
            "No hostile social engineering tactics detected. The message structure and referenced endpoints "
            "align with normal informational or service communication."
        )
        recommendation = "Safe to proceed. Exercise standard caution when navigating external links."
        confidence = 95
    else:
        executive_summary = (
            f"High-confidence {threat_category} detected impersonating {targeted_entity}. "
            f"Adversary deploys {len(triggers)} psychological coercion triggers alongside unverified links/contacts."
        )
        recommendation = (
            "Do NOT click any embedded links, enter credentials, or send OTP/UPI approvals. "
            "Verify account status exclusively through the verified official app or customer care line."
        )
        confidence = 92

    return AIBriefingReport(
        executive_summary=executive_summary,
        threat_category=threat_category,
        targeted_entity=targeted_entity,
        psychological_triggers=triggers or ["None detected"],
        mitre_attack_techniques=unique_mitre,
        extracted_indicators=all_indicators,
        analyst_recommendation=recommendation,
        confidence_score=confidence,
        ai_engine="Deterministic Fallback (Rule-Based Expert System)",
        offline_mode=True,
    )


def analyze_with_groq_llm(
    text: str,
    extracted_iocs: dict[str, list[str]],
    domain_report: Optional[DomainThreatSchema] = None,
    nlp_report: Optional[UrgencyNlpSchema] = None,
) -> Optional[AIBriefingReport]:
    """
    Orchestrates LangChain + Groq structured threat analysis across available models.
    Safely returns None if API is unavailable, unconfigured, or encounters network exceptions.
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return None

    candidate_models = [
        "openai/gpt-oss-120b",
        "openai/gpt-oss-20b",
        "llama-3.3-70b-versatile",
        "llama-3.1-70b-versatile",
        "qwen/qwen3.8-27b",
    ]

    from langchain_groq import ChatGroq
    from langchain_core.messages import SystemMessage, HumanMessage

    system_prompt = (
        "You are K9 Sentinel AI, an elite digital trust intelligence analyst. "
        "Analyze the provided message, URL context, and threat heuristics. "
        "Identify scam intent, extract key indicators, map threat behaviors to concrete MITRE ATT&CK techniques "
        "(e.g., T1566.002, T1598.002, T1657, T1584, T1204.001), and produce actionable incident response recommendations. "
        "Be precise, objective, and adhere strictly to the AIBriefingReport schema."
    )

    all_indicators: list[str] = []
    for k, items in extracted_iocs.items():
        all_indicators.extend([f"{k.upper()}: {item}" for item in items])

    context_info = f"Extracted IOCs: {extracted_iocs}\n"
    if domain_report:
        context_info += f"Domain Audit: {domain_report.model_dump()}\n"
    if nlp_report:
        context_info += f"Urgency NLP Audit: {nlp_report.model_dump()}\n"

    human_prompt = f"Target Input Text:\n{text}\n\nTechnical Signals Context:\n{context_info}"

    for model_name in candidate_models:
        try:
            llm = ChatGroq(
                model_name=model_name,
                temperature=0.1,
                api_key=api_key,
            )
            structured_llm = llm.with_structured_output(AIBriefingReport)

            response = structured_llm.invoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=human_prompt),
            ])

            if isinstance(response, AIBriefingReport):
                response.ai_engine = f"Groq {model_name}"
                response.offline_mode = False
                if not response.extracted_indicators:
                    response.extracted_indicators = all_indicators
                return response

        except (
            groq.NotFoundError,
            groq.GroqError,
            groq.APIError,
            groq.APIConnectionError,
            groq.RateLimitError,
            groq.AuthenticationError,
            httpx.RequestError,
            ValueError,
            KeyError,
            TimeoutError,
            RuntimeError,
        ):
            continue

    return None


def generate_threat_ai_briefing(
    text: str,
    domain_report: Optional[DomainThreatSchema] = None,
    nlp_report: Optional[UrgencyNlpSchema] = None,
) -> AIBriefingReport:
    """
    Main entry point for Phase 4 AI Analysis.
    Attempts Groq Llama 3.3 execution first; on any absence of credentials or network error,
    seamlessly falls back to deterministic expert rules returning typed AIBriefingReport.
    """
    extracted = extract_indicators_of_compromise(text)

    # 1. Try Groq if available
    llm_report = analyze_with_groq_llm(
        text=text,
        extracted_iocs=extracted,
        domain_report=domain_report,
        nlp_report=nlp_report,
    )
    if llm_report is not None:
        return llm_report

    # 2. Seamlessly execute deterministic expert analysis
    return _deterministic_ai_briefing(
        text=text,
        extracted_iocs=extracted,
        domain_report=domain_report,
        nlp_report=nlp_report,
    )
