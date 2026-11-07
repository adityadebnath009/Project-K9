"""
Comprehensive 20-Test Suite for Phase 6: Threat Intelligence Feeds & Campaign Correlation.
Covers:
1-7: abuse.ch URLhaus threat feed querying, port/scheme normalization & curated seed blacklists
8-16: Multi-report correlation across active cybercrime campaigns (BlueKite, VoltCut, QuickLure, CryptoDrain)
17-20: Confidence ranking, brand boosts, MITRE technique integrity & Pydantic JSON round-trips
"""

import re
import pytest
from models.schemas import ThreatIntelSchema, ThreatCorrelationReport
from engine.intel.urlhaus import query_urlhaus_threat_intel, OFFLINE_INTEL_BLACKLIST
from engine.intel.correlator import correlate_threat_campaigns


# -------------------------------------------------------------
# Tests 1 - 7: URLhaus & Threat Feed Interrogation
# -------------------------------------------------------------
@pytest.mark.anyio
async def test_urlhaus_curated_seed_match_sbi_kyc():
    """Identifies known malicious domain sbi-kyc-update.in in curated threat intelligence."""
    res = await query_urlhaus_threat_intel("http://sbi-kyc-update.in/login")
    assert isinstance(res, ThreatIntelSchema)
    assert res.blacklisted is True
    assert res.matches_count >= 1
    assert any("banking_phish" in f.tags for f in res.findings)


@pytest.mark.anyio
async def test_urlhaus_curated_seed_match_paypal_typosquat():
    """Identifies known typosquatted PayPal credential harvesting portal."""
    res = await query_urlhaus_threat_intel("https://paypa1-secure.com/webscr")
    assert res.blacklisted is True
    assert any("typosquat" in f.tags for f in res.findings)


@pytest.mark.anyio
async def test_urlhaus_curated_seed_match_url_shortener():
    """Identifies evasive shortener weurl.co/NINJAC in threat blacklist."""
    res = await query_urlhaus_threat_intel("https://weurl.co/NINJAC/05DDMU")
    assert res.blacklisted is True
    assert any("url_shortener" in f.tags for f in res.findings)


@pytest.mark.anyio
async def test_urlhaus_test_malware_curated_seed():
    """Identifies URLhaus official malware distribution test vector."""
    res = await query_urlhaus_threat_intel("https://test-malware.urlhaus.abuse.ch/download.exe")
    assert res.blacklisted is True
    assert res.findings[0].threat_type == "malware_download"


@pytest.mark.anyio
async def test_urlhaus_airtel_sim_curated_seed():
    """Identifies known telecom SIM deactivation phishing domain."""
    res = await query_urlhaus_threat_intel("http://airtel-sim-kyc.net/verify")
    assert res.blacklisted is True
    assert any("sim_block_scam" in f.tags for f in res.findings)


@pytest.mark.anyio
async def test_urlhaus_port_stripping_and_scheme_normalization():
    """Verifies that non-standard ports and complex paths normalize to matching hostname."""
    res = await query_urlhaus_threat_intel("http://sbi-kyc-update.in:8443/auth/index.php?token=xyz")
    assert res.blacklisted is True


@pytest.mark.anyio
async def test_urlhaus_clean_domain_unflagged():
    """Verifies legitimate domains like python.org or wikipedia.org are clean."""
    res = await query_urlhaus_threat_intel("https://python.org")
    assert res.blacklisted is False
    assert res.matches_count == 0
    assert len(res.findings) == 0


@pytest.mark.anyio
async def test_urlhaus_live_or_timeout_resilience():
    """Ensures offline / non-existent hosts fail open gracefully without exception."""
    res = await query_urlhaus_threat_intel("https://this-domain-is-definitely-fake-123456789.org", timeout_seconds=1.0)
    assert isinstance(res, ThreatIntelSchema)
    assert res.blacklisted is False


# -------------------------------------------------------------
# Tests 8 - 16: Campaign Correlation & Cybercrime Clustering
# -------------------------------------------------------------
def test_correlator_bluekite_banking_kyc_match():
    """Correlates SBI / HDFC mandatory KYC pretexting to Operation BlueKite."""
    text = "Dear customer, your SBI netbanking account is blocked. Update mandatory KYC immediately."
    report = correlate_threat_campaigns(message_text=text)

    assert isinstance(report, ThreatCorrelationReport)
    assert report.has_campaign_match is True
    assert "Operation BlueKite" in (report.primary_campaign or "")
    top_camp = report.campaigns[0]
    assert "T1598.002" in top_camp.associated_mitre
    assert top_camp.confidence >= 85


def test_correlator_voltcut_electricity_match():
    """Correlates nocturnal electricity cutoff extortion to Operation VoltCut."""
    text = "URGENT: Your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill."
    report = correlate_threat_campaigns(message_text=text)

    assert report.has_campaign_match is True
    assert "Operation VoltCut" in (report.primary_campaign or "")
    assert any("KEYWORD: electricity" in ind for ind in report.campaigns[0].shared_indicators)


def test_correlator_quicklure_shortlink_match():
    """Correlates deceptive URL shorteners to Operation QuickLure."""
    target = "https://weurl.co/NINJAC/05DDMU"
    report = correlate_threat_campaigns(target_url=target)

    assert report.has_campaign_match is True
    assert "Operation QuickLure" in (report.primary_campaign or "")
    assert "T1584" in report.campaigns[0].associated_mitre


def test_correlator_cryptodrain_web3_match():
    """Correlates fake airdrop and MetaMask seed phrase traps to Operation CryptoDrain."""
    text = "Exclusive Token Airdrop! Connect your MetaMask or Phantom wallet and confirm seed phrase to claim."
    report = correlate_threat_campaigns(message_text=text)

    assert report.has_campaign_match is True
    assert "Operation CryptoDrain" in (report.primary_campaign or "")
    assert "T1657" in report.campaigns[0].associated_mitre


def test_correlator_compound_multi_campaign_overlap():
    """Compound lure using both shortlink and KYC pretext triggers both BlueKite and QuickLure."""
    text = "SBI KYC update pending. Link: https://bit.ly/sbi-verify"
    report = correlate_threat_campaigns(message_text=text)

    assert report.has_campaign_match is True
    assert report.total_correlated_campaigns >= 2
    camp_names = [c.campaign_name for c in report.campaigns]
    assert any("BlueKite" in name for name in camp_names)
    assert any("QuickLure" in name for name in camp_names)


def test_correlator_case_insensitive_matching():
    """Mixed-case and uppercase keywords match correctly."""
    text = "YOUR BESCOM ELECTRICITY POWER WILL BE CUT TONIGHT UNLESS BILL IS PAID"
    report = correlate_threat_campaigns(message_text=text)

    assert report.has_campaign_match is True
    assert "Operation VoltCut" in (report.primary_campaign or "")


def test_correlator_benign_text_no_match():
    """Verifies standard benign business or educational text matches zero hostile campaigns."""
    text = "Thank you for attending the annual university mathematics symposium. Have a great day!"
    report = correlate_threat_campaigns(message_text=text)

    assert report.has_campaign_match is False
    assert report.total_correlated_campaigns == 0
    assert report.primary_campaign is None


def test_correlator_empty_input_graceful():
    """Verifies passing None/empty strings handles safely without error."""
    report = correlate_threat_campaigns(target_url="", message_text=None, extracted_indicators=[])
    assert report.has_campaign_match is False
    assert report.total_correlated_campaigns == 0


# -------------------------------------------------------------
# Tests 17 - 20: Confidence Metrics, MITRE Format & Serialization
# -------------------------------------------------------------
def test_correlator_confidence_ranking():
    """Verifies that multiple matching campaigns are sorted by confidence descending."""
    text = "SBI electricity airdrop update bill"
    report = correlate_threat_campaigns(message_text=text)

    assert report.total_correlated_campaigns > 1
    scores = [c.confidence for c in report.campaigns]
    assert scores == sorted(scores, reverse=True)


def test_correlator_brand_bonus_confidence_boost():
    """Mentioning an explicit targeted brand boosts the confidence score."""
    generic_text = "Mandatory KYC update pending. Account deactivated."
    branded_text = "Dear customer, your SBI mandatory KYC update is pending. Account deactivated."
    rep_generic = correlate_threat_campaigns(message_text=generic_text)
    rep_branded = correlate_threat_campaigns(message_text=branded_text)

    assert rep_branded.campaigns[0].confidence > rep_generic.campaigns[0].confidence


def test_correlator_mitre_technique_syntax_integrity():
    """Verifies all associated MITRE technique identifiers adhere to the standard TXXXX[.XXX] format."""
    mitre_regex = re.compile(r"^T\d{4}(?:\.\d{3})?$")
    report = correlate_threat_campaigns(message_text="Metamask airdrop claim seed phrase")
    for camp in report.campaigns:
        for t_id in camp.associated_mitre:
            assert mitre_regex.match(t_id), f"Invalid MITRE syntax: {t_id}"


def test_phase6_pydantic_json_roundtrip_serialization():
    """Verifies ThreatCorrelationReport cleanly serializes to JSON and reconstructs identical schema."""
    text = "Urgent: SBI account locked! Update KYC at http://sbi-kyc.in"
    report = correlate_threat_campaigns(message_text=text)
    json_str = report.model_dump_json()

    rebuilt = ThreatCorrelationReport.model_validate_json(json_str)
    assert rebuilt.has_campaign_match == report.has_campaign_match
    assert rebuilt.primary_campaign == report.primary_campaign
    assert len(rebuilt.campaigns) == len(report.campaigns)
