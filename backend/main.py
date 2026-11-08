"""
K9 Sentinel AI - Main FastAPI Application
AI-Powered Web Threat Detection & Digital Trust Intelligence
Hack Matrix 2026 - Hacktober
"""

import json
from typing import Any, Optional
from fastapi import FastAPI, HTTPException, status, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from models.schemas import (
    ScanRequest,
    MasterScanResponse,
    AIBriefingReport,
    Web3CommitmentRecord,
    RiskTier,
    InputType,
    CommunityIncident,
    CreateIncidentRequest,
    VoteIncidentRequest,
)
from engine.orchestrator import orchestrate_full_scan, orchestrate_qr_scan
from engine.threat.ai_analyst import generate_threat_ai_briefing
from engine.web3.registry_client import default_registry_client
from engine.intel.community_store import (
    get_all_incidents,
    get_incident_by_id,
    add_incident,
    vote_on_incident,
)
from scenarios.demo_cases import list_benchmark_scenarios, run_benchmark_scenario

app = FastAPI(
    title="K9 Sentinel AI API",
    version="1.0.0",
    description="AI-Powered Web Threat Detection & Digital Trust Intelligence Platform",
)

# Enable Cross-Origin Resource Sharing for Frontend (Next.js / Vite)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Web3VerifyRequest(BaseModel):
    report_hash: str = Field(..., description="The keccak256 hash to verify on-chain")
    payload: Optional[dict[str, Any]] = None


class MessageScanRequest(BaseModel):
    message: str = Field(..., min_length=1, description="Raw SMS, email, or instant message text")


class QrScanRequest(BaseModel):
    image_base64: str = Field(..., description="Base64 encoded QR image (with or without data:image/png;base64, prefix)")


@app.get("/", tags=["System"])
@app.get("/health", tags=["System"])
async def root_health_check() -> dict[str, Any]:
    """Health check and core intelligence capabilities."""
    return {
        "service": "K9 Sentinel AI",
        "status": "OPERATIONAL",
        "online": True,
        "version": "1.0.0",
        "engine": {
            "phase1_crypto": "Active (eMudhra Bug 2083449 + OneCRL + RSA + CT)",
            "phase2_threat": "Active (Levenshtein + Homographs + DOM Harvesting + Urgency NLP)",
            "phase3_posture": "Active (100pt Headers Scorecard + SSRF Probes)",
            "phase4_ai": "Active (Groq Llama 3.3 / GPT-OSS 120B + Deterministic Expert)",
            "phase5_web3": "Active (Solidity ThreatRegistry + keccak256 On-Chain Commitment)",
            "phase6_intel": "Active (abuse.ch URLhaus + Campaign Correlation)",
        },
    }


@app.post("/api/v1/scan", response_model=MasterScanResponse, tags=["Scans"])
async def scan_target(request: ScanRequest) -> MasterScanResponse:
    """
    Unified inspection endpoint.
    Accepts target URL, domain, or message, runs all 6 inspection phases concurrently,
    and returns an evidence-grounded MasterScanResponse committed to Web3.
    """
    try:
        return await orchestrate_full_scan(target=request.target)
    except (ValueError, TypeError) as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target input: {err}",
        )


@app.post("/api/v1/scan/message", response_model=MasterScanResponse, tags=["Scans"])
async def scan_message(request: MessageScanRequest) -> MasterScanResponse:
    """Specialized endpoint for analyzing suspicious SMS, emails, or chat messages."""
    return await orchestrate_full_scan(target=request.message, override_input_type=InputType.TEXT_MESSAGE)


@app.post("/api/v1/scan/qr", response_model=MasterScanResponse, tags=["Scans"])
async def scan_qr_code(http_request: Request) -> MasterScanResponse:
    """
    Decodes an uploaded QR image (file or base64 string) and audits embedded URLs or UPI payments.
    Protects against Quishing (QR Phishing) and fraudulent UPI merchant/utility impostors.
    """
    content_type = http_request.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            body = await http_request.json()
        except (ValueError, json.JSONDecodeError):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON body")
        image_base64 = body.get("image_base64")
        if not image_base64:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Field 'image_base64' is required.",
            )
        return await orchestrate_qr_scan(image_base64)
    elif "multipart/form-data" in content_type:
        form = await http_request.form()
        uploaded_file = form.get("file")
        if uploaded_file and hasattr(uploaded_file, "read"):
            raw_bytes = await uploaded_file.read()
            return await orchestrate_qr_scan(raw_bytes)
        image_base64 = form.get("image_base64")
        if image_base64:
            return await orchestrate_qr_scan(str(image_base64))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Multipart form must contain 'file' or 'image_base64'.",
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported Content-Type. Use 'application/json' or 'multipart/form-data'.",
        )


@app.get("/api/v1/scenarios", tags=["Benchmarks"])
async def get_benchmark_scenarios() -> list[dict[str, Any]]:
    """Returns the 6 mandatory benchmark scenarios (3 suspicious + 3 benign) required by competition guidelines."""
    return list_benchmark_scenarios()


@app.post("/api/v1/scenarios/{scenario_id}/run", response_model=MasterScanResponse, tags=["Benchmarks"])
async def run_scenario(scenario_id: str) -> MasterScanResponse:
    """Executes a pre-configured benchmark evaluation case live."""
    try:
        return await run_benchmark_scenario(scenario_id)
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err))


@app.post("/api/v1/web3/verify", tags=["Web3 Registry"])
async def verify_on_chain_report(request: Web3VerifyRequest) -> dict[str, Any]:
    """Verifies that an off-chain threat report matches its on-chain keccak256 commitment."""
    is_valid = default_registry_client.verify_report(
        report_hash=request.report_hash,
        expected_payload=request.payload,
    )
    report_data = default_registry_client.get_report_by_hash(request.report_hash)

    return {
        "report_hash": request.report_hash,
        "is_valid": is_valid,
        "tamper_detected": not is_valid and request.payload is not None,
        "on_chain_record": report_data,
    }


@app.get("/api/v1/web3/latest", tags=["Web3 Registry"])
async def get_latest_on_chain_threats(limit: int = 10) -> list[dict[str, Any]]:
    """Fetches the latest registered on-chain threat commitments from the decentralized registry."""
    return default_registry_client.get_latest_reports(limit=limit)


@app.get("/api/v1/threats/stix", tags=["Threat Intelligence"])
async def export_stix_threat_indicators() -> dict[str, Any]:
    """Exports recent threat intelligence commitments in STIX 2.1 standard format."""
    recent_reports = default_registry_client.get_latest_reports(limit=25)
    stix_objects = []

    for r in recent_reports:
        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{r.get('report_hash', '')[:36].replace('0x', '')}",
            "created": r.get("timestamp"),
            "name": f"Malicious Domain: {r.get('domain')}",
            "pattern": f"[domain-name:value = '{r.get('domain')}']",
            "pattern_type": "stix",
            "confidence": 90,
            "external_references": [
                {
                    "source_name": "K9-Sentinel-Web3-Commitment",
                    "description": f"On-chain commitment: {r.get('report_hash')}",
                    "url": r.get("verification_url"),
                }
            ],
        })

    return {
        "type": "bundle",
        "id": "bundle--k9-sentinel-threat-telemetry",
        "objects": stix_objects,
    }


# ---------------------------------------------------------------------
# Phase 6 & Collaborative Radar: Community Incident Feed & Voting
# ---------------------------------------------------------------------
@app.get("/api/v1/incidents", response_model=list[CommunityIncident], tags=["Community Radar"])
async def list_community_incidents() -> list[CommunityIncident]:
    """
    Returns live community-reported threat incidents with user experience details,
    victim impact status, and countdown-style consensus vote counts.
    """
    return get_all_incidents()


@app.post("/api/v1/incidents", response_model=CommunityIncident, tags=["Community Radar"], status_code=status.HTTP_201_CREATED)
async def report_community_incident(incident: CreateIncidentRequest) -> CommunityIncident:
    """
    Submits a new community scam/phishing incident describing what the user experienced,
    problems encountered, and victim status.
    """
    try:
        return add_incident(incident)
    except (ValueError, TypeError) as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))


@app.post("/api/v1/incidents/{incident_id}/vote", response_model=CommunityIncident, tags=["Community Radar"])
async def vote_community_incident(incident_id: str, req: VoteIncidentRequest) -> CommunityIncident:
    """
    Casts a categorical vote ('fake' vs 'legit') on a community incident and updates the consensus verdict.
    """
    if req.vote not in ("fake", "legit"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vote must be either 'fake' (Yes, it's fake) or 'legit' (No, it's not fake).",
        )

    updated = vote_on_incident(incident_id, req.vote)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with id '{incident_id}' not found.",
        )
    return updated
