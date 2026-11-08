"""
Thread-safe JSON-backed Community Incidents & Voting Consensus Store
Provides local off-chain storage for community victim reports, user experiences,
and countdown-style voting consensus (fake vs. legit).
"""

import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from models.schemas import CommunityIncident, CreateIncidentRequest


DATA_FILE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "community_incidents.json",
)

_LOCK = threading.Lock()


def _ensure_data_file() -> None:
    """Ensures the data directory and JSON seed file exist."""
    data_dir = os.path.dirname(DATA_FILE_PATH)
    if not os.path.exists(data_dir):
        os.makedirs(data_dir, exist_ok=True)
    if not os.path.exists(DATA_FILE_PATH):
        with open(DATA_FILE_PATH, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)


def get_all_incidents() -> list[CommunityIncident]:
    """Retrieves all community reported incidents ordered by most recent."""
    _ensure_data_file()
    with _LOCK:
        try:
            with open(DATA_FILE_PATH, "r", encoding="utf-8") as f:
                raw_list = json.load(f)
                return [CommunityIncident(**item) for item in raw_list]
        except (OSError, json.JSONDecodeError, ValueError):
            return []


def get_incident_by_id(incident_id: str) -> Optional[CommunityIncident]:
    """Retrieves a single incident by ID."""
    incidents = get_all_incidents()
    for inc in incidents:
        if inc.id == incident_id:
            return inc
    return None


def add_incident(req: CreateIncidentRequest) -> CommunityIncident:
    """Creates a new community report with user experience and victim status."""
    _ensure_data_file()
    incidents = get_all_incidents()

    # Determine domain from target
    parsed = urlparse(req.target if "://" in req.target else f"https://{req.target}")
    domain = parsed.hostname or req.target.split("/")[0]

    incident_id = f"inc-{len(incidents) + 1:03d}"
    fake_votes = 1 if req.initial_vote == "fake" else 0
    legit_votes = 1 if req.initial_vote == "legit" else 0

    new_incident = CommunityIncident(
        id=incident_id,
        target=req.target,
        domain=domain,
        category=req.category,
        reporter=req.reporter or "Anonymous Reporter",
        timestamp=datetime.now(timezone.utc).isoformat(),
        user_experience=req.user_experience,
        victim_status=req.victim_status,
        fake_votes=fake_votes,
        legit_votes=legit_votes,
        consensus_status="Active Verification",
        countdown_hours_remaining=24,
    )

    with _LOCK:
        try:
            with open(DATA_FILE_PATH, "r", encoding="utf-8") as f:
                current_data = json.load(f)
        except (OSError, json.JSONDecodeError):
            current_data = []

        current_data.insert(0, new_incident.model_dump())

        with open(DATA_FILE_PATH, "w", encoding="utf-8") as f:
            json.dump(current_data, f, indent=2)

    return new_incident


def vote_on_incident(incident_id: str, vote_type: str) -> Optional[CommunityIncident]:
    """
    Submits a vote ('fake' or 'legit') for a community incident.
    Recalculates consensus status once quorum is reached.
    """
    _ensure_data_file()
    with _LOCK:
        try:
            with open(DATA_FILE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

        matched = None
        for item in data:
            if item.get("id") == incident_id:
                if vote_type == "fake":
                    item["fake_votes"] = item.get("fake_votes", 0) + 1
                elif vote_type == "legit":
                    item["legit_votes"] = item.get("legit_votes", 0) + 1
                else:
                    return None

                # Compute consensus
                total = item["fake_votes"] + item["legit_votes"]
                if total >= 5:
                    fake_ratio = item["fake_votes"] / total
                    if fake_ratio >= 0.8:
                        item["consensus_status"] = f"Consensus: Confirmed Fake ({int(fake_ratio * 100)}%)"
                    elif fake_ratio <= 0.2:
                        item["consensus_status"] = f"Consensus: Confirmed Safe ({int((1 - fake_ratio) * 100)}%)"
                    else:
                        item["consensus_status"] = "Disputed / Mixed Community Verdict"

                matched = item
                break

        if matched:
            with open(DATA_FILE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return CommunityIncident(**matched)

        return None
