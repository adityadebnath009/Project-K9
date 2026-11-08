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
_INCIDENTS_CACHE: Optional[list[dict]] = None


def _init_cache() -> list[dict]:
    """Initializes in-memory incidents cache from disk or default seed."""
    global _INCIDENTS_CACHE
    if _INCIDENTS_CACHE is not None:
        return _INCIDENTS_CACHE

    _ensure_data_file()
    try:
        with open(DATA_FILE_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
            _INCIDENTS_CACHE = raw if isinstance(raw, list) else []
    except (OSError, json.JSONDecodeError):
        _INCIDENTS_CACHE = []

    return _INCIDENTS_CACHE


def _persist_cache() -> None:
    """Attempts to flush current cache to disk without failing if read-only."""
    if _INCIDENTS_CACHE is None:
        return
    try:
        with open(DATA_FILE_PATH, "w", encoding="utf-8") as f:
            json.dump(_INCIDENTS_CACHE, f, indent=2)
    except OSError:
        pass


def _ensure_data_file() -> None:
    """Ensures the data directory and JSON seed file exist."""
    data_dir = os.path.dirname(DATA_FILE_PATH)
    if not os.path.exists(data_dir):
        os.makedirs(data_dir, exist_ok=True)
    if not os.path.exists(DATA_FILE_PATH):
        try:
            with open(DATA_FILE_PATH, "w", encoding="utf-8") as f:
                json.dump([], f, indent=2)
        except OSError:
            pass


def get_all_incidents() -> list[CommunityIncident]:
    """Retrieves all community reported incidents ordered by most recent."""
    with _LOCK:
        cache = _init_cache()
        return [CommunityIncident(**item) for item in cache]


def get_incident_by_id(incident_id: str) -> Optional[CommunityIncident]:
    """Retrieves a single incident by ID."""
    incidents = get_all_incidents()
    for inc in incidents:
        if inc.id == incident_id:
            return inc
    return None


def add_incident(req: CreateIncidentRequest) -> CommunityIncident:
    """Creates a new community report with user experience and victim status."""
    with _LOCK:
        cache = _init_cache()

        # Determine domain from target
        parsed = urlparse(req.target if "://" in req.target else f"https://{req.target}")
        domain = parsed.hostname or req.target.split("/")[0]

        incident_id = f"inc-{len(cache) + 1:03d}"
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

        cache.insert(0, new_incident.model_dump())
        _persist_cache()
        return new_incident


def vote_on_incident(incident_id: str, vote_type: str) -> Optional[CommunityIncident]:
    """
    Submits a vote ('fake' or 'legit') for a community incident.
    Recalculates consensus status once quorum is reached.
    """
    with _LOCK:
        cache = _init_cache()

        matched = None
        for item in cache:
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
            _persist_cache()
            return CommunityIncident(**matched)

        return None
