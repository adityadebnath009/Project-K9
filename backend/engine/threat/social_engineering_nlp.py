"""
Social Engineering & Deceptive Urgency NLP Engine
Detects psychological coercion, fear appeals, fake administrative notices,
and fraudulent urgent call-to-actions into UrgencyNlpSchema.
"""

import re
from models.schemas import UrgencyNlpSchema

URGENCY_PATTERNS: dict[str, list[str]] = {
    "account_suspension": [
        r"account (will be|has been) (suspended|terminated|frozen|blocked|closed)",
        r"(within|in) (24|12|48) hours?",
        r"immediate(ly)? (action|verification|attention) (required|needed)",
        r"failure to (respond|verify|update) will result in",
    ],
    "fake_kyc_and_compliance": [
        r"(mandatory|urgent|pending) kyc (update|verification|process)",
        r"(pan|aadhaar|id) (link|update|verification) (failed|pending|required)",
        r"sim (card|service) (will be|is) (deactivated|blocked)",
        r"update your (banking|kyc) details immediately",
    ],
    "unauthorized_transaction": [
        r"unauthorized (transaction|access|login|activity) detected",
        r"payment of (rs\.?|inr|\$|usd) .* (debited|approved|charged)",
        r"if this was not you,? (click|verify|dispute) here",
        r"security alert:? new device logged in",
    ],
    "fake_reward_and_recharge": [
        r"congratulations!? you (have won|are selected)",
        r"free (recharge|data|5g|gift|iphone)",
        r"claim your (cashback|bonus|refund|lottery) now",
        r"expires (today|soon|in \d+ minutes?)",
    ],
}


def audit_social_engineering_text(content_text: str) -> UrgencyNlpSchema:
    """
    Scans plain text / extracted webpage content for deceptive urgency and fear triggers.
    Returns a typed UrgencyNlpSchema Pydantic model.
    """
    if not content_text or not content_text.strip():
        return UrgencyNlpSchema(
            urgency_score=0,
            detected_categories=[],
            matched_phrases=[],
            is_coercive=False,
            severity="SAFE",
        )

    lower_text = content_text.lower()
    matched_categories: list[str] = []
    matched_phrases: list[str] = []
    weight_score = 0

    for category, regex_list in URGENCY_PATTERNS.items():
        category_matched = False
        for pattern in regex_list:
            matches = re.findall(pattern, lower_text)
            if matches:
                category_matched = True
                matched_phrases.append(pattern)
                weight_score += 25
        if category_matched:
            matched_categories.append(category)

    final_score = min(weight_score, 100)
    is_coercive = final_score >= 50

    severity = "SAFE"
    if final_score >= 75:
        severity = "CRITICAL"
    elif final_score >= 25:
        severity = "SUSPICIOUS"

    return UrgencyNlpSchema(
        urgency_score=final_score,
        detected_categories=matched_categories,
        matched_phrases=matched_phrases,
        is_coercive=is_coercive,
        severity=severity,
    )
