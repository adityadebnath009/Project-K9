"""
Homograph & Typosquatting Detection Engine
Detects brand impersonation, Levenshtein distance typosquatting, IDN/Punycode homographs,
and URL entropy against top global and Indian financial/corporate/government domains into DomainThreatSchema.
"""

import math
import idna
import tldextract
from models.schemas import DomainThreatSchema

PROTECTED_BRANDS: dict[str, str] = {
    # Banking & Financial Services
    "paypal": "PayPal Inc.",
    "sbi": "State Bank of India",
    "hdfc": "HDFC Bank",
    "icici": "ICICI Bank",
    "axisbank": "Axis Bank",
    "chase": "JPMorgan Chase",
    "bankofamerica": "Bank of America",
    "wellsfargo": "Wells Fargo",
    "stripe": "Stripe Payments",
    
    # Tech & Infrastructure
    "google": "Google LLC",
    "microsoft": "Microsoft Corporation",
    "apple": "Apple Inc.",
    "amazon": "Amazon.com",
    "netflix": "Netflix Inc.",
    "facebook": "Meta Platforms",
    "instagram": "Instagram",
    "github": "GitHub Inc.",
    
    # Indian Telecom & Utilities
    "jio": "Reliance Jio",
    "airtel": "Bharti Airtel",
    
    # Cryptocurrency
    "binance": "Binance Exchange",
    "coinbase": "Coinbase",
    "metamask": "MetaMask Wallet",
    
    # Government & Tax
    "incometax": "Income Tax Department",
    "uidai": "UIDAI / Aadhaar",
    "irs": "Internal Revenue Service",
}

KNOWN_URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "weurl.co", "cutt.ly", "is.gd", "t.co", "rb.gy", "ow.ly", "goo.gl"
}

DECEPTIVE_TOKENS: set[str] = {
    "login", "signin", "verify", "verification", "secure", "security",
    "update", "kyc", "account", "support", "billing", "authenticate",
    "free", "bonus", "reward", "recharge", "blocked", "unblock"
}


def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq: dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes standard Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def audit_domain_threats(url_or_domain: str) -> DomainThreatSchema:
    """
    Audits domain for typosquatting, homographs, suspicious tokens,
    URL shortener usage, and entropy. Returns a typed DomainThreatSchema.
    """
    cleaned = url_or_domain.lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    extracted = tldextract.extract(cleaned)
    domain_name = extracted.domain
    subdomain = extracted.subdomain
    full_host = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else domain_name

    is_shortener = full_host in KNOWN_URL_SHORTENERS

    # 1. Homograph / Punycode Check
    is_homograph = False
    decoded_punycode = None
    if cleaned.startswith("xn--") or ".xn--" in cleaned:
        is_homograph = True
        try:
            decoded_punycode = idna.decode(cleaned)
        except (idna.IDNAError, UnicodeError):
            decoded_punycode = "Invalid-IDN"

    # 2. Typosquatting Check against Protected Brands
    is_typosquatted = False
    impersonated_brand: str | None = None
    brand_owner: str | None = None
    closest_distance = 999

    for brand_key, brand_label in PROTECTED_BRANDS.items():
        if domain_name == brand_key:
            continue

        tokens_to_test = [domain_name] + [t for t in domain_name.split("-") if len(t) >= 3]

        for token in tokens_to_test:
            dist = levenshtein_distance(token, brand_key)
            if dist in (1, 2) and len(token) >= 4:
                is_typosquatted = True
                impersonated_brand = brand_key
                brand_owner = brand_label
                closest_distance = dist
                break

        if is_typosquatted:
            break

        if brand_key in domain_name or brand_key in subdomain:
            has_deceptive_token = any(token in domain_name or token in subdomain for token in DECEPTIVE_TOKENS)
            if has_deceptive_token:
                is_typosquatted = True
                impersonated_brand = brand_key
                brand_owner = brand_label
                closest_distance = 0
                break

    matched_tokens = [token for token in DECEPTIVE_TOKENS if token in domain_name or token in subdomain]
    entropy = calculate_shannon_entropy(domain_name)
    high_entropy = entropy > 3.8 and len(domain_name) > 12

    severity = "SAFE"
    threat_detected = False
    if is_typosquatted or is_homograph:
        severity = "CRITICAL"
        threat_detected = True
    elif is_shortener or matched_tokens or high_entropy:
        severity = "SUSPICIOUS"
        threat_detected = True

    return DomainThreatSchema(
        hostname=cleaned,
        domain_name=domain_name,
        is_shortener=is_shortener,
        is_homograph=is_homograph,
        decoded_punycode=decoded_punycode,
        is_typosquatted=is_typosquatted,
        impersonated_brand=impersonated_brand,
        brand_owner=brand_owner,
        levenshtein_distance=closest_distance if is_typosquatted else None,
        deceptive_tokens=matched_tokens,
        entropy=entropy,
        high_entropy_flag=high_entropy,
        threat_detected=threat_detected,
        severity=severity,
    )
