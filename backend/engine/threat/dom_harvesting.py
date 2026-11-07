"""
DOM & Credential Harvesting Heuristics Engine
Analyzes webpage HTML to detect password/card input fields, cross-origin form exfiltration,
obfuscated JavaScript patterns, and hidden iframes into DomHarvestingSchema.
"""

import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from models.schemas import DomHarvestingSchema

SENSITIVE_FIELD_PATTERNS = [
    r"pass(word)?", r"pwd", r"pin", r"cvv", r"cvc", r"credit.?card", r"card.?number",
    r"exp(ir)?(y|ation)?", r"ssn", r"aadhaar", r"pan.?card", r"otp", r"token"
]


def audit_dom_credential_harvesting(html_content: str, current_origin: str) -> DomHarvestingSchema:
    """
    Parses webpage HTML to identify credential harvesting forms,
    cross-origin submission risks, and obfuscated scripting techniques.
    Returns a typed DomHarvestingSchema Pydantic model.
    """
    if not html_content or not html_content.strip():
        return DomHarvestingSchema(
            forms_count=0,
            has_password_field=False,
            sensitive_inputs_found=[],
            cross_origin_submission=False,
            suspicious_form_actions=[],
            obfuscated_js=False,
            obfuscation_indicators=[],
            hidden_iframes=False,
            harvesting_detected=False,
            severity="SAFE",
        )

    soup = BeautifulSoup(html_content, "html.parser")
    parsed_origin = urlparse(current_origin if "://" in current_origin else f"https://{current_origin}")
    origin_netloc = parsed_origin.netloc.lower()

    forms = soup.find_all("form")
    sensitive_inputs_found: list[str] = []
    has_password_field = False
    cross_origin_submission = False
    suspicious_form_actions: list[str] = []

    for form in forms:
        action = form.get("action", "")
        if action:
            parsed_action = urlparse(action)
            action_netloc = parsed_action.netloc.lower()
            if action_netloc and action_netloc != origin_netloc:
                cross_origin_submission = True
                suspicious_form_actions.append(action)

        inputs = form.find_all(["input", "textarea", "select"])
        for inp in inputs:
            inp_type = (inp.get("type") or "").lower()
            inp_name = (inp.get("name") or "").lower()
            inp_id = (inp.get("id") or "").lower()
            inp_placeholder = (inp.get("placeholder") or "").lower()

            if inp_type == "password":
                has_password_field = True
                sensitive_inputs_found.append("password_input")

            combined_descriptor = f"{inp_name} {inp_id} {inp_placeholder}"
            for pattern in SENSITIVE_FIELD_PATTERNS:
                if re.search(pattern, combined_descriptor):
                    sensitive_inputs_found.append(f"sensitive_token({pattern})")
                    break

    obfuscated_js = False
    obfuscation_indicators: list[str] = []
    scripts = soup.find_all("script")
    for script in scripts:
        script_text = script.string or ""
        if "eval(unescape(" in script_text or "eval(atob(" in script_text:
            obfuscated_js = True
            obfuscation_indicators.append("eval_unescape_or_atob")
        if re.search(r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}", script_text):
            obfuscated_js = True
            obfuscation_indicators.append("hex_packed_payload")

    hidden_iframes = False
    iframes = soup.find_all("iframe")
    for iframe in iframes:
        style = (iframe.get("style") or "").lower()
        if "width: 100%" in style or "opacity: 0" in style or "visibility: hidden" in style:
            hidden_iframes = True

    unique_sensitive_inputs = list(set(sensitive_inputs_found))
    severity = "SAFE"
    harvesting_detected = False

    if cross_origin_submission and has_password_field:
        severity = "CRITICAL"
        harvesting_detected = True
    elif has_password_field or len(unique_sensitive_inputs) >= 2 or obfuscated_js:
        severity = "SUSPICIOUS"
        harvesting_detected = True

    return DomHarvestingSchema(
        forms_count=len(forms),
        has_password_field=has_password_field,
        sensitive_inputs_found=unique_sensitive_inputs,
        cross_origin_submission=cross_origin_submission,
        suspicious_form_actions=suspicious_form_actions,
        obfuscated_js=obfuscated_js,
        obfuscation_indicators=obfuscation_indicators,
        hidden_iframes=hidden_iframes,
        harvesting_detected=harvesting_detected,
        severity=severity,
    )
