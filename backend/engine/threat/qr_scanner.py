"""
QR Code Scam & Malicious UPI Payment Detector (Quishing Protection)
Decodes raw image bytes or Base64 QR codes, inspects embedded payloads,
and audits UPI payment parameters (VPA, payee name, prefilled amounts) for deceptive fraud.
"""

import io
import base64
import binascii
from urllib.parse import urlparse, parse_qs
from typing import Union
from PIL import Image
from pyzbar.pyzbar import decode as pyzbar_decode

from models.schemas import QrInspectionSchema, UpiPaymentDetails

# Sensitive keywords fraudsters abuse in individual VPAs to mimic authority
SUSPICIOUS_VPA_KEYWORDS = [
    "electricity", "bijli", "bescom", "tneb", "mseb", "uppcl",
    "sbi", "hdfc", "icici", "pnb", "axis", "kotak",
    "refund", "cashback", "lottery", "support", "helpdesk",
    "challan", "traffic", "police", "kyc", "verification"
]


def parse_upi_payment_uri(uri: str) -> UpiPaymentDetails:
    """
    Parses upi://pay URI according to NPCI UPI Linking Specifications.
    Audits for deceptive payee addresses posing as official institutions.
    """
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)

    pa = params.get("pa", [None])[0]  # Payee VPA
    pn = params.get("pn", [None])[0]  # Payee Name
    am = params.get("am", [None])[0]  # Amount
    cu = params.get("cu", ["INR"])[0]  # Currency
    tn = params.get("tn", [None])[0]  # Transaction Note

    is_suspicious = False
    reasons = []

    if pa:
        pa_lower = pa.lower()
        vpa_user = pa_lower.split("@")[0] if "@" in pa_lower else pa_lower
        vpa_handle = pa_lower.split("@")[1] if "@" in pa_lower else ""

        # Individual consumer handles (e.g., @okhdfcbank, @paytm, @ybl) posing as corporate/utility
        for kw in SUSPICIOUS_VPA_KEYWORDS:
            if kw in vpa_user:
                is_suspicious = True
                reasons.append(f"Individual PSP handle '{pa}' masquerades as official authority '{kw.upper()}'")
                break

    if am and float(am) > 10000:
        reasons.append(f"Unusually high automated payment demand: INR {am}")

    return UpiPaymentDetails(
        is_upi=True,
        payee_vpa=pa,
        payee_name=pn,
        amount=am,
        currency=cu,
        transaction_note=tn,
        is_suspicious_vpa=is_suspicious,
        suspicious_reasons=reasons,
    )


def decode_qr_image(image_input: Union[bytes, str]) -> QrInspectionSchema:
    """
    Decodes a QR code image from raw bytes or a base64 encoded string.
    Returns typed QrInspectionSchema.
    """
    raw_bytes: bytes

    try:
        if isinstance(image_input, str):
            clean_str = image_input.strip()
            if clean_str.lower().startswith("upi://pay"):
                upi_info = parse_upi_payment_uri(clean_str)
                return QrInspectionSchema(
                    decoded=True,
                    raw_payload=clean_str,
                    payload_type="upi_payment",
                    upi_details=upi_info,
                )
            if clean_str.startswith(("http://", "https://")) and "base64," not in clean_str:
                return QrInspectionSchema(
                    decoded=True,
                    raw_payload=clean_str,
                    payload_type="url",
                )
            # Strip data URL prefix if present (e.g., data:image/png;base64,...)
            clean_b64 = image_input.split("base64,")[-1].strip()
            raw_bytes = base64.b64decode(clean_b64)
        elif isinstance(image_input, bytes):
            raw_bytes = image_input
        else:
            return QrInspectionSchema(
                decoded=False,
                raw_payload="",
                error="Unsupported image input type; expected bytes or base64 string.",
            )

        image = Image.open(io.BytesIO(raw_bytes))
        decoded_symbols = pyzbar_decode(image)

        if not decoded_symbols:
            return QrInspectionSchema(
                decoded=False,
                raw_payload="",
                error="No valid QR code symbol detected in provided image.",
            )

        payload = decoded_symbols[0].data.decode("utf-8", errors="replace").strip()

        # Classify and audit payload
        if payload.lower().startswith("upi://pay"):
            upi_info = parse_upi_payment_uri(payload)
            return QrInspectionSchema(
                decoded=True,
                raw_payload=payload,
                payload_type="upi_payment",
                upi_details=upi_info,
            )
        elif payload.startswith(("http://", "https://")):
            return QrInspectionSchema(
                decoded=True,
                raw_payload=payload,
                payload_type="url",
            )
        else:
            return QrInspectionSchema(
                decoded=True,
                raw_payload=payload,
                payload_type="plain_text",
            )

    except (ValueError, TypeError, OSError, binascii.Error) as err:
        return QrInspectionSchema(
            decoded=False,
            raw_payload="",
            error=f"Failed to process or decode image: {err}",
        )
