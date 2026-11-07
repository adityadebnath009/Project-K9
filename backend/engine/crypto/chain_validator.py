"""
Live TLS Chain Fetcher & X.509 Trust Validator
Connects to live target hosts over TLS (port 443) with strict timeouts,
extracts the certificate chain, and parses validity, SANs, and issuer details into TlsChainSchema.
"""

import socket
import ssl
import datetime
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from models.schemas import TlsChainSchema


def fetch_and_validate_tls_chain(
    hostname: str, 
    port: int = 443, 
    timeout_seconds: float = 3.0
) -> tuple[TlsChainSchema, x509.Certificate | None]:
    """
    Connects to hostname:port over TLS, extracts peer certificate,
    and returns a typed TlsChainSchema alongside the raw x509.Certificate object.
    """
    cleaned_host = hostname.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((cleaned_host, port), timeout=timeout_seconds) as sock:
            with ctx.wrap_socket(sock, server_hostname=cleaned_host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                tls_version = ssock.version()

                if not der_cert:
                    return TlsChainSchema(
                        connected=False,
                        error="No peer certificate returned by server",
                    ), None

                cert = x509.load_der_x509_certificate(der_cert)
                schema = _parse_certificate_details(cert, cleaned_host, cipher, tls_version)
                return schema, cert

    except (socket.timeout, TimeoutError):
        return TlsChainSchema(
            connected=False,
            error=f"Connection timed out after {timeout_seconds}s connecting to {cleaned_host}:{port}",
        ), None
    except (socket.gaierror, ConnectionRefusedError, ssl.SSLError, OSError) as net_err:
        return TlsChainSchema(
            connected=False,
            error=f"TLS handshake failed: {net_err}",
        ), None


def _parse_certificate_details(
    cert: x509.Certificate, 
    expected_hostname: str, 
    cipher: tuple[str, str, int] | None, 
    tls_version: str | None
) -> TlsChainSchema:
    """Parses X.509 certificate fields into a clean TlsChainSchema Pydantic model."""
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    is_expired = now > not_after
    is_not_yet_valid = now < not_before
    days_until_expiry = (not_after - now).days

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [str(name) for name in san_ext.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        pass

    subject_cn = cert.subject.rfc4514_string()
    issuer_org = cert.issuer.rfc4514_string()
    is_self_signed = cert.subject == cert.issuer

    hostname_matches = expected_hostname in sans or any(
        s.startswith("*.") and expected_hostname.endswith(s[1:]) for s in sans
    ) if sans else False

    return TlsChainSchema(
        connected=True,
        subject=subject_cn,
        issuer=issuer_org,
        sans=sans,
        is_self_signed=is_self_signed,
        is_expired=is_expired,
        is_not_yet_valid=is_not_yet_valid,
        days_until_expiry=days_until_expiry,
        hostname_matches=hostname_matches,
        tls_version=tls_version,
        cipher=cipher[0] if cipher else "Unknown",
    )
