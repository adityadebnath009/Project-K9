"""
Sensitive Endpoints & Information Leakage Auditor
Passively inspects publicly accessible endpoints for source code exposure (/.git/HEAD)
and configuration leaks (/.env) into ExposedSecretsSchema.
"""

import ipaddress
import socket
from urllib.parse import urlparse
import httpx
from models.schemas import ExposedSecretsSchema, ExposedLeakFinding

PROBE_TARGETS = [
    {
        "path": "/.git/HEAD",
        "name": "Git Repository Metadata",
        "expected_indicator": "ref: refs/",
        "severity": "CRITICAL",
        "impact": "Exposed .git repository allows attackers to download entire application source code."
    },
    {
        "path": "/.env",
        "name": "Environment Variables & Secrets",
        "expected_indicator": "=",
        "severity": "CRITICAL",
        "impact": "Exposed .env file may leak database credentials, API keys, and secret tokens."
    },
    {
        "path": "/swagger.json",
        "name": "OpenAPI / Swagger Definition",
        "expected_indicator": "swagger",
        "severity": "LOW",
        "impact": "Public API documentation reveals internal endpoints and schemas."
    }
]

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.169.254/32"),
]


def is_ssrf_safe_host(hostname: str) -> bool:
    """Validates that destination hostname does not resolve to private or loopback IP ranges."""
    try:
        ip_str = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip_str)
        return not any(ip_obj in net for net in PRIVATE_NETWORKS)
    except (socket.gaierror, ValueError):
        return False


async def probe_exposed_endpoints(
    base_url: str,
    timeout_seconds: float = 2.0
) -> ExposedSecretsSchema:
    """
    Passively tests if common sensitive endpoints are accidentally public.
    Returns a typed ExposedSecretsSchema Pydantic model.
    """
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    scheme = parsed.scheme if parsed.scheme in ("http", "https") else "https"
    hostname = parsed.netloc.split(":")[0]

    if not is_ssrf_safe_host(hostname):
        return ExposedSecretsSchema(
            probed=False,
            reason="Host blocked by SSRF protection filter (resolves to private/internal IP)",
            leaks_count=0,
            has_critical_leaks=False,
            leaks=[],
        )

    leaks: list[ExposedLeakFinding] = []

    async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False) as client:
        for probe in PROBE_TARGETS:
            probe_url = f"{scheme}://{hostname}{probe['path']}"
            try:
                resp = await client.get(probe_url, headers={"User-Agent": "K9-Sentinel-Auditor/1.0"})
                if resp.status_code == 200 and probe["expected_indicator"] in resp.text[:200]:
                    leaks.append(ExposedLeakFinding(
                        name=probe["name"],
                        path=probe["path"],
                        url=probe_url,
                        severity=probe["severity"],
                        impact=probe["impact"],
                        status_code=resp.status_code,
                    ))
            except (httpx.TimeoutException, httpx.RequestError, OSError):
                continue

    has_critical_leaks = any(leak.severity == "CRITICAL" for leak in leaks)

    return ExposedSecretsSchema(
        probed=True,
        leaks_count=len(leaks),
        has_critical_leaks=has_critical_leaks,
        leaks=leaks,
    )


# Alias for orchestrator compatibility
probe_exposed_secrets = probe_exposed_endpoints
