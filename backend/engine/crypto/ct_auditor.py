"""
Certificate Transparency (CT) Log Auditor
Asynchronously interrogates public Certificate Transparency logs (crt.sh)
to audit certificate velocity and identify anomalous issuances into CtLogSchema.
"""

import httpx
from models.schemas import CtLogSchema


async def query_certificate_transparency_logs(
    domain: str, 
    timeout_seconds: float = 3.0
) -> CtLogSchema:
    """
    Queries crt.sh API for domain certificate history with a strict fallback timeout.
    Returns a typed CtLogSchema Pydantic model.
    """
    cleaned_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    url = f"https://crt.sh/?q={cleaned_domain}&output=json"

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            resp = await client.get(url, headers={"User-Agent": "K9-Sentinel-Auditor/1.0"})
            if resp.status_code != 200:
                return CtLogSchema(
                    available=False,
                    records_count=0,
                    reason=f"crt.sh returned status {resp.status_code}",
                )

            data = resp.json()
            if not isinstance(data, list):
                return CtLogSchema(available=False, records_count=0, reason="Invalid response format")

            recent_certs = data[:10]
            issuers = list({entry.get("issuer_name", "Unknown") for entry in recent_certs})

            return CtLogSchema(
                available=True,
                records_count=len(data),
                recent_sample_count=len(recent_certs),
                issuers_seen=issuers[:5],
            )

    except (httpx.TimeoutException, httpx.RequestError) as err:
        return CtLogSchema(
            available=False,
            records_count=0,
            reason=f"CT log query skipped or timed out: {err}",
        )
