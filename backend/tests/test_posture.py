"""
Unit tests for Phase 3: Web Security Posture Scanner.
Tests HTTP security headers evaluation, grading algorithms, SSRF defense, and exposed leaks logic
using typed Pydantic models.
"""

import pytest
from engine.posture.header_scanner import audit_security_headers
from engine.posture.exposed_secrets import is_ssrf_safe_host, probe_exposed_endpoints


# -------------------------------------------------------------
# Tests 1 - 4: Security Headers Scoring & Letter Grades
# -------------------------------------------------------------
def test_perfect_security_headers_award_a_plus():
    """Websites with comprehensive defense-in-depth headers must receive Grade A+."""
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' cdn.example.com; frame-ancestors 'none'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()",
    }
    result = audit_security_headers(headers)
    assert result.posture_score == 100
    assert result.grade == "A+"
    assert result.passed_headers_count == 6
    assert result.failed_headers_count == 0


def test_missing_critical_headers_receive_grade_f():
    """Websites missing HSTS, CSP, and XFO must receive Grade F."""
    headers = {
        "Server": "Apache/2.4.41",
        "Content-Type": "text/html; charset=UTF-8",
    }
    result = audit_security_headers(headers)
    assert result.posture_score == 0
    assert result.grade == "F"
    assert result.failed_headers_count == 6


def test_partial_headers_receive_intermediate_grade():
    """Websites with some headers (HSTS and X-Content-Type-Options) receive a balanced score."""
    headers = {
        "Strict-Transport-Security": "max-age=15768000",
        "X-Content-Type-Options": "nosniff",
    }
    result = audit_security_headers(headers)
    assert result.posture_score == 40
    assert result.grade == "C"


def test_hsts_preload_criteria_checked():
    """HSTS with preload and includeSubDomains gets full credit."""
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    }
    res = audit_security_headers(headers)
    hsts_finding = next(f for f in res.findings if f.header == "Strict-Transport-Security")
    assert hsts_finding.status == "PASS"


# -------------------------------------------------------------
# Tests 5 - 7: SSRF Protection & Safe Probing
# -------------------------------------------------------------
def test_ssrf_filter_blocks_loopback_and_internal_ips():
    """Asserts that 127.0.0.1 and private ranges are blocked from external scanning."""
    assert is_ssrf_safe_host("127.0.0.1") is False
    assert is_ssrf_safe_host("localhost") is False


def test_ssrf_filter_permits_public_ips():
    """Public domains pass SSRF filter safely."""
    assert is_ssrf_safe_host("google.com") is True


@pytest.mark.anyio
async def test_exposed_secrets_handles_ssrf_blocked_hosts():
    """Probing an internal loopback IP is halted before making network calls."""
    res = await probe_exposed_endpoints("http://127.0.0.1:8080")
    assert res.probed is False
    assert "SSRF" in (res.reason or "")
