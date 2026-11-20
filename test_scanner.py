
import os
import tempfile

from scanner.headers import check_security_headers
from scanner.ssl_checker import check_https
from scanner.vulnerability_checks import (
    check_cookies,
    check_server_disclosure,
    detect_vulnerabilities
)
from scanner.risk_assessment import (
    calculate_security_score,
    classify_risks
)


def test_security_headers():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY"
    }

    results = check_security_headers(headers)

    assert len(results) == 6
    assert any(
        item["name"] == "Content-Security-Policy"
        and item["status"] == "Present"
        for item in results
    )


def test_https_check():
    result = check_https("https://example.com")
    assert result["status"] == "Enabled"

    result = check_https("http://example.com")
    assert result["status"] == "Not Enabled"


def test_cookie_check():
    headers = {
        "Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Lax"
    }

    results = check_cookies(headers)

    assert len(results) == 3
    assert all(item["status"] == "Present" for item in results)


def test_server_disclosure():
    result = check_server_disclosure({
        "Server": "ExampleServer"
    })

    assert result["status"] == "Disclosed"


def test_vulnerability_detection():
    scan_results = {
        "https_check": {"status": "Not Enabled"},
        "security_headers": [
            {
                "name": "Content-Security-Policy",
                "description": "Content Security Policy",
                "status": "Missing"
            }
        ],
        "cookie_checks": [],
        "server_check": {
            "status": "Not Disclosed"
        }
    }

    findings = detect_vulnerabilities(scan_results)

    assert len(findings) == 2
    assert any(
        item["title"] == "HTTPS Not Enabled"
        for item in findings
    )


def test_security_score():
    findings = [
        {"severity": "High"},
        {"severity": "Medium"},
        {"severity": "Low"}
    ]

    result = calculate_security_score(findings)

    assert result["score"] == 60
    assert result["rating"] == "Moderate"


def test_risk_classification():
    findings = [
        {"severity": "High"},
        {"severity": "High"},
        {"severity": "Medium"},
        {"severity": "Low"}
    ]

    result = classify_risks(findings)

    assert result["High"] == 2
    assert result["Medium"] == 1
    assert result["Low"] == 1
