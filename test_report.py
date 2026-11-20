
import os

from scanner.report_generator import generate_pdf_report


def test_pdf_report_generation():
    scan_results = {
        "url": "https://example.com",
        "status_code": 200,
        "security_score": {
            "score": 85,
            "rating": "Good"
        },
        "findings": [
            {
                "title": "Missing CSP",
                "severity": "Medium",
                "description": "Content Security Policy header was not detected."
            }
        ],
        "security_headers": []
    }

    filename = generate_pdf_report(scan_results)

    filepath = os.path.join("reports", filename)

    assert os.path.exists(filepath)
    assert os.path.getsize(filepath) > 0

    os.remove(filepath)
