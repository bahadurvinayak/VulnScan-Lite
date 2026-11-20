
def check_security_headers(headers):
    """Check common HTTP security response headers."""

    security_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking Protection",
        "X-Content-Type-Options": "MIME Sniffing Protection",
        "Referrer-Policy": "Referrer Information Protection",
        "Permissions-Policy": "Browser Permissions Control"
    }

    results = []

    for header, description in security_headers.items():

        if header in headers:
            results.append({
                "name": header,
                "description": description,
                "status": "Present",
                "risk": "Information"
            })

        else:
            results.append({
                "name": header,
                "description": description,
                "status": "Missing",
                "risk": "Review"
            })

    return results
