
from urllib.parse import urlparse


def check_https(url):
    """Check whether the supplied website URL uses HTTPS."""

    parsed = urlparse(url)

    if parsed.scheme == "https":
        return {
            "name": "HTTPS",
            "status": "Enabled",
            "risk": "Information",
            "message": "Website uses HTTPS."
        }

    return {
        "name": "HTTPS",
        "status": "Not Enabled",
        "risk": "High",
        "message": "Website URL does not use HTTPS."
    }
