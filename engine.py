
import time
import requests
from urllib.parse import urlparse


def scan_website(url):
    """
    Perform a lightweight HTTP security assessment.
    Only use on websites you own or are authorized to test.
    """

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {
            "success": False,
            "error": "Invalid website URL."
        }

    start_time = time.perf_counter()

    try:
        # Do not follow redirects automatically.
        # Keep TLS certificate verification enabled.
        with requests.Session() as session:
            session.trust_env = False

            response = session.get(
                url,
                timeout=10,
                allow_redirects=False,
                stream=True,
                headers={
                    "User-Agent": "VulnScan-Lite/1.0"
                }
            )

            elapsed_time = round(
                time.perf_counter() - start_time, 3
            )

            results = {
                "success": True,
                "url": url,
                "status_code": response.status_code,
                "status_message": response.reason,
                "server": response.headers.get("Server", "Not disclosed"),
                "content_type": response.headers.get(
                    "Content-Type", "Not disclosed"
                ),
                "response_time": elapsed_time,
                "headers": dict(response.headers),
                "redirect_detected": response.is_redirect,
                "redirect_location": response.headers.get(
                    "Location", "None"
                )
            }

            response.close()

            return results

    except requests.exceptions.SSLError:
        return {
            "success": False,
            "error": "SSL certificate verification failed."
        }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": "Website connection timed out."
        }

    except requests.exceptions.RequestException as error:
        return {
            "success": False,
            "error": str(error)
        }
