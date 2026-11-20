
from flask import Flask, render_template, request
from config import Config
from urllib.parse import urlparse
import os
import ipaddress
import socket

from scanner.engine import scan_website
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

from scanner.database import (
    create_scan_table,
    save_scan,
    get_scan_history
)
from scanner.database import (
    create_scan_table,
    save_scan,
    get_scan_history,
    get_dashboard_stats
)
from flask import send_from_directory
from scanner.report_generator import generate_pdf_report


app = Flask(__name__)
app.config.from_object(Config)

os.makedirs(app.config["REPORT_FOLDER"], exist_ok=True)

# Step 10: Create database table
create_scan_table()


def validate_website_url(url):
    """Validate a public HTTP/HTTPS website URL."""

    if not url:
        return False, "Please enter a website URL."

    url = url.strip()

    if len(url) > 2048:
        return False, "URL is too long."

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False, "Only HTTP and HTTPS URLs are allowed."

        if not parsed.hostname:
            return False, "Please enter a valid website hostname."

        if parsed.username or parsed.password:
            return False, "URLs containing login credentials are not allowed."

        hostname = parsed.hostname

        if hostname.lower() == "localhost" or "." not in hostname:
            return False, "Local or invalid hostnames are not allowed."

        addresses = socket.getaddrinfo(
            hostname, None, type=socket.SOCK_STREAM
        )

        if not addresses:
            return False, "Website hostname could not be resolved."

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                return False, "Private or reserved network addresses are not allowed."

        return True, "Website URL is valid."

    except (ValueError, socket.gaierror, OSError):
        return False, "Invalid URL or hostname could not be resolved."


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    stats = get_dashboard_stats()
    return render_template("dashboard.html", stats=stats)


@app.route("/results")
def results():
    return render_template("results.html")


# Step 10: Scan History
@app.route("/history")
def history():
    scan_history = get_scan_history()

    return render_template(
        "history.html",
        scan_history=scan_history
    )
@app.route("/download-report/<int:scan_id>")
def download_report(scan_id):
    scan_history = get_scan_history()

    selected_scan = next(
        (item for item in scan_history if item["id"] == scan_id),
        None
    )

    if selected_scan is None:
        return "Scan report not found.", 404

    report_data = {
        "url": selected_scan["website_url"],
        "status_code": selected_scan["status_code"],
        "security_score": {
            "score": selected_scan["security_score"],
            "rating": selected_scan["risk_rating"]
        },
        "findings": selected_scan["findings"],
        "security_headers": []
    }

    filename = generate_pdf_report(report_data)

    return send_from_directory(
        app.config["REPORT_FOLDER"],
        filename,
        as_attachment=True
    )


# Main Website Scanner
@app.route("/scan", methods=["POST"])
def scan():

    website_url = request.form.get("url", "").strip()

    # Step 5: URL validation
    is_valid, message = validate_website_url(website_url)

    if not is_valid:
        return render_template(
            "index.html",
            scan_message=message,
            scan_success=False
        )

    # Step 6: Scanner engine
    scan_results = scan_website(website_url)

    if not scan_results["success"]:
        return render_template(
            "results.html",
            results=scan_results
        )

    headers = scan_results["headers"]

    # Step 7: Security checks
    scan_results["https_check"] = check_https(website_url)

    scan_results["security_headers"] = (
        check_security_headers(headers)
    )

    scan_results["cookie_checks"] = check_cookies(headers)

    scan_results["server_check"] = (
        check_server_disclosure(headers)
    )

    # Step 8: Vulnerability detection
    scan_results["findings"] = detect_vulnerabilities(
        scan_results
    )

    # Step 9: Risk assessment
    scan_results["security_score"] = calculate_security_score(
        scan_results["findings"]
    )

    scan_results["risk_summary"] = classify_risks(
        scan_results["findings"]
    )

    # Step 10.3: Save scan results to SQLite
    save_scan(scan_results)

    return render_template(
        "results.html",
        results=scan_results
    )


if __name__ == "__main__":
    app.run(debug=True)
