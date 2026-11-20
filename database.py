
import sqlite3
import json
from datetime import datetime, timezone
from config import Config


def get_connection():
    """Create a connection to the SQLite database."""

    connection = sqlite3.connect(Config.DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_scan_table():
    """Create scan history table if it does not exist."""

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website_url TEXT NOT NULL,
            status_code INTEGER,
            security_score INTEGER,
            risk_rating TEXT,
            findings TEXT,
            scan_date TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_scan(scan_results):
    """Save a successful scan to the database."""

    score_data = scan_results.get("security_score", {})
    findings = scan_results.get("findings", [])

    connection = get_connection()

    connection.execute("""
        INSERT INTO scan_history (
            website_url,
            status_code,
            security_score,
            risk_rating,
            findings,
            scan_date
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        scan_results.get("url", ""),
        scan_results.get("status_code"),
        score_data.get("score", 0),
        score_data.get("rating", "Unknown"),
        json.dumps(findings),
        datetime.now(timezone.utc).isoformat()
    ))

    connection.commit()
    connection.close()


def get_scan_history():
    """Retrieve previous scans, newest first."""

    connection = get_connection()

    records = connection.execute("""
        SELECT *
        FROM scan_history
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    history = []

    for record in records:
        item = dict(record)
        item["findings"] = json.loads(item["findings"] or "[]")
        history.append(item)

    return history
def get_dashboard_stats():
    connection = get_connection()

    total_scans = connection.execute(
        "SELECT COUNT(*) FROM scan_history"
    ).fetchone()[0]

    average_score = connection.execute(
        "SELECT AVG(security_score) FROM scan_history"
    ).fetchone()[0]

    risk_counts = connection.execute("""
        SELECT risk_rating, COUNT(*)
        FROM scan_history
        GROUP BY risk_rating
    """).fetchall()

    recent_scans = connection.execute("""
        SELECT id, website_url, security_score,
               risk_rating, scan_date
        FROM scan_history
        ORDER BY id DESC
        LIMIT 5
    """).fetchall()

    connection.close()

    return {
        "total_scans": total_scans,
        "average_score": round(average_score or 0, 1),
        "risk_counts": {
            row[0]: row[1] for row in risk_counts
        },
        "recent_scans": [dict(row) for row in recent_scans]
    }