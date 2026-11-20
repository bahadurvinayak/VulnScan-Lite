
def calculate_security_score(findings):
    """Calculate an educational website security score."""

    score = 100

    deductions = {
        "High": 25,
        "Medium": 10,
        "Low": 5,
        "Information": 0
    }

    for finding in findings:
        severity = finding.get("severity", "Information")
        score -= deductions.get(severity, 0)

    # Keep score between 0 and 100.
    score = max(0, min(100, score))

    if score >= 80:
        rating = "Good"
    elif score >= 60:
        rating = "Moderate"
    else:
        rating = "Needs Improvement"

    return {
        "score": score,
        "rating": rating
    }


def classify_risks(findings):
    """Count findings by severity."""

    summary = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Information": 0
    }

    for finding in findings:
        severity = finding.get("severity", "Information")

        if severity in summary:
            summary[severity] += 1

    return summary
