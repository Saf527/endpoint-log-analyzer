"""Severity and finding scoring."""

SEVERITY_SCORE = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def score_finding(severity: str, supporting_indicators: int = 0) -> int:
    """Calculate a transparent 0-100 risk score."""
    base = SEVERITY_SCORE.get(severity.upper(), 1) * 20
    bonus = min(supporting_indicators * 10, 20)
    return min(base + bonus, 100)
