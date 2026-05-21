def normalize_severity(severity: str) -> str:

    if not severity:
        return "UNKNOWN"

    text = severity.strip().lower()

    mapping = {

        "critical": "CRITICAL",

        "high": "HIGH",

        "medium": "MODERATE",
        "moderate": "MODERATE",

        "low": "LOW",

        "unknown": "UNKNOWN"
    }

    return mapping.get(text, "UNKNOWN")