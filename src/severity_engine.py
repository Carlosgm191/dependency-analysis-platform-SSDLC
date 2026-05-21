from src.dread_engine import calculate_dread


def infer_severity(description: str) -> tuple:

    dread = calculate_dread(description)

    score = dread["score"]

    if score >= 9:
        severity = "CRITICAL"

    elif score >= 7:
        severity = "HIGH"

    elif score >= 4:
        severity = "MODERATE"

    else:
        severity = "LOW"

    return severity, dread