from src.models import Vulnerability
from src.family_classifier import classify_family
from src.severity_normalizer import normalize_severity
from src.dread_engine import calculate_dread


def normalize_osv(raw_data):

    vulnerabilities = []

    results = raw_data.get("results", [])

    for item in results:

        description = item.get("summary", "") + " " + item.get("details", "")

        package = item.get("package", "unknown")
        version = item.get("version", "unknown")
        vuln_id = item.get("id", "unknown")

        family = classify_family(description)
        severity = normalize_severity("UNKNOWN")

        dread = calculate_dread(description, family)

        vulnerabilities.append(
            Vulnerability(
                package=package,
                version=version,
                vuln_id=vuln_id,
                severity=severity,
                description=description,
                family=family,
                dread_score=dread["score"],
                dread=dread
            )
        )

    return vulnerabilities