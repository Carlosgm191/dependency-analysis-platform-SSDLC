from src.models import Vulnerability
from src.severity_normalizer import normalize_severity
from src.family_classifier import classify_family
from src.dread_engine import calculate_dread


def normalize_trivy(raw_data):

    vulnerabilities = []

    results = raw_data.get("Results", [])

    if not results:
        return []

    for result in results:

        vulns = result.get("Vulnerabilities", [])
        
        if not vulns:
            continue

        for vuln in vulns:

            description = vuln.get("Title", "") or ""

            package = vuln.get("PkgName", "unknown")
            version = vuln.get("InstalledVersion", "unknown")
            vuln_id = vuln.get("VulnerabilityID", "unknown")

            # 1. family classification
            family = classify_family(description)

            # 2. severity normalization (Trivy viene con su propia severidad)
            severity = normalize_severity(vuln.get("Severity", "UNKNOWN"))

            # 3. DREAD computation (ESTO FALTABA)
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