from src.models import Vulnerability
from src.severity_normalizer import normalize_severity
from src.severity_engine import infer_severity

def normalize_pip_audit(raw_results):

    normalized = []

    dependencies = raw_results.get("dependencies", [])

    for dependency in dependencies:

        package_name = dependency.get("name")
        package_version = dependency.get("version")

        vulns = dependency.get("vulns", [])

        for vuln in vulns:

            normalized.append(
                Vulnerability(
                    vuln_id=vuln.get("id", "UNKNOWN"),
                    package=package_name,
                    version=package_version,
                    severity=normalize_severity(vuln.get("severity", "UNKNOWN")),
                    description=vuln.get("description", ""),
                    dread_score=vuln.get("dread_score", 0.0),
                    dread=vuln.get("dread", None)
                )
            )

    return normalized