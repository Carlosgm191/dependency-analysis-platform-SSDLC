import json
from datetime import datetime, timezone

from src.scanners.pip_audit import run_pip_audit
from src.normalizers.pip_audit import normalize_pip_audit

from src.scanners.trivy import run_trivy
from src.normalizers.trivy import normalize_trivy

from src.scanners.osv import run_osv
from src.normalizers.osv import normalize_osv

from src.scanners.safety import run_safety
from src.normalizers.safety import normalize_safety

from src.scanners.grype import run_grype
from src.normalizers.grype import normalize_grype

from src.family_classifier import classify_family
from src.deduplicator import group_vulnerabilities
from src.risk_engine import calculate_risk
from src.dread_engine import calculate_dread


SCANNERS = {

    "pip-audit": run_pip_audit,

    "trivy": run_trivy,

    "osv": run_osv,

    "safety": run_safety,

    "grype": run_grype
}


NORMALIZERS = {

    "pip-audit": normalize_pip_audit,

    "trivy": normalize_trivy,

    "osv": normalize_osv,

    "safety": normalize_safety,

    "grype": normalize_grype
}


def determine_risk_level(score):

    if score < 5:
        return "LOW"

    elif score < 15:
        return "MODERATE"

    elif score < 25:
        return "HIGH"

    return "CRITICAL"


def run_scan_pipeline(scanner_name, requirements_file):

    selected_scanner = SCANNERS[scanner_name]

    raw_results = selected_scanner(requirements_file)

    selected_normalizer = NORMALIZERS[scanner_name]

    vulnerabilities = selected_normalizer(raw_results)

    for vuln in vulnerabilities:

        detected_family = classify_family(
            vuln.description
        )

        vuln.family = detected_family

        dread_result = calculate_dread(

            vuln.description,

            detected_family
        )

        vuln.dread = dread_result

        vuln.dread_score = dread_result["score"]

        vuln.severity = dread_result["severity"]

    grouped = group_vulnerabilities(
        vulnerabilities
    )

    report = build_report(
        vulnerabilities,
        grouped,
        scanner_name
    )

    return report


def build_report(vulnerabilities, grouped, scanner_name):

    risk_score = calculate_risk(grouped)

    summary = {

        "CRITICAL": sum(
            1 for v in vulnerabilities
            if v.severity == "CRITICAL"
        ),

        "HIGH": sum(
            1 for v in vulnerabilities
            if v.severity == "HIGH"
        ),

        "MODERATE": sum(
            1 for v in vulnerabilities
            if v.severity == "MODERATE"
        ),

        "LOW": sum(
            1 for v in vulnerabilities
            if v.severity == "LOW"
        )
    }

    details = []

    for vuln in vulnerabilities:

        details.append({

            "id": vuln.vuln_id,

            "package": vuln.package,

            "severity": vuln.severity,

            "description": vuln.description,

            "family": vuln.family,

            "dread_score": vuln.dread_score
        })

    return {

        "project_name": "Dependency Analysis Platform",

        "scanner": scanner_name,

        "scan_date": datetime.now(
            timezone.utc
        ).isoformat(),

        "weighted_risk_score": risk_score,

        "risk_level": determine_risk_level(
            risk_score
        ),

        "status": "FAILED" if vulnerabilities else "PASSED",

        "critical_issues": summary["CRITICAL"],

        "vulnerability_summary": summary,

        "details": details
    }