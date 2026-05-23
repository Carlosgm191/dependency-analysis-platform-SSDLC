import json
import sys
import argparse
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
from src.reporters import write_report_formats

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

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--scanner",
        default="pip-audit",
        choices=SCANNERS.keys(),
        help="Scanner engine to use"
    )

    parser.add_argument(
        "--requirements",
        default="requirements.txt",
        help="Requirements file to scan"
    )

    parser.add_argument(
        "--output-formats",
        default="json,sarif,csv",
        help="Comma-separated output formats: json,sarif,csv"
    )

    parser.add_argument(
        "--output-stem",
        default="db_scan_results",
        help="Output file stem without extension"
    )

    args = parser.parse_args()

    print(f"\n[+] Running {args.scanner} scanner...\n")

    selected_scanner = SCANNERS[args.scanner]

    try:
        raw_results = selected_scanner(args.requirements)
    except RuntimeError as e:
        print(f"[-] Scanner error: {e}")
        sys.exit(1)
    
    selected_normalizer = NORMALIZERS[args.scanner]

    vulnerabilities = selected_normalizer(raw_results)  

    for vuln in vulnerabilities:

        detected_family = classify_family(vuln.description)

        vuln.family = detected_family

        dread_result = calculate_dread(

            vuln.description,

            detected_family
        )

        vuln.dread = dread_result

        vuln.dread_score = dread_result["score"]

        vuln.severity = dread_result["severity"]

    grouped = group_vulnerabilities(vulnerabilities)

    risk_score = calculate_risk(grouped)

    if risk_score < 5:
        risk_level = "GREEN"

    elif risk_score < 15:
        risk_level = "YELLOW"

    else:
        risk_level = "RED"

    total_vulns = len(vulnerabilities)
    total_groups = len(grouped)

    print("=" * 50)
    print("DEPENDENCY ANALYSIS REPORT")
    print("=" * 50)

    print(f"\nTotal Vulnerabilities Found: {total_vulns}")
    print(f"Unique Vulnerability Groups: {total_groups}")

    print("\n" + "=" * 50)
    print("GROUPED FINDINGS")
    print("=" * 50)

    for index, (key, group) in enumerate(grouped.items(), start=1):

        package, family, severity = key

        print(f"\n[{index}] {package} | {family} | {severity}")
        print(f"    CVEs grouped: {len(group)}")
        average_dread = round(

            sum(v.dread_score for v in group) / len(group),

            2
        )

        print(f"    Average DREAD: {average_dread}")

    print("\n" + "=" * 50)
    print("RISK SUMMARY")
    print("=" * 50)

    print(f"\nGrouped Risk Score: {risk_score}")

    print(f"Risk Level: {risk_level}\n")

    report = {

        "project_name": "Dependency Analysis Platform",

        "scan_date": datetime.now(timezone.utc).isoformat(),

        "summary": {

            "total_vulnerabilities": total_vulns,

            "unique_groups": total_groups,

            "grouped_risk_score": risk_score,

            "risk_level": risk_level
        },

        "groups": []
    }

    for key, group in grouped.items():

        package, family, severity = key

        group_entry = {

            "package": package,

            "family": family,

            "group_severity": severity,

            "count": len(group),

            "vulnerabilities": []
        }

        for vuln in group:

            group_entry["vulnerabilities"].append({

                "id": vuln.vuln_id,

                "severity": vuln.severity,

                "description": vuln.description,

                "dread_score": vuln.dread_score,

                "dread": vuln.dread
            })

        report["groups"].append(group_entry)

    requested_formats = [f.strip() for f in args.output_formats.split(",") if f.strip()]
    output_paths = write_report_formats(report, requested_formats, args.output_stem)

    print("[+] Reports generated:")
    for fmt, path in output_paths.items():
        print(f"    - {fmt.upper()}: {path}")
    print()


if __name__ == "__main__":
    main()