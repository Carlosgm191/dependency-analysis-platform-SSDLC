import argparse
import json
import subprocess
from datetime import datetime, timezone
from .parser import calculate_custom_risk_score, normalize_tool_report


def determine_risk_level(vulnerabilities):
    severities = {v.get("severity", "LOW").upper() for v in vulnerabilities}
    if "CRITICAL" in severities or "HIGH" in severities:
        return "RED"
    if "MODERATE" in severities:
        return "YELLOW"
    return "GREEN"


def run_pipaudit_scan(requirements_file):
    try:
        result = subprocess.run(
            ['pip-audit', '-r', requirements_file, '-f', 'json'],
            capture_output=True,
            text=True,
            timeout=60
        )
    except FileNotFoundError:
        print("[!] pip-audit not installed")
        return []
    except subprocess.TimeoutExpired:
        print("[!] scan timeout")
        return []

    stdout = result.stdout or ""

    if not stdout.strip():
        return []

    try:
        raw = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    return normalize_tool_report(raw, "pipaudit")


def load_json_report(file_path, input_type):
    with open(file_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return normalize_tool_report(raw, input_type)


def enrich_vulnerabilities(vulnerabilities):
    enriched = []

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue

        vuln.setdefault("state", "open")
        vuln.setdefault("workflow_state", "open")
        vuln.setdefault(
            "created_at",
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )

        enriched.append(vuln)

    return enriched


def build_report(vulnerabilities):
    risk_data = calculate_custom_risk_score(vulnerabilities)

    summary = {
        "CRITICAL": sum(1 for v in vulnerabilities if v.get("severity") == "CRITICAL"),
        "HIGH": sum(1 for v in vulnerabilities if v.get("severity") == "HIGH"),
        "MODERATE": sum(1 for v in vulnerabilities if v.get("severity") == "MODERATE"),
        "LOW": sum(1 for v in vulnerabilities if v.get("severity") == "LOW"),
    }

    return {
        "project_name": "Dependency Analysis Platform",
        "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "weighted_risk_score": risk_data["weighted_score"],
        "risk_level": determine_risk_level(vulnerabilities),
        "status": "FAILED" if vulnerabilities else "PASSED",
        "critical_issues": risk_data["critical_issues"],
        "vulnerability_summary": summary,
        "details": vulnerabilities,
    }


# CLI opcional (NO guarda archivo)
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--requirements", default="requirements.txt")
    parser.add_argument("--input-json")
    parser.add_argument("--input-type", default="pipaudit")

    args = parser.parse_args()

    if args.input_json:
        vulnerabilities = load_json_report(args.input_json, args.input_type)
    else:
        vulnerabilities = run_pipaudit_scan(args.requirements)

    vulnerabilities = enrich_vulnerabilities(vulnerabilities)
    report = build_report(vulnerabilities)

    print(f"[+] Scan done. Score: {report['weighted_risk_score']}")


if __name__ == "__main__":
    main()