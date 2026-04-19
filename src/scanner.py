import argparse
import json
import subprocess
from datetime import datetime
from .parser import calculate_custom_risk_score, normalize_tool_report

def determine_risk_level(vulnerabilities):
    severities = {v.get("severity", "LOW").upper() for v in vulnerabilities}
    if "CRITICAL" in severities or "HIGH" in severities:
        return "RED"
    if "MODERATE" in severities:
        return "YELLOW"
    return "GREEN"

def run_pipaudit_scan(requirements_file):
    result = subprocess.run(
        ['pip-audit', '-r', requirements_file, '-f', 'json'],
        capture_output=True, text=True
    )
    raw = json.loads(result.stdout or "[]")
    if not isinstance(raw, (list, dict)):
        print("[!] Unexpected pip-audit output:", raw)
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
        vuln.setdefault("created_at", datetime.utcnow().isoformat() + "Z")
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
        "scan_date": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ"),
        "weighted_risk_score": risk_data["weighted_score"],
        "risk_level": determine_risk_level(vulnerabilities),
        "status": "FAILED" if vulnerabilities else "PASSED",
        "critical_issues": risk_data["critical_issues"],
        "vulnerability_summary": summary,
        "details": vulnerabilities,
    }

def main():
    parser = argparse.ArgumentParser(description="DAP scanner")
    parser.add_argument("--requirements", default="requirements.txt")
    parser.add_argument("--input-json", help="Path to imported JSON report")
    parser.add_argument("--input-type", choices=["pipaudit", "semgrep"], default="pipaudit")
    args = parser.parse_args()

    if args.input_json:
        vulnerabilities = load_json_report(args.input_json, args.input_type)
    else:
        vulnerabilities = run_pipaudit_scan(args.requirements)

    vulnerabilities = enrich_vulnerabilities(vulnerabilities)
    report = build_report(vulnerabilities)

    with open("db_scan_results.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    print(f"[+] Scan complete. Weighted Risk Score: {report['weighted_risk_score']}")

if __name__ == "__main__":
    main()