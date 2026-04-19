def infer_severity(vuln):
    if not vuln:
        return "LOW"
    vuln_id = vuln.get("id", "").upper()
    if vuln_id.startswith("CVE-"):
        return "HIGH"
    if vuln_id.startswith("PYSEC-"):
        return "HIGH"
    return "MODERATE"

def normalize_tool_report(raw_report, tool_type):
    normalized = []

    if tool_type == "pipaudit":
        if isinstance(raw_report, dict) and "dependencies" in raw_report:
            raw_report = raw_report["dependencies"]

        for item in raw_report:
            if not isinstance(item, dict):
                continue

            package_name = item.get("name")
            package_version = item.get("version")

            for vuln in item.get("vulns", []):
                if not isinstance(vuln, dict):
                    continue

                severity = vuln.get("severity")
                if not severity:
                    severity = infer_severity(vuln)
                severity = severity.upper()

                normalized.append({
                    "id": vuln.get("id"),
                    "package": package_name,
                    "version": package_version,
                    "severity": severity,
                    "description": vuln.get("description", ""),
                    "reference": vuln.get("url"),
                })

        return normalized

    elif tool_type == "semgrep":
        for result in raw_report.get("results", []):
            extra = result.get("extra", {})
            severity = extra.get("severity", "LOW").upper()
            normalized.append({
                "id": result.get("check_id"),
                "package": result.get("path"),
                "version": None,
                "severity": severity,
                "description": extra.get("message", ""),
                "reference": extra.get("metadata", {}).get("reference"),
            })

    return normalized

def calculate_custom_risk_score(vulnerabilities):
    total_score = 0
    high_count = 0
    critical_count = 0

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "LOW").upper()
        if severity == "CRITICAL":
            total_score += 10
            critical_count += 1
        elif severity == "HIGH":
            total_score += 7
            high_count += 1
        elif severity == "MODERATE":
            total_score += 4
        else:
            total_score += 1

    return {
        "risk_level": "RED" if critical_count > 0 else ("YELLOW" if high_count > 0 else "GREEN"),
        "weighted_score": total_score,
        "critical_issues": critical_count,
    }