def _extract_cvss_score(vuln):
    cvss_data = vuln.get("cvss")

    if isinstance(cvss_data, (int, float)):
        return float(cvss_data)

    if isinstance(cvss_data, dict):
        score = cvss_data.get("score", cvss_data.get("baseScore"))
        if isinstance(score, (int, float)):
            return float(score)
        if isinstance(score, str):
            try:
                return float(score)
            except ValueError:
                return None

    if isinstance(cvss_data, list):
        for item in cvss_data:
            if not isinstance(item, dict):
                continue
            score = item.get("score", item.get("baseScore"))
            if isinstance(score, (int, float)):
                return float(score)
            if isinstance(score, str):
                try:
                    return float(score)
                except ValueError:
                    continue
    return None


def _extract_cvss_vector(vuln):
    cvss_data = vuln.get("cvss")
    candidates = []

    if isinstance(cvss_data, dict):
        candidates.append(cvss_data)
    elif isinstance(cvss_data, list):
        candidates.extend(item for item in cvss_data if isinstance(item, dict))

    for candidate in candidates:
        for key in ("vector", "vectorString", "cvssV3Vector"):
            vector = candidate.get(key)
            if isinstance(vector, str) and "CVSS:" in vector.upper():
                return vector.upper()
    return None


def _heuristic_severity(vuln):
    vector = _extract_cvss_vector(vuln)
    
    if vector:
        high_impact = sum(token in vector for token in ("C:H", "I:H", "A:H"))
        no_privileges = "PR:N" in vector
        no_ui = "UI:N" in vector

        if high_impact >= 2 and no_privileges and no_ui:
            return "CRITICAL"

        if high_impact >= 1:
            return "HIGH"

        return "MODERATE"

    description = " ".join(
        str(vuln.get(field, ""))
        for field in ("description", "summary", "details")
        if vuln.get(field)
    ).lower()

    critical_terms = (
        "remote code execution",
        "rce",
        "arbitrary code execution",
    )

    high_terms = (
        "sql injection",
        "command injection",
        "privilege escalation",
        "auth bypass",
        "authentication bypass",
    )

    moderate_terms = (
        "xss",
        "cross-site scripting",
        "denial of service",
        "dos",
        "redos",
        "path traversal",
        "open redirect",
        "ssrf",
        "information disclosure",
        "memory consumption",
    )

    if any(term in description for term in critical_terms):
        return "CRITICAL"

    if any(term in description for term in high_terms):
        return "HIGH"

    if any(term in description for term in moderate_terms):
        return "MODERATE"

    aliases = vuln.get("aliases", [])
    normalized_aliases = [str(alias).upper() for alias in aliases] if isinstance(aliases, list) else []
    vuln_id = str(vuln.get("id", "")).upper()

    if any(alias.startswith(("CVE-", "GHSA-")) for alias in normalized_aliases) or vuln_id.startswith(("CVE-", "GHSA-")):
        return "MODERATE"

    return "LOW"


def infer_severity(vuln):
    if not vuln:
        return "LOW"
    
    raw_severity = vuln.get("severity")
    if isinstance(raw_severity, str):
        severity = raw_severity.strip().upper()
        if severity == "MEDIUM":
            return "MODERATE"
        if severity in {"CRITICAL", "HIGH", "MODERATE", "LOW"}:
            return severity

    cvss_score = _extract_cvss_score(vuln)
    if isinstance(cvss_score, (int, float)):
        if cvss_score >= 9.0:
            return "CRITICAL"
        if cvss_score >= 7.0:
            return "HIGH"
        if cvss_score >= 4.0:
            return "MODERATE"
        return "LOW"

    # Third criterion: heuristic classification when CVSS lacks enough information.
    return _heuristic_severity(vuln)

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
                if isinstance(severity, dict):
                    severity = severity.get("level") or severity.get("name")
                elif isinstance(severity, list):
                    severity = next(
                        (
                            item.get("level") or item.get("name")
                            for item in severity
                            if isinstance(item, dict) and (item.get("level") or item.get("name"))
                        ),
                        None,
                    )

                if not severity:
                    severity = infer_severity(vuln)
                else:
                    severity = str(severity).strip().upper()
                    if severity == "MEDIUM":
                        severity = "MODERATE"
                    if severity not in {"CRITICAL", "HIGH", "MODERATE", "LOW"}:
                        severity = infer_severity(vuln)

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
        "risk_level": "RED" if (critical_count > 0 or high_count > 0) else "GREEN",
        "weighted_score": total_score,
        "critical_issues": critical_count,
    }