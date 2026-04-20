import re

try:
    from packaging.version import InvalidVersion, Version
except ImportError:  # pragma: no cover - fallback if packaging is unavailable
    InvalidVersion = ValueError
    Version = None


def _parse_version(version):
    if version is None:
        return None
    text = str(version).strip()
    if not text:
        return None

    if Version is not None:
        try:
            return Version(text)
        except InvalidVersion:
            pass

    parts = re.findall(r"\d+", text)
    if not parts:
        return None
    return tuple(int(part) for part in parts)


def _version_lt(left, right):
    left, right = _normalize_versions_for_compare(left, right)
    return left < right


def _version_lte(left, right):
    left, right = _normalize_versions_for_compare(left, right)
    return left <= right


def _version_gte(left, right):
    left, right = _normalize_versions_for_compare(left, right)
    return left >= right


def _normalize_versions_for_compare(left, right):
    if Version is not None and isinstance(left, Version) and isinstance(right, Version):
        return left, right
    return _version_to_tuple(left), _version_to_tuple(right)


def _version_to_tuple(version):
    if isinstance(version, tuple):
        return version
    if Version is not None and isinstance(version, Version):
        release = version.release or (0,)
        return tuple(int(part) for part in release)

    parts = re.findall(r"\d+", str(version))
    if not parts:
        return (0,)
    return tuple(int(part) for part in parts)

def _parse_affected_text_ranges(text):
    if not isinstance(text, str):
        return []

    normalized = text.lower()
    ranges = []


    before_match = re.search(r"before\s+([0-9][a-z0-9.\-_+]*)", normalized)
    if before_match:
        upper = _parse_version(before_match.group(1))
        if upper is not None:
            ranges.append({"min": None, "max": upper, "include_min": True, "include_max": False})

    from_to_match = re.search(r"from\s+([0-9][a-z0-9.\-_+]*)\s+to\s+([0-9][a-z0-9.\-_+]*)", normalized)
    if from_to_match:
        lower = _parse_version(from_to_match.group(1))
        upper = _parse_version(from_to_match.group(2))
        if lower is not None and upper is not None:
            ranges.append({"min": lower, "max": upper, "include_min": True, "include_max": True})

    comparators = re.findall(r"(>=|<=|>|<)\s*([0-9][a-z0-9.\-_+]*)", normalized)
    if comparators:
        lower = None
        upper = None
        include_min = True
        include_max = True
        for operator, value in comparators:
            parsed = _parse_version(value)
            if parsed is None:
                continue
            if operator == ">=":
                lower = parsed
                include_min = True
            elif operator == ">":
                lower = parsed
                include_min = False
            elif operator == "<=":
                upper = parsed
                include_max = True
            elif operator == "<":
                upper = parsed
                include_max = False
        if lower is not None or upper is not None:
            ranges.append({"min": lower, "max": upper, "include_min": include_min, "include_max": include_max})

    return ranges


def _collect_affected_ranges(vuln):
    ranges = []
    introduced = _parse_version(vuln.get("introduced_in"))
    fixed_in = vuln.get("fixed_in")

    if isinstance(fixed_in, str):
        fixed = _parse_version(fixed_in)
        if introduced is not None and fixed is not None:
            ranges.append({"min": introduced, "max": fixed, "include_min": True, "include_max": False})
        elif fixed is not None:
            ranges.append({"min": None, "max": fixed, "include_min": True, "include_max": False})
    elif isinstance(fixed_in, list):
        for item in fixed_in:
            fixed = _parse_version(item)
            if fixed is None:
                continue
            if introduced is not None:
                ranges.append({"min": introduced, "max": fixed, "include_min": True, "include_max": False})
            else:
                ranges.append({"min": None, "max": fixed, "include_min": True, "include_max": False})
    elif introduced is not None:
        ranges.append({"min": introduced, "max": None, "include_min": True, "include_max": True})

    affected_versions = vuln.get("affected_versions")
    if isinstance(affected_versions, str):
        ranges.extend(_parse_affected_text_ranges(affected_versions))
    elif isinstance(affected_versions, list):
        for item in affected_versions:
            if isinstance(item, str):
                ranges.extend(_parse_affected_text_ranges(item))

    description = vuln.get("description")
    if isinstance(description, str):
        ranges.extend(_parse_affected_text_ranges(description))

    return ranges


def _is_version_in_range(version, range_data):
    lower = range_data.get("min")
    upper = range_data.get("max")
    include_min = range_data.get("include_min", True)
    include_max = range_data.get("include_max", True)

    if lower is not None:
        if include_min and not _version_gte(version, lower):
            return False
        if not include_min and _version_lte(version, lower):
            return False
    if upper is not None:
        if include_max and not _version_lte(version, upper):
            return False
        if not include_max and not _version_lt(version, upper):
            return False
    return True


def _is_vulnerability_applicable(package_version, vuln):
    parsed_version = _parse_version(package_version)
    if parsed_version is None:
        return True

    ranges = _collect_affected_ranges(vuln)
    if not ranges:
        return True

    return any(_is_version_in_range(parsed_version, range_data) for range_data in ranges)


def _is_non_empty(value):
    return value not in (None, "", [], {}, ())


def _entry_completeness(entry):
    populated_fields = sum(1 for value in entry.values() if _is_non_empty(value))
    description_length = len(str(entry.get("description", "")))
    return populated_fields, description_length


def _deduplicate_vulnerabilities(vulnerabilities):
    deduplicated = {}
    for vuln in vulnerabilities:
        key = (vuln.get("id"), vuln.get("package"), vuln.get("version"))
        existing = deduplicated.get(key)
        if existing is None or _entry_completeness(vuln) > _entry_completeness(existing):
            deduplicated[key] = vuln
    return list(deduplicated.values())

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

                if not _is_vulnerability_applicable(package_version, vuln):
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

        return _deduplicate_vulnerabilities(normalized)

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

    return _deduplicate_vulnerabilities(normalized)

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