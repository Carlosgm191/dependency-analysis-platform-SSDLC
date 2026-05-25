import csv
import json
from pathlib import Path


def write_json(report: dict, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)


def write_csv(report: dict, output_path: str) -> None:
    rows = []
    for group in report.get("groups", []):
        package = group.get("package")
        family = group.get("family")
        group_severity = group.get("group_severity")
        count = group.get("count", 0)
        for vuln in group.get("vulnerabilities", []):
            rows.append(
                {
                    "package": package,
                    "family": family,
                    "group_severity": group_severity,
                    "group_count": count,
                    "vulnerability_id": vuln.get("id"),
                    "severity": vuln.get("severity"),
                    "description": vuln.get("description"),
                    "dread_score": vuln.get("dread_score"),
                }
            )

    fieldnames = [
        "package",
        "family",
        "group_severity",
        "group_count",
        "vulnerability_id",
        "severity",
        "description",
        "dread_score",
    ]

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _to_sarif_level(severity: str) -> str:
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MODERATE": "warning",
        "LOW": "note",
    }
    return mapping.get((severity or "").upper(), "warning")


def write_sarif(report: dict, output_path: str) -> None:
    results = []
    rules = {}

    for group in report.get("groups", []):
        package = group.get("package") or "unknown-package"
        family = group.get("family") or "unknown-family"
        for vuln in group.get("vulnerabilities", []):
            vuln_id = vuln.get("id") or "UNKNOWN"
            severity = vuln.get("severity") or "MODERATE"
            rule_id = f"DAP::{vuln_id}"

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": vuln_id,
                    "shortDescription": {"text": f"{vuln_id} in {package}"},
                    "fullDescription": {"text": vuln.get("description") or "No description provided."},
                    "properties": {
                        "tags": ["dependency", family],
                        "security-severity": str(vuln.get("dread_score", "")),
                    },
                }

            results.append(
                {
                    "ruleId": rule_id,
                    "level": _to_sarif_level(severity),
                    "message": {
                        "text": (
                            f"{vuln_id} detected in package '{package}' "
                            f"(family={family}, severity={severity}, dread_score={vuln.get('dread_score')})."
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": package}
                            }
                        }
                    ],
                    "properties": {
                        "family": family,
                        "package": package,
                        "severity": severity,
                        "dread": vuln.get("dread", {}),
                    },
                }
            )

    sarif_report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Dependency Analysis Platform",
                        "informationUri": "https://github.com/Carlosgm191/dependency-analysis-platform-SSDLC",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_report, f, indent=2)


def write_report_formats(report: dict, formats: list[str], output_stem: str) -> dict:
    output_paths = {}
    base = Path(output_stem)

    for fmt in formats:
        normalized = fmt.strip().lower()
        if normalized == "json":
            path = f"{base}.json"
            write_json(report, path)
            output_paths[normalized] = path
        elif normalized == "csv":
            path = f"{base}.csv"
            write_csv(report, path)
            output_paths[normalized] = path
        elif normalized == "sarif":
            path = f"{base}.sarif"
            write_sarif(report, path)
            output_paths[normalized] = path
        else:
            raise ValueError(f"Unsupported report format: {fmt}")

    return output_paths
