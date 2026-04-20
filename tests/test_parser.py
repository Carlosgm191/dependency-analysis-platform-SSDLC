from src.parser import infer_severity, normalize_tool_report, calculate_custom_risk_score

def test_normalize_pipaudit_dependencies():
    raw = {
        "dependencies": [
            {
                "name": "flask",
                "version": "0.12",
                "vulns": [
                    {"id": "CVE-2026-27205", "description": "test"},
                ],
            }
        ]
    }
    normalized = normalize_tool_report(raw, "pipaudit")
    assert normalized[0]["package"] == "flask"
    assert normalized[0]["severity"] == "MODERATE"
    assert normalized[0]["id"] == "CVE-2026-27205"

def test_calculate_custom_risk_score_high():
    result = calculate_custom_risk_score([{"severity": "HIGH"}])
    assert result["weighted_score"] == 7
    assert result["risk_level"] == "RED"


def test_infer_severity_from_cvss_dict_medium():
    severity = infer_severity({"cvss": {"score": 5.6}})
    assert severity == "MODERATE"


def test_infer_severity_uses_alias_heuristic_when_no_cvss():
    severity = infer_severity({"aliases": ["CVE-2026-99999"]})
    assert severity == "MODERATE"


def test_infer_severity_from_cvss_vector_heuristic():
    severity = infer_severity({
        "cvss": [{"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    })
    assert severity == "CRITICAL"


def test_normalize_pipaudit_deduplicates_and_keeps_most_complete_entry():
    raw = {
        "dependencies": [
            {
                "name": "requests",
                "version": "2.20.0",
                "vulns": [
                    {"id": "CVE-2020-1234", "description": "short"},
                    {
                        "id": "CVE-2020-1234",
                        "description": "longer vulnerability description with more detail",
                        "url": "https://example.com/CVE-2020-1234",
                    },
                ],
            }
        ]
    }

    normalized = normalize_tool_report(raw, "pipaudit")
    assert len(normalized) == 1
    assert normalized[0]["reference"] == "https://example.com/CVE-2020-1234"
    assert "more detail" in normalized[0]["description"]


def test_normalize_pipaudit_excludes_vuln_when_version_is_not_affected_by_fixed_in():
    raw = {
        "dependencies": [
            {
                "name": "examplepkg",
                "version": "2.2.4",
                "vulns": [
                    {
                        "id": "CVE-2026-0001",
                        "description": "Applies before 2.2.4",
                        "fixed_in": "2.2.4",
                    }
                ],
            }
        ]
    }

    normalized = normalize_tool_report(raw, "pipaudit")
    assert normalized == []


def test_normalize_pipaudit_includes_vuln_when_version_falls_in_description_range():
    raw = {
        "dependencies": [
            {
                "name": "examplepkg",
                "version": "2.2.5",
                "vulns": [
                    {
                        "id": "CVE-2026-0002",
                        "description": "Affected from 2.1 to 2.2.10",
                    }
                ],
            }
        ]
    }

    normalized = normalize_tool_report(raw, "pipaudit")
    assert len(normalized) == 1
    assert normalized[0]["id"] == "CVE-2026-0002"


def test_normalize_pipaudit_handles_mixed_version_types_without_crashing():
    raw = {
        "dependencies": [
            {
                "name": "examplepkg",
                "version": "2.2.5",
                "vulns": [
                    {
                        "id": "CVE-2026-0003",
                        "description": "Affected before 2.2.x",
                        "fixed_in": "2.2.x",
                    }
                ],
            }
        ]
    }

    normalized = normalize_tool_report(raw, "pipaudit")
    assert isinstance(normalized, list)
