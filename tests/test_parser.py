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