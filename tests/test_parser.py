import json
from src.parser import normalize_tool_report, calculate_custom_risk_score

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
    assert normalized[0]["severity"] == "HIGH"
    assert normalized[0]["id"] == "CVE-2026-27205"

def test_calculate_custom_risk_score_high():
    result = calculate_custom_risk_score([{"severity": "HIGH"}])
    assert result["weighted_score"] == 7
    assert result["risk_level"] == "YELLOW"