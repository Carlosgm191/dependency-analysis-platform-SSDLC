from src.scanner import build_report

def test_build_report_fails_on_vulnerability():
    report = build_report([{"severity": "HIGH"}])
    assert report["status"] == "FAILED"
    assert report["risk_level"] == "RED"
    assert report["weighted_risk_score"] == 7