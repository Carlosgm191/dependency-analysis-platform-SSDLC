import subprocess
from src.scanner import build_report, run_pipaudit_scan

def test_build_report_fails_on_vulnerability():
    report = build_report([{"severity": "HIGH"}])
    assert report["status"] == "FAILED"
    assert report["risk_level"] == "RED"
    assert report["weighted_risk_score"] == 7

def test_run_pipaudit_scan_returns_empty_on_missing_binary(monkeypatch):
    def _raise_file_not_found(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", _raise_file_not_found)
    assert run_pipaudit_scan("requirements.txt") == []


def test_run_pipaudit_scan_returns_empty_on_invalid_json(monkeypatch):
    def _fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=2,
            stdout="not-json",
            stderr="parse error",
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)
    assert run_pipaudit_scan("requirements.txt") == []
