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


def test_run_safety_uses_python_module(monkeypatch):
    import sys
    from src.scanners.safety import run_safety

    captured = {}

    def _fake_run(cmd, capture_output, text):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="[]",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)
    run_safety("requirements.txt")

    assert captured["cmd"][0] == sys.executable
    assert captured["cmd"][1:] == ["-m", "safety", "check", "-r", "requirements.txt", "--output", "json", "--json-output-format", "1.1"]


def test_normalize_safety_supports_modern_json_report():
    from src.normalizers.safety import normalize_safety

    raw_data = {
        "report_meta": {
            "vulnerabilities_found": 1
        },
        "vulnerabilities": [
            {
                "vulnerability_id": "PYUP-2026-001",
                "package_name": "requests",
                "analyzed_version": "2.25.1",
                "advisory": "The Requests package has a known remote code execution issue.",
                "severity": "high"
            }
        ]
    }

    vulns = normalize_safety(raw_data)

    assert len(vulns) == 1
    assert vulns[0].package == "requests"
    assert vulns[0].version == "2.25.1"
    assert vulns[0].vuln_id == "PYUP-2026-001"
    assert vulns[0].severity == "HIGH"


def test_normalize_safety_supports_legacy_list_output():
    from src.normalizers.safety import normalize_safety

    raw_data = [["django", "==3.2.0", "3.2.0", "CVE-2023-1234 vulnerability found.", "PYUP-2023-1234"]]

    vulns = normalize_safety(raw_data)

    assert len(vulns) == 1
    assert vulns[0].package == "django"
    assert vulns[0].vuln_id == "PYUP-2023-1234"
