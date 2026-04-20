# Dependency Analysis Platform (DAP)

[![DevSecOps Pipeline](https://github.com/Carlosgm191/dependency-analysis-platform-SSDLC/actions/workflows/security.yml/badge.svg)](https://github.com/Carlosgm191/dependency-analysis-platform-SSDLC/actions/workflows/security.yml)
![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)

## Project Overview

This repository contains a working prototype for Milestone 2: a dependency vulnerability scanner with risk scoring and pipeline evidence.

The **Dependency Analysis Platform (DAP)** is a security orchestration prototype that automates the ingestion, parsing, and prioritization of software vulnerabilities from dependency analysis tools. This project is built for the SSDLC course and demonstrates how to manage findings, calculate risk, and integrate security controls into a CI/CD pipeline.

## 📊 Milestone 2: Evidence Dashboard

| Goal | Evidence | Verification |
| :--- | :--- | :--- |
| **Active Repository** | Git History | [Commits](https://github.com/Carlosgm191/dependency-analysis-platform-SSDLC/commits/main) |
| **Functional Scanner** | Local CLI | Run `python src/scanner.py` and inspect `db_scan_results.json` |
| **Vulnerability Scoring** | Risk Report | `weighted_risk_score` and `risk_level` in `db_scan_results.json` |
| **Dependency Scanning** | CI Job | `.github/workflows/security.yml` runs `pip-audit` |
| **Static Analysis** | CI Job | `.github/workflows/security-pipeline.yml` runs `Semgrep` |
| **Threat Modeling** | Documentation | See `docs/THREAT_MODEL.md` |

## System Architecture & 3-Layer Implementation

### Layer 1: Core Scanner & Parser
The engine reads dependency manifests and normalizes vulnerability findings into a structured report.

- **Input:** `requirements.txt` or imported JSON scan results
- **Scanner:** executes `pip-audit`
- **Parser:** converts tool output into standardized findings
- **Output:** `db_scan_results.json`

### Layer 2: SSDLC Security & Risk Scoring
The platform enriches findings with risk scoring and tracking metadata.

- **Risk scoring:** converts severities into a `weighted_risk_score`
- **Risk levels:** `GREEN`, `YELLOW`, `RED`
- **Vulnerability states:** `open`, `in_progress`, `resolved`
- **Threat model:** documented in `docs/THREAT_MODEL.md`

### Layer 3: DevSecOps Automation
Security checks are integrated into GitHub Actions.

- **Dependency scanning:** `pip-audit`
- **Static scanning:** `Semgrep`
- **Quality gate:** pipeline is configured to fail when findings indicate serious risk

---

## How to Run

1. Create and activate a Python virtual environment:

```bash
python -m venv venv
source venv/bin/activate
```

2. Install  dependencies:

```bash
pip install -r requirements.txt
pip install pip-audit
```

3. Run the scanner with the default requirement (`requirements.txt`):

```bash
python -m src.scanner
```

4. (Optional) Scan a specific requirements file:

```bash
python -m src.scanner --requirements requirements-vuln-classic.txt
```

5. (Optional) Import an existing JSON report instead of running `pip-audit`:

```bash
python -m src.scanner --input-json docs/examples/semgrep-sample.json --input-type semgrep
```

6. Review the generated report:
```bash
cat db_scan_results.json
```

## Real vulnerability demos
Use the included sample manifests to validate behavior:
```bash
# Expected low/no findings profile
python -m src.scanner --requirements requirements-safe.txt

# Mixed profile
python -m src.scanner --requirements requirements-mixed.txt

# Intentionally vulnerable profile
python -m src.scanner --requirements requirements-vuln-classic.txt
```
