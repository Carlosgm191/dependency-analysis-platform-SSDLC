# Dependency Analysis Platform (DAP) 🛡️

[![DevSecOps Pipeline](https://github.com/Carlosgm191/dependency-analysis-platform-SSDLC/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/Carlosgm191/dependency-analysis-platform-SSDLC/actions/workflows/security-pipeline.yml)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![Architecture](https://img.shields.io/badge/Architecture-3--Layer%20SSDLC-brightgreen)
![Risk Engine](https://img.shields.io/badge/Risk%20Engine-Weighted%20DREAD-orange)

## 🎯 Executive Summary

The **Dependency Analysis Platform (DAP)** is a comprehensive Security Orchestration and Response prototype specialized in **Software Composition Analysis (SCA)**. Built as a core component for a Secure Software Development Life Cycle (SSDLC), DAP unifies findings from 5 industry-standard scanners and applies a sophisticated **Weighted DREAD Risk Model** to prioritize vulnerabilities based on actual environmental risk rather than static severity scores.

---

## 🚀 Key Technical Features

* **Multi-Engine Orchestration:** Simultaneously manages and normalizes outputs from `Grype`, `Trivy`, `OSV-Scanner`, `pip-audit`, and `Safety`.
* **Advanced DREAD Engine:** Custom scoring logic assessing Damage, Reproducibility, Exploitability, Affected Users, and Discoverability.
* **DevSecOps Governance:** Automated "Security Gates" that fail CI/CD builds if the **DREAD Score** exceeds critical thresholds.
* **Shift-Left PR Feedback:** Automated Markdown audit reports injected directly into Pull Request comments via GitHub Actions.
* **Secrets Detection:** Integrated `Gitleaks` stage to prevent credential exposure in the Git history.

---

## 🏗️ System Architecture: The 3-Layer Approach

### 🔹 Layer 1: Multi-Scanner Orchestration
DAP provides an abstraction layer for security tooling. It executes multiple scanners to eliminate vendor blind spots and parses various formats (JSON, SARIF) into a unified, strictly typed `Vulnerability` model.

### 🔹 Layer 2: Risk Intelligence (Weighted DREAD)
The platform evolves beyond standard CVSS by using a weighted risk formula that prioritizes impact and exploitability:

$$Score = \frac{(Damage \times 3.0) + (Reproducibility \times 2.0) + (Exploitability \times 2.5) + (Affected Users \times 1.5) + (Discoverability \times 1.0)}{10}$$

* **Contextual Escalation:** Automatically identifies "Wormable" threats (Remote + Unauthenticated + RCE) and adjusts scores to maximum critical levels.
* **False Positive Mitigation:** Analyzes scan descriptions for mitigation keywords (e.g., "non-default config required") to intelligently penalize exploitability.

### 🔹 Layer 3: DevSecOps Automation Pipeline
A fully automated workflow integrated into GitHub Actions:
1.  **Secrets Guard:** Scans commits for API keys/secrets before analysis begins.
2.  **SCA Orchestration:** Runs the tool suite and normalizes results.
3.  **Governance Gate:** Evaluates the **DREAD Score**. If any finding $\ge 8.5$, the build is failed.
4.  **Interactive Audit:** Publishes a Markdown summary in the PR to streamline developer remediation.

---

## 📊 Milestone 2: Evidence Dashboard

| Goal | Implementation | Verification |
| :--- | :--- | :--- |
| **Scanner Orchestration** | 5 Engines Integrated | See `src/scanners/` & `src/scanner.py` |
| **Risk Scoring** | Weighted DREAD Engine | Logic in `src/dread_engine.py` |
| **CI/CD Integration** | DevSecOps Pipeline | `.github/workflows/security-pipeline.yml` |
| **Supply Chain Security** | Gitleaks Integration | Pipeline job: `secrets-scan` |
| **Developer Feedback** | Automated PR Comments | `src/utils/report_gen.py` output in PRs |

---

## 🛠️ Installation & Usage

### Prerequisites
Ensure you have Python 3.10+ and the required binary scanners (Grype/Trivy) installed in your environment.

```bash
# Clone and enter repository
git clone [https://github.com/Carlosgm191/dependency-analysis-platform-SSDLC.git](https://github.com/Carlosgm191/dependency-analysis-platform-SSDLC.git)
cd dependency-analysis-platform-SSDLC
```

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
python -m src.scanner --requirements requirements-vuln.txt
```
