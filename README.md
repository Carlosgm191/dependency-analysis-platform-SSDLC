# Dependency Analysis Platform (DAP)

[![DevSecOps Pipeline](https://github.com/Carlosgm191/dependency-analysis-platform-SSDLC/actions/workflows/security.yml/badge.svg)]
![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)

## Project Overview
The **Dependency Analysis Platform (DAP)** is a centralized security orchestration tool designed to bridge the gap between continuous integration and threat intelligence. Developed as part of the *Software Development Lifecycle Security* course, this platform automates the ingestion, parsing, and prioritization of software vulnerabilities across custom code and third-party dependencies.

The project is architected across three fundamental pillars, mirroring a mature DevSecOps ecosystem:
* **Layer 1: Core Functional Prototype** (SCA Engine & Data Parsing)
* **Layer 2: SSDLC Integration** (Threat Modeling & Custom Risk Scoring)
* **Layer 3: DevSecOps Automation** (CI/CD Quality Gates & Secret Scanning)

---

## 📊 Milestone 2: Evidence Dashboard

| Goal | Evidence Type | Verification |
| :--- | :--- | :--- |
| **Active Repo** | Git History | [View Commits](https://github.com/your-username/your-repo/commits/main) |
| **Functional Scanner** | Local CLI | Run `python src/scanner.py` to see JSON output. |
| **Vulnerability Scoring** | Algorithm | Check `weighted_risk_score` in `db_scan_results.json`. |
| **SAST Integration** | Pipeline | Check GitHub Actions tab for Semgrep results. |
| **Secret Scanning** | Pipeline | Check GitHub Actions tab for TruffleHog logs. |
| **Threat Analysis** | Documentation | Refer to [docs/THREAT_MODEL.md](./docs/THREAT_MODEL.md). |

## System Architecture & 3-Layer Implementation

### Layer 1: Core Scanner & Parser
The engine executes continuous Software Composition Analysis (SCA). It identifies known vulnerabilities in project dependencies by intersecting local manifests with global vulnerability databases.
* **Dynamic Ingestion:** Extracts data from `requirements.txt`.
* **Standardized Output:** Normalizes raw security advisories into a structured JSON database format for downstream analysis.

### Layer 2: SSDLC Security & Risk Scoring
Security is embedded into the DAP's DNA. We incorporate a **STRIDE-based Threat Model** to safeguard the platform's data flow and implement a proprietary algorithm to calculate a **Weighted Risk Score**.
* **Contextual Risk Categorization:** Instead of relying solely on generic CVSS scores, DAP computes a risk level (RED/GREEN) based on the volume and exploitability of critical exposures.
* **Threat Resilience:** The architecture is designed to handle untrusted JSON inputs and mitigate tampering risks during the analysis phase.

### Layer 3: DevSecOps & CI/CD Guardrails
The DAP repository operates under strict security policies enforced via GitHub Actions, serving as a "living example" of a secure pipeline.
* **Hardcoded Secrets Detection:** Powered by *TruffleHog* to prevent API keys or credentials leakage within the source code.
* **Static Application Security Testing (SAST):** Powered by *Semgrep* to analyze Python source code against common OWASP Top 10 vulnerabilities.

---

## Detailed Implementation Breakdown

### 🔧 Core Implementation (Step 2: Functional Prototype)
The primary engine, located in `src/scanner.py`, follows a strict functional flow:
1.  **Ingestion:** Reads the `requirements.txt` manifest.
2.  **Audit:** Triggers an automated scan against the PyPA (Python Packaging Advisory) database.
3.  **Risk Calculation:** The engine applies the following weighting logic:
    * **CRITICAL:** 10 points
    * **HIGH:** 7 points
    * **MODERATE:** 4 points
4.  **Reporting:** Generates a `db_scan_results.json` file for historical tracking.

### Automation Workflow (Step 3: Security Pipeline)
The pipeline is defined in `.github/workflows/security-pipeline.yml`. It ensures that the code meets the following security standards before merging:

```yaml
# Simplified Pipeline View
jobs:
  security-checks:
    steps:
      - name: Secret Scan (TruffleHog)
        # Prevents leaking API Keys/Passwords
      - name: Code Analysis (Semgrep)
        # Checks for SQLi, XSS, and insecure OS calls
      - name: Dependency Audit (pip-audit)
        # Checks the project's own dependencies

## Getting Started

Follow these instructions to set up the platform locally and execute your first security audit.

### Prerequisites
* **Python 3.9+**: Ensure Python is installed (`python --version`).
* **Git**: Required for version control and pipeline triggers.
* **Virtual Environment**: Recommended to avoid dependency conflicts.

### Installation & Setup
1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/your-username/your-repo.git](https://github.com/your-username/your-repo.git)
    cd your-repo
    ```

2.  **Initialize Environment:**
    Create and activate a virtual environment to manage security tooling.
    ```bash
    python -m venv venv
    # On Windows:
    venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate
    ```

3.  **Deploy Dependencies:**
    Install the core analysis engine and the required audit tools.
    ```bash
    pip install -r requirements.txt
    pip install pip-audit  # Primary SCA tool
    ```

### Running a Local Security Audit
To demonstrate the **Layer 1** functionality, execute the main scanner. This will parse your `requirements.txt`, query vulnerability databases, and generate a prioritized report.
```bash
python src/scanner.py