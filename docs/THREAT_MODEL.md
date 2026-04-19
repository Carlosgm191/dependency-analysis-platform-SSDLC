# Threat Model: Dependency Analysis Platform (STRIDE)

This document outlines the security analysis of the DAP architecture to ensure the integrity of our vulnerability reports.

## Data Flow Diagram (DFD)
1. **User** provides `requirements.txt`.
2. **Scanner Engine** executes external audit tools.
3. **Parser** calculates the Weighted Risk Score.
4. **Database (JSON)** stores the final report.

## STRIDE Analysis

| Threat | Category | Mitigation in DAP |
| :--- | :--- | :--- |
| **Spoofing** | User Identity | Implementation of RBAC (Planned for Milestone 3). |
| **Tampering** | Data Integrity | Checksum validation of the `requirements.txt` before scanning. |
| **Repudiation** | Audit Trail | Automated logging of every scan execution with timestamps. |
| **Information Disclosure** | Privacy | Scan results are stored locally and encrypted in the CI/CD pipeline secrets. |
| **Denial of Service** | Availability | Resource limits on the Subprocess execution to prevent memory exhaustion. |
| **Elevation of Privilege** | Authorization | Use of non-root containers for the GitHub Actions execution. |