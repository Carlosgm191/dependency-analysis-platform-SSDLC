from src.models import Vulnerability
from src.deduplicator import group_vulnerabilities


def test_grouping():

    vulns = [

        Vulnerability(
            vuln_id="1",
            package="django",
            version="4.2",
            severity="HIGH",
            description="SQL injection vulnerability",
            source="pip-audit",
            family="sql_injection"
        ),

        Vulnerability(
            vuln_id="2",
            package="django",
            version="4.2",
            severity="MODERATE",
            description="Another SQL injection",
            source="pip-audit",
            family="sql_injection"
        ),

        Vulnerability(
            vuln_id="3",
            package="django",
            version="4.2",
            severity="MODERATE",
            description="Denial of service",
            source="pip-audit",
            family="dos"
        )
    ]

    grouped = group_vulnerabilities(vulns)

    assert len(grouped) == 2