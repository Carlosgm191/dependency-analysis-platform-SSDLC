from src.models import Vulnerability
from src.risk_engine import calculate_risk


def test_grouped_risk():

    grouped = {

        ("django", "sql_injection"): [

            Vulnerability(
                vuln_id="1",
                package="django",
                version="4.2",
                severity="HIGH",
                description="SQLi",
                source="pip-audit",
                family="sql_injection"
            ),

            Vulnerability(
                vuln_id="2",
                package="django",
                version="4.2",
                severity="MODERATE",
                description="SQLi",
                source="pip-audit",
                family="sql_injection"
            )
        ],

        ("django", "dos"): [

            Vulnerability(
                vuln_id="3",
                package="django",
                version="4.2",
                severity="MODERATE",
                description="DoS",
                source="pip-audit",
                family="dos"
            )
        ]
    }

    score = calculate_risk(grouped)

    assert score == 11