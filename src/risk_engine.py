def calculate_risk(grouped_vulnerabilities):

    weights = {

        "CRITICAL": 10,
        "HIGH": 7,
        "MODERATE": 4,
        "LOW": 1
    }

    total_score = 0

    for _, group in grouped_vulnerabilities.items():

        max_weight = 0

        for vuln in group:

            severity_weight = weights.get(
                vuln.severity,
                1
            )

            if severity_weight > max_weight:
                max_weight = severity_weight

        total_score += max_weight

    return total_score