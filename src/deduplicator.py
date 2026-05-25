from collections import defaultdict
from typing import List, Dict, Tuple

from src.models import Vulnerability


def group_vulnerabilities(
    vulnerabilities: List[Vulnerability]
) -> Dict[Tuple[str, str], List[Vulnerability]]:

    grouped = defaultdict(list)

    for vuln in vulnerabilities:

        key = (
            vuln.package.lower(),
            vuln.family,
            vuln.severity
        )

        grouped[key].append(vuln)

    return grouped