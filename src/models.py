from dataclasses import dataclass, field

@dataclass
class Vulnerability:

    vuln_id: str

    package: str

    version: str

    severity: str

    description: str

    family: str = "UNKNOWN"

    dread: dict = field(default_factory=dict)

    dread_score: float = 0.0