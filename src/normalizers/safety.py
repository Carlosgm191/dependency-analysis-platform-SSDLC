from src.models import Vulnerability
from src.severity_normalizer import normalize_severity
from src.family_classifier import classify_family
from src.dread_engine import calculate_dread

def normalize_safety(raw_data):
    vulnerabilities = []
    
    # El formato de Safety v1 es: [ [package, spec, current, desc, id], ... ]
    for item in raw_data:
        package = item[0]
        version = item[2]
        description = item[3]
        vuln_id = item[4]
        
        # Safety v1 no siempre da severidad, por eso DREAD es vital aquí
        family = classify_family(description)
        dread = calculate_dread(description, family)

        vulnerabilities.append(
            Vulnerability(
                package=package,
                version=version,
                vuln_id=vuln_id,
                severity=dread["severity"], # Usamos la de DREAD si el scanner no da una
                description=description,
                family=family,
                dread_score=dread["score"],
                dread=dread
            )
        )
    return vulnerabilities