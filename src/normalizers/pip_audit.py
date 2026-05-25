from src.models import Vulnerability
from src.severity_normalizer import normalize_severity
from src.dread_engine import calculate_dread
from src.family_classifier import classify_family

def normalize_pip_audit(raw_results):
    normalized = []
    
    # Verificamos qué tipo de dato recibimos
    if isinstance(raw_results, dict):
        dependencies = raw_results.get("dependencies", [])
    elif isinstance(raw_results, list):
        dependencies = raw_results
    else:
        print("[-] Normalizer error: raw_results is neither dict nor list")
        return []

    print(f"[*] Normalizing {len(dependencies)} dependencies from pip-audit...")

    for dependency in dependencies:
        package_name = dependency.get("name")
        package_version = dependency.get("version")
        vulns = dependency.get("vulns", [])

        if vulns:
            print(f"    [+] Found {len(vulns)} vulns in {package_name}")

        for vuln in vulns:
            try:
                description = vuln.get("description", "No description")
                vuln_id = vuln.get("id", "UNKNOWN")

                # Clasificación y DREAD
                family = classify_family(description)
                dread = calculate_dread(description, family)

                # Intentamos crear el objeto
                v = Vulnerability(
                    vuln_id=vuln_id,
                    package=package_name,
                    version=package_version,
                    severity=normalize_severity(vuln.get("severity", "UNKNOWN")),
                    description=description,
                    family=family,
                    dread_score=dread.get("score", 0),
                    dread=dread
                )
                normalized.append(v)
            except Exception as e:
                print(f"    [!] Error normalising vuln {vuln.get('id')}: {e}")

    return normalized