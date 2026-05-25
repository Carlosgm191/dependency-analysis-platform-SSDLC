from src.models import Vulnerability
from src.severity_normalizer import normalize_severity
from src.family_classifier import classify_family
from src.dread_engine import calculate_dread

def normalize_grype(raw_data):
    vulnerabilities = []
    
    # Grype guarda los hallazgos en la lista 'matches'
    matches = raw_data.get("matches", [])
    
    if not matches:
        return []

    for match in matches:
        vuln_info = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        
        # Extraemos los datos básicos
        vuln_id = vuln_info.get("id", "Unknown-CVE")
        package = artifact.get("name", "unknown")
        version = artifact.get("version", "unknown")
        
        # Obtenemos la descripción
        description = vuln_info.get("description") or f"Vulnerabilidad {vuln_id} en {package}"
        
        # --- AQUÍ ESTABA EL ERROR ---
        # Ahora sí, llamamos a tus funciones importadas
        raw_severity = vuln_info.get("severity", "UNKNOWN").upper()
        severity = normalize_severity(raw_severity)
        
        family = classify_family(description)
        dread = calculate_dread(description, family)
        # -----------------------------

        vulnerabilities.append(
            Vulnerability(
                package=package,
                version=version,
                vuln_id=vuln_id,
                severity=severity,
                description=description,
                family=family,
                dread_score=dread["score"],
                dread=dread
            )
        )
    return vulnerabilities