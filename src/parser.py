def calculate_custom_risk_score(vulnerabilities):
    """
    Asigna un score de 0 a 10 basado en la severidad encontrada.
    Prioriza vulnerabilidades críticas que requieren atención inmediata.
    """
    total_score = 0
    high_count = 0
    
    for vuln in vulnerabilities:
        # Extraemos la severidad (esto varía según la herramienta, adaptamos a pip-audit)
        severity = vuln.get('advisory', {}).get('severity', 'LOW').upper()
        
        if severity == 'CRITICAL':
            total_score += 10
            high_count += 1
        elif severity == 'HIGH':
            total_score += 7
            high_count += 1
        elif severity == 'MODERATE':
            total_score += 4
        else:
            total_score += 1
            
    # Retornamos un promedio o un valor ponderado
    return {
        "risk_level": "RED" if high_count > 0 else "GREEN",
        "weighted_score": total_score,
        "critical_issues": high_count
    }