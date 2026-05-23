import re

def calculate_dread(description: str, family: str) -> dict:
    """
    Calcula el riesgo DREAD de forma robusta usando pesos ponderados,
    análisis de vectores de ataque y mitigaciones mencionadas.
    """
    if not description:
        return {
            "damage": 5, "reproducibility": 5, "exploitability": 5,
            "affected_users": 5, "discoverability": 5,
            "score": 5.0, "severity": "MODERATE"
        }

    text = description.lower()
    fam = (family or "").lower()

    # --- 1. DICCIONARIOS DE INTELIGENCIA DE AMENAZAS ---
    KEYWORDS = {
        "damage": {
            10: ["rce", "remote code execution", "arbitrary code", "command injection", "sandbox escape", "root", "kernel"],
            8: ["sql injection", "authentication bypass", "privilege escalation", "ssrf", "account takeover"],
            6: ["dos", "denial of service", "directory traversal", "path traversal", "xss", "cross-site scripting"],
            4: ["info leak", "disclosure", "version leakage", "headers"]
        },
        "exploitability": {
            10: ["unauthenticated", "remote attacker", "no interaction", "zero-click", "easy"],
            7: ["authenticated", "network access", "user interaction required", "complex"],
            4: ["local access", "physical access", "specific configuration"]
        },
        "reproducibility": {
            10: ["public exploit", "poc available", "metasploit", "stable", "deterministic"],
            7: ["crafted request", "malicious input", "timing attack"],
            3: ["race condition", "intermittent", "unstable", "hard to reproduce"]
        }
    }

    # --- 2. LÓGICA DE EXTRACCIÓN DE VALORES ---
    
    def get_score(category_dict, default=5):
        for score, keywords in sorted(category_dict.items(), reverse=True):
            if any(k in text for k in keywords):
                return score
        return default

    d = get_score(KEYWORDS["damage"])
    e = get_score(KEYWORDS["exploitability"])
    r = get_score(KEYWORDS["reproducibility"])
    
    # AFFECTED USERS (A): Basado en el impacto sistémico
    a = 5
    if any(k in text for k in ["all users", "global", "default", "root", "admin"]): a = 10
    elif any(k in text for k in ["specific", "non-default", "optional"]): a = 3

    # DISCOVERABILITY (I): Basado en la madurez de la información
    i = 5
    if any(k in text for k in ["cve-", "ghsa-", "public advisory"]): i = 10
    elif "undisclosed" in text or "hidden" in text: i = 3

    # --- 3. REGLAS DE NEGOCIO AVANZADAS (Vectores Críticos) ---
    # Si es RCE y es Remoto, el daño es máximo y la explotabilidad sube
    if d == 10 and e >= 7:
        e = 10
        r = max(r, 8)
    
    # Penalización por mitigaciones mencionadas (False Positive Reduction)
    if any(k in text for k in ["requires manual configuration", "not enabled by default", "difficult to exploit"]):
        e = max(1, e - 3)
        r = max(1, r - 2)

    # --- 4. CÁLCULO PONDERADO ---
    # D:30%, R:20%, E:25%, A:15%, I:10%
    weighted_score = (
        (d * 3.0) + 
        (r * 2.0) + 
        (e * 2.5) + 
        (a * 1.5) + 
        (i * 1.0)
    ) / 10

    # --- 5. BOOSTS POR FAMILIA (Contexto del DAP) ---
    family_boosts = {
        "rce": 1.5,
        "injection": 1.0,
        "broken_auth": 1.0,
        "sensitive_data": 0.8,
        "ssrf": 0.8,
        "dos": 0.3
    }
    
    final_score = weighted_score + family_boosts.get(fam, 0)
    final_score = round(min(final_score, 10.0), 2)

    # --- 6. CATEGORIZACIÓN DE SEVERIDAD ---
    if final_score >= 9.0: severity = "CRITICAL"
    elif final_score >= 7.0: severity = "HIGH"
    elif final_score >= 4.0: severity = "MODERATE"
    else: severity = "LOW"

    return {
        "damage": d, "reproducibility": r, "exploitability": e,
        "affected_users": a, "discoverability": i,
        "score": final_score, "severity": severity
    }