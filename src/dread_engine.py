def calculate_dread(description: str, family: str) -> dict:

    if not description:
        return {
            "damage": 5,
            "reproducibility": 5,
            "exploitability": 5,
            "affected_users": 5,
            "discoverability": 5,
            "score": 5.0,
            "severity": "MODERATE"
        }

    text = (description or "").lower()
    family = (family or "").lower()

    damage = 5
    reproducibility = 5
    exploitability = 5
    affected_users = 5
    discoverability = 5

    # =========================
    # DAMAGE
    # =========================
    if any(keyword in text for keyword in [
        "remote code execution",
        "arbitrary code execution",
        "rce",
        "sandbox escape",
        "privilege escalation"
    ]):
        damage = 10

    elif any(keyword in text for keyword in [
        "credential leak",
        "man-in-the-middle",
        "authentication bypass"
    ]):
        damage = 8

    elif any(keyword in text for keyword in [
        "denial of service",
        "dos"
    ]):
        damage = 6

    # =========================
    # REPRODUCIBILITY
    # =========================
    if any(keyword in text for keyword in [
        "predictable filename",
        "public exploit",
        "easily exploitable"
    ]):
        reproducibility = 9

    elif any(keyword in text for keyword in [
        "crafted url",
        "malicious request"
    ]):
        reproducibility = 7

    # =========================
    # EXPLOITABILITY
    # =========================
    if any(keyword in text for keyword in [
        "remote attacker",
        "unauthenticated attacker"
    ]):
        exploitability = 9

    elif any(keyword in text for keyword in [
        "local attacker"
    ]):
        exploitability = 5

    # =========================
    # AFFECTED USERS
    # =========================
    if any(keyword in text for keyword in [
        "all users",
        "all applications",
        "widely used"
    ]):
        affected_users = 9

    elif any(keyword in text for keyword in [
        "specific configurations",
        "specific use cases"
    ]):
        affected_users = 4

    # =========================
    # DISCOVERABILITY
    # =========================
    if any(keyword in text for keyword in [
        "public advisory",
        "cve",
        "known vulnerability"
    ]):
        discoverability = 9

    elif any(keyword in text for keyword in [
        "hard to discover"
    ]):
        discoverability = 3

    # =========================
    # BASE SCORE
    # =========================
    score = round(
        (
            damage +
            reproducibility +
            exploitability +
            affected_users +
            discoverability
        ) / 5,
        2
    )

    # =========================
    # FAMILY BOOST
    # =========================
    if family in ["rce", "sandbox_escape"]:
        score += 2

    elif family in ["credential_leak", "ssrf"]:
        score += 1.5

    elif family in ["dos"]:
        score += 0.5

    # Clamp score
    if score > 10:
        score = 10

    # =========================
    # SEVERITY
    # =========================
    if score >= 8:
        severity = "CRITICAL"
    elif score >= 6:
        severity = "HIGH"
    elif score >= 4:
        severity = "MODERATE"
    else:
        severity = "LOW"

    # =========================
    # RETURN
    # =========================
    return {
        "damage": damage,
        "reproducibility": reproducibility,
        "exploitability": exploitability,
        "affected_users": affected_users,
        "discoverability": discoverability,
        "score": score,
        "severity": severity
    }