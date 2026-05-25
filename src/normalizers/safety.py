from src.models import Vulnerability
from src.severity_normalizer import normalize_severity
from src.family_classifier import classify_family
from src.dread_engine import calculate_dread

def normalize_safety(raw_data):
    """
    Normalize Safety JSON output to Vulnerability objects.
    
    Handles both:
    - Modern format (Safety v3+): {"report": {"vulnerabilities": [...]}, "scan": {...}} or {"vulnerabilities": [...]}
    - Legacy format (Safety v1): [{vuln}, {vuln}, ...]
    """
    print(f"[DEBUG NORMALIZER] Input type: {type(raw_data)}")
    
    if isinstance(raw_data, dict):
        print(f"[DEBUG NORMALIZER] Dict format detected. Keys: {list(raw_data.keys())}")
        # Handle nested "report" key (Safety v3 format)
        if "report" in raw_data:
            print("[DEBUG NORMALIZER] Found nested 'report' key")
            raw_vulns = raw_data.get("report", {}).get("vulnerabilities", [])
        else:
            # Direct vulnerabilities key
            raw_vulns = raw_data.get("vulnerabilities", [])
        print(f"[DEBUG NORMALIZER] Extracted {len(raw_vulns)} vulnerabilities from dict")
    elif isinstance(raw_data, list):
        print(f"[DEBUG NORMALIZER] List format detected. Length: {len(raw_data)}")
        raw_vulns = raw_data
    else:
        print(f"[DEBUG NORMALIZER] Unexpected type: {type(raw_data)}")
        return []

    if not raw_vulns:
        print("[DEBUG NORMALIZER] No vulnerabilities to process")
        return []

    vulnerabilities = []
    
    for idx, item in enumerate(raw_vulns):
        print(f"[DEBUG NORMALIZER] Processing item {idx}: type={type(item)}")
        
        if isinstance(item, dict):
            package = item.get("package_name") or item.get("package") or "unknown"
            version = item.get("analyzed_version") or item.get("current") or ""
            description = item.get("advisory") or item.get("description") or ""
            vuln_id = (
                item.get("vulnerability_id")
                or item.get("id")
                or item.get("cve")
                or "UNKNOWN"
            )
            severity = normalize_severity(item.get("severity", ""))
            print(f"[DEBUG NORMALIZER] Dict vuln: package={package}, severity={severity}, vuln_id={vuln_id}")
        elif isinstance(item, (list, tuple)) and len(item) >= 5:
            package = item[0]
            version = item[2]
            description = item[3]
            vuln_id = item[4]
            severity = ""
            print(f"[DEBUG NORMALIZER] Legacy tuple vuln: package={package}")
        else:
            print(f"[DEBUG NORMALIZER] Skipping item - unsupported type/format")
            continue
        
        # Safety v1 no siempre da severidad, por eso DREAD es vital aquí
        family = classify_family(description)
        dread = calculate_dread(description, family)
        
        print(f"[DEBUG NORMALIZER] Family: {family}, DREAD score: {dread['score']}, severity: {severity or dread['severity']}")

        vulnerabilities.append(
            Vulnerability(
                package=package,
                version=version,
                vuln_id=vuln_id,
                severity=severity or dread["severity"],
                description=description,
                family=family,
                dread_score=dread["score"],
                dread=dread
            )
        )
    
    print(f"[DEBUG NORMALIZER] Returned {len(vulnerabilities)} normalized vulnerabilities")
    return vulnerabilities