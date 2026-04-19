import subprocess
import json
import os
from datetime import datetime

def run_vulnerability_scan(file_path="requirements.txt"):
    print(f"[*] Starting Security Audit for: {file_path}")
    
    try:
        # Ejecutamos el escaneo
        result = subprocess.run(
            ['pip-audit', '-r', file_path, '-f', 'json'],
            capture_output=True, text=True
        )
        
        raw_data = json.loads(result.stdout) if result.stdout else []
        
        # Lógica de la Capa 2: Risk Scoring
        total_score = 0
        summary = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0}
        
        for issue in raw_data:
            # En pip-audit, la severidad suele venir en el advisory
            sev = issue.get('advisory', {}).get('severity', 'LOW').upper()
            if "CRITICAL" in sev:
                total_score += 10
                summary["CRITICAL"] += 11
            elif "HIGH" in sev:
                total_score += 7
                summary["HIGH"] += 1
            elif "MODERATE" in sev:
                total_score += 4
                summary["MODERATE"] += 1
            else:
                total_score += 1
                summary["LOW"] += 1

        # Estructura final del reporte (Capa 1)
        final_report = {
            "project_name": "Dependency Analysis Platform",
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "weighted_risk_score": total_score,
            "vulnerability_summary": summary,
            "status": "FAILED" if summary["CRITICAL"] > 0 else "PASSED",
            "details": raw_data
        }

        # Guardar en JSON (Persistencia de datos)
        with open("db_scan_results.json", "w") as f:
            json.dump(final_report, f, indent=4)
            
        print(f"[+] Scan Complete. Weighted Risk Score: {total_score}")
        print("[+] Results saved to 'db_scan_results.json'")
        
    except Exception as e:
        print(f"[!] Error during execution: {e}")

if __name__ == "__main__":
    run_vulnerability_scan()