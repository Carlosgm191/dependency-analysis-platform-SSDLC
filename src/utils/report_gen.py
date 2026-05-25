import json
import os

def generate_markdown_report(json_file):
    if not os.path.exists(json_file):
        return "### ⚠️ Error: No se encontró el reporte de escaneo."

    with open(json_file, 'r') as f:
        data = json.load(f)

    if not data:
        return "### ✅ DAP: No se encontraron vulnerabilidades. ¡Buen trabajo!"

    # Contadores
    total = len(data)
    critical = len([v for v in data if v['severity'] == 'CRITICAL'])
    high = len([v for v in data if v['severity'] == 'HIGH'])

    # Construcción del Markdown
    report = f"## 🛡️ DAP Security Compliance Report\n\n"
    report += f"Se han analizado las dependencias y se han encontrado **{total}** hallazgos.\n\n"
    
    # Resumen rápido
    report += "| 🔴 Críticas | 🟠 Altas | 🟡 Moderadas | 🔵 Bajas |\n"
    report += "| :---: | :---: | :---: | :---: |\n"
    report += f"| {critical} | {high} | {len([v for v in data if v['severity'] == 'MODERATE'])} | {len([v for v in data if v['severity'] == 'LOW'])} |\n\n"

    report += "### 🚨 Top 5 Riesgos (DREAD)\n"
    report += "| Paquete | Vulnerabilidad | Score | Severidad |\n"
    report += "| :--- | :--- | :---: | :--- |\n"

    # Ordenamos por score DREAD descendente
    sorted_vulns = sorted(data, key=lambda x: x['dread_score'], reverse=True)[:5]
    
    for v in sorted_vulns:
        report += f"| `{v['package']}` | {v['vuln_id']} | **{v['dread_score']}** | {v['severity']} |\n"

    report += "\n---\n*Reporte generado automáticamente por **Dependency Analysis Platform (DAP)**.*"
    return report

if __name__ == "__main__":
    # Guardamos el markdown en un archivo temporal para el pipeline
    md_content = generate_markdown_report('db_scan_results.json')
    with open('dap_report.md', 'w') as f:
        f.write(md_content)