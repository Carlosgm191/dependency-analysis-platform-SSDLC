import subprocess
import json
import sys

def run_dependency_scan(file_path):
    print(f"[*] Iniciando escaneo de dependencias en: {file_path}...\n")
    try:
        # Ejecutamos pip-audit y capturamos la salida en formato JSON
        result = subprocess.run(
            ['pip-audit', '-r', file_path, '-f', 'json'],
            capture_output=True,
            text=True
        )
        
        # Si la herramienta devuelve resultados (incluso si hay vulnerabilidades)
        if result.stdout:
            vulnerabilities = json.loads(result.stdout)
            return vulnerabilities
        else:
            return {"status": "success", "message": "No se encontraron vulnerabilidades o la salida está vacía."}

    except FileNotFoundError:
        print("[!] Error: pip-audit no está instalado o no se encuentra en el PATH.")
        sys.exit(1)
    except json.JSONDecodeError:
        print("[!] Error: No se pudo procesar la respuesta en formato JSON.")
        return {"error": result.stderr}

if __name__ == "__main__":
    archivo_objetivo = 'requirements.txt'
    
    # Ejecutar el escaneo
    reporte = run_dependency_scan(archivo_objetivo)
    
    # Mostrar los resultados estructurados en la consola
    print("[+] Resultados del Escaneo:\n")
    print(json.dumps(reporte, indent=4))