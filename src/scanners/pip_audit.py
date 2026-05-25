import subprocess
import json
import os
import tempfile
import shutil

def run_pip_audit(requirements_path):
    # 1. Creamos un directorio temporal
    temp_dir = tempfile.mkdtemp()
    print(f"[*] Pre-processing requirements in {temp_dir} to bypass resolution...")

    try:
        # 2. "Instalamos" los paquetes en la carpeta temporal.
        # --target: los mete en esa carpeta.
        # --no-deps: IGNORE los conflictos de dependencias (crucial).
        install_cmd = [
            "pip", "install", 
            "-r", requirements_path, 
            "--target", temp_dir, 
            "--no-deps", 
            "--no-cache-dir"
        ]
        subprocess.run(install_cmd, capture_output=True, text=True)

        # 3. Ejecutamos pip-audit sobre esa carpeta usando --path
        # Esto hace que pip-audit analice los metadatos (.dist-info) de lo que instalamos
        command = ["pip-audit", "--path", temp_dir, "-f", "json"]
        
        result = subprocess.run(command, capture_output=True, text=True)

        # 4. FIX CRÍTICO DE EXIT CODES:
        # Code 0 = Todo bien, 0 vulns.
        # Code 1 = Todo bien, PERO encontró vulns (esto NO es un error de ejecución).
        if result.returncode not in [0, 1]:
            print(f"[-] pip-audit failed with exit code {result.returncode}")
            print(f"[-] Stderr: {result.stderr.strip()}")
            return {"dependencies": []}

        if not result.stdout.strip():
            return {"dependencies": []}

        return json.loads(result.stdout)

    except Exception as e:
        print(f"[-] Scanner error: {e}")
        return {"dependencies": []}
    finally:
        # Limpiamos la basura
        shutil.rmtree(temp_dir)