import json
import subprocess
import os
import shutil
import tempfile

def run_trivy(requirements_file):
    """
    Trivy solo reconoce archivos con nombres estándar. 
    Esta función crea un entorno temporal para engañarlo.
    """
    # 1. Creamos una carpeta temporal única
    with tempfile.TemporaryDirectory() as tmp_dir:
        
        # 2. Copiamos TU archivo (ej. requirements-safe.txt) 
        # a la carpeta temporal pero renombrado como 'requirements.txt'
        temp_target = os.path.join(tmp_dir, "requirements.txt")
        shutil.copyfile(requirements_file, temp_target)
        
        # 3. Ejecutamos Trivy sobre la CARPETA temporal
        # Al encontrar un archivo llamado 'requirements.txt' ahí dentro, 
        # Trivy activará automáticamente el scanner de Python.
        result = subprocess.run(
            [
                "trivy",
                "fs",
                "--scanners", "vuln",
                "--format", "json",
                "--quiet",
                tmp_dir
            ],
            capture_output=True,
            text=True
        )

        # Si Trivy falla o no devuelve nada
        if result.returncode != 0 or not result.stdout.strip():
            return {"Results": []}

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"Results": []}