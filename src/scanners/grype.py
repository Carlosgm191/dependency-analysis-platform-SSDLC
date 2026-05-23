import json
import subprocess
import os
import shutil
import tempfile

def run_grype(requirements_file):
    # Creamos un directorio temporal
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Grype SOLO busca archivos llamados 'requirements.txt'
        # Así que copiamos tu archivo con ese nombre exacto
        temp_requirements = os.path.join(tmp_dir, "requirements.txt")
        shutil.copyfile(requirements_file, temp_requirements)
        
        # Ejecutamos Grype apuntando al DIRECTORIO con el prefijo 'dir:'
        # Esto obliga a Grype a usar sus catalogadores de archivos
        result = subprocess.run(
            [
                "grype",
                f"dir:{tmp_dir}",
                "-o", "json",
                "--quiet"
            ],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            # Si hay error, lo vemos en la consola de debug
            print(f"Error en Grype: {result.stderr}")
            return {"matches": []}

        try:
            return json.loads(result.stdout)
        except:
            return {"matches": []}