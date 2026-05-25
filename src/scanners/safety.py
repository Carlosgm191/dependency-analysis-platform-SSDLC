import json
import subprocess

def run_safety(requirements_file):
    # Safety v1.10.3 devuelve un JSON que es una lista de listas
    result = subprocess.run(
        [
            "safety",
            "check",
            "-r", requirements_file,
            "--json"
        ],
        capture_output=True,
        text=True
    )

    if not result.stdout.strip():
        return []

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []