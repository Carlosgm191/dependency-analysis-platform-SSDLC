import json
import subprocess


def run_pip_audit(requirements_file="requirements.txt"):

    result = subprocess.run(
        [
            "pip-audit",
            "-r",
            requirements_file,
            "--format=json"
        ],
        capture_output=True,
        text=True
    )

    if result.returncode not in [0, 1]:
        raise Exception(result.stderr)

    return json.loads(result.stdout)