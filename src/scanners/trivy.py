import json
import subprocess


def run_trivy(requirements_file):

    result = subprocess.run(
        [
            "trivy",
            "fs",
            ".",
            "--scanners",
            "vuln",
            "--format",
            "json"
        ],
        capture_output=True,
        text=True
    )

    return json.loads(result.stdout)