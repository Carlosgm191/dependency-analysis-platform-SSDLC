import json
import subprocess
import sys

def run_safety(requirements_file):
    # Use the current Python interpreter so Safety runs correctly when the binary
    # is not available on PATH.
    command = [
        sys.executable,
        "-m",
        "safety",
        "check",
        "-r",
        requirements_file,
        "--output",
        "json",
        "--json-output-format",
        "1.1",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as e:
        print(f"[-] safety binary not found: {e}")
        return []

    print(f"[DEBUG] Safety exit code: {result.returncode}")
    print(f"[DEBUG] Safety stderr: {result.stderr[:500] if result.stderr else 'empty'}")
    print(f"[DEBUG] Safety stdout length: {len(result.stdout)}")
    
    if result.returncode not in [0, 64]:
        print(f"[-] safety failed with exit code {result.returncode}")
        print(f"[-] Stderr: {result.stderr.strip()}")
        return []

    if not result.stdout.strip():
        print("[DEBUG] Safety output is empty")
        return []

    try:
        data = json.loads(result.stdout)
        print(f"[DEBUG] Safety JSON parsed. Type: {type(data)}, Keys: {data.keys() if isinstance(data, dict) else 'N/A'}")
        return data
    except json.JSONDecodeError as e:
        print(f"[-] safety produced invalid JSON output: {e}")
        print(f"[DEBUG] Raw output: {result.stdout[:500]}")
        return []
