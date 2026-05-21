import requests


def run_osv(requirements_path: str):

    print("[+] Running OSV scanner (API mode)...")

    results = []

    with open(requirements_path, "r") as f:
        lines = f.readlines()

    for line in lines:

        line = line.strip()

        if "==" not in line:
            continue

        package, version = line.split("==")

        package = package.strip()
        version = version.strip()

        payload = {
            "package": {
                "name": package,
                "ecosystem": "PyPI",
                "version": version
            }
        }

        response = requests.post(
            "https://api.osv.dev/v1/query",
            json=payload
        )

        if response.status_code != 200:
            print(f"[!] OSV request failed for {package}=={version}")
            continue

        data = response.json()

        vulns = data.get("vulns", [])

        for v in vulns:

            results.append({
                "package": package,
                "version": version,
                "id": v.get("id", "UNKNOWN"),
                "summary": v.get("summary", ""),
                "details": v.get("details", "")
            })

    return {"results": results}