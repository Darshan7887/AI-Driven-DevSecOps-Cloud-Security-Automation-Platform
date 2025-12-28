import json
from datetime import datetime

CONTAINER_METADATA_FILE = "security-scans/container_image.json"

def run_container_scan():
    findings = []

    try:
        with open(CONTAINER_METADATA_FILE, "r") as f:
            image_data = json.load(f)

        for pkg in image_data.get("os_packages", []):
            findings.append({
                "scanner": "Container Image Scanner",
                "image": image_data["image_name"],
                "package": pkg["name"],
                "version": pkg["version"],
                "severity": pkg["severity"],
                "cve": pkg["cve"],
                "explanation": pkg["reason"]
            })

    except FileNotFoundError:
        pass

    return {
        "scan_type": "Container Image Security Scan",
        "timestamp": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "findings": findings
    }

if __name__ == "__main__":
    result = run_container_scan()
    print(json.dumps(result, indent=2))
