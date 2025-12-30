import json
from datetime import datetime

# Simulated Vulnerability Database
VULNERABLE_DEPENDENCIES = {
    "flask": {
        "1.0": {
            "severity": "HIGH",
            "cve": "CVE-2018-1000656",
            "why": "Multiple security issues including information disclosure"
        }
    },
    "requests": {
        "2.19.0": {
            "severity": "CRITICAL",
            "cve": "CVE-2018-18074",
            "why": "Authorization bypass vulnerability"
        }
    }
}

def load_dependencies(file_path="requirements.txt"):
    dependencies = []

    try:
        with open(file_path, "r") as f:
            for line in f:
                if "==" in line:
                    name, version = line.strip().split("==")
                    dependencies.append((name.lower(), version))
    except FileNotFoundError:
        pass

    return dependencies

def run_dependency_scan():
    findings = []
    dependencies = load_dependencies()

    for name, version in dependencies:
        if name in VULNERABLE_DEPENDENCIES:
            vulnerable_versions = VULNERABLE_DEPENDENCIES[name]
            if version in vulnerable_versions:
                vuln = vulnerable_versions[version]
                findings.append({
                    "scanner": "Dependency Scanner",
                    "dependency": name,
                    "version": version,
                    "severity": vuln["severity"],
                    "cve": vuln["cve"],
                    "explanation": vuln["why"]
                })

    return {
        "scan_type": "Dependency Vulnerability Scan",
        "timestamp": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "findings": findings
    }

if __name__ == "__main__":
    result = run_dependency_scan()
    print(json.dumps(result, indent=2))
