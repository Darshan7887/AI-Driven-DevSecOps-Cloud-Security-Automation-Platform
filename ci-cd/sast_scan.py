import os
import re
import json
from datetime import datetime

# -------------------------------
# SAST RULE SET (SIMULATED)
# -------------------------------

SAST_RULES = [
    {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "issue": "Hardcoded AWS Access Key",
        "severity": "CRITICAL",
        "why": "Leaked cloud credentials can allow full account takeover"
    },
    {
        "pattern": r"password\s*=\s*[\"'].*[\"']",
        "issue": "Hardcoded Password",
        "severity": "CRITICAL",
        "why": "Secrets stored in code are easily exposed via source control"
    },
    {
        "pattern": r"eval\(",
        "issue": "Use of eval()",
        "severity": "HIGH",
        "why": "eval() enables arbitrary code execution if input is untrusted"
    },
    {
        "pattern": r"os\.system\(",
        "issue": "Unsafe OS Command Execution",
        "severity": "HIGH",
        "why": "Improper sanitization can lead to command injection"
    },
    {
        "pattern": r"subprocess\.Popen",
        "issue": "Unsafe subprocess usage",
        "severity": "MEDIUM",
        "why": "Improper handling may allow injection or privilege abuse"
    }
]

# -------------------------------
# SAST SCAN FUNCTION
# -------------------------------

def run_sast_scan(code_path="scripts"):
    findings = []

    for root, _, files in os.walk(code_path):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)

                try:
                    with open(file_path, "r", errors="ignore") as f:
                        content = f.read()

                    for rule in SAST_RULES:
                        if re.search(rule["pattern"], content):
                            findings.append({
                                "scanner": "SAST",
                                "file": file_path,
                                "issue": rule["issue"],
                                "severity": rule["severity"],
                                "explanation": rule["why"]
                            })

                except Exception as e:
                    continue

    return {
        "scan_type": "Static Application Security Testing",
        "timestamp": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "findings": findings
    }

# -------------------------------
# CLI ENTRYPOINT (CI SIMULATION)
# -------------------------------

if __name__ == "__main__":
    result = run_sast_scan()
    print(json.dumps(result, indent=2))
