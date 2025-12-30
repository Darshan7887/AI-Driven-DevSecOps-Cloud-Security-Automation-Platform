import json
from datetime import datetime

CONFIG_FILE = "cloud_checks/cloud_config.json"

def run_cloud_security_scan():
    findings = []

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    # ---- Security Group Checks ----
    for sg in config.get("security_groups", []):
        for rule in sg.get("inbound_rules", []):
            if rule["cidr"] == "0.0.0.0/0" and rule["port"] == 22:
                findings.append({
                    "scanner": "Cloud Security Scanner",
                    "resource": sg["name"],
                    "issue": "SSH open to the internet",
                    "severity": "CRITICAL",
                    "explanation": "Exposes SSH to brute-force and remote exploitation"
                })

    # ---- Storage Checks ----
    for bucket in config.get("storage_buckets", []):
        if bucket.get("public"):
            findings.append({
                "scanner": "Cloud Security Scanner",
                "resource": bucket["name"],
                "issue": "Public storage bucket",
                "severity": "HIGH",
                "explanation": "Public buckets can leak sensitive data"
            })

    # ---- IAM Checks ----
    for policy in config.get("iam_policies", []):
        if "*" in policy.get("permissions", []):
            findings.append({
                "scanner": "Cloud Security Scanner",
                "resource": policy["name"],
                "issue": "Over-permissive IAM policy",
                "severity": "CRITICAL",
                "explanation": "Wildcard permissions allow full account compromise"
            })

    return {
        "scan_type": "Cloud Infrastructure Security Scan",
        "timestamp": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "findings": findings
    }

if __name__ == "__main__":
    result = run_cloud_security_scan()
    print(json.dumps(result, indent=2))
