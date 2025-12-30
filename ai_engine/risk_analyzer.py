from collections import defaultdict

SEVERITY_PRIORITY = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}

REMEDIATION_GUIDE = {
    "Hardcoded Password": "Move secrets to environment variables or a secrets manager.",
    "Use of eval()": "Avoid eval(). Use safe parsing or explicit logic.",
    "SSH open to the internet": "Restrict SSH access to trusted IP ranges or use bastion hosts.",
    "Public storage bucket": "Disable public access and use IAM-based access controls.",
    "Over-permissive IAM policy": "Apply least-privilege permissions instead of wildcards."
}


def analyze_risks(scan_results):
    prioritized = []
    grouped_issues = defaultdict(list)

    for result in scan_results:
        for finding in result.get("findings", []):

            issue_name = (
                finding.get("issue")
                or finding.get("dependency")
                or finding.get("package")
                or finding.get("resource")
                or "Unknown Security Issue"
            )

            grouped_issues[issue_name].append(finding)

    for issue, findings in grouped_issues.items():
        highest = max(
            findings,
            key=lambda f: SEVERITY_PRIORITY.get(f.get("severity", "LOW"), 1)
        )

        prioritized.append({
            "issue": issue,
            "severity": highest.get("severity", "LOW"),
            "affected_resources": len(findings),
            "risk_explanation": highest.get(
                "explanation",
                "This issue may impact system security."
            ),
            "recommended_action": REMEDIATION_GUIDE.get(
                issue,
                "Review and remediate according to security best practices."
            )
        })

    return prioritized
def generate_executive_summary(prioritized_findings):
    critical = sum(1 for f in prioritized_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in prioritized_findings if f["severity"] == "HIGH")

    return (
        f"Security analysis identified {critical} critical and "
        f"{high} high-risk issues requiring immediate attention. "
        "If left unresolved, these issues may lead to unauthorized access, "
        "data exposure, or full system compromise."
    )
