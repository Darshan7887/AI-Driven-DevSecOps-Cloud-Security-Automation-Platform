import json
from datetime import datetime

OWASP_MAPPING = {
    "Hardcoded Password": "A2: Cryptographic Failures",
    "Use of eval()": "A3: Injection",
    "Vulnerable Dependency": "A6: Vulnerable and Outdated Components",
    "SSH open to the internet": "A5: Security Misconfiguration",
    "Public storage bucket": "A5: Security Misconfiguration",
    "Over-permissive IAM policy": "A5: Security Misconfiguration"
}

def generate_technical_report(prioritized_findings):
    report = []

    for finding in prioritized_findings:
        report.append({
            "issue": finding["issue"],
            "severity": finding["severity"],
            "affected_resources": finding["affected_resources"],
            "risk_explanation": finding["risk_explanation"],
            "recommended_action": finding["recommended_action"],
            "owasp_category": OWASP_MAPPING.get(
                finding["issue"],
                "Not mapped"
            )
        })

    return report

def generate_executive_summary(summary_text):
    return {
        "summary": summary_text,
        "generated_at": datetime.utcnow().isoformat(),
        "risk_level": "HIGH" if "critical" in summary_text.lower() else "MODERATE"
    }

def generate_full_report(prioritized_findings, executive_summary):
    return {
        "report_type": "Security Risk Assessment",
        "generated_at": datetime.utcnow().isoformat(),
        "executive_summary": executive_summary,
        "technical_findings": generate_technical_report(prioritized_findings)
    }

if __name__ == "__main__":
    print("Security report generator ready")
