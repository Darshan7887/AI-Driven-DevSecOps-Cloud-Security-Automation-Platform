import json
import sys

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}

FAIL_THRESHOLD = SEVERITY_ORDER["CRITICAL"]

def evaluate_risk(scan_results):
    highest_severity = 0
    severity_count = {}

    for result in scan_results:
        for finding in result.get("findings", []):
            severity = finding.get("severity", "LOW")
            severity_value = SEVERITY_ORDER.get(severity, 1)

            highest_severity = max(highest_severity, severity_value)
            severity_count[severity] = severity_count.get(severity, 0) + 1

    decision = "PASS"
    reason = "No high-risk issues detected"

    if highest_severity >= FAIL_THRESHOLD:
        decision = "FAIL"
        reason = "Critical security risks detected"
    elif highest_severity == SEVERITY_ORDER["HIGH"]:
        decision = "WARN"
        reason = "High severity issues detected"

    return {
        "decision": decision,
        "reason": reason,
        "severity_summary": severity_count
    }

if __name__ == "__main__":
    # This file is not meant to be run standalone
    print("Risk gate module loaded")
