import sys
import json

from ci_cd.sast_scan import run_sast_scan
from ci_cd.dependency_scan import run_dependency_scan
from ci_cd.container_scan import run_container_scan
from ci_cd.risk_gate import evaluate_risk

def main():
    print("🔐 Starting DevSecOps CI/CD Security Pipeline\n")

    scan_results = []

    print("▶ Running SAST scan...")
    sast_result = run_sast_scan()
    scan_results.append(sast_result)

    print("▶ Running dependency vulnerability scan...")
    dependency_result = run_dependency_scan()
    scan_results.append(dependency_result)

    print("▶ Running container image scan...")
    container_result = run_container_scan()
    scan_results.append(container_result)

    print("\n▶ Evaluating risk gate policy...")
    risk_decision = evaluate_risk(scan_results)

    print("\n🧾 Risk Summary:")
    print(json.dumps(risk_decision, indent=2))

    decision = risk_decision["decision"]

    if decision == "FAIL":
        print("\n❌ Pipeline FAILED due to critical security risks")
        sys.exit(1)
    elif decision == "WARN":
        print("\n⚠️ Pipeline PASSED with warnings (review required)")
        sys.exit(0)
    else:
        print("\n✅ Pipeline PASSED with no blocking issues")
        sys.exit(0)

if __name__ == "__main__":
    main()
