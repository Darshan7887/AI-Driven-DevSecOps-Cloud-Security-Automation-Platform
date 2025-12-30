import json
import sys

# CI/CD Scans
from ci_cd.sast_scan import run_sast_scan
from ci_cd.dependency_scan import run_dependency_scan
from ci_cd.container_scan import run_container_scan
from ci_cd.risk_gate import evaluate_risk

# Cloud Scan
from cloud_checks.cloud_scanner import run_cloud_security_scan

# AI Engine
from ai_engine.risk_analyzer import analyze_risks, generate_executive_summary

# Reporting
from reports.security_report_generator import generate_full_report

def main():
    print("\n🔐 Starting AI-Driven DevSecOps & Cloud Security Platform\n")

    all_scan_results = []

    # --- CI/CD Security ---
    print("▶ Running CI/CD security scans...")
    all_scan_results.append(run_sast_scan())
    all_scan_results.append(run_dependency_scan())
    all_scan_results.append(run_container_scan())

    # --- Cloud Security ---
    print("▶ Running cloud security scan...")
    all_scan_results.append(run_cloud_security_scan())

    # --- Risk Gate ---
    print("\n▶ Evaluating pipeline risk gate...")
    pipeline_decision = evaluate_risk(all_scan_results)

    # --- AI Risk Analysis ---
    print("\n🤖 Running AI risk analysis...")
    prioritized_findings = analyze_risks(all_scan_results)
    executive_summary = generate_executive_summary(prioritized_findings)

    # --- Reporting ---
    print("\n📊 Generating security reports...")
    full_report = generate_full_report(
        prioritized_findings,
        executive_summary
    )

    with open("reports/final_security_report.json", "w") as f:
        json.dump(full_report, f, indent=2)

    print("\n🧾 Pipeline Decision:")
    print(json.dumps(pipeline_decision, indent=2))

    print("\n📄 Report saved to: reports/final_security_report.json")

    # --- Final Exit Code ---
    if pipeline_decision["decision"] == "FAIL":
        print("\n❌ Security platform detected critical risks")
        sys.exit(1)
    elif pipeline_decision["decision"] == "WARN":
        print("\n⚠️ Security platform completed with warnings")
        sys.exit(0)
    else:
        print("\n✅ Security platform passed with no blocking issues")
        sys.exit(0)

if __name__ == "__main__":
    main()
