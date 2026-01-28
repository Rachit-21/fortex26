from datetime import datetime
import json
import os


class ReportGenerator:
    def __init__(self, target, findings):
        self.target = target
        self.findings = findings
        self.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # -----------------------------------
    # Executive Summary
    # -----------------------------------
    def executive_summary(self):
        if not self.findings:
            return (
                f"Security Scan Report for {self.target}\n\n"
                f"Scan Time: {self.timestamp}\n\n"
                "No critical security issues were discovered.\n"
            )

        return (
            f"Security Scan Report for {self.target}\n\n"
            f"Scan Time: {self.timestamp}\n\n"
            f"Total Vulnerabilities Found: {len(self.findings)}\n"
            "Risk Level: HIGH\n\n"
            "Immediate remediation is strongly recommended.\n"
        )

    # -----------------------------------
    # Bug Bounty Style Details
    # -----------------------------------
    def vulnerability_details(self):
        content = ""

        for idx, f in enumerate(self.findings, 1):
            content += (
                f"### {idx}. {f.get('vulnerability')} — {f.get('severity')}\n\n"
                f"**Severity Score:** {f.get('severity_score')}/9\n\n"
                f"**Endpoint:** {f.get('endpoint')}\n\n"
                f"**Affected Parameter:** `{f.get('parameter')}`\n\n"
                f"**Impact:** {f.get('impact')}\n\n"
                "**Steps to Reproduce:**\n"
                f"1. Access the endpoint with `{f.get('parameter')}={f.get('original_id')}`\n"
                f"2. Change the value to `{f.get('tampered_id')}`\n"
                "3. Observe unauthorized data access\n\n"
                "**Recommended Fix:**\n"
                "Ensure proper object-level authorization checks on the server.\n\n"
                "---\n\n"
            )

        return content

    # -----------------------------------
    # Generate Markdown Report
    # -----------------------------------
    def generate_markdown(self):
        report = "# 🛡️ Security Assessment Report\n\n"
        report += self.executive_summary()
        report += "\n---\n\n"
        report += "## Vulnerability Details\n\n"
        report += self.vulnerability_details()

        return report

    # -----------------------------------
    # Save Report to File
    # -----------------------------------
    def save(self, output_dir="reports"):
        os.makedirs(output_dir, exist_ok=True)

        filename = f"security_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.generate_markdown())

        return filepath

    # -----------------------------------
    # Optional: JSON output (for future)
    # -----------------------------------
    def save_json(self, output_dir="reports"):
        os.makedirs(output_dir, exist_ok=True)

        filename = f"security_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "target": self.target,
                    "timestamp": self.timestamp,
                    "findings": self.findings,
                },
                f,
                indent=2,
            )

        return filepath
