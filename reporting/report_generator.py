from datetime import datetime
import json
import os

class ReportGenerator:
    def __init__(self, target, findings):
        self.target = target
        self.findings = findings
        self.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    def executive_summary(self):
        if not self.findings:
            return f"Security Scan Report for {self.target}\n\nScan Time: {self.timestamp}\n\nNo critical security issues were discovered.\n"
        return f"Security Scan Report for {self.target}\n\nScan Time: {self.timestamp}\n\nTotal Vulnerabilities Found: {len(self.findings)}\nRisk Level: HIGH\n\nImmediate remediation is strongly recommended.\n"

    def vulnerability_details(self):
        content = ""
        for idx, f in enumerate(self.findings, 1):
            content += f"### {idx}. {f.get('vulnerability')} — {f.get('severity')}\n\n"
            content += f"**Severity Score:** {f.get('severity_score')}/9\n\n"
            content += f"**Endpoint:** {f.get('endpoint')}\n\n"
            content += f"**Affected Parameter:** `{f.get('parameter')}`\n\n"
            content += f"**Impact:** {f.get('impact')}\n\n"
            content += "---\n\n"
        return content

    def generate_markdown(self):
        report = "# 🛡️ Security Assessment Report\n\n"
        report += self.executive_summary()
        report += "\n---\n\n"
        report += "## Vulnerability Details\n\n"
        report += self.vulnerability_details()
        return report

    def save(self, output_dir="reports"):
        os.makedirs(output_dir, exist_ok=True)
        filename = f"security_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.generate_markdown())
        return filepath
