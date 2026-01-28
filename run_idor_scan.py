import os
from dotenv import load_dotenv

from zap.zap_client import ZAPClient
from zap.adapter import zap_surface_to_endpoints
from attacks.idor import IDORTester


def main():
    print("\n[+] Starting IDOR Scan Orchestrator")

    # -------------------------------------------------
    # Load environment variables
    # -------------------------------------------------
    load_dotenv()

    ZAP_PROXY = os.getenv("ZAP_PROXY_URL")
    ZAP_API_KEY = os.getenv("ZAP_API_KEY")
    TARGET_URL = os.getenv("TARGET_URL")

    print("[DEBUG] ZAP_PROXY  :", ZAP_PROXY)
    print("[DEBUG] TARGET_URL:", TARGET_URL)

    if not ZAP_PROXY or not TARGET_URL:
        print("[-] Missing ZAP_PROXY or TARGET_URL in .env file")
        return

    # -------------------------------------------------
    # Initialize ZAP
    # -------------------------------------------------
    print("\n[+] Connecting to OWASP ZAP")
    zap = ZAPClient(
        zap_proxy=ZAP_PROXY,
        api_key=ZAP_API_KEY,
    )

    try:
        print("[+] ZAP Version:", zap.zap.core.version)
    except Exception as e:
        print("[-] Failed to connect to ZAP:", e)
        return

    # -------------------------------------------------
    # Reset & Recon
    # -------------------------------------------------
    print("\n[+] Resetting ZAP session")
    zap.reset_session()

    print("[+] Spidering target")
    zap.spider(TARGET_URL)

    print("[+] Waiting for passive scan")
    zap.wait_for_passive_scan()

    # -------------------------------------------------
    # Extract Attack Surface
    # -------------------------------------------------
    print("\n[+] Extracting attack surface")
    attack_surface = zap.extract_attack_surface()

    print(f"[+] ZAP discovered {len(attack_surface)} request patterns")

    if not attack_surface:
        print("[-] No endpoints discovered. Is the target running?")
        return

    # -------------------------------------------------
    # Convert ZAP output → IDOR endpoints
    # -------------------------------------------------
    print("\n[+] Preparing IDOR test targets")
    idor_endpoints = zap_surface_to_endpoints(
        attack_surface=attack_surface,
        base_url=TARGET_URL.rstrip("/"),
    )

    print(f"[+] {len(idor_endpoints)} endpoints prepared for IDOR testing")

    if not idor_endpoints:
        print("[-] No ID-based endpoints found")
        return

    # -------------------------------------------------
    # Run IDOR Tests
    # -------------------------------------------------
    print("\n[+] Running IDOR tests")
    idor = IDORTester(
        base_url=TARGET_URL,
        headers={
            # Add auth header if needed
            # "Authorization": "Bearer YOUR_TOKEN"
        },
    )

    findings = idor.run(idor_endpoints)

    # -------------------------------------------------
    # Results
    # -------------------------------------------------
    print("\n========== IDOR SCAN RESULTS ==========")

    if findings:
        for i, f in enumerate(findings, 1):
            print(f"\n[{i}] IDOR FOUND")
            print("    Endpoint :", f["endpoint"])
            print("    Parameter:", f["parameter"])
            print("    Impact   :", f["impact"])
    else:
        print("[+] No IDOR vulnerabilities found")

    print("\n[+] Scan completed\n")


if __name__ == "__main__":
    main()



from reporting.report_generator import ReportGenerator

if findings:
    report = ReportGenerator(
        target=TARGET_URL,
        findings=findings,
    )
    path = report.save()
    print(f"\n[+] Report saved to: {path}")
