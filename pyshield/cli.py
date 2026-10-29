from pyshield.scanner import run_full_scan
from pyshield.report import generate_report, save_report

def main():
    print("[+] Running PyShield Security Scan...")

    raw = run_full_scan()

    final_report = generate_report(raw)

    save_report(final_report)

    print("[+] Scan completed. Report saved as pyshield_report.json")