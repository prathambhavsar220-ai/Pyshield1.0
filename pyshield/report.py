# pyshield/report.py

import json
from datetime import datetime


def calculate_risk_score(report):
    score = 0

    # Processes
    score += len(report.get("processes", [])) * 5

    # Open Ports
    score += len(report.get("ports", [])) * 3

    # Files (VirusTotal)
    for file in report.get("files", []):
        vt = file.get("virustotal", {})
        score += vt.get("malicious", 0) * 10
        score += vt.get("suspicious", 0) * 5

    return min(score, 100)


def classify_severity(score):
    if score >= 70:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    else:
        return "LOW"


def generate_summary(report):
    return {
        "total_suspicious_processes": len(report.get("processes", [])),
        "total_open_ports": len(report.get("ports", [])),
        "total_files_scanned": len(report.get("files", [])),
        "total_vulnerabilities": len(report.get("vulnerabilities", []))
    }


def generate_report(raw_report):
    final_report = {}

    # Timestamp
    final_report["scan_time"] = datetime.now().isoformat()

    # Raw Data
    final_report["details"] = raw_report

    # Summary
    summary = generate_summary(raw_report)
    final_report["summary"] = summary

    # Risk Score
    risk_score = calculate_risk_score(raw_report)
    final_report["risk_score"] = risk_score

    # Severity
    final_report["severity"] = classify_severity(risk_score)

    # Boolean flags for quick checks
    final_report["vulnerabilities_found"] = len(raw_report.get("vulnerabilities", [])) > 0
    final_report["viruses_found"] = any(
        f.get("virustotal", {}).get("malicious", 0) > 0 
        for f in raw_report.get("files", [])
    )

    # Explanation (for chatbot)
    final_report["explanation"] = generate_explanation(final_report)

    return final_report


def generate_explanation(report):
    severity = report.get("severity")

    if severity == "CRITICAL":
        return "System is at high risk. Immediate action required."
    elif severity == "HIGH":
        return "Multiple threats detected. Investigate soon."
    elif severity == "MEDIUM":
        return "Some vulnerabilities found. Monitor system."
    else:
        return "System appears safe."


def save_report(report, filename="pyshield_report.json"):
    # Save JSON format
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    # Save human-readable Text format
    txt_filename = filename.replace(".json", ".txt")
    with open(txt_filename, "w") as f:
        f.write("=== PyShield Security Report ===\n")
        f.write(f"Scan Time: {report.get('scan_time')}\n")
        f.write(f"Risk Score: {report.get('risk_score')}/100\n")
        f.write(f"Severity: {report.get('severity')}\n")
        f.write(f"Explanation: {report.get('explanation')}\n\n")
        
        f.write(f"Vulnerabilities Found: {'Yes' if report.get('vulnerabilities_found') else 'No'}\n")
        f.write(f"Viruses Found: {'Yes' if report.get('viruses_found') else 'No'}\n\n")
        
        summary = report.get('summary', {})
        f.write("--- Summary ---\n")
        f.write(f"Suspicious Processes: {summary.get('total_suspicious_processes', 0)}\n")
        f.write(f"Open Ports: {summary.get('total_open_ports', 0)}\n")
        f.write(f"Files Scanned: {summary.get('total_files_scanned', 0)}\n")
        f.write(f"Vulnerabilities: {summary.get('total_vulnerabilities', 0)}\n\n")
        
        f.write("For detailed technical information on the specific threats, see the JSON report.\n")

    return filename