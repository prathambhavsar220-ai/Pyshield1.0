from pyshield.process import scan_processes
from pyshield.ports import scan_ports
from pyshield.files import scan_files
from pyshield.vuln import scan_vulnerabilities

def run_full_scan():
    report = {}

    report["processes"] = scan_processes()
    report["ports"] = scan_ports()
    report["files"] = scan_files()
    report["vulnerabilities"] = scan_vulnerabilities()

    return report