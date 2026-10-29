import requests

def scan_vulnerabilities():
    try:
        response = requests.get("https://cve.circl.lu/api/last")
        return response.json()[:5]
    except:
        return []