import os
import hashlib
import requests
import time

VT_API_KEY = os.environ.get("VT_API_KEY", "")

def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except:
        return None


def check_virustotal(file_hash):
    if not VT_API_KEY:
        return {"error": "VT_API_KEY is not configured"}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0)
            }

        else:
            return {"error": "Not found in VirusTotal"}

    except:
        return {"error": "API error"}


def scan_files():
    results = []

    for root, dirs, files in os.walk("C:\\"):
        for file in files:
            if file.endswith(".exe"):
                filepath = os.path.join(root, file)

                file_hash = get_file_hash(filepath)
                if not file_hash:
                    continue

                vt_result = check_virustotal(file_hash)

                results.append({
                    "file": filepath,
                    "hash": file_hash,
                    "virustotal": vt_result
                })

                time.sleep(15)  # VERY IMPORTANT (API rate limit)

        if len(results) >= 20:  # limit scan
            break

    return results