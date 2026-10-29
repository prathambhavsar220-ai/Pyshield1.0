import psutil

SUSPICIOUS_KEYWORDS = ["keylogger", "miner", "trojan"]

def scan_processes():
    suspicious = []

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            if any(k in name for k in SUSPICIOUS_KEYWORDS):
                suspicious.append(proc.info)
        except:
            pass

    return suspicious