import socket

COMMON_PORTS = [21, 22, 23, 80, 443, 3389]

def scan_ports():
    open_ports = []

    for port in COMMON_PORTS:
        s = socket.socket()
        s.settimeout(0.5)

        try:
            s.connect(("127.0.0.1", port))
            open_ports.append(port)
        except:
            pass

    return open_ports


