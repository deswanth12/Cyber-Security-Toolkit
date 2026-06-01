import socket

def scan_common_ports(host):

    ports = [21, 22, 25, 53, 80, 110, 143, 443]

    open_ports = []

    for port in ports:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        result = s.connect_ex((host, port))

        if result == 0:
            open_ports.append(port)

        s.close()

    return open_ports
