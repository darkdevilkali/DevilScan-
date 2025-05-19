import socket

def port_scan(target, ports=[80, 443, 22, 21, 25, 110, 8080]):
    open_ports = []
    for port in ports:
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect((target, port))
            banner = f"Port {port} is open"
            open_ports.append((port, True, banner))
        except:
            pass
        finally:
            s.close()
    return open_ports
