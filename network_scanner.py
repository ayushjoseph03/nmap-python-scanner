import nmap
import socket

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # Google DNS
        local_ip = s.getsockname()[0]
    except:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip

nm = nmap.PortScanner()
local_ip = get_local_ip()
network = local_ip[:local_ip.rfind(".")] + ".0/24"

print(f"Scanning network: {network}")
nm.scan(hosts=network, arguments="-sn")

print("\nActive Devices:")
print("IP Address\tMAC Address\tHostname")
for host in nm.all_hosts():
    mac = nm[host]["addresses"].get("mac", "Unknown")
    hostname = nm[host].hostname()
    print(f"{host}\t{mac}\t{hostname}")