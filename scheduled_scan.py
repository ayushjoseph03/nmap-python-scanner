import nmap
import datetime

def scan_network():
    nm = nmap.PortScanner()
    target = "192.168.1.0/24"
    
    print(f"Scanning {target} at {datetime.datetime.now()}")
    nm.scan(hosts=target, arguments="-sn")
    
    with open("scan_results.txt", "a") as f:
        f.write(f"Scan at {datetime.datetime.now()}\n")
        for host in nm.all_hosts():
            f.write(f"{host}\t{nm[host].hostname()}\n")

if __name__ == "__main__":
    scan_network()