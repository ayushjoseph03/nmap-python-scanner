import nmap

# Initialize Nmap PortScanner
nm = nmap.PortScanner()

# Define target IP (change this)
target = "192.168.1.1"

# Run a basic scan (SYN scan)
print(f"Scanning {target}...")
nm.scan(hosts=target, arguments="-sS")

# Print results
for host in nm.all_hosts():
    print(f"\nHost: {host}")
    print(f"Status: {nm[host].state()}")
    
    for proto in nm[host].all_protocols():  # TCP/UDP
        print(f"\nProtocol: {proto}")
        ports = nm[host][proto].keys()
        
        for port in ports:
            print(f"Port {port}: {nm[host][proto][port]['state']}")