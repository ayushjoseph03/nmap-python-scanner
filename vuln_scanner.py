import nmap

nm = nmap.PortScanner()
target = "192.168.1.1"

print(f"Scanning {target} for vulnerabilities...")
nm.scan(hosts=target, arguments="--script vuln")

for host in nm.all_hosts():
    print(f"\nResults for {host}:")
    if "script" in nm[host]:
        for script, output in nm[host]["script"].items():
            print(f"\n{script}:")
            print(output)