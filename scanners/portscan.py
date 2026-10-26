import nmap

def scan(host, ports="1-1000"):
    nm = nmap.PortScanner()
    # Using -Pn skips host discovery (assumes host is up), which fixes most silent drop issues
    nm.scan(hosts=host, arguments=f"-p {ports} -sT -T4 -Pn")
    out = []
    for h in nm.all_hosts():
        if "tcp" in nm[h]:
            for p in nm[h]["tcp"]:
                if nm[h]["tcp"][p]["state"] == "open":
                    out.append({"port": p, "service": nm[h]["tcp"][p]["name"]})
    return out
