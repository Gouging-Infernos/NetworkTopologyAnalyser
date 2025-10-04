#!/usr/bin/env python3
import os
import sys
import socket
import netifaces  # type: ignore
from scapy.all import ARP, srp, Ether  # type: ignore
import nmap
import concurrent.futures
import time
from typing import List, Dict

# ----- utility functions -----
def get_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def get_default_gateway() -> str:
    gws = netifaces.gateways()
    return gws['default'][netifaces.AF_INET][0]

# ----- discovery (ARP) -----
def arp_discover(target_cidr: str, timeout: float = 3.0) -> List[Dict[str,str]]:
    """
    Return list of dicts: [{'ip': '192.168.1.10', 'mac': 'aa:bb:cc:...'}, ...]
    """
    arp = ARP(pdst=target_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    # srp returns (answered, unanswered)
    answered = srp(packet, timeout=timeout, verbose=0)[0]
    clients = []
    for sent, received in answered:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    return clients

# ----- nmap scanning -----
def scan_host_nmap(host_ip: str, ports: str = "1-1024", args: str = "-sT -T4 --open") -> Dict:
    """
    Uses python-nmap PortScanner to scan a single host.
    Returns a dict with host, timestamp, and list of open ports (or error).
    """
    try:
        nm = nmap.PortScanner()
    except Exception as e:
        return {"host": host_ip, "error": f"nmap.PortScanner init error: {e}"}

    try:
        nm.scan(hosts=host_ip, ports=ports, arguments=args)
    except Exception as e:
        return {"host": host_ip, "error": f"nmap scan error: {e}"}

    if host_ip not in nm.all_hosts():
        return {"host": host_ip, "ports": [], "note": "host not in scan result"}

    host_entry = nm[host_ip]
    results = []
    for proto in host_entry.all_protocols():
        proto_ports = host_entry[proto].keys()
        for port in sorted(proto_ports):
            pinfo = host_entry[proto][port]
            results.append({
                "proto": proto,
                "port": int(port),
                "state": pinfo.get("state"),
                "service": pinfo.get("name"),
                "product": pinfo.get("product"),
                "version": pinfo.get("version"),
            })
    return {"host": host_ip, "ports": results, "timestamp": time.time()}

# ----- coordinator -----
def main():
    # quick permission hint for ARP
    if os.geteuid() != 0:
        print("⚠️  Warning: ARP discovery requires root privileges on Linux.")
        print("   Run with sudo or grant CAP_NET_RAW to the interpreter.")
        print("   You can still run Nmap TCP-connect scans without root.")
        print()

    # network detection
    try:
        my_ip = get_ip()
        gw = get_default_gateway()
    except Exception as e:
        print("Error detecting IP/gateway:", e)
        sys.exit(1)

    print(f"My IP: {my_ip}")
    print(f"Default Gateway: {gw}")

    # build target CIDR - conservative /24; you can change if needed
    target_cidr = f"{'.'.join(gw.split('.')[:3])}.0/24"
    print(f"Discovering hosts in {target_cidr} via ARP...")

    try:
        clients = arp_discover(target_cidr, timeout=3)
    except PermissionError as e:
        print("Permission error during ARP discovery:", e)
        print("Run as root or setcap cap_net_raw+ep on the python binary in your venv.")
        clients = []

    if not clients:
        print("No ARP clients found (or ARP discovery failed). Exiting.")
        # Optionally: fall back to a ping-sweep or nmap host discovery here.
        sys.exit(0)

    print("Available devices in the network:")
    print("IP" + " "*18 + "MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))

    # Extract IPs for scanning
    ips = [c['ip'] for c in clients]

    # concurrent nmap scanning
    print("\nStarting Nmap scans (concurrent)...")
    max_workers = min(20, len(ips) or 1)
    scan_args = "-sS -T4 --open -sV"  # -sT avoids needing root; use -sS if you run the helper as root
    ports="22,80,443,3389,5900"

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_host_nmap, ip, ports, scan_args): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            results.append(res)
            host = res.get("host", futures[fut])
            if "error" in res:
                print(f"[{host}] scan error: {res['error']}")
            else:
                port_list = res.get("ports", [])
                if not port_list:
                    print(f"[{host}] no open ports found (or none reported).")
                else:
                    print(f"\n[{host}] Open ports:")
                    for p in port_list:
                        print("  - {proto}/{port}  {state}  service={service}  product={product} {version}".format(
                            proto=p.get("proto"),
                            port=p.get("port"),
                            state=p.get("state"),
                            service=p.get("service") or "",
                            product=p.get("product") or "",
                            version=p.get("version") or ""
                        ))

    # Optionally, save results to file or DB
    # import json, datetime
    # with open("nmap_results.json","w") as fh:
    #     json.dump({"ts": datetime.datetime.utcnow().isoformat(), "results": results}, fh, indent=2)

if __name__ == "__main__":
    main()
