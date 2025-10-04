import scapy.all as scapy

def scan(ip_range):
    print(f"Scanning IP range: {ip_range}")
    
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    print("Sending ARP requests...")
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=True)[0]
    
    if not answered_list:
        print("No responses received.")
    else:
        print("Responses received.")
    
    devices = []
    for element in answered_list:
        device = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        devices.append(device)
        print(f"Device found: IP = {device['ip']}, MAC = {device['mac']}")
    
    return devices

ip_range = "192.168.1.1/24"

devices = scan(ip_range)

print(devices)

