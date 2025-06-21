from scapy.all import ARP, Ether, srp, sniff, wrpcap
import nmap
import time
import json
from datetime import datetime

# Load MAC address whitelist
def load_whitelist():
    with open("whitelist.txt") as f:
        return set(line.strip().lower() for line in f if line.strip())

# Scan the network using ARP
def scan_network(target_ip="192.168.254.0/24"):
    print("[*] Scanning network...")
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc.lower()
        devices.append((ip, mac))
    return devices

# Save packet capture for suspicious IP
def capture_pcap(ip, duration=10):
    filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{ip.replace('.', '_')}.pcap"
    print(f"[!] Capturing traffic for {ip} into {filename}...")
    packets = sniff(filter=f"host {ip}", timeout=duration)
    wrpcap(filename, packets)
    print("[+] PCAP saved.")
    return filename

# Save scan result to a JSON file
def save_scan_to_json(scan_info, ip):
    json_filename = f"scan_{ip.replace('.', '_')}.json"
    with open(json_filename, "w") as f:
        json.dump(scan_info, f, indent=4)
    print(f"[+] Nmap scan data saved to {json_filename}")

# Scan a device with Nmap
def scan_with_nmap(ip):
    print(f"[!] Scanning {ip} with Nmap...")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip, arguments="-O -sV")

    if ip in scanner.all_hosts():
        info = {
            "IP": ip,
            "Hostname": scanner[ip].hostname(),
            "State": scanner[ip].state(),
            "MAC": scanner[ip]['addresses'].get('mac', 'N/A'),
            "Vendor": scanner[ip].get('vendor', {}),
            "OS_Match": [],
            "Ports": []
        }

        for match in scanner[ip].get('osmatch', []):
            info["OS_Match"].append({
                "Name": match.get("name"),
                "Accuracy": match.get("accuracy"),
                "OS_Class": match.get("osclass", [])
            })

        for proto in scanner[ip].all_protocols():
            for port in scanner[ip][proto]:
                svc = scanner[ip][proto][port]
                info["Ports"].append({
                    "Port": port,
                    "State": svc['state'],
                    "Name": svc['name'],
                    "Product": svc.get('product', ''),
                    "Version": svc.get('version', '')
                })

        return info
    else:
        return None

# Main loop
def main():
    whitelist = load_whitelist()
    print("[*] Loaded whitelist MACs:", whitelist)
    
    while True:
        devices = scan_network()
        unauthorized = [(ip, mac) for ip, mac in devices if mac not in whitelist]

        if unauthorized:
            print("\n[!] Unauthorized devices found:")
            for ip, mac in unauthorized:
                print(f" -> {ip} ({mac})")

                # Capture traffic
                capture_pcap(ip)

                # Run Nmap scan
                scan_info = scan_with_nmap(ip)
                if scan_info:
                    scan_info['Detected_MAC'] = mac  # add actual detected MAC
                    save_scan_to_json(scan_info, ip)

                    print("\n--- Nmap Scan Result ---")
                    print(f"IP: {scan_info['IP']}")
                    print(f"Hostname: {scan_info['Hostname']}")
                    print(f"MAC: {scan_info['MAC']}")
                    print("Vendor:", scan_info["Vendor"])
                    if scan_info['OS_Match']:
                        print("OS Guess:", scan_info['OS_Match'][0]['Name'])
                    print("Open Ports:")
                    for port in scan_info['Ports']:
                        print(f"  {port['Port']}/{port['Name']} - {port['State']} - {port['Product']} {port['Version']}")
                    print("--------------------------\n")
                else:
                    print("[!] No scan data returned from Nmap.")
        else:
            print("[+] No unauthorized devices detected.")

        print("[*] Waiting 60 seconds before next scan...\n")
        time.sleep(60)

if __name__ == "__main__":
    main()
