import nmap
import shodan
import urllib.parse

def scan_website(target):
    parsed_url = urllib.parse.urlparse(target)
    hostname = parsed_url.hostname
    nm = nmap.PortScanner()
    scan_result = nm.scan(hostname)
    scan_dict = {}

    for host in scan_result:
        host_data = scan_result[host]
        print(f"Host data for {host}: {host_data}")
        scan_dict[host] = {
            "status": host_data.get('state', 'unknown'), 
            "ports": {}
        }

        if 'tcp' in host_data: 
            for port in host_data['tcp']:
                port_data = host_data['tcp'][port]
                scan_dict[host]["ports"][port] = {
                    "state": port_data['state'],
                    "service": port_data['product'],
                    "protocol": port_data['protocol']
                }

    return scan_dict

def detect_rdp_firewall(target):
    shodan_api = shodan.Shodan("MASUKAN_API_SHODAN")  # Ubah Shodan API Kalian

    try:
        hosts = shodan_api.search(f"port:3389 {target}") 
    except shodan.APIError as e:
        print(f"Error: {e}")
        return None

    if not hosts:
        return None

    firewall_type = None
    for host in hosts:
        if "firewall" in host.data:
            firewall_type = host.data["firewall"]
            break

    return firewall_type

if __name__ == "__main__":
    target_website = "MASUKAN_TARGET" # Masukan website target anda (gunakan https:// atau http://)
    
    scan_results = scan_website(target_website)

    # Cetak hasil scan
    print("Hasil Scan Website:")
    for host, data in scan_results.items():
        print(f"\nHost: {host}")
        print(f"Status: {data['status']}")
        print(f"Port: {data['ports']}")

    # Deteksi RDP Server dan jenis firewall
    rdp_firewall_info = detect_rdp_firewall(target_website)

    # Cetak informasi RDP Server dan jenis firewall
    if rdp_firewall_info:
        print("\nInformasi RDP Server:")
        print(f"RDP Server ditemukan: Ya")
        print(f"Jenis firewall: {rdp_firewall_info}")
    else:
        print("\nInformasi RDP Server:")
        print(f"RDP Server ditemukan: Tidak")
