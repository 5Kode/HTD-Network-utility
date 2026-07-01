import subprocess
import platform
import socket
import concurrent.futures
import ipaddress

class ARPCacheSweeper:
    def __init__(self):
        self.os_type = platform.system()
        
        # Massive built-in dictionary covering common router, phone, PC, and IoT prefixes
        self.mac_vendors = {
            # --- Personal Computers & Hardware Vendors ---
            "10:2C:6B": "ASUSTeK", "00:1E:8C": "ASUSTeK", "50:46:5D": "ASUSTeK", "B0:6E:BF": "ASUSTeK",
            "B4:AE:2B": "Intel", "00:1B:21": "Intel", "4C:77:CB": "Intel", "A0:C5:89": "Intel",
            "48:90:F0": "Dell", "00:14:22": "Dell", "F8:BC:12": "Dell",
            "00:03:FF": "Microsoft", "00:15:5D": "Microsoft", "28:18:78": "Microsoft",
            "00:11:85": "Hewlett-Packard", "00:25:B3": "Hewlett-Packard", "A0:D3:C1": "Hewlett-Packard",
            "00:16:D3": "Lenovo", "48:51:B5": "Lenovo", "60:99:D1": "Lenovo",
            
            # --- Smart Mobile Devices & Tablets ---
            "BC:D0:74": "Apple", "00:1C:B3": "Apple", "78:4F:43": "Apple", "D8:30:62": "Apple", "F0:18:98": "Apple",
            "F8:FF:C2": "Samsung", "00:12:36": "Samsung", "48:42:0B": "Samsung", "98:0D:2E": "Samsung",
            "00:1A:11": "Google", "F8:8F:CA": "Google", "3C:5C:C4": "Google",
            "00:E0:66": "LG Electronics", "34:FC:9F": "LG Electronics",
            
            # --- Core Networking Equipment (Routers, Switches, Extenders) ---
            "00:00:0C": "Cisco", "00:14:69": "Cisco", "00:2A:10": "Cisco", "70:69:5A": "Cisco",
            "00:0F:66": "Cisco Linksys", "00:25:9C": "Cisco Linksys",
            "00:14:BF": "Linksys", "60:38:E0": "Linksys",
            "00:0F:B5": "Netgear", "00:1E:2A": "Netgear", "20:4E:7F": "Netgear", "84:1B:5E": "Netgear",
            "00:1D:0F": "TP-Link", "50:C7:BF": "TP-Link", "98:DE:D0": "TP-Link", "E8:DE:27": "TP-Link",
            "00:0F:3D": "D-Link", "18:62:2C": "D-Link", "B8:A3:86": "D-Link",
            "70:A6:CC": "Ubiquiti", "F0:9F:C2": "Ubiquiti",
            "24:A4:3C": "Ubiquiti Networks",
            
            # --- Home Streaming, Audio & IoT Platforms ---
            "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
            "44:65:0D": "Amazon Technologies", "F0:D2:F1": "Amazon Technologies", "FC:A1:3E": "Amazon Technologies",
            "00:0D:4B": "Roku", "20:F5:43": "Roku", "74:C6:3B": "Roku",
            "00:01:4A": "Sony", "F8:D0:AC": "Sony", "70:9E:29": "Sony",
            "00:07:E9": "Intelbras",
            
            # --- Microcontrollers & IoT Modules ---
            "24:0A:C4": "Espressif", "30:AE:A4": "Espressif", "A4:CF:12": "Espressif",
            
            # --- Virtualized Infrastructures ---
            "00:0C:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware",
            "08:00:27": "Oracle VirtualBox"
        }

    def _get_local_subnet_prefix(self):
        """Discovers the active local subnet dynamically."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}."
        except Exception:
            pass
        return "192.168.1."  # Sensible fallback

    def _ping_address(self, ip_address):
        """Wakes up dead hosts to populate the kernel's volatile ARP database."""
        if self.os_type == "Windows":
            subprocess.run(
                ["ping", "-n", "1", "-w", "200", ip_address],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

    def _populate_arp_cache(self):
        """Asynchronously blasts the network to unmask all active elements."""
        subnet_prefix = self._get_local_subnet_prefix()
        print(f"[*] Priming local subnet: {subnet_prefix}0/24... Please wait...")
        
        ip_addresses = [f"{subnet_prefix}{i}" for i in range(1, 255)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(self._ping_address, ip_addresses)

    def _guess_device(self, mac_address):
        """Inspects OUI markers to evaluate the hardware manufacturer."""
        oui = mac_address[:8]
        return self.mac_vendors.get(oui, "Unknown Vendor")

    def _resolve_hostname(self, ip_address):
        """Resolves target host DNS attributes safely using clean fallbacks."""
        socket.setdefaulttimeout(1.0) 
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname if hostname else "N/A"
        except Exception:
            return "N/A"

    def fetch_local_devices(self):
        if self.os_type != "Windows":
            print("[-] Error: This engine implementation is specific to the Windows platform structure.")
            return []
            
        # Run background sweeping to refresh the host environment cache map
        self._populate_arp_cache()
        
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return self._parse_arp_table(result.stdout)
        except Exception as e:
            return [{"error": f"ARP retrieval anomaly: {str(e)}"}]

    def _parse_arp_table(self, raw_stdout):
        device_list = []
        raw_devices = []

        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line or "Interface:" in line or "Internet Address" in line:
                continue
                
            parts = line.split()
            if len(parts) >= 2:
                ip_addr = parts[0]
                mac_addr = parts[1]
                
                if ip_addr.count('.') == 3 and mac_addr.count('-') == 5:
                    mac_addr = mac_addr.upper().replace("-", ":")
                    
                    try:
                        ip_obj = ipaddress.ip_address(ip_addr)
                        # Excludes local multi-cast pools (224.x.x.x - 239.x.x.x) and sub broadcasts
                        if ip_obj.is_multicast or ip_obj.is_loopback or ip_addr.endswith(".255"):
                            continue
                    except ValueError:
                        continue 
                        
                    raw_devices.append({"ip": ip_addr, "mac": mac_addr})

        # Drop multi-interface line duplications if present
        unique_devices = {d['ip']: d for d in raw_devices}.values()

        # Concurrent task execution pool for tracking naming structures safely
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            future_to_device = {
                executor.submit(self._resolve_hostname, dev["ip"]): dev 
                for dev in unique_devices
            }
            
            for future in concurrent.futures.as_completed(future_to_device):
                dev = future_to_device[future]
                hostname = future.result()
                
                device_list.append({
                    "ip_address": dev["ip"],
                    "mac_address": dev["mac"],
                    "hostname": hostname,
                    "device_guess": self._guess_device(dev["mac"])
                })

        return device_list

if __name__ == "__main__":
    sweeper = ARPCacheSweeper()
    devices = sweeper.fetch_local_devices()
    
    print(f"\n[+] Processing completed. Identified {len(devices)} active local targets:")
    print("=" * 95)
    print(f"{'IP ADDRESS':<16} | {'MAC ADDRESS':<17} | {'ESTIMATED VENDOR':<25} | {'HOSTNAME'}")
    print("-" * 95)
    
    # Sort addresses linearly by network sequence for simple analysis mapping
    sorted_devices = sorted(devices, key=lambda x: [int(num) for num in x["ip_address"].split('.')])
    for d in sorted_devices:
        print(f"{d['ip_address']:<16} | {d['mac_address']:<17} | {d['device_guess']:<25} | {d['hostname']}")