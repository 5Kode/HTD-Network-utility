import socket
import struct
import time
import threading

class NetworkIOSniffer:
    """Captures live IP packets using raw sockets (Requires Administrator Privileges)."""
    
    def __init__(self):
        self.active = False
        self.packet_buffer = []
        self.max_buffer = 50 # Keep the UI from lagging by capping the list
        
        # Get the local machine's primary IP to bind the sniffer
        try:
            self.host_ip = socket.gethostbyname(socket.gethostname())
        except:
            self.host_ip = "127.0.0.1"

    def start_sniffing(self):
        self.active = True
        threading.Thread(target=self._sniff_loop, daemon=True).start()

    def _sniff_loop(self):
        try:
            # Set up the raw socket (Requires Admin on Windows)
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((self.host_ip, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except Exception as e:
            self.packet_buffer.append({"error": f"Admin required for raw sockets: {e}"})
            return

        while self.active:
            try:
                raw_data, _ = sniffer.recvfrom(65565)
                self._parse_packet(raw_data)
            except Exception:
                pass

    def _parse_packet(self, raw_data):
        # Extract the first 20 bytes (IPv4 Header)
        ip_header = raw_data[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        # Extract Protocol and IP addresses
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        
        # Map protocol numbers to names
        proto_name = "TCP" if protocol == 6 else "UDP" if protocol == 17 else "ICMP" if protocol == 1 else str(protocol)
        
        timestamp = time.strftime("%H:%M:%S")
        
        # Format: 192.168.1.10 > 192.168.1.20 | UDP | 14:05:01
        packet_record = {
            "source": s_addr,
            "destination": d_addr,
            "protocol": proto_name,
            "timestamp": timestamp
        }
        
        self.packet_buffer.insert(0, packet_record)
        if len(self.packet_buffer) > self.max_buffer:
            self.packet_buffer.pop()

    def get_latest_packets(self):
        return list(self.packet_buffer)