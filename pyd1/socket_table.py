import psutil
import socket
import time

class SocketTableReader:
    """Interrogates the kernel socket structures and calculates per-process I/O deltas."""
    
    def __init__(self):
        self.connection_kind = 'inet'
        self.last_io_snapshot = {}
        self.last_time = time.time()
        self._take_io_snapshot()

    def _take_io_snapshot(self):
        """Captures a baseline of network bytes sent/received per process."""
        snapshot = {}
        current_time = time.time()
        try:
            # Gather aggregate counters per PID if supported by OS
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    io_counters = proc.net_io_counters()
                    snapshot[proc.info['pid']] = {
                        "bytes": io_counters.bytes_sent + io_counters.bytes_recv,
                        "time": current_time
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    continue
        except Exception:
            pass
        self.last_io_snapshot = snapshot

    def calculate_process_throughput(self, pid):
        """Computes current data transfer rate (KB/s) for a given PID since last check."""
        if not pid or pid not in self.last_io_snapshot:
            return "0.00 KB/s"
            
        try:
            proc = psutil.Process(pid)
            io_now = proc.net_io_counters()
            bytes_now = io_now.bytes_sent + io_now.bytes_recv
            time_now = time.time()
            
            bytes_delta = bytes_now - self.last_io_snapshot[pid]["bytes"]
            time_delta = time_now - self.last_io_snapshot[pid]["time"]
            
            if time_delta > 0 and bytes_delta > 0:
                kb_s = (bytes_delta / 1024) / time_delta
                return f"{kb_s:.2f} KB/s"
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            pass
        return "0.00 KB/s"

    def get_active_sockets(self):
        """Fetches advanced structural records containing IP families and live delta metrics."""
        active_connections = []
        
        for conn in psutil.net_connections(kind=self.connection_kind):
            process_name = "Unknown"
            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "System/Protected"

            # 1. Advanced Telemetry: Resolve Protocol Family (IPv4 vs IPv6)
            ip_family = "IPv4"
            if conn.family == socket.AF_INET6:
                ip_family = "IPv6"

            # 2. Advanced Telemetry: Calculate Live Data Throughput
            throughput = self.calculate_process_throughput(conn.pid) if conn.pid else "0.00 KB/s"

            local_endpoint = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "0.0.0.0:*"
            remote_endpoint = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "*:*"
            transport_protocol = "TCP" if conn.type == 1 else "UDP"

            active_connections.append({
                "transport_protocol": transport_protocol,
                "ip_family": ip_family,
                "local_endpoint": local_endpoint,
                "remote_endpoint": remote_endpoint,
                "connection_state": conn.status,
                "pid": conn.pid if conn.pid else 0,
                "process_name": process_name,
                "throughput": throughput
            })
            
        # Refresh baseline snapshot for the next paint loop cycle
        self._take_io_snapshot()
        return active_connections