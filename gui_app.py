import tkinter as tk
from tkinter import ttk, messagebox
import sys
import ctypes
import threading
import time
import hashlib
import os
import json
from datetime import datetime

# Engine modules
from htd_setup import load_config
from pyd1.socket_table import SocketTableReader
from pyd1.arp_cache_sweeper import ARPCacheSweeper
from pyd1.wlan_interface import WLANInterfaceController
from pyd1.packet_sniffer import NetworkIOSniffer

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

if sys.platform.startswith("win") and not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        " ".join(f'"{a}"' for a in sys.argv),
        None,
        1,
    )
    sys.exit()


class HTDSystemExplorerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("HTD | Network Utility")
        
        self.style = ttk.Style(self)
        self.style.theme_use("winnative" if "win" in sys.platform else "clam")
        self.style.configure("Treeview", font=("Consolas", 9), rowheight=20)
        self.style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        
        self.config = load_config()
        
        if self.config.get("cv_enabled", False):
            self.build_security_gate_view()
        else:
            self.initialize_core_application()

    def center_window(self, width, height):
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = int((screen_width / 2) - (width / 2))
        y = int((screen_height / 2) - (height / 2))
        self.geometry(f'{width}x{height}+{x}+{y}')

    # ==========================================
    # SECURITY GATE INTERFACE
    # ==========================================
    def build_security_gate_view(self):
        self.center_window(350, 180)
        self.resizable(False, False)
        
        self.gate_frame = ttk.Frame(self, padding=20)
        self.gate_frame.pack(fill="both", expand=True)
        
        lbl_title = ttk.Label(self.gate_frame, font=("Segoe UI", 10, "bold"), text="Enter your [CV] Code")
        lbl_title.pack(pady=(0, 10))
        
        self.ent_pin = ttk.Entry(self.gate_frame, font=("Consolas", 12), show="*", justify="center")
        self.ent_pin.pack(fill="x", pady=5)
        self.ent_pin.focus_set()
        
        self.lbl_error = ttk.Label(self.gate_frame, font=("Segoe UI", 8), foreground="red", text="")
        self.lbl_error.pack(pady=2)
        
        btn_submit = ttk.Button(self.gate_frame, text="Unlock", command=self.validate_cv_credentials)
        btn_submit.pack(fill="x", pady=(5, 0))
        
        self.bind("<Return>", lambda event: self.validate_cv_credentials())
        self.remaining_attempts = 3

    def validate_cv_credentials(self):
        entered_pin = self.ent_pin.get().strip()
        if hashlib.sha256(entered_pin.encode('utf-8')).hexdigest() == self.config.get("cv_hash"):
            self.unbind("<Return>")
            self.gate_frame.destroy()
            self.initialize_core_application()
        else:
            self.remaining_attempts -= 1
            self.ent_pin.delete(0, tk.END)
            if self.remaining_attempts <= 0:
                self.destroy()
                sys.exit()
            else:
                self.lbl_error.config(text=f"Invalid code. Attempts left: {self.remaining_attempts}")

    # ==========================================
    # CORE DASHBOARD APPLICATION
    # ==========================================
    def initialize_core_application(self):
        self.center_window(1250, 750)
        self.resizable(True, True)
        
        self.socket_reader = SocketTableReader()
        self.arp_sweeper = ARPCacheSweeper()
        self.wlan_controller = WLANInterfaceController()
        
        self.packet_sniffer = NetworkIOSniffer()
        self.packet_sniffer.start_sniffing()
        
        self.latest_wlan_data = {}
        self.latest_socket_data = []
        self.latest_lan_data = []
        self.latest_wifi_networks = []
        self.seen_packet_signatures = set()
        
        # Security IDS State
        self.blacklisted_ips = set()
        self.flagged_events_log = []
        
        # State tracking for data population notifications
        self.lan_is_refreshing = False
        self.wlan_is_refreshing = False
        
        self.build_layout_grid()
        self.start_background_workers()
        self.paint_ui_loop()

    def build_layout_grid(self):
        self.header_frame = ttk.LabelFrame(self, text=" Current WiFi Network ")
        self.header_frame.pack(fill="x", padx=5, pady=5)
        
        self.lbl_wlan_meta = ttk.Label(self.header_frame, font=("Segoe UI", 9, "bold"), text="Initializing telemetry...")
        self.lbl_wlan_meta.pack(anchor="w", padx=8, pady=4)

        self.filter_frame = ttk.LabelFrame(self, text=" Make a filter query ")
        self.filter_frame.pack(fill="x", padx=5, pady=2)
        
        ttk.Label(self.filter_frame, text="Protocol / Time query:").pack(side="left", padx=5, pady=5)
        self.ent_search_filter = ttk.Entry(self.filter_frame, width=35)
        self.ent_search_filter.insert(0, "UDP") 
        self.ent_search_filter.pack(side="left", padx=5, pady=5)
        
        btn_filter = ttk.Button(self.filter_frame, text="filter", command=self.execute_traffic_highlighting)
        btn_filter.pack(side="left", padx=5, pady=5)

        btn_export = ttk.Button(self.filter_frame, text="💾 Export System State", command=self.export_telemetry_logs)
        btn_export.pack(side="right", padx=10, pady=5)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)

        # TAB 1: Process Sockets
        self.tab_sockets = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sockets, text=" Active Proccesses ")
        self._build_treeview(self.tab_sockets, "sockets", ("PID", "PROCESS", "PROTO", "LOCAL ENDPOINT", "REMOTE ENDPOINT", "STATE", "I/O RATE"))

        # TAB 2: ARP LAN Map
        self.tab_lan = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_lan, text=" LAN Devices ")
        self._build_lan_tab()
        
        # TAB 3: Network I/O
        self.tab_traffic = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_traffic, text=" Captured Traffic ")
        self._build_treeview(self.tab_traffic, "traffic", ("TIMESTAMP", "PROTOCOL", "SOURCE IP", "DESTINATION IP"))

        # TAB 4: WLAN Scanner
        self.tab_wifi = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_wifi, text=" WLAN  ")
        self._build_wifi_tab()
        
        # TAB 5: Security Flagging (IDS)
        self.tab_security = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_security, text=" IP Tripping (beta) (Pinging only!) ")
        self._build_security_tab()

        # TAB 6: Legend
        self.tab_legend = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_legend, text=" Tips ")
        self._build_legend_tab()

    def _build_treeview(self, parent, attr_name, cols):
        tree = ttk.Treeview(parent, columns=cols, show="headings")
        setattr(self, f"tree_{attr_name}", tree)
        
        tree.tag_configure('tcp', background='#e3f2fd') 
        tree.tag_configure('udp', background='#fff9c4') 
        tree.tag_configure('icmp', background='#e8f5e9') 
        tree.tag_configure('listen', foreground='#9e9e9e') 
        tree.tag_configure('separator', background='#bdbdbd', foreground='#ffffff') 
        tree.tag_configure('highlighted_match', background='#a5d6a7', font=("Consolas", 9, "bold")) 
        tree.tag_configure('flagged', foreground='#d32f2f', background='#ffebee', font=("Consolas", 9, "bold")) 
        
        for col in cols:
            tree.heading(col, text=col, anchor="w")
            tree.column(col, width=150, anchor="w")
            
        scroll = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _build_lan_tab(self):
        top_ctrl = ttk.Frame(self.tab_lan, padding=5)
        top_ctrl.pack(fill="x")
        
        btn_refresh_lan = ttk.Button(top_ctrl, text="🔄 Rescan Local Network", command=self.trigger_manual_lan_rescan)
        btn_refresh_lan.pack(side="left", padx=5)
        
        self.lbl_lan_notice = ttk.Label(top_ctrl, text="⚠️ Notice: Population time may vary", font=("Segoe UI", 9, "italic"), foreground="orange")
        self.lbl_lan_notice.pack(side="left", padx=15)
        
        tree_container = ttk.Frame(self.tab_lan)
        tree_container.pack(fill="both", expand=True)
        self._build_treeview(tree_container, "lan", ("IP ADDRESS", "MAC ADDRESS", "HOSTNAME"))

    def _build_security_tab(self):
        ctrl_frame = ttk.LabelFrame(self.tab_security, text=" Target IDS Configuration ")
        ctrl_frame.pack(fill="x", padx=5, pady=5)
        
        left_input = ttk.Frame(ctrl_frame)
        left_input.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        ttk.Label(left_input, text="Create Tripwire:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.ent_blacklist = ttk.Entry(left_input, width=30)
        self.ent_blacklist.grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        btn_add = ttk.Button(left_input, text="Add Tripwire", command=self.add_to_blacklist)
        btn_add.grid(row=0, column=2, sticky="w", padx=5, pady=5)
        
        self.lbl_blacklist_status = ttk.Label(left_input, text="Active Blacklist: None", foreground="gray")
        self.lbl_blacklist_status.grid(row=1, column=0, columnspan=3, sticky="w", padx=5, pady=5)

        right_list = ttk.LabelFrame(ctrl_frame, text=" Managed Target Entries ")
        right_list.pack(side="right", padx=10, pady=5, fill="y")
        
        self.lst_blacklist = tk.Listbox(right_list, height=4, width=35, font=("Consolas", 9))
        self.lst_blacklist.pack(side="left", padx=5, pady=5)
        
        sc_list = ttk.Scrollbar(right_list, orient="vertical", command=self.lst_blacklist.yview)
        self.lst_blacklist.configure(yscrollcommand=sc_list.set)
        sc_list.pack(side="left", fill="y", pady=5)
        
        btn_pane = ttk.Frame(right_list)
        btn_pane.pack(side="right", padx=5)
        
        ttk.Button(btn_pane, text="Purge Selected", command=self.purge_selected_blacklist_item).pack(fill="x", pady=2)
        ttk.Button(btn_pane, text="Purge All", command=self.clear_blacklist).pack(fill="x", pady=2)

        log_frame = ttk.LabelFrame(self.tab_security, text=" Security Event Logs ")
        log_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        cols = ("TIMESTAMP", "LOCAL DEVICE", "TARGET IP", "DIRECTION")
        self.tree_flagged = ttk.Treeview(log_frame, columns=cols, show="headings")
        self.tree_flagged.tag_configure('flagged', foreground='#d32f2f', background='#ffebee', font=("Consolas", 9, "bold"))
        
        for col in cols:
            self.tree_flagged.heading(col, text=col, anchor="w")
            self.tree_flagged.column(col, width=200)
            
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.tree_flagged.yview)
        self.tree_flagged.configure(yscrollcommand=scroll.set)
        self.tree_flagged.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _build_wifi_tab(self):
        top_ctrl = ttk.Frame(self.tab_wifi, padding=5)
        top_ctrl.pack(fill="x")
        
        btn_refresh_wifi = ttk.Button(top_ctrl, text="🔄 Rescan Environment Interfaces", command=self.trigger_manual_wlan_rescan)
        btn_refresh_wifi.pack(side="left", padx=5)
        
        self.lbl_wlan_notice = ttk.Label(top_ctrl, text="⚠️ Notice: Population time may vary", font=("Segoe UI", 9, "italic"), foreground="orange")
        self.lbl_wlan_notice.pack(side="left", padx=15)

        display_container = ttk.Frame(self.tab_wifi)
        display_container.pack(fill="both", expand=True)

        scan_frame = ttk.LabelFrame(display_container, text=" Available Networks in Range ")
        scan_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        cols = ("SSID", "SECURITY", "SIGNAL STRENGTH")
        self.tree_wifi = ttk.Treeview(scan_frame, columns=cols, show="headings")
        for col in cols:
            self.tree_wifi.heading(col, text=col, anchor="w")
            self.tree_wifi.column(col, width=120)
        self.tree_wifi.pack(fill="both", expand=True)

        conn_frame = ttk.LabelFrame(display_container, text=" Advanced Direct Connect ")
        conn_frame.pack(side="right", fill="y", padx=5, pady=5)
        ttk.Label(conn_frame, text="Target SSID:").pack(anchor="w", padx=10, pady=(10,0))
        self.ent_ssid = ttk.Entry(conn_frame, width=30)
        self.ent_ssid.pack(padx=10, pady=2)
        ttk.Label(conn_frame, text="Password / Key:").pack(anchor="w", padx=10, pady=(10,0))
        self.ent_pass = ttk.Entry(conn_frame, width=30, show="*")
        self.ent_pass.pack(padx=10, pady=2)
        ttk.Label(conn_frame, text="Security Protocol:").pack(anchor="w", padx=10, pady=(10,0))
        self.combo_sec = ttk.Combobox(conn_frame, values=["WPA2-Personal", "WPA-Personal", "Open"], state="readonly", width=27)
        self.combo_sec.current(0)
        self.combo_sec.pack(padx=10, pady=2)
        ttk.Button(conn_frame, text="Inject Profile & Connect", command=self.handle_direct_connect).pack(fill="x", padx=10, pady=20)

    def _build_legend_tab(self):
        text_area = tk.Text(self.tab_legend, font=("Segoe UI", 10), wrap="word", bg="#f5f5f5", padx=20, pady=20)
        text_area.pack(fill="both", expand=True)
        legend_content = """HTD SYSTEM EXPLORER - UTILITY LEGEND
--------------------------------------------------

[ SYNTAX COLORING ]
BLUE (TCP)    : Connection-based traffic.
YELLOW (UDP)  : Fast, connectionless datagram streams.
GREEN (ICMP)  : Status queries and diagnostics.
GREY TEXT     : Passive listeners waiting for socket assignment.
RED (IDS)     : Security tripwire triggered. Traffic matched the active IP blacklist.

[ SECURITY FLAGGING ]
- Allows you to construct a local blacklist. Any packet captured in the main I/O stream that touches a blacklisted IP will be hard-logged in the Security Tab and mapped to its originating physical device on your LAN.
"""
        text_area.insert(tk.END, legend_content)
        text_area.config(state="disabled")

    # ==========================================
    # LOGIC HANDLERS
    # ==========================================
    def trigger_manual_lan_rescan(self):
        self.lan_is_refreshing = True
        self.lbl_lan_notice.pack(side="left", padx=15) 
        self.tree_lan.delete(*self.tree_lan.get_children())
        threading.Thread(target=self._execute_lan_sweep, daemon=True).start()

    def _execute_lan_sweep(self):
        try:
            self.latest_lan_data = self.arp_sweeper.fetch_local_devices()
        except: pass

    def trigger_manual_wlan_rescan(self):
        self.wlan_is_refreshing = True
        self.lbl_wlan_notice.pack(side="left", padx=15) 
        self.tree_wifi.delete(*self.tree_wifi.get_children())
        threading.Thread(target=self._execute_wlan_sweep, daemon=True).start()

    def _execute_wlan_sweep(self):
        try:
            self.latest_wifi_networks = self.wlan_controller.fetch_available_networks()
        except: pass

    def add_to_blacklist(self):
        ip = self.ent_blacklist.get().strip()
        if ip and ip not in self.blacklisted_ips:
            self.blacklisted_ips.add(ip)
            self.lst_blacklist.insert(tk.END, ip)
            self.ent_blacklist.delete(0, tk.END)
            self.lbl_blacklist_status.config(text=f"Active Blacklist: {len(self.blacklisted_ips)} IPs loaded")

    def purge_selected_blacklist_item(self):
        try:
            selected_idx = self.lst_blacklist.curselection()
            if selected_idx:
                ip = self.lst_blacklist.get(selected_idx)
                self.blacklisted_ips.remove(ip)
                self.lst_blacklist.delete(selected_idx)
                status_text = f"Active Blacklist: {len(self.blacklisted_ips)} IPs loaded" if self.blacklisted_ips else "Active Blacklist: None"
                self.lbl_blacklist_status.config(text=status_text)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to drop target item: {e}")

    def clear_blacklist(self):
        self.blacklisted_ips.clear()
        self.lst_blacklist.delete(0, tk.END)
        self.lbl_blacklist_status.config(text="Active Blacklist: None")
        self.tree_flagged.delete(*self.tree_flagged.get_children())
        self.flagged_events_log.clear()

    def export_telemetry_logs(self):
        os.makedirs("logs", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_data = {
            "timestamp_generated": timestamp,
            "wlan_status": self.latest_wlan_data,
            "active_sockets": self.latest_socket_data,
            "local_devices": self.latest_lan_data,
            "traffic_history": list(self.packet_sniffer.packet_buffer),
            "wifi_environment": self.latest_wifi_networks,
            "security_flags": self.flagged_events_log
        }
        json_filename = f"htd_telemetry_{timestamp}.json"
        with open(os.path.join("logs", json_filename), "w") as f:
            json.dump(export_data, f, indent=4)
            
        md_filename = f"htd_report_{timestamp}.md"
        with open(os.path.join("logs", md_filename), "w") as f:
            f.write(f"# HTD System Explorer - Automated Telemetry Report\n")
            f.write(f"**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            if self.flagged_events_log:
                f.write(f"## 🛡️ SECURITY ALERTS DETECTED\n")
                f.write("| Timestamp | Device Context | Target IP | Direction |\n")
                f.write("|---|---|---|---|\n")
                for e in self.flagged_events_log:
                    f.write(f"| {e['timestamp']} | {e['device']} | {e['target_ip']} | {e['direction']} |\n")
            f.write(f"\n## 1. Local Subnet Devices (ARP)\n")
            for d in self.latest_lan_data:
                if "error" not in d: f.write(f"- {d.get('ip_address', '')} | {d.get('mac_address', '')} | {d.get('hostname', '')}\n")
        messagebox.showinfo("Export Successful", f"Data and Security Logs safely exported to /logs.")

    def execute_traffic_highlighting(self):
        query = self.ent_search_filter.get().strip().upper()
        if not query: return
        self.notebook.select(self.tab_traffic)
        found_target = None
        for item in self.tree_traffic.get_children():
            values = [str(v).upper() for v in self.tree_traffic.item(item, "values")]
            if any(query in val for val in values):
                self.tree_traffic.item(item, tags=('highlighted_match',))
                if not found_target: found_target = item
            else:
                proto = self.tree_traffic.item(item, "values")[1]
                if proto == "TCP": self.tree_traffic.item(item, tags=('tcp',))
                elif proto == "UDP": self.tree_traffic.item(item, tags=('udp',))
                elif proto == "ICMP": self.tree_traffic.item(item, tags=('icmp',))

        if found_target:
            self.tree_traffic.see(found_target)
            self.tree_traffic.selection_set(found_target)

    def handle_direct_connect(self):
        ssid = self.ent_ssid.get().strip()
        pwd = self.ent_pass.get().strip()
        sec = self.combo_sec.get()
        if not ssid: return
        success, msg = self.wlan_controller.connect_to_network(ssid, pwd, sec)
        if success: messagebox.showinfo("Executed", msg)
        else: messagebox.showerror("Injection Failed", msg)

    def start_background_workers(self):
        threading.Thread(target=self._worker_fast_telemetry, daemon=True).start()
        threading.Thread(target=self._worker_slow_telemetry, daemon=True).start()

    def _worker_fast_telemetry(self):
        while True:
            try:
                self.latest_wlan_data = self.wlan_controller.fetch_wlan_telemetry()
                self.latest_socket_data = self.socket_reader.get_active_sockets()
            except: pass
            time.sleep(2)

    def _worker_slow_telemetry(self):
        while True:
            try:
                # Background updates run context loops without forcing GUI layout blocking state
                if not self.lan_is_refreshing:
                    self.latest_lan_data = self.arp_sweeper.fetch_local_devices()
                if not self.wlan_is_refreshing:
                    self.latest_wifi_networks = self.wlan_controller.fetch_available_networks()
            except: pass
            time.sleep(10)

    # ==========================================
    # THE REPAINT & IDS ENGINE LOOP
    # ==========================================
    def paint_ui_loop(self):
        if self.latest_wlan_data and "error" not in self.latest_wlan_data:
            meta = f"SSID: {self.latest_wlan_data.get('ssid','')}  |  BSSID: {self.latest_wlan_data.get('bssid','')}  |  Signal: {self.latest_wlan_data.get('signal_strength','')}  |  Target Hardware: {self.latest_wlan_data.get('hardware_vendor','')}"
            self.lbl_wlan_meta.config(text=meta)

        if self.latest_socket_data:
            self.tree_sockets.delete(*self.tree_sockets.get_children())
            active_sockets = [s for s in self.latest_socket_data if s["connection_state"] != "LISTEN"]
            listening_sockets = [s for s in self.latest_socket_data if s["connection_state"] == "LISTEN"]
            
            for sock in active_sockets:
                tags = ('tcp',) if sock["transport_protocol"] == "TCP" else ('udp',)
                self.tree_sockets.insert("", "end", values=(sock["pid"], sock["process_name"], sock["transport_protocol"], sock["local_endpoint"], sock["remote_endpoint"], sock["connection_state"], sock["throughput"]), tags=tags)
            if active_sockets and listening_sockets:
                self.tree_sockets.insert("", "end", values=("---", "PASSIVE LISTEN BOUNDARY CORE", "---", "---", "---", "---", "---"), tags=('separator',))
            for sock in listening_sockets:
                self.tree_sockets.insert("", "end", values=(sock["pid"], sock["process_name"], sock["transport_protocol"], sock["local_endpoint"], sock["remote_endpoint"], sock["connection_state"], sock["throughput"]), tags=('listen',))

        # Render LAN treeview & toggle warning label constraints
        if self.latest_lan_data:
            valid_rows = [dev for dev in self.latest_lan_data if "error" not in dev]
            if valid_rows:
                self.lbl_lan_notice.pack_forget()  # Drop notice element upon entry loops
                self.lan_is_refreshing = False
                self.tree_lan.delete(*self.tree_lan.get_children())
                for dev in valid_rows:
                    self.tree_lan.insert("", "end", values=(dev["ip_address"], dev["mac_address"], dev["hostname"]))

        # PACKET STREAM & IDS TRIPWIRE
        packets = self.packet_sniffer.get_latest_packets()
        if packets:
            for pkt in reversed(packets):
                if "error" in pkt: continue
                sig = f"{pkt['timestamp']}_{pkt['protocol']}_{pkt['source']}_{pkt['destination']}"
                
                if sig not in self.seen_packet_signatures:
                    self.seen_packet_signatures.add(sig)
                    proto = pkt["protocol"]
                    tags = ('tcp',) if proto == "TCP" else ('udp',) if proto == "UDP" else ('icmp',)
                    self.tree_traffic.insert("", 0, values=(pkt["timestamp"], proto, pkt["source"], pkt["destination"]), tags=tags)
                    
                    # --- THE SECURITY TRIPWIRE LOGIC ---
                    if pkt['source'] in self.blacklisted_ips or pkt['destination'] in self.blacklisted_ips:
                        target_ip = pkt['destination'] if pkt['source'] not in self.blacklisted_ips else pkt['source']
                        local_ip = pkt['source'] if target_ip == pkt['destination'] else pkt['destination']
                        direction = "OUTBOUND" if target_ip == pkt['destination'] else "INBOUND"
                        
                        # Cross-reference the ARP table for the Hostname
                        hostname = "Unknown Device"
                        for dev in self.latest_lan_data:
                            if "error" not in dev and dev["ip_address"] == local_ip:
                                hostname = dev["hostname"]
                                break
                                
                        device_context = f"{hostname} ({local_ip})"
                        self.tree_flagged.insert("", 0, values=(pkt["timestamp"], device_context, target_ip, direction), tags=('flagged',))
                        
                        # Save to memory for JSON/MD Export
                        self.flagged_events_log.append({
                            "timestamp": pkt["timestamp"],
                            "device": device_context,
                            "target_ip": target_ip,
                            "direction": direction
                        })

        # Render WLAN Environment treeview & hide loading message constraints
        if self.latest_wifi_networks:
            self.lbl_wlan_notice.pack_forget()  # Drop notice element upon entry loops
            self.wlan_is_refreshing = False
            self.tree_wifi.delete(*self.tree_wifi.get_children())
            for net in self.latest_wifi_networks:
                self.tree_wifi.insert("", "end", values=(net["ssid"], net["auth"], net["signal"]))

        self.after(1000, self.paint_ui_loop)

if __name__ == "__main__":
    app = HTDSystemExplorerApp()
    app.mainloop()