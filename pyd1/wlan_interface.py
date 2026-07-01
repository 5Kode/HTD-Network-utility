import subprocess
import platform
import os
import tempfile

class WLANInterfaceController:
    def __init__(self):
        self.os_type = platform.system()
        self.isp_hardware_signatures = {
            "98:42:65": "Sagemcom (Common ISP Hubs)",
            "CC:F4:11": "TP-Link Infrastructure",
        }

    def infer_hardware_provider(self, bssid):
        if not bssid or bssid == "00:00:00:00:00:00": return "Unknown"
        prefix = bssid[:8].upper()
        return self.isp_hardware_signatures.get(prefix, "Standard Vendor")

    def fetch_wlan_telemetry(self):
        if self.os_type != "Windows": return {"error": "Windows only"}
        try:
            result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return self._parse_windows_wlan(result.stdout)
        except Exception as e:
            return {"error": str(e)}

    def _parse_windows_wlan(self, raw_stdout):
        telemetry = {"interface_name": "Unknown", "connection_state": "Disconnected", "ssid": "None", "bssid": "00:00:00:00:00:00", "signal_strength": "0%", "hardware_vendor": "Unknown"}
        for line in raw_stdout.splitlines():
            line = line.strip()
            if ":" not in line: continue
            key, val = [x.strip() for x in line.split(":", 1)]
            key_lower = key.lower()
            if "name" in key_lower and telemetry["interface_name"] == "Unknown": telemetry["interface_name"] = val
            elif "state" in key_lower: telemetry["connection_state"] = val
            elif "ssid" in key_lower and "bssid" not in key_lower: telemetry["ssid"] = val
            elif "bssid" in key_lower: telemetry["bssid"] = val.upper()
            elif "signal" in key_lower: telemetry["signal_strength"] = val
        telemetry["hardware_vendor"] = self.infer_hardware_provider(telemetry["bssid"])
        return telemetry

    def fetch_available_networks(self):
        """Scans the airwaves for visible BSSIDs."""
        if self.os_type != "Windows": return []
        networks = []
        try:
            result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            current_ssid = "Unknown"
            current_auth = "Unknown"
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("SSID"):
                    current_ssid = line.split(":", 1)[1].strip() if ":" in line else "Hidden"
                elif line.startswith("Authentication"):
                    current_auth = line.split(":", 1)[1].strip() if ":" in line else "Unknown"
                elif line.startswith("Signal"):
                    sig = line.split(":", 1)[1].strip() if ":" in line else "0%"
                    if current_ssid:  # Add entry per BSSID signal found
                        networks.append({"ssid": current_ssid, "auth": current_auth, "signal": sig})
            return networks
        except:
            return []

    def connect_to_network(self, ssid, password, security_type):
        """Generates a temporary Windows XML profile and attempts a connection."""
        if self.os_type != "Windows": return False, "Requires Windows environment."
        
        # Determine Windows auth string
        auth = "WPA2PSK" if "WPA2" in security_type.upper() else "WPAPSK" if "WPA" in security_type.upper() else "open"
        enc = "AES" if auth != "open" else "none"
        
        xml_profile = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID><name>{ssid}</name></SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>{auth}</authentication>
                <encryption>{enc}</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""

        try:
            # Write temp XML, add profile to OS, connect, then clean up
            fd, path = tempfile.mkstemp(suffix=".xml")
            with os.fdopen(fd, 'w') as f: f.write(xml_profile)
            subprocess.run(["netsh", "wlan", "add", "profile", f"filename={path}"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            result = subprocess.run(["netsh", "wlan", "connect", f"name={ssid}"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            os.remove(path)
            
            if "successfully" in result.stdout.lower():
                return True, f"Connection command sent for {ssid}."
            return False, result.stdout.strip()
        except Exception as e:
            return False, f"Failed to interface with wlanapi: {e}"