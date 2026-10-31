"""
ShieldNet Windows Service - DNS & Network Adapter Manager
Handles adapter discovery, DNS redirection to 127.0.0.1, persistent backup of previous
settings, DNS cache flushing, and clean restoration on shutdown or uninstall.
"""

from __future__ import annotations
import ctypes
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("shieldnet.windows.dns")


def is_admin() -> bool:
    """Checks if the current process has Windows Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class WindowsDNSManager:
    """
    Manages Windows network adapter DNS settings.
    Saves snapshot of network adapter configurations before touching anything.
    """

    def __init__(self, state_file: Optional[Path] = None) -> None:
        if state_file is None:
            state_file = Path.home() / ".shieldnet" / "dns_backup.json"
        self.state_file = Path(state_file)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

    def flush_dns_cache(self) -> Tuple[bool, str]:
        """Flushes the Windows resolver cache via ipconfig /flushdns."""
        try:
            res = subprocess.run(
                ["ipconfig", "/flushdns"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            return (res.returncode == 0, res.stdout.strip())
        except Exception as e:
            logger.error("Failed to flush DNS cache: %s", e)
            return (False, str(e))

    def get_active_adapters(self) -> List[Dict[str, Any]]:
        """
        Retrieves active network interfaces and their current DNS servers using PowerShell.
        """
        adapters = []
        ps_cmd = (
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
            "Select-Object -Property Name, InterfaceIndex, InterfaceDescription | "
            "ConvertTo-Json -Compress"
        )
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    name = item.get("Name")
                    idx = item.get("InterfaceIndex")
                    if name and idx:
                        dns_info = self._get_adapter_dns(idx)
                        adapters.append({
                            "name": name,
                            "index": idx,
                            "description": item.get("InterfaceDescription", ""),
                            "dns": dns_info,
                        })
        except Exception as e:
            logger.error("Error enumerating network adapters: %s", e)
            # Fallback to netsh
            adapters = self._get_adapters_netsh_fallback()

        return adapters

    def _get_adapter_dns(self, interface_index: int) -> Dict[str, Any]:
        """Gets IPv4 DNS configuration for an interface index."""
        ps_cmd = f"Get-DnsClientServerAddress -InterfaceIndex {interface_index} -AddressFamily IPv4 | ConvertTo-Json -Compress"
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                addresses = data.get("ServerAddresses", [])
                if isinstance(addresses, str):
                    addresses = [addresses]
                return {
                    "is_dhcp": len(addresses) == 0,
                    "servers": addresses,
                }
        except Exception:
            pass
        return {"is_dhcp": True, "servers": []}

    def _get_adapters_netsh_fallback(self) -> List[Dict[str, Any]]:
        adapters = []
        try:
            res = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "interfaces"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            for line in res.stdout.splitlines():
                if "connected" in line.lower():
                    parts = line.split()
                    if len(parts) >= 5:
                        idx = parts[0]
                        name = " ".join(parts[4:])
                        adapters.append({
                            "name": name,
                            "index": int(idx) if idx.isdigit() else 0,
                            "description": name,
                            "dns": {"is_dhcp": True, "servers": []},
                        })
        except Exception:
            pass
        return adapters

    def enable_shieldnet_dns(self, listen_ip: str = "127.0.0.1") -> Tuple[bool, str]:
        """
        Sets DNS on active adapters to point to ShieldNet local proxy (127.0.0.1).
        Preserves original adapter settings in backup file.
        """
        if not is_admin():
            return False, "Administrator permissions are required to modify system network DNS settings."

        adapters = self.get_active_adapters()
        if not adapters:
            return False, "No active network adapters found."

        # Backup current configuration before modifying
        backup_data = {}
        if self.state_file.exists():
            try:
                with open(self.state_file, "r") as f:
                    backup_data = json.load(f)
            except Exception:
                backup_data = {}

        success_count = 0
        for adp in adapters:
            name = adp["name"]
            # Save original configuration if not already saved
            if name not in backup_data:
                backup_data[name] = adp["dns"]

            # Apply 127.0.0.1 as static primary DNS
            cmd = ["netsh", "interface", "ipv4", "set", "dnsservers", f"name={name}", "static", listen_ip, "primary"]
            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                if res.returncode == 0:
                    success_count += 1
                else:
                    logger.warning("netsh failed for adapter %s: %s", name, res.stderr)
            except Exception as e:
                logger.error("Exception setting DNS for %s: %s", name, e)

        # Save backup to file
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(backup_data, f, indent=2)
        except Exception as e:
            logger.error("Could not write DNS backup: %s", e)

        # Flush DNS cache so changes take immediate effect
        self.flush_dns_cache()

        if success_count > 0:
            return True, f"ShieldNet DNS activated on {success_count} network adapter(s)."
        return False, "Failed to apply DNS configuration to network adapters."

    def restore_original_dns(self) -> Tuple[bool, str]:
        """
        Restores original network adapter DNS settings from backup file or reverts to DHCP.
        """
        if not is_admin():
            return False, "Administrator permissions are required to restore system network DNS settings."

        backup_data = {}
        if self.state_file.exists():
            try:
                with open(self.state_file, "r") as f:
                    backup_data = json.load(f)
            except Exception:
                backup_data = {}

        adapters = self.get_active_adapters()
        restored = 0

        for adp in adapters:
            name = adp["name"]
            saved = backup_data.get(name, {"is_dhcp": True, "servers": []})

            if saved.get("is_dhcp") or not saved.get("servers"):
                # Reset to DHCP
                cmd = ["netsh", "interface", "ipv4", "set", "dnsservers", f"name={name}", "source=dhcp"]
            else:
                # Restore original static DNS
                primary_server = saved["servers"][0]
                cmd = ["netsh", "interface", "ipv4", "set", "dnsservers", f"name={name}", "static", primary_server, "primary"]

            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                if res.returncode == 0:
                    restored += 1
                    # If secondary servers exist, add them
                    if not saved.get("is_dhcp") and len(saved.get("servers", [])) > 1:
                        for sec in saved["servers"][1:]:
                            add_cmd = ["netsh", "interface", "ipv4", "add", "dnsservers", f"name={name}", sec, "index=2"]
                            subprocess.run(add_cmd, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            except Exception as e:
                logger.error("Failed restoring DNS for %s: %s", name, e)

        # Clean backup file
        if self.state_file.exists():
            try:
                self.state_file.unlink()
            except Exception:
                pass

        self.flush_dns_cache()
        return True, f"Original network DNS configuration restored for {restored} adapter(s)."
