"""
ShieldNet Windows Desktop - Local IPC Client
Communicates over localhost TCP socket with the ShieldNet Service Daemon.
"""

from __future__ import annotations
import json
import socket
from typing import Any, Dict, Optional

DEFAULT_IPC_HOST = "127.0.0.1"
DEFAULT_IPC_PORT = 49512


class ShieldNetIPCClient:
    """Client for local ShieldNet daemon control and status monitoring."""

    def __init__(self, host: str = DEFAULT_IPC_HOST, port: int = DEFAULT_IPC_PORT) -> None:
        self.host = host
        self.port = port

    def call(self, action: str, params: Optional[Dict[str, Any]] = None, timeout: float = 3.0) -> Dict[str, Any]:
        """Sends a request to the daemon and parses the JSON response."""
        payload = json.dumps({"action": action, "params": params or {}}).encode("utf-8")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((self.host, self.port))
                sock.sendall(payload)
                data = sock.recv(65536)
                if not data:
                    return {"status": "error", "message": "Empty response from daemon"}
                return json.loads(data.decode("utf-8"))
        except ConnectionRefusedError:
            return {"status": "error", "message": "Service daemon is not running"}
        except socket.timeout:
            return {"status": "error", "message": "Daemon request timed out"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def is_alive(self) -> bool:
        res = self.call("status", timeout=1.0)
        return res.get("status") == "ok"

    def get_status(self) -> Dict[str, Any]:
        return self.call("status")

    def start_protection(self) -> Dict[str, Any]:
        return self.call("start_protection")

    def stop_protection(self) -> Dict[str, Any]:
        return self.call("stop_protection")

    def update_blocklists(self) -> Dict[str, Any]:
        return self.call("update_blocklists", timeout=30.0)

    def get_logs(self, limit: int = 100, filter_status: Optional[str] = None, search: str = "") -> Dict[str, Any]:
        return self.call("get_logs", {"limit": limit, "filter_status": filter_status, "search": search})

    def clear_logs(self) -> Dict[str, Any]:
        return self.call("clear_logs")

    def add_rule(self, domain: str, rule_type: str = "BLOCK", category: str = "Custom", comment: str = "") -> Dict[str, Any]:
        return self.call("add_rule", {"domain": domain, "rule_type": rule_type, "category": category, "comment": comment})

    def remove_rule(self, domain: str) -> Dict[str, Any]:
        return self.call("remove_rule", {"domain": domain})

    def toggle_category(self, category: str, enabled: bool) -> Dict[str, Any]:
        return self.call("toggle_category", {"category": category, "enabled": enabled})

    def flush_dns(self) -> Dict[str, Any]:
        return self.call("flush_dns")

    def get_config(self) -> Dict[str, Any]:
        return self.call("get_config")

    def save_config(self, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        return self.call("save_config", {"config": config_dict})
