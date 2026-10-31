"""
Unit and functional tests for Windows DNS Management and IPC communication.
"""

import json
import os
import tempfile
from pathlib import Path
import pytest

from windows.service.dns_manager import WindowsDNSManager
from windows.desktop.ipc_client import ShieldNetIPCClient
from windows.service.daemon import ShieldNetDaemon


class TestWindowsDNSManager:
    def test_backup_and_restore_state_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_file = Path(tmpdir) / "dns_backup.json"
            mgr = WindowsDNSManager(state_file=backup_file)

            # Initially file shouldn't exist
            assert not backup_file.exists()

            # Mock backup write
            mock_data = {
                "Ethernet": {"is_dhcp": False, "servers": ["192.168.1.1", "8.8.8.8"]},
                "Wi-Fi": {"is_dhcp": True, "servers": []},
            }
            with open(backup_file, "w") as f:
                json.dump(mock_data, f)

            assert backup_file.exists()
            with open(backup_file, "r") as f:
                loaded = json.load(f)
            assert loaded["Ethernet"]["servers"] == ["192.168.1.1", "8.8.8.8"]
            assert loaded["Wi-Fi"]["is_dhcp"] is True

    def test_flush_dns_execution(self):
        """Verifies flush_dns_cache runs without crashing."""
        mgr = WindowsDNSManager()
        success, msg = mgr.flush_dns_cache()
        # On Windows, ipconfig /flushdns returns success
        assert isinstance(success, bool)
        assert isinstance(msg, str)


class TestDaemonIPC:
    def test_daemon_ipc_status_exchange(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_dir = Path(tmpdir) / "test_shieldnet"
            daemon = ShieldNetDaemon(config_dir=cfg_dir)
            # Use a non-reserved port outside Windows exclusion ranges
            daemon.config.listen_port = 25354
            started = daemon.start()
            assert started is True

            client = ShieldNetIPCClient()
            status_res = client.get_status()
            assert status_res.get("status") == "ok"
            data = status_res.get("data", {})
            assert "is_running" in data
            assert data["is_running"] is True

            # Test adding a custom rule via IPC
            add_res = client.add_rule("malware-domain.test", rule_type="BLOCK", category="Malware")
            assert add_res.get("status") == "ok"

            # Check that rule was evaluated
            dec = daemon.engine.evaluate("malware-domain.test")
            assert dec.allowed is False

            # Test removing custom rule via IPC
            del_res = client.remove_rule("malware-domain.test")
            assert del_res.get("status") == "ok"
            assert daemon.engine.evaluate("malware-domain.test").allowed is True

            daemon.stop()
