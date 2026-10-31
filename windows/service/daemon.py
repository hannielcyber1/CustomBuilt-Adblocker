"""
ShieldNet Windows Background Service Daemon
Runs as a background service process or system daemon. Manages the DNS proxy,
blocklist auto-updates, adapter DNS redirect, and provides a local IPC interface
for desktop dashboards and CLI controls.
"""

from __future__ import annotations
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from shared.config.settings import AppConfig, CustomRuleItem
from shared.dns.proxy import DNSProxyServer, QueryLogEntry
from shared.filtering.cache import DecisionCache
from shared.filtering.engine import FilterEngine
from shared.rules.blocklist_manager import BlocklistManager
from shared.rules.domain_rule import DomainRule, RuleCategory, RuleType
from windows.service.dns_manager import WindowsDNSManager, is_admin

# Default IPC port for local client-service communication
IPC_HOST = "127.0.0.1"
IPC_PORT = 49512

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("shieldnet.daemon")


class ShieldNetDaemon:
    """Core background coordinator for ShieldNet Windows Service."""

    def __init__(self, config_dir: Optional[Path] = None) -> None:
        if config_dir is None:
            config_dir = Path.home() / ".shieldnet"
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.config_file = self.config_dir / "config.json"
        self.config = AppConfig.load_from_file(self.config_file)

        self.engine = FilterEngine()
        self.cache = DecisionCache(
            max_size=self.config.cache_max_size,
            default_ttl_seconds=self.config.cache_ttl_seconds,
        )
        self.blocklist_mgr = BlocklistManager(cache_dir=self.config_dir / "cache")
        self.dns_manager = WindowsDNSManager(state_file=self.config_dir / "dns_backup.json")
        self.proxy = DNSProxyServer(
            engine=self.engine,
            config=self.config,
            cache=self.cache,
        )

        self._running = False
        self._ipc_socket: Optional[socket.socket] = None
        self._auto_update_thread: Optional[threading.Thread] = None
        self.start_time = 0.0

    def start(self) -> bool:
        """Starts the daemon, loads rules, and launches IPC and auto-update threads."""
        logger.info("Initializing ShieldNet Service Daemon (PID: %d)", os.getpid())
        self._running = True
        self.start_time = time.time()

        # 1. Apply category toggles from config
        self._apply_category_toggles()

        # 2. Load built-in adult/gambling rules immediately (works offline)
        builtin_rules = self.blocklist_mgr.get_builtin_rules()
        self.engine.load_rules(builtin_rules, clear_existing=False)
        logger.info("Loaded %d built-in content rules (adult/gambling)", len(builtin_rules))

        # 3. Load custom user rules from config
        custom_rules = []
        for item in self.config.custom_rules:
            r = item.to_rule()
            if r:
                custom_rules.append(r)
        self.engine.load_rules(custom_rules, clear_existing=False)

        # 4. Load cached blocklists or download if first run
        cached_rules = self.blocklist_mgr.load_offline_rules()
        if cached_rules:
            logger.info("Loaded %d cached blocklist rules", len(cached_rules))
            self.engine.load_rules(cached_rules, clear_existing=False)
        else:
            logger.info("No cached rules found. Triggering initial blocklist sync...")
            threading.Thread(target=self._initial_blocklist_sync, daemon=True).start()

        # 3. Start DNS proxy
        proxy_started = self.proxy.start()
        if not proxy_started:
            logger.error("Failed to start local DNS proxy server")
            return False

        # 4. Redirect Windows network adapter DNS if running as admin
        if is_admin():
            success, msg = self.dns_manager.enable_shieldnet_dns(self.config.listen_host)
            logger.info("Windows DNS Redirection: %s", msg)
        else:
            logger.warning("Running without Administrator rights; adapter DNS was not redirected automatically.")

        # 5. Start IPC server
        self._start_ipc_server()

        # 6. Start auto-update scheduler thread
        if self.config.auto_update_enabled:
            self._auto_update_thread = threading.Thread(target=self._auto_update_loop, name="AutoUpdate", daemon=True)
            self._auto_update_thread.start()

        # Register shutdown signal handlers
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        logger.info("ShieldNet Service is fully active.")
        return True

    def _apply_category_toggles(self) -> None:
        """Applies category enable/disable states based on config."""
        for cat in RuleCategory:
            enabled = cat.value in self.config.enabled_categories
            if cat == RuleCategory.ADULT_CONTENT:
                enabled = getattr(self.config, "block_adult_content", True)
            elif cat == RuleCategory.GAMBLING:
                enabled = getattr(self.config, "block_gambling", False)
            self.engine.set_category_enabled(cat, enabled)

    def _initial_blocklist_sync(self) -> None:
        rules, report = self.blocklist_mgr.update_all()
        if rules:
            self.engine.load_rules(rules, clear_existing=False)
            logger.info("Initial sync complete: loaded %d rules", len(rules))

    def _auto_update_loop(self) -> None:
        interval_seconds = max(3600, self.config.auto_update_hours * 3600)
        while self._running:
            time.sleep(interval_seconds)
            if not self._running:
                break
            logger.info("Starting scheduled blocklist update...")
            try:
                rules, _ = self.blocklist_mgr.update_all()
                if rules:
                    # Reload with custom rules preserved
                    custom_rules = [item.to_rule() for item in self.config.custom_rules if item.to_rule()]
                    self.engine.load_rules(rules + custom_rules, clear_existing=True)
                    self.cache.clear()
                    logger.info("Scheduled update applied successfully (%d total rules)", len(rules))
            except Exception as e:
                logger.error("Auto-update failed: %s", e)

    def _start_ipc_server(self) -> None:
        self._ipc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._ipc_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._ipc_socket.bind((IPC_HOST, IPC_PORT))
        self._ipc_socket.listen(16)
        self._ipc_socket.settimeout(1.0)
        threading.Thread(target=self._ipc_worker, name="Daemon-IPC", daemon=True).start()

    def _ipc_worker(self) -> None:
        while self._running:
            try:
                conn, _ = self._ipc_socket.accept()
            except (socket.timeout, BlockingIOError):
                continue
            except OSError:
                break
            except Exception:
                continue

            threading.Thread(target=self._handle_ipc_client, args=(conn,), daemon=True).start()

    def _handle_ipc_client(self, conn: socket.socket) -> None:
        conn.settimeout(5.0)
        try:
            data = conn.recv(65536)
            if not data:
                conn.close()
                return

            req = json.loads(data.decode("utf-8"))
            action = req.get("action")
            params = req.get("params", {})

            resp = self._dispatch_action(action, params)
            resp_bytes = json.dumps(resp).encode("utf-8")
            conn.sendall(resp_bytes)
        except Exception as e:
            logger.debug("IPC error: %s", e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _dispatch_action(self, action: str, params: dict) -> dict:
        """Dispatches an IPC request and returns a structured response."""
        if action == "status":
            metrics = self.proxy.get_metrics()
            metrics["uptime_seconds"] = int(time.time() - self.start_time)
            metrics["is_admin"] = is_admin()
            metrics["blocklist_sources"] = [s.to_dict() for s in self.blocklist_mgr.sources.values()]
            return {"status": "ok", "data": metrics}

        elif action == "start_protection":
            if not self.proxy.is_running:
                self.proxy.start()
            if is_admin():
                self.dns_manager.enable_shieldnet_dns(self.config.listen_host)
            return {"status": "ok", "message": "Protection activated"}

        elif action == "stop_protection":
            if self.proxy.is_running:
                self.proxy.stop()
            if is_admin():
                self.dns_manager.restore_original_dns()
            return {"status": "ok", "message": "Protection paused"}

        elif action == "update_blocklists":
            rules, report = self.blocklist_mgr.update_all()
            if rules:
                custom_rules = [item.to_rule() for item in self.config.custom_rules if item.to_rule()]
                self.engine.load_rules(rules + custom_rules, clear_existing=True)
                self.cache.clear()
            return {"status": "ok", "message": "Blocklists updated", "report": report}

        elif action == "get_logs":
            limit = params.get("limit", 100)
            status = params.get("filter_status")
            search = params.get("search", "")
            logs = self.proxy.get_recent_logs(limit=limit, filter_status=status, search=search)
            return {"status": "ok", "logs": logs}

        elif action == "clear_logs":
            self.proxy.clear_logs()
            return {"status": "ok", "message": "Logs cleared"}

        elif action == "add_rule":
            domain = params.get("domain", "")
            rtype = params.get("rule_type", "BLOCK")
            category = params.get("category", "Custom")
            comment = params.get("comment", "")
            rule_item = CustomRuleItem(domain=domain, rule_type=rtype, category=category, comment=comment)
            rule = rule_item.to_rule()
            if not rule:
                return {"status": "error", "message": "Invalid domain name"}

            self.engine.add_rule(rule)
            self.cache.invalidate(rule.pattern)
            self.config.custom_rules.append(rule_item)
            self.config.save_to_file(self.config_file)
            return {"status": "ok", "message": f"Rule for {rule.pattern} added"}

        elif action == "remove_rule":
            domain = params.get("domain", "").lower()
            self.config.custom_rules = [r for r in self.config.custom_rules if r.domain.lower() != domain]
            self.config.save_to_file(self.config_file)
            # Rebuild rules
            cached_rules = self.blocklist_mgr.load_offline_rules()
            custom_rules = [item.to_rule() for item in self.config.custom_rules if item.to_rule()]
            self.engine.load_rules(cached_rules + custom_rules, clear_existing=True)
            self.cache.clear()
            return {"status": "ok", "message": f"Rule for {domain} removed"}

        elif action == "toggle_category":
            category_str = params.get("category")
            enabled = bool(params.get("enabled", True))
            matched_cat = None
            for c in RuleCategory:
                if c.value.lower() == str(category_str).lower():
                    matched_cat = c
                    break
            if matched_cat:
                self.engine.set_category_enabled(matched_cat, enabled)
                if enabled and matched_cat.value not in self.config.enabled_categories:
                    self.config.enabled_categories.append(matched_cat.value)
                elif not enabled and matched_cat.value in self.config.enabled_categories:
                    self.config.enabled_categories.remove(matched_cat.value)
                if matched_cat == RuleCategory.ADULT_CONTENT:
                    self.config.block_adult_content = enabled
                elif matched_cat == RuleCategory.GAMBLING:
                    self.config.block_gambling = enabled
                self.config.save_to_file(self.config_file)
                self.cache.clear()
                return {"status": "ok", "message": f"Category {matched_cat.value} set to {enabled}"}
            return {"status": "error", "message": f"Unknown category: {category_str}"}

        elif action == "flush_dns":
            success, msg = self.dns_manager.flush_dns_cache()
            return {"status": "ok" if success else "error", "message": msg}

        elif action == "get_config":
            return {"status": "ok", "config": self.config.to_dict()}

        elif action == "save_config":
            new_cfg_dict = params.get("config", {})
            self.config = AppConfig.from_dict(new_cfg_dict)
            self.config.save_to_file(self.config_file)
            return {"status": "ok", "message": "Configuration saved"}

        elif action == "shutdown":
            threading.Thread(target=self.stop, daemon=True).start()
            return {"status": "ok", "message": "Daemon shutting down"}

        return {"status": "error", "message": f"Unknown action: {action}"}

    def _handle_signal(self, signum: int, frame: Any) -> None:
        logger.info("Received termination signal (%d), stopping...", signum)
        self.stop()
        sys.exit(0)

    def stop(self) -> None:
        """Performs clean shutdown, restoring adapter DNS to prevent connectivity loss."""
        if not self._running:
            return
        logger.info("Stopping ShieldNet Service Daemon...")
        self._running = False

        if is_admin():
            logger.info("Restoring original Windows network DNS settings...")
            self.dns_manager.restore_original_dns()

        self.proxy.stop()

        if self._ipc_socket:
            try:
                self._ipc_socket.close()
            except Exception:
                pass
            self._ipc_socket = None

        logger.info("ShieldNet Daemon stopped cleanly.")


def run_daemon() -> None:
    daemon = ShieldNetDaemon()
    if daemon.start():
        try:
            while daemon._running:
                time.sleep(1.0)
        except KeyboardInterrupt:
            daemon.stop()


if __name__ == "__main__":
    run_daemon()
