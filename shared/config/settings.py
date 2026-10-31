"""
ShieldNet Shared Filtering Engine - Configuration Management
Defines cross-platform JSON schema for rules, DNS preferences, blocklists, and logs.
Supports export/import between Windows and Android.
"""

from __future__ import annotations
import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from shared.rules.domain_rule import DomainRule, RuleCategory, RuleType

logger = logging.getLogger("shieldnet.config")

DEFAULT_UPSTREAM_SERVERS = [
    {"name": "Quad9 (Malware Blocking + Privacy)", "ip": "9.9.9.9", "port": 53},
    {"name": "Cloudflare DNS", "ip": "1.1.1.1", "port": 53},
    {"name": "Google Public DNS", "ip": "8.8.8.8", "port": 53},
    {"name": "AdGuard DNS Non-Filtering", "ip": "94.140.14.140", "port": 53},
]


@dataclass
class CustomRuleItem:
    domain: str
    rule_type: str = "BLOCK"  # BLOCK or ALLOW
    category: str = "Custom"
    comment: str = ""

    def to_rule(self) -> Optional[DomainRule]:
        rtype = RuleType.ALLOW if self.rule_type.upper() == "ALLOW" else RuleType.BLOCK
        try:
            rcat = RuleCategory(self.category)
        except ValueError:
            rcat = RuleCategory.CUSTOM
        return DomainRule.create(
            domain=self.domain,
            rule_type=rtype,
            category=rcat,
            is_wildcard=True,
            source_list="custom_user_rule",
            comment=self.comment,
        )


@dataclass
class AppConfig:
    version: str = "1.0.0"
    listen_host: str = "127.0.0.1"
    listen_port: int = 53
    upstream_primary: str = "9.9.9.9"
    upstream_secondary: str = "1.1.1.1"
    upstream_port: int = 53
    blocking_mode: str = "IP"  # "IP" (returns 0.0.0.0) or "NXDOMAIN"
    block_ttl: int = 300
    cache_max_size: int = 10000
    cache_ttl_seconds: int = 300
    enable_query_logging: bool = True
    max_log_entries: int = 5000
    auto_update_enabled: bool = True
    auto_update_hours: int = 24
    start_at_boot: bool = False
    custom_rules: List[CustomRuleItem] = field(default_factory=list)
    enabled_blocklist_ids: List[str] = field(
        default_factory=lambda: [
            "stevenblack_hosts", "adguard_dns", "oisd_basic",
            "stevenblack_adult", "ut1_blacklist_adult", "adguard_adult",
        ]
    )
    enabled_categories: List[str] = field(
        default_factory=lambda: [cat.value for cat in RuleCategory]
    )
    # Content filtering toggles — stored separately for quick UI binding
    block_adult_content: bool = True
    block_gambling: bool = False

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AppConfig:
        custom_items = [
            CustomRuleItem(
                domain=item.get("domain", ""),
                rule_type=item.get("rule_type", "BLOCK"),
                category=item.get("category", "Custom"),
                comment=item.get("comment", ""),
            )
            for item in data.get("custom_rules", [])
            if item.get("domain")
        ]

        cfg = cls(
            version=data.get("version", "1.0.0"),
            listen_host=data.get("listen_host", "127.0.0.1"),
            listen_port=data.get("listen_port", 53),
            upstream_primary=data.get("upstream_primary", "9.9.9.9"),
            upstream_secondary=data.get("upstream_secondary", "1.1.1.1"),
            upstream_port=data.get("upstream_port", 53),
            blocking_mode=data.get("blocking_mode", "IP"),
            block_ttl=data.get("block_ttl", 300),
            cache_max_size=data.get("cache_max_size", 10000),
            cache_ttl_seconds=data.get("cache_ttl_seconds", 300),
            enable_query_logging=data.get("enable_query_logging", True),
            max_log_entries=data.get("max_log_entries", 5000),
            auto_update_enabled=data.get("auto_update_enabled", True),
            auto_update_hours=data.get("auto_update_hours", 24),
            start_at_boot=data.get("start_at_boot", False),
            custom_rules=custom_items,
            enabled_blocklist_ids=data.get(
                "enabled_blocklist_ids", [
                    "stevenblack_hosts", "adguard_dns", "oisd_basic",
                    "stevenblack_adult", "ut1_blacklist_adult", "adguard_adult",
                ]
            ),
            enabled_categories=data.get(
                "enabled_categories", [cat.value for cat in RuleCategory]
            ),
        )
        cfg.block_adult_content = data.get("block_adult_content", True)
        cfg.block_gambling = data.get("block_gambling", False)
        return cfg

    def save_to_file(self, path: Path) -> bool:
        """Saves configuration securely to JSON file."""
        try:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2)
            return True
        except Exception as e:
            logger.error("Failed to save config to %s: %s", path, e)
            return False

    @classmethod
    def load_from_file(cls, path: Path) -> AppConfig:
        """Loads configuration from JSON file or returns default."""
        path = Path(path)
        if not path.exists():
            return cls()
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls.from_dict(data)
        except Exception as e:
            logger.error("Failed to load config from %s: %s, using defaults", path, e)
            return cls()
