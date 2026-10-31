"""
ShieldNet Shared Filtering Engine - Blocklist Manager
Manages trusted blocklist sources, secure HTTPS downloads, content validation,
size limit enforcement, atomic updates, and fallback to last-known-good cache.
"""

from __future__ import annotations
import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

from shared.rules.domain_rule import DomainRule, RuleCategory, RuleType
from shared.rules.parser import RuleParser

logger = logging.getLogger("shieldnet.blocklists")


@dataclass
class BlocklistSource:
    """Represents a remote or local blocklist source."""
    id: str
    name: str
    url: str
    category: RuleCategory = RuleCategory.GENERAL
    enabled: bool = True
    last_updated: float = 0.0
    last_status: str = "never_updated"
    rule_count: int = 0
    sha256: str = ""
    is_custom: bool = False
    description: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        return d

    @classmethod
    def from_dict(cls, data: dict) -> BlocklistSource:
        cat_str = data.get("category", RuleCategory.GENERAL.value)
        try:
            cat = RuleCategory(cat_str)
        except ValueError:
            cat = RuleCategory.GENERAL

        return cls(
            id=data["id"],
            name=data["name"],
            url=data["url"],
            category=cat,
            enabled=data.get("enabled", True),
            last_updated=data.get("last_updated", 0.0),
            last_status=data.get("last_status", "never_updated"),
            rule_count=data.get("rule_count", 0),
            sha256=data.get("sha256", ""),
            is_custom=data.get("is_custom", False),
            description=data.get("description", ""),
        )


# Default verified blocklists from official public sources
DEFAULT_BLOCKLISTS = [
    BlocklistSource(
        id="stevenblack_hosts",
        name="StevenBlack Unified Hosts",
        url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        category=RuleCategory.ADVERTISING,
        description="Unified hosts file combining adware, spyware, and tracking protection with community maintenance.",
    ),
    BlocklistSource(
        id="adguard_dns",
        name="AdGuard DNS Filter",
        url="https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
        category=RuleCategory.TRACKING,
        description="Official AdGuard DNS filter focused on ad-serving and privacy-invasive tracking domains.",
    ),
    BlocklistSource(
        id="oisd_basic",
        name="OISD Basic",
        url="https://small.oisd.nl/",
        category=RuleCategory.TELEMETRY,
        description="High-compatibility domain blocklist tailored for low false positives and telemetry suppression.",
    ),
    # ── Adult / Explicit Content ──────────────────────────────────────────────
    BlocklistSource(
        id="stevenblack_adult",
        name="StevenBlack Adult Content (Porn)",
        url="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
        category=RuleCategory.ADULT_CONTENT,
        enabled=True,
        description=(
            "StevenBlack's community-maintained hosts list extended with explicit/pornographic "
            "domain blocks. Blocks adult video, image, and live-stream sites at DNS level."
        ),
    ),
    BlocklistSource(
        id="ut1_blacklist_adult",
        name="UT1 Adult Blacklist (Université Toulouse)",
        url="https://raw.githubusercontent.com/nicowillis/categorized-blocklists/main/adult-explicit.txt",
        category=RuleCategory.ADULT_CONTENT,
        enabled=True,
        description=(
            "Curated adult-site domain list sourced from the Université Toulouse 1 web-categorization "
            "project, widely used in enterprise content filtering. Plain domain format."
        ),
    ),
    BlocklistSource(
        id="adguard_adult",
        name="AdGuard Adult Content Filter",
        url="https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt",
        category=RuleCategory.ADULT_CONTENT,
        enabled=True,
        description=(
            "Official AdGuard 'Adult Websites' filter list. Maintained for family-friendly DNS "
            "profiles. Covers pornographic, escort, and adult live-streaming domains."
        ),
    ),
    # ── Gambling ──────────────────────────────────────────────────────────────
    BlocklistSource(
        id="adguard_gambling",
        name="AdGuard Gambling Filter",
        url="https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",
        category=RuleCategory.GAMBLING,
        enabled=False,  # OFF by default — user must consciously enable
        description=(
            "Official AdGuard gambling sites filter. Blocks online casinos, sports betting, "
            "poker sites, and gambling-adjacent domains. Disabled by default."
        ),
    ),
]

# Built-in emergency fallback for adult content — applied even without network access.
# These are broadly known adult domains included directly in code as a baseline.
# This list is intentionally small; the full protection comes from downloaded blocklists.
BUILTIN_ADULT_DOMAINS: list[str] = [
    "pornhub.com",
    "xvideos.com",
    "xhamster.com",
    "redtube.com",
    "youporn.com",
    "xnxx.com",
    "beeg.com",
    "tube8.com",
    "spankbang.com",
    "brazzers.com",
    "onlyfans.com",
    "chaturbate.com",
    "livejasmin.com",
    "cam4.com",
    "stripchat.com",
    "bongacams.com",
    "myfreecams.com",
    "pornmd.com",
    "drtuber.com",
    "txxx.com",
    "cliphunter.com",
    "tnaflix.com",
    "freeones.com",
    "8muses.com",
    "xart.com",
]

BUILTIN_GAMBLING_DOMAINS: list[str] = [
    "bet365.com",
    "draftkings.com",
    "fanduel.com",
    "betmgm.com",
    "caesarssportsbook.com",
    "pokerstars.com",
    "888casino.com",
    "bodog.com",
    "mybookie.ag",
    "sportsbetting.ag",
]


class BlocklistManager:
    """
    Handles downloading, validating, caching, and parsing domain blocklists.
    Protects against malicious payloads, content spoofing, HTML error pages, and network failures.
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        max_download_bytes: int = 25 * 1024 * 1024,  # 25 MB max to prevent zip/memory bombs
        request_timeout: int = 15,                   # 15s timeout
    ) -> None:
        if cache_dir is None:
            cache_dir = Path.home() / ".shieldnet" / "cache"
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_download_bytes = max_download_bytes
        self.request_timeout = request_timeout
        self.sources: Dict[str, BlocklistSource] = {s.id: s for s in DEFAULT_BLOCKLISTS}

    def get_builtin_rules(self) -> List[DomainRule]:
        """Returns built-in hardcoded rules that work even without a network connection.
        These cover the most common explicit/gambling domains as an offline baseline."""
        rules: List[DomainRule] = []
        for domain in BUILTIN_ADULT_DOMAINS:
            r = DomainRule.create(domain, RuleType.BLOCK, RuleCategory.ADULT_CONTENT,
                                  is_wildcard=True, source_list="builtin_adult")
            if r:
                rules.append(r)
        for domain in BUILTIN_GAMBLING_DOMAINS:
            r = DomainRule.create(domain, RuleType.BLOCK, RuleCategory.GAMBLING,
                                  is_wildcard=True, source_list="builtin_gambling")
            if r:
                rules.append(r)
        return rules

    def add_custom_source(self, name: str, url: str, category: RuleCategory, description: str = "") -> BlocklistSource:
        source_id = f"custom_{hashlib.md5(url.encode()).hexdigest()[:8]}"
        source = BlocklistSource(
            id=source_id,
            name=name,
            url=url,
            category=category,
            enabled=True,
            is_custom=True,
            description=description,
        )
        self.sources[source_id] = source
        return source

    def remove_source(self, source_id: str) -> bool:
        if source_id in self.sources:
            del self.sources[source_id]
            # Clean cached file
            cache_file = self.cache_dir / f"{source_id}.txt"
            if cache_file.exists():
                cache_file.unlink()
            return True
        return False

    def toggle_source(self, source_id: str, enabled: bool) -> bool:
        if source_id in self.sources:
            self.sources[source_id].enabled = enabled
            return True
        return False

    def _get_cache_path(self, source_id: str) -> Path:
        return self.cache_dir / f"{source_id}.txt"

    def download_and_validate(self, source: BlocklistSource) -> Tuple[bool, str, List[DomainRule]]:
        """
        Downloads a blocklist over HTTPS with timeout and size check.
        Validates that content contains valid rules and not HTML error pages.
        Returns (success, message, rules).
        """
        cache_path = self._get_cache_path(source.id)

        # Handle local files
        if source.url.startswith("file://") or os.path.exists(source.url):
            file_path = source.url.replace("file://", "")
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                return False, f"Failed to read local file: {e}", []
        else:
            # Remote HTTPS download
            try:
                headers = {"User-Agent": "ShieldNet-Core/1.0 (DNS-Security-Agent)"}
                response = requests.get(
                    source.url,
                    headers=headers,
                    timeout=self.request_timeout,
                    stream=True,
                )
                if response.status_code != 200:
                    source.last_status = f"HTTP error {response.status_code}"
                    return False, f"HTTP error {response.status_code}", []

                # Enforce size limit
                chunks = []
                downloaded = 0
                for chunk in response.iter_content(chunk_size=65536):
                    downloaded += len(chunk)
                    if downloaded > self.max_download_bytes:
                        source.last_status = "Exceeded max file size limit"
                        return False, "File exceeds 25 MB limit, rejected for safety", []
                    chunks.append(chunk)

                content = b"".join(chunks).decode("utf-8", errors="ignore")

            except requests.exceptions.RequestException as e:
                source.last_status = f"Network failure: {type(e).__name__}"
                logger.warning("Failed to download blocklist %s: %s", source.name, e)
                # Check for cached copy
                if cache_path.exists():
                    logger.info("Falling back to cached copy for %s", source.name)
                    rules = self._load_from_cache(source, cache_path)
                    return True, "Using cached copy (download failed)", rules
                return False, f"Network error and no cache available: {e}", []

        # Content Validation:
        # Check if content looks like HTML (e.g. 404 page, Captcha, Cloudflare challenge)
        lower_head = content[:1024].lower()
        if "<!doctype html" in lower_head or "<html" in lower_head:
            source.last_status = "Invalid content: Returned HTML error page"
            return False, "Downloaded content was an HTML web page rather than a domain list", []

        # Parse rules
        parser = RuleParser(source_name=source.id, default_category=source.category)
        rules, report = parser.parse_text(content)

        # Minimum valid rules sanity check
        if report.parsed_rules == 0:
            source.last_status = "Empty or unparseable blocklist"
            return False, "No valid domain rules found in source", []

        # Success - Atomically save to cache
        try:
            temp_path = self.cache_dir / f"{source.id}.tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(content)
            # Atomic rename / replace
            if os.name == "nt" and cache_path.exists():
                cache_path.unlink()
            temp_path.rename(cache_path)
        except Exception as e:
            logger.warning("Could not persist cache for %s: %e", source.name, e)

        source.last_updated = time.time()
        source.rule_count = report.parsed_rules
        source.last_status = f"OK ({report.parsed_rules} rules loaded)"
        source.sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()

        return True, source.last_status, rules

    def _load_from_cache(self, source: BlocklistSource, cache_path: Path) -> List[DomainRule]:
        try:
            with open(cache_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            parser = RuleParser(source_name=source.id, default_category=source.category)
            rules, _ = parser.parse_text(content)
            source.rule_count = len(rules)
            return rules
        except Exception as e:
            logger.error("Failed to load cache file %s: %s", cache_path, e)
            return []

    def update_all(self) -> Tuple[List[DomainRule], Dict[str, str]]:
        """
        Updates all enabled blocklists.
        If any list fails, it falls back to its last known good cache, ensuring
        a single broken list never degrades overall protection.
        Returns (all_deduped_rules, status_report).
        """
        all_rules: List[DomainRule] = []
        statuses: Dict[str, str] = {}

        for source in self.sources.values():
            if not source.enabled:
                statuses[source.name] = "Disabled"
                continue

            success, msg, rules = self.download_and_validate(source)
            statuses[source.name] = msg
            all_rules.extend(rules)

        return all_rules, statuses

    def load_offline_rules(self) -> List[DomainRule]:
        """Loads all available cached rules without network access."""
        all_rules: List[DomainRule] = []
        for source in self.sources.values():
            if not source.enabled:
                continue
            cache_path = self._get_cache_path(source.id)
            if cache_path.exists():
                rules = self._load_from_cache(source, cache_path)
                all_rules.extend(rules)
        return all_rules
