"""
ShieldNet Shared Filtering Engine - Rule Parsers
Parses hosts files, ABP/AdGuard domain syntax, and plain domain lists.
Safely ignores cosmetic/HTML/scriptlet rules with diagnostics.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Set, Tuple
from shared.rules.domain_rule import DomainRule, RuleCategory, RuleType, normalize_domain

# Common local loopback hostnames to ignore in hosts files
LOCALHOST_NAMES = {
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "0.0.0.0",
}

# Regex to detect cosmetic, HTML element-hiding, or URL path rules that cannot be resolved at DNS level
UNSUPPORTED_RULE_PATTERNS = [
    re.compile(r"##"),          # Cosmetic element hiding (e.g. ##.ad-banner)
    re.compile(r"#\?#"),        # Extended cosmetic
    re.compile(r"#%#"),         # Scriptlet injection
    re.compile(r"\$\$"),        # HTML filter
    re.compile(r"^/[^/]+/"),    # Regex URL path filter
    re.compile(r"^https?://"),  # Full URL filter with path
]


@dataclass
class ParseReport:
    """Statistics and diagnostics from parsing a rule file or text."""
    total_lines: int = 0
    parsed_rules: int = 0
    allow_rules: int = 0
    block_rules: int = 0
    unsupported_rules: int = 0
    comments_and_empty: int = 0
    invalid_domains: int = 0
    duplicates_dropped: int = 0


class RuleParser:
    """Parses various blocklist formats into unified DomainRule instances."""

    def __init__(self, source_name: str = "custom", default_category: RuleCategory = RuleCategory.GENERAL):
        self.source_name = source_name
        self.default_category = default_category

    def parse_text(self, text: str) -> Tuple[List[DomainRule], ParseReport]:
        """Parses lines of text and returns a list of unique DomainRules and a ParseReport."""
        report = ParseReport()
        rules: List[DomainRule] = []
        seen_signatures: Set[Tuple[str, RuleType]] = set()

        for line in text.splitlines():
            report.total_lines += 1
            line = line.strip()

            if not line or line.startswith("!") or line.startswith(";"):
                report.comments_and_empty += 1
                continue

            # Check if this is an unsupported ABP cosmetic/scriptlet/URL rule
            if any(p.search(line) for p in UNSUPPORTED_RULE_PATTERNS):
                report.unsupported_rules += 1
                continue

            if line.startswith("#"):
                report.comments_and_empty += 1
                continue

            parsed_rule = self._parse_line(line)
            if not parsed_rule:
                report.invalid_domains += 1
                continue

            sig = (parsed_rule.pattern, parsed_rule.rule_type)
            if sig in seen_signatures:
                report.duplicates_dropped += 1
                continue

            seen_signatures.add(sig)
            rules.append(parsed_rule)
            report.parsed_rules += 1
            if parsed_rule.rule_type == RuleType.ALLOW:
                report.allow_rules += 1
            else:
                report.block_rules += 1

        return rules, report

    def _parse_line(self, line: str) -> Optional[DomainRule]:
        """Parses a single line into a DomainRule, identifying format."""
        # Strip inline comment
        comment = None
        if "#" in line:
            parts = line.split("#", 1)
            line = parts[0].strip()
            comment = parts[1].strip()

        if not line:
            return None

        # 1. Check for Adblock Plus / AdGuard style syntax:
        # Allowlist: @@||domain^ or @@||domain
        if line.startswith("@@||") or line.startswith("@@|"):
            raw = line[4:] if line.startswith("@@||") else line[3:]
            return self._parse_adblock_domain(raw, RuleType.ALLOW, comment)

        # Blocklist: ||domain^ or ||domain^$options
        if line.startswith("||"):
            raw = line[2:]
            return self._parse_adblock_domain(raw, RuleType.BLOCK, comment)

        # 2. Check for Hosts file format: IP <whitespace> domain(s)
        # e.g. 127.0.0.1 domain.com or 0.0.0.0 domain.com
        tokens = line.split()
        if len(tokens) >= 2 and self._is_hosts_ip(tokens[0]):
            domain_part = tokens[1]
            if domain_part.lower() in LOCALHOST_NAMES:
                return None
            return DomainRule.create(
                domain=domain_part,
                rule_type=RuleType.BLOCK,
                category=self.default_category,
                is_wildcard=True,
                source_list=self.source_name,
                comment=comment,
            )

        # 3. Plain domain rule: e.g. domain.com or *.domain.com
        raw_domain = tokens[0]
        is_wildcard = True
        if raw_domain.startswith("*."):
            raw_domain = raw_domain[2:]
            is_wildcard = True

        if raw_domain.lower() in LOCALHOST_NAMES:
            return None

        return DomainRule.create(
            domain=raw_domain,
            rule_type=RuleType.BLOCK,
            category=self.default_category,
            is_wildcard=is_wildcard,
            source_list=self.source_name,
            comment=comment,
        )

    def _parse_adblock_domain(self, raw: str, rule_type: RuleType, comment: Optional[str]) -> Optional[DomainRule]:
        # Handle options suffix e.g. ^$important or ^$third-party,badfilter
        domain_part = raw
        if "^" in domain_part:
            domain_part = domain_part.split("^", 1)[0]
        elif "$" in domain_part:
            domain_part = domain_part.split("$", 1)[0]

        # Strip trailing slashes or pipes
        domain_part = domain_part.rstrip("/|")

        if not domain_part or domain_part.lower() in LOCALHOST_NAMES:
            return None

        return DomainRule.create(
            domain=domain_part,
            rule_type=rule_type,
            category=self.default_category,
            is_wildcard=True,
            source_list=self.source_name,
            comment=comment,
        )

    @staticmethod
    def _is_hosts_ip(token: str) -> bool:
        """Determines if a token is a hosts-file IP prefix like 127.0.0.1 or 0.0.0.0."""
        return token in {"127.0.0.1", "0.0.0.0", "::1", "::", "0"}
