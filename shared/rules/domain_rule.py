"""
ShieldNet Shared Filtering Engine - Domain Rule Definitions
Handles rule categorization, normalization, validation, and domain parsing.
"""

from __future__ import annotations
import enum
import re
from dataclasses import dataclass, field
from typing import Optional


class RuleType(str, enum.Enum):
    BLOCK = "BLOCK"
    ALLOW = "ALLOW"


class RuleCategory(str, enum.Enum):
    ADVERTISING = "Advertising"
    TRACKING = "Tracking"
    ANALYTICS = "Analytics"
    TELEMETRY = "Telemetry"
    MALWARE = "Malware"
    ADULT_CONTENT = "Adult Content"   # Explicit / pornographic sites
    GAMBLING = "Gambling"             # Online gambling sites
    CUSTOM = "Custom"
    GENERAL = "General"


# RFC 1035 / RFC 1123 compliant domain label pattern:
# Labels 1-63 alphanumeric/hyphen characters, not starting or ending with hyphen.
# Total length up to 253 characters.
LABEL_REGEX = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def normalize_domain(domain: str) -> Optional[str]:
    """
    Normalizes a domain name:
    - Strips leading/trailing whitespace
    - Converts to lowercase
    - Strips leading schemes (http://, https://) if present
    - Strips paths, query parameters, and port numbers
    - Removes trailing dot (FQDN root notation)
    - Converts IDN (Internationalized Domain Names) to Punycode ASCII
    - Validates label lengths and character sets
    Returns the normalized domain string, or None if invalid.
    """
    if not domain or not isinstance(domain, str):
        return None

    cleaned = domain.strip().lower()

    # Strip scheme if pasted with http/https
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]

    # Strip path / query
    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0]
    if "?" in cleaned:
        cleaned = cleaned.split("?", 1)[0]

    # Strip port if present (ensure not IPv6)
    if ":" in cleaned and not cleaned.startswith("["):
        cleaned = cleaned.split(":", 1)[0]

    # Remove trailing dot
    cleaned = cleaned.rstrip(".")

    if not cleaned:
        return None

    # Length checks
    if len(cleaned) > 253:
        return None

    # IDN / Punycode conversion
    try:
        cleaned = cleaned.encode("idna").decode("ascii")
    except Exception:
        # Invalid IDN characters
        return None

    labels = cleaned.split(".")
    if not labels:
        return None

    for label in labels:
        if not label or len(label) > 63:
            return None
        if not LABEL_REGEX.match(label):
            return None

    return cleaned


@dataclass(frozen=True, slots=True)
class DomainRule:
    """Represents a validated domain filtering rule."""
    pattern: str
    rule_type: RuleType = RuleType.BLOCK
    category: RuleCategory = RuleCategory.GENERAL
    is_wildcard: bool = True  # True matches the domain AND all subdomains
    source_list: str = "custom"
    comment: Optional[str] = None

    @classmethod
    def create(
        cls,
        domain: str,
        rule_type: RuleType = RuleType.BLOCK,
        category: RuleCategory = RuleCategory.GENERAL,
        is_wildcard: bool = True,
        source_list: str = "custom",
        comment: Optional[str] = None,
    ) -> Optional[DomainRule]:
        normalized = normalize_domain(domain)
        if not normalized:
            return None
        return cls(
            pattern=normalized,
            rule_type=rule_type,
            category=category,
            is_wildcard=is_wildcard,
            source_list=source_list,
            comment=comment,
        )
