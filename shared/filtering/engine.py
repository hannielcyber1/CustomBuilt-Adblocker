"""
ShieldNet Shared Filtering Engine - Core Domain Matching Engine
Implements deterministic rule precedence, Trie-based domain boundary matching,
allowlist overrides, category filtering, and metrics.
"""

from __future__ import annotations
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from shared.rules.domain_rule import DomainRule, RuleCategory, RuleType, normalize_domain


@dataclass(slots=True)
class FilterDecision:
    """The result of a domain filtering evaluation."""
    allowed: bool
    domain: str
    rule: Optional[DomainRule] = None
    reason: str = "default_allow"
    category: Optional[RuleCategory] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "domain": self.domain,
            "reason": self.reason,
            "category": self.category.value if self.category else None,
            "rule_pattern": self.rule.pattern if self.rule else None,
            "source_list": self.rule.source_list if self.rule else None,
        }


class DomainTrieNode:
    """Node in a reverse-label domain trie for exact and suffix matching."""
    __slots__ = ("children", "rule", "is_terminal")

    def __init__(self) -> None:
        self.children: Dict[str, DomainTrieNode] = {}
        self.rule: Optional[DomainRule] = None
        self.is_terminal: bool = False


class DomainTrie:
    """Trie structured by reversed domain labels to support boundary-accurate suffix matching."""

    def __init__(self) -> None:
        self.root = DomainTrieNode()
        self.size = 0

    def insert(self, rule: DomainRule) -> None:
        labels = rule.pattern.split(".")[::-1]  # Reverse labels: 'ad.doubleclick.net' -> ['net', 'doubleclick', 'ad']
        node = self.root
        for label in labels:
            if label not in node.children:
                node.children[label] = DomainTrieNode()
            node = node.children[label]

        node.is_terminal = True
        node.rule = rule
        self.size += 1

    def match(self, domain_labels_reversed: List[str]) -> Optional[DomainRule]:
        """
        Walks the trie using reversed domain labels.
        If any ancestor node has a wildcard rule (is_terminal and is_wildcard),
        or if the exact leaf matches, returns that rule.
        """
        node = self.root
        for label in domain_labels_reversed:
            if label not in node.children:
                return None
            node = node.children[label]
            # If this node represents a wildcard rule, any subdomains below it are matched!
            if node.is_terminal and node.rule and node.rule.is_wildcard:
                return node.rule

        # If we reached the end of labels and the node is terminal, exact match
        if node.is_terminal:
            return node.rule
        return None

    def clear(self) -> None:
        self.root = DomainTrieNode()
        self.size = 0


class FilterEngine:
    """
    Deterministic domain filtering engine.
    Precedence:
    1. Normalize and validate input domain.
    2. Check explicit Allow rules (Exact & Subdomain).
    3. Check Block rules (Exact & Subdomain).
    4. Category filtering check: if matched rule belongs to a disabled category, allow it.
    5. Default: Allow.
    """

    def __init__(self) -> None:
        self._lock = threading.RWMutex() if hasattr(threading, "RWMutex") else threading.RLock()
        self.allow_trie = DomainTrie()
        self.block_trie = DomainTrie()
        self.enabled_categories: Set[RuleCategory] = set(RuleCategory)

        # Aggregate metrics
        self.total_queries = 0
        self.blocked_queries = 0
        self.allowed_queries = 0
        self.category_counts: Dict[str, int] = {cat.value: 0 for cat in RuleCategory}

    def set_category_enabled(self, category: RuleCategory, enabled: bool) -> None:
        """Enables or disables filtering for a specific category."""
        with self._lock:
            if enabled:
                self.enabled_categories.add(category)
            else:
                self.enabled_categories.discard(category)

    def is_category_enabled(self, category: RuleCategory) -> bool:
        with self._lock:
            return category in self.enabled_categories

    def add_rule(self, rule: DomainRule) -> None:
        """Adds a single DomainRule to the engine."""
        with self._lock:
            if rule.rule_type == RuleType.ALLOW:
                self.allow_trie.insert(rule)
            else:
                self.block_trie.insert(rule)

    def load_rules(self, rules: List[DomainRule], clear_existing: bool = True) -> None:
        """Loads a list of rules atomically into the engine."""
        new_allow = DomainTrie()
        new_block = DomainTrie()

        for rule in rules:
            if rule.rule_type == RuleType.ALLOW:
                new_allow.insert(rule)
            else:
                new_block.insert(rule)

        with self._lock:
            if clear_existing:
                self.allow_trie = new_allow
                self.block_trie = new_block
            else:
                for r in rules:
                    self.add_rule(r)

    def clear(self) -> None:
        """Clears all rules from the engine."""
        with self._lock:
            self.allow_trie.clear()
            self.block_trie.clear()

    @property
    def rule_count(self) -> Tuple[int, int]:
        """Returns (allow_count, block_count)."""
        with self._lock:
            return self.allow_trie.size, self.block_trie.size

    def evaluate(self, domain: str) -> FilterDecision:
        """
        Evaluates a domain and returns a deterministic FilterDecision.
        Safe against domain boundary bugs (e.g. 'notexample.com' won't match 'example.com').
        """
        normalized = normalize_domain(domain)
        if not normalized:
            return FilterDecision(
                allowed=True,
                domain=domain,
                reason="invalid_domain_allowed",
            )

        labels_reversed = normalized.split(".")[::-1]

        with self._lock:
            self.total_queries += 1

            # 1. Check Allow Rules
            allow_rule = self.allow_trie.match(labels_reversed)
            if allow_rule:
                self.allowed_queries += 1
                return FilterDecision(
                    allowed=True,
                    domain=normalized,
                    rule=allow_rule,
                    reason="allowlist_precedence",
                    category=allow_rule.category,
                )

            # 2. Check Block Rules
            block_rule = self.block_trie.match(labels_reversed)
            if block_rule:
                # 3. Check if category is enabled
                if block_rule.category not in self.enabled_categories:
                    self.allowed_queries += 1
                    return FilterDecision(
                        allowed=True,
                        domain=normalized,
                        rule=block_rule,
                        reason="category_disabled_allow",
                        category=block_rule.category,
                    )

                self.blocked_queries += 1
                cat_val = block_rule.category.value
                self.category_counts[cat_val] = self.category_counts.get(cat_val, 0) + 1
                return FilterDecision(
                    allowed=False,
                    domain=normalized,
                    rule=block_rule,
                    reason="blocklist_match",
                    category=block_rule.category,
                )

            # 4. Default: Allowed
            self.allowed_queries += 1
            return FilterDecision(
                allowed=True,
                domain=normalized,
                reason="default_allow",
            )

    def get_statistics(self) -> Dict[str, Any]:
        """Returns aggregate filtering metrics."""
        with self._lock:
            return {
                "total_queries": self.total_queries,
                "blocked_queries": self.blocked_queries,
                "allowed_queries": self.allowed_queries,
                "allow_rules_loaded": self.allow_trie.size,
                "block_rules_loaded": self.block_trie.size,
                "category_counts": dict(self.category_counts),
                "enabled_categories": [cat.value for cat in self.enabled_categories],
            }

    def reset_statistics(self) -> None:
        """Resets query count metrics."""
        with self._lock:
            self.total_queries = 0
            self.blocked_queries = 0
            self.allowed_queries = 0
            self.category_counts = {cat.value: 0 for cat in RuleCategory}
