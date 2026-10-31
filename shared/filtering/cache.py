"""
ShieldNet Shared Filtering Engine - Thread-Safe LRU Decision Cache
Caches DNS filter decisions and upstream resolutions with TTL expiration.
"""

from __future__ import annotations
import collections
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from shared.filtering.engine import FilterDecision


@dataclass(slots=True)
class CacheEntry:
    decision: FilterDecision
    expires_at: float


class DecisionCache:
    """Thread-safe LRU cache for domain filtering decisions with TTL support."""

    def __init__(self, max_size: int = 10000, default_ttl_seconds: float = 300.0) -> None:
        self.max_size = max_size
        self.default_ttl = default_ttl_seconds
        self._cache: collections.OrderedDict[str, CacheEntry] = collections.OrderedDict()
        self._lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def get(self, domain: str) -> Optional[FilterDecision]:
        """Retrieves a cached decision if not expired, moving entry to MRU position."""
        now = time.monotonic()
        key = domain.lower()
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self.misses += 1
                return None

            if now > entry.expires_at:
                # Expired
                del self._cache[key]
                self.misses += 1
                return None

            # Mark recently used
            self._cache.move_to_end(key)
            self.hits += 1
            return entry.decision

    def put(self, domain: str, decision: FilterDecision, ttl_seconds: Optional[float] = None) -> None:
        """Stores a decision in the cache with a specified or default TTL."""
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        now = time.monotonic()
        expires_at = now + ttl
        key = domain.lower()

        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = CacheEntry(decision=decision, expires_at=expires_at)

            # Evict LRU if over capacity
            while len(self._cache) > self.max_size:
                self._cache.popitem(last=False)

    def invalidate(self, domain: str) -> None:
        """Removes a specific domain from the cache."""
        key = domain.lower()
        with self._lock:
            self._cache.pop(key, None)

    def clear(self) -> None:
        """Flushes the entire decision cache."""
        with self._lock:
            self._cache.clear()
            self.hits = 0
            self.misses = 0

    def get_stats(self) -> Dict[str, Any]:
        """Returns cache utilization statistics."""
        with self._lock:
            total = self.hits + self.misses
            hit_ratio = (self.hits / total) if total > 0 else 0.0
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "hit_ratio_percent": round(hit_ratio * 100, 2),
            }
