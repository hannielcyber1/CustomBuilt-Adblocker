"""
ShieldNet Shared Filtering Engine - High-Performance DNS Proxy Server
Listens for DNS requests over UDP & TCP, evaluates domains against FilterEngine,
returns synthetic block responses (0.0.0.0 or NXDOMAIN) or forwards permitted requests to upstream.
"""

from __future__ import annotations
import collections
import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset

from shared.config.settings import AppConfig
from shared.filtering.cache import DecisionCache
from shared.filtering.engine import FilterDecision, FilterEngine
from shared.rules.domain_rule import RuleCategory

logger = logging.getLogger("shieldnet.dns")


@dataclass(slots=True)
class QueryLogEntry:
    timestamp: float
    client_ip: str
    domain: str
    qtype: str
    status: str  # "BLOCKED" or "ALLOWED"
    reason: str
    category: Optional[str] = None
    rule_pattern: Optional[str] = None
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)),
            "client_ip": self.client_ip,
            "domain": self.domain,
            "qtype": self.qtype,
            "status": self.status,
            "reason": self.reason,
            "category": self.category,
            "rule_pattern": self.rule_pattern,
            "latency_ms": round(self.latency_ms, 2),
        }


class DNSProxyServer:
    """
    Multithreaded UDP and TCP DNS Proxy with domain-based ad/tracker blocking.
    """

    def __init__(
        self,
        engine: FilterEngine,
        config: Optional[AppConfig] = None,
        cache: Optional[DecisionCache] = None,
        on_query_logged: Optional[Callable[[QueryLogEntry], None]] = None,
    ) -> None:
        self.engine = engine
        self.config = config or AppConfig()
        self.cache = cache or DecisionCache(
            max_size=self.config.cache_max_size,
            default_ttl_seconds=self.config.cache_ttl_seconds,
        )
        self.on_query_logged = on_query_logged

        self._running = False
        self._udp_socket: Optional[socket.socket] = None
        self._tcp_socket: Optional[socket.socket] = None
        self._threads: List[threading.Thread] = []

        # Circular query log buffer
        self._logs_lock = threading.RLock()
        self.query_logs: Deque[QueryLogEntry] = collections.deque(maxlen=self.config.max_log_entries)

        # Performance & error metrics
        self.total_queries = 0
        self.blocked_queries = 0
        self.allowed_queries = 0
        self.upstream_errors = 0
        self.avg_latency_ms = 0.0

    def start(self) -> bool:
        """Starts the UDP and TCP DNS proxy servers."""
        if self._running:
            return True

        self._running = True

        try:
            # 1. Setup UDP socket
            self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._udp_socket.bind((self.config.listen_host, self.config.listen_port))
            self._udp_socket.settimeout(0.5)

            # 2. Setup TCP socket
            self._tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._tcp_socket.bind((self.config.listen_host, self.config.listen_port))
            self._tcp_socket.listen(64)
            self._tcp_socket.settimeout(0.5)

            logger.info("DNS Proxy listening on %s:%d (UDP & TCP)", self.config.listen_host, self.config.listen_port)
        except Exception as e:
            logger.error("Failed to bind DNS proxy socket on %s:%d: %s", self.config.listen_host, self.config.listen_port, e)
            self.stop()
            return False

        # Launch listener threads
        udp_thread = threading.Thread(target=self._udp_worker, name="DNSProxy-UDP", daemon=True)
        tcp_thread = threading.Thread(target=self._tcp_worker, name="DNSProxy-TCP", daemon=True)
        self._threads = [udp_thread, tcp_thread]

        for t in self._threads:
            t.start()

        return True

    def stop(self) -> None:
        """Gracefully stops the DNS proxy servers."""
        self._running = False

        if self._udp_socket:
            try:
                self._udp_socket.close()
            except Exception:
                pass
            self._udp_socket = None

        if self._tcp_socket:
            try:
                self._tcp_socket.close()
            except Exception:
                pass
            self._tcp_socket = None

        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()
        logger.info("DNS Proxy stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    def _udp_worker(self) -> None:
        while self._running:
            try:
                data, addr = self._udp_socket.recvfrom(4096)
            except (socket.timeout, BlockingIOError):
                continue
            except OSError:
                break
            except Exception as e:
                logger.debug("UDP recv error: %s", e)
                continue

            # Process in thread pool or inline
            threading.Thread(target=self._handle_udp_query, args=(data, addr), daemon=True).start()

    def _handle_udp_query(self, data: bytes, addr: Tuple[str, int]) -> None:
        start_time = time.perf_counter()
        response_wire = self._process_dns_wire(data, addr[0], start_time)
        if response_wire and self._udp_socket and self._running:
            try:
                self._udp_socket.sendto(response_wire, addr)
            except Exception as e:
                logger.debug("Failed to send UDP response to %s: %s", addr, e)

    def _tcp_worker(self) -> None:
        while self._running:
            try:
                client_sock, addr = self._tcp_socket.accept()
            except (socket.timeout, BlockingIOError):
                continue
            except OSError:
                break
            except Exception as e:
                logger.debug("TCP accept error: %s", e)
                continue

            threading.Thread(target=self._handle_tcp_client, args=(client_sock, addr), daemon=True).start()

    def _handle_tcp_client(self, client_sock: socket.socket, addr: Tuple[str, int]) -> None:
        client_sock.settimeout(3.0)
        start_time = time.perf_counter()
        try:
            # DNS over TCP uses a 2-byte length prefix
            len_bytes = client_sock.recv(2)
            if len(len_bytes) < 2:
                client_sock.close()
                return
            msg_len = struct.unpack("!H", len_bytes)[0]
            data = b""
            while len(data) < msg_len:
                chunk = client_sock.recv(min(4096, msg_len - len(data)))
                if not chunk:
                    break
                data += chunk

            if len(data) == msg_len:
                response_wire = self._process_dns_wire(data, addr[0], start_time)
                if response_wire:
                    prefix = struct.pack("!H", len(response_wire))
                    client_sock.sendall(prefix + response_wire)
        except Exception as e:
            logger.debug("TCP connection error with %s: %s", addr, e)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _process_dns_wire(self, wire_data: bytes, client_ip: str, start_time: float) -> Optional[bytes]:
        """Parses DNS request wire format, evaluates against rules, and crafts response."""
        try:
            query_msg = dns.message.from_wire(wire_data)
        except Exception:
            return None

        if not query_msg.question:
            # No question in query
            resp = dns.message.make_response(query_msg)
            resp.set_rcode(dns.rcode.FORMERR)
            return resp.to_wire()

        q = query_msg.question[0]
        domain = q.name.to_text().rstrip(".").lower()
        qtype_str = dns.rdatatype.to_text(q.rdtype)

        self.total_queries += 1

        # 1. Check cache first
        decision = self.cache.get(domain)
        if decision is None:
            # Evaluate against filter engine
            decision = self.engine.evaluate(domain)
            self.cache.put(domain, decision)

        latency_ms = (time.perf_counter() - start_time) * 1000

        # Log query
        log_entry = QueryLogEntry(
            timestamp=time.time(),
            client_ip=client_ip,
            domain=domain,
            qtype=qtype_str,
            status="ALLOWED" if decision.allowed else "BLOCKED",
            reason=decision.reason,
            category=decision.category.value if decision.category else None,
            rule_pattern=decision.rule.pattern if decision.rule else None,
            latency_ms=latency_ms,
        )
        self._record_log(log_entry)

        if not decision.allowed:
            # Blocked domain: synthesize blocking response
            self.blocked_queries += 1
            return self._build_block_response(query_msg, q)
        else:
            # Allowed domain: forward to upstream DNS
            self.allowed_queries += 1
            return self._forward_upstream(wire_data, query_msg)

    def _build_block_response(self, query_msg: dns.message.Message, question: dns.rrset.RRset) -> bytes:
        """Constructs synthetic DNS block response (0.0.0.0 for A, :: for AAAA, or NXDOMAIN)."""
        response = dns.message.make_response(query_msg)
        ttl = self.config.block_ttl

        if self.config.blocking_mode.upper() == "NXDOMAIN":
            response.set_rcode(dns.rcode.NXDOMAIN)
            return response.to_wire()

        # IP null-route mode
        if question.rdtype == dns.rdatatype.A:
            rrs = dns.rrset.from_text(question.name, ttl, dns.rdataclass.IN, dns.rdatatype.A, "0.0.0.0")
            response.answer.append(rrs)
        elif question.rdtype == dns.rdatatype.AAAA:
            rrs = dns.rrset.from_text(question.name, ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, "::")
            response.answer.append(rrs)
        else:
            # Other query types: return NOERROR with 0 answers (NODATA)
            response.set_rcode(dns.rcode.NOERROR)

        return response.to_wire()

    def _forward_upstream(self, wire_data: bytes, query_msg: dns.message.Message) -> bytes:
        """Forwards query to primary or secondary upstream resolver over UDP/TCP."""
        upstreams = [self.config.upstream_primary, self.config.upstream_secondary]
        port = self.config.upstream_port

        for upstream in upstreams:
            if not upstream:
                continue
            try:
                # Try UDP first
                resp = dns.query.udp(query_msg, upstream, port=port, timeout=2.0)
                # Check for truncation flag (TC bit)
                if resp.flags & dns.flags.TC:
                    logger.debug("Response truncated (TC=1), falling back to TCP for %s", upstream)
                    resp = dns.query.tcp(query_msg, upstream, port=port, timeout=3.0)
                return resp.to_wire()
            except Exception as e:
                logger.debug("Upstream %s failed: %s, trying fallback", upstream, e)

        self.upstream_errors += 1
        # If all upstreams failed, return SERVFAIL
        servfail = dns.message.make_response(query_msg)
        servfail.set_rcode(dns.rcode.SERVFAIL)
        return servfail.to_wire()

    def _record_log(self, entry: QueryLogEntry) -> None:
        if not self.config.enable_query_logging:
            return
        with self._logs_lock:
            self.query_logs.append(entry)
        if self.on_query_logged:
            try:
                self.on_query_logged(entry)
            except Exception:
                pass

    def get_recent_logs(self, limit: int = 100, filter_status: Optional[str] = None, search: str = "") -> List[Dict[str, Any]]:
        """Returns recent query logs matching optional filters."""
        search_lower = search.strip().lower()
        with self._logs_lock:
            logs = list(self.query_logs)[::-1]  # most recent first

        results = []
        for entry in logs:
            if filter_status and entry.status != filter_status.upper():
                continue
            if search_lower and search_lower not in entry.domain:
                continue
            results.append(entry.to_dict())
            if len(results) >= limit:
                break
        return results

    def clear_logs(self) -> None:
        with self._logs_lock:
            self.query_logs.clear()

    def get_metrics(self) -> Dict[str, Any]:
        """Returns live dashboard metrics."""
        cache_stats = self.cache.get_stats()
        engine_stats = self.engine.get_statistics()
        total = self.total_queries
        block_rate = (self.blocked_queries / total * 100) if total > 0 else 0.0

        return {
            "is_running": self._running,
            "total_queries": self.total_queries,
            "blocked_queries": self.blocked_queries,
            "allowed_queries": self.allowed_queries,
            "block_rate_percent": round(block_rate, 2),
            "upstream_errors": self.upstream_errors,
            "cache": cache_stats,
            "rules": {
                "allow": engine_stats["allow_rules_loaded"],
                "block": engine_stats["block_rules_loaded"],
            },
            "category_counts": engine_stats["category_counts"],
        }
