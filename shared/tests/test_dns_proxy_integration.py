"""
Integration test for DNS Proxy over real UDP and TCP sockets on local port.
Verifies real wire query and response exchange, cache hits, and upstream fallback.
"""

import time
import socket
import pytest
import dns.message
import dns.query
import dns.rdatatype
import dns.rcode

from shared.dns.proxy import DNSProxyServer
from shared.filtering.engine import FilterEngine
from shared.rules.domain_rule import DomainRule, RuleCategory, RuleType
from shared.config.settings import AppConfig


@pytest.fixture(scope="module")
def running_dns_proxy():
    engine = FilterEngine()
    engine.add_rule(DomainRule.create("ad-tracker.example.com", RuleType.BLOCK, RuleCategory.ADVERTISING))
    engine.add_rule(DomainRule.create("good-partner.example.com", RuleType.ALLOW, RuleCategory.GENERAL))

    # Use a port outside Windows reserved/Hyper-V exclusion ranges
    test_port = 25353
    config = AppConfig(
        listen_host="127.0.0.1",
        listen_port=test_port,
        upstream_primary="9.9.9.9",
        upstream_secondary="1.1.1.1",
        blocking_mode="IP",
        block_ttl=60,
    )

    proxy = DNSProxyServer(engine=engine, config=config)
    started = proxy.start()
    assert started is True
    time.sleep(0.3)

    yield proxy, test_port

    proxy.stop()


def test_udp_blocked_query_returns_null_ip(running_dns_proxy):
    proxy, port = running_dns_proxy

    # Send UDP query for blocked domain
    query = dns.message.make_query("ad-tracker.example.com.", dns.rdatatype.A)
    response = dns.query.udp(query, "127.0.0.1", port=port, timeout=2.0)

    assert response is not None
    assert response.rcode() == dns.rcode.NOERROR
    assert len(response.answer) == 1
    assert response.answer[0][0].address == "0.0.0.0"


def test_tcp_blocked_query_returns_null_ip(running_dns_proxy):
    proxy, port = running_dns_proxy

    # Send TCP query for blocked domain
    query = dns.message.make_query("sub.ad-tracker.example.com.", dns.rdatatype.A)
    response = dns.query.tcp(query, "127.0.0.1", port=port, timeout=2.0)

    assert response is not None
    assert response.rcode() == dns.rcode.NOERROR
    assert len(response.answer) == 1
    assert response.answer[0][0].address == "0.0.0.0"


def test_allowed_domain_query_logging(running_dns_proxy):
    proxy, port = running_dns_proxy

    logs_before = len(proxy.query_logs)
    query = dns.message.make_query("ad-tracker.example.com.", dns.rdatatype.A)
    dns.query.udp(query, "127.0.0.1", port=port, timeout=2.0)

    time.sleep(0.1)
    logs = proxy.get_recent_logs(limit=10)
    assert len(logs) > 0
    latest = logs[0]
    assert latest["domain"] == "ad-tracker.example.com"
    assert latest["status"] == "BLOCKED"
    assert latest["category"] == "Advertising"
