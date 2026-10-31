"""
Comprehensive Unit and Integration Tests for ShieldNet Shared Filtering Engine
Tests domain normalization, rule parser, reverse-label trie, allowlist precedence,
cache behavior, and DNS wire response generation.
"""

import time
import pytest
import dns.message
import dns.rdatatype
import dns.rcode

from shared.rules.domain_rule import DomainRule, RuleCategory, RuleType, normalize_domain
from shared.rules.parser import RuleParser
from shared.filtering.engine import FilterEngine
from shared.filtering.cache import DecisionCache
from shared.dns.proxy import DNSProxyServer
from shared.config.settings import AppConfig


class TestDomainNormalization:
    def test_basic_domains(self):
        assert normalize_domain("example.com") == "example.com"
        assert normalize_domain("EXAMPLE.COM") == "example.com"
        assert normalize_domain("  sub.example.com.  ") == "sub.example.com"

    def test_strip_schemes_and_paths(self):
        assert normalize_domain("https://ads.tracker.org/banner?id=123") == "ads.tracker.org"
        assert normalize_domain("http://doubleclick.net:8080/") == "doubleclick.net"

    def test_idn_punycode(self):
        # German umlaut domain: münchen.de -> xn--mnchen-3ya.de
        normalized = normalize_domain("münchen.de")
        assert normalized == "xn--mnchen-3ya.de"

    def test_invalid_domains(self):
        assert normalize_domain("") is None
        assert normalize_domain("   ") is None
        assert normalize_domain("-starts-with-hyphen.com") is None
        assert normalize_domain("ends-with-hyphen-.com") is None
        assert normalize_domain("a" * 64 + ".com") is None  # Label exceeds 63 chars


class TestRuleParser:
    def test_parse_hosts_format(self):
        hosts_data = """
        # This is a sample hosts file
        127.0.0.1 localhost
        ::1 localhost
        0.0.0.0 ad.doubleclick.net # Tracking ad server
        127.0.0.1 telemetry.windows.com
        """
        parser = RuleParser(source_name="test_hosts", default_category=RuleCategory.ADVERTISING)
        rules, report = parser.parse_text(hosts_data)

        assert report.parsed_rules == 2
        assert len(rules) == 2
        domains = {r.pattern for r in rules}
        assert "ad.doubleclick.net" in domains
        assert "telemetry.windows.com" in domains
        assert "localhost" not in domains

    def test_parse_adblock_syntax(self):
        abp_data = """
        ! Adblock list sample
        ||googleadservices.com^
        ||analytics.tiktok.com^$third-party
        @@||trusted-cdn.googleadservices.com^
        ##.advertisement-banner
        #%#//scriptlet('abort-current-inline-script')
        /banner/ads/*
        """
        parser = RuleParser(source_name="test_abp", default_category=RuleCategory.TRACKING)
        rules, report = parser.parse_text(abp_data)

        assert report.block_rules == 2
        assert report.allow_rules == 1
        assert report.unsupported_rules == 3  # CSS element, scriptlet, path regex
        allow_rule = next(r for r in rules if r.rule_type == RuleType.ALLOW)
        assert allow_rule.pattern == "trusted-cdn.googleadservices.com"

    def test_duplicate_dropping(self):
        dup_data = """
        0.0.0.0 badsite.com
        0.0.0.0 badsite.com
        ||badsite.com^
        """
        parser = RuleParser()
        rules, report = parser.parse_text(dup_data)
        assert len(rules) == 1
        assert report.duplicates_dropped == 2


class TestFilterEngine:
    def setup_method(self):
        self.engine = FilterEngine()

    def test_exact_and_subdomain_matching(self):
        # Block doubleclick.net and subdomains
        rule = DomainRule.create("doubleclick.net", RuleType.BLOCK, RuleCategory.ADVERTISING, is_wildcard=True)
        self.engine.add_rule(rule)

        # Exact match
        dec1 = self.engine.evaluate("doubleclick.net")
        assert dec1.allowed is False
        assert dec1.reason == "blocklist_match"

        # Subdomain match
        dec2 = self.engine.evaluate("ad.doubleclick.net")
        assert dec2.allowed is False

        dec3 = self.engine.evaluate("deep.nested.sub.doubleclick.net")
        assert dec3.allowed is False

    def test_domain_boundary_isolation(self):
        """Crucial test: Ensure 'example.com' does NOT match 'notexample.com' or 'example.com.org'"""
        rule = DomainRule.create("example.com", RuleType.BLOCK, RuleCategory.ADVERTISING, is_wildcard=True)
        self.engine.add_rule(rule)

        # Exact and subdomains should match
        assert self.engine.evaluate("example.com").allowed is False
        assert self.engine.evaluate("ads.example.com").allowed is False

        # Sibling or prefix domains MUST NOT match!
        assert self.engine.evaluate("notexample.com").allowed is True
        assert self.engine.evaluate("myexample.com").allowed is True
        assert self.engine.evaluate("example.com.evil.org").allowed is True

    def test_allowlist_precedence(self):
        """Allow rules must override block rules unconditionally."""
        block_rule = DomainRule.create("company.com", RuleType.BLOCK, RuleCategory.TRACKING, is_wildcard=True)
        allow_rule = DomainRule.create("api.company.com", RuleType.ALLOW, RuleCategory.GENERAL, is_wildcard=True)

        self.engine.add_rule(block_rule)
        self.engine.add_rule(allow_rule)

        # Parent blocked
        assert self.engine.evaluate("company.com").allowed is False
        assert self.engine.evaluate("telemetry.company.com").allowed is False

        # Specific subdomain allowlisted
        assert self.engine.evaluate("api.company.com").allowed is True
        assert self.engine.evaluate("api.company.com").reason == "allowlist_precedence"
        assert self.engine.evaluate("sub.api.company.com").allowed is True

    def test_category_filtering(self):
        telemetry_rule = DomainRule.create("telemetry.app.com", RuleType.BLOCK, RuleCategory.TELEMETRY)
        self.engine.add_rule(telemetry_rule)

        # Enabled by default
        assert self.engine.evaluate("telemetry.app.com").allowed is False

        # Disable Telemetry category
        self.engine.set_category_enabled(RuleCategory.TELEMETRY, False)
        assert self.engine.evaluate("telemetry.app.com").allowed is True
        assert self.engine.evaluate("telemetry.app.com").reason == "category_disabled_allow"

        # Re-enable
        self.engine.set_category_enabled(RuleCategory.TELEMETRY, True)
        assert self.engine.evaluate("telemetry.app.com").allowed is False


class TestDecisionCache:
    def test_cache_hits_and_expiration(self):
        cache = DecisionCache(max_size=5, default_ttl_seconds=0.2)
        dec = FilterEngine().evaluate("test.com")

        # Cache miss
        assert cache.get("test.com") is None
        assert cache.misses == 1

        # Cache put
        cache.put("test.com", dec, ttl_seconds=0.2)
        assert cache.get("test.com") is not None
        assert cache.hits == 1

        # Wait for expiration
        time.sleep(0.25)
        assert cache.get("test.com") is None
        assert cache.misses == 2

    def test_lru_eviction(self):
        cache = DecisionCache(max_size=3, default_ttl_seconds=10.0)
        dec = FilterEngine().evaluate("dummy.com")

        cache.put("d1.com", dec)
        cache.put("d2.com", dec)
        cache.put("d3.com", dec)
        assert cache.get("d1.com") is not None  # touches d1

        # Adding 4th should evict d2 (least recently used)
        cache.put("d4.com", dec)
        assert cache.get("d2.com") is None
        assert cache.get("d1.com") is not None
        assert cache.get("d4.com") is not None


class TestDNSProxyPacketHandling:
    def test_block_response_generation_ip_mode(self):
        engine = FilterEngine()
        engine.add_rule(DomainRule.create("blocked-ad.com", RuleType.BLOCK, RuleCategory.ADVERTISING))

        config = AppConfig(blocking_mode="IP", block_ttl=120)
        proxy = DNSProxyServer(engine=engine, config=config)

        # Craft query for blocked-ad.com A record
        query = dns.message.make_query("blocked-ad.com.", dns.rdatatype.A)
        response_bytes = proxy._process_dns_wire(query.to_wire(), "127.0.0.1", time.perf_counter())

        assert response_bytes is not None
        resp_msg = dns.message.from_wire(response_bytes)
        assert resp_msg.rcode() == dns.rcode.NOERROR
        assert len(resp_msg.answer) == 1
        rr = resp_msg.answer[0]
        assert rr.rdtype == dns.rdatatype.A
        assert rr[0].address == "0.0.0.0"
        assert rr.ttl == 120

    def test_block_response_generation_nxdomain_mode(self):
        engine = FilterEngine()
        engine.add_rule(DomainRule.create("blocked-tracker.com", RuleType.BLOCK, RuleCategory.TRACKING))

        config = AppConfig(blocking_mode="NXDOMAIN")
        proxy = DNSProxyServer(engine=engine, config=config)

        query = dns.message.make_query("blocked-tracker.com.", dns.rdatatype.A)
        response_bytes = proxy._process_dns_wire(query.to_wire(), "127.0.0.1", time.perf_counter())

        assert response_bytes is not None
        resp_msg = dns.message.from_wire(response_bytes)
        assert resp_msg.rcode() == dns.rcode.NXDOMAIN
