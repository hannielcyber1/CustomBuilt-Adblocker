# ShieldNet Privacy Policy & Data Architecture

ShieldNet is engineered for **legitimate personal privacy protection**. This document describes how user data is handled, the limits of DNS filtering, and disclosures regarding external network communications.

---

## 1. Core Privacy Commitments

1. **100% Local Decision Engine**: Every domain evaluation, allowlist check, and blocklist match happens entirely on your local device.
2. **Zero Telemetry**: ShieldNet contains no analytic trackers, no crash reporters sending data to third parties, and no diagnostic telemetry endpoints.
3. **No TLS Interception**: ShieldNet never installs root certificates on your machine or mobile device, does not decrypt HTTPS traffic, and cannot see passwords, messages, financial data, or browsing paths.
4. **Transparent Query Logging**:
   - Query logging is stored locally in volatile RAM or private device storage.
   - Users can turn off query logging at any time in Settings.
   - A single-click "Clear Logs" button immediately flushes all historical records.

---

## 2. External Network Communications

ShieldNet communicates externally in only two scenarios:

### 2.1 Upstream DNS Resolution
When a requested domain is **permitted** by your blocklists, ShieldNet must resolve the domain so your application can connect.
- Permitted queries are forwarded to your configured upstream DNS resolver (default: **Quad9** `9.9.9.9` or **Cloudflare** `1.1.1.1`).
- ShieldNet does NOT forward queries to multiple providers concurrently without user knowledge.
- Users can change the upstream resolver to any DNS server of their choice, including self-hosted Unbound or Pi-hole instances.

### 2.2 Blocklist Updates
When automatic or manual list updates are triggered, ShieldNet downloads updated blocklist definitions over HTTPS from the official project repositories:
- StevenBlack Hosts (`raw.githubusercontent.com`)
- AdGuard Hostlists (`adguardteam.github.io`)
- OISD (`small.oisd.nl`)

---

## 3. Realistic Limitations of DNS-Based Blocking

To maintain transparency, users should understand the technical boundaries of DNS-layer filtering:

1. **Same-Domain (First-Party) Advertisements**:
   DNS blockers operate at domain level (`subdomain.example.com`). If an advertisement or sponsored content is served from the exact same domain and IP address as the legitimate video or article (e.g., YouTube in-stream video ads, sponsored posts in social media feeds), a DNS blocker cannot block the advertisement without completely breaking the legitimate content.
2. **Hardcoded IP Addresses / DoH in Applications**:
   Some proprietary applications bypass OS DNS resolvers by hardcoding fallback IP addresses or bundling their own internal DNS-over-HTTPS client with hardcoded DoH providers.
3. **Android Private DNS (DoT)**:
   If Android has "Private DNS" enabled with a custom hostname, Android's OS resolver queries that DoT endpoint directly, bypassing local VPN DNS filters. ShieldNet provides on-screen guidance to configure this appropriately.
