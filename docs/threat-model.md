# ShieldNet Security & Threat Model

This document outlines the threat model, attack surface analysis, and defensive countermeasures implemented across the ShieldNet architecture.

---

## 1. System Classification & Boundaries

ShieldNet is a local, privacy-preserving DNS filtering agent.
- **Trust Boundary 1**: User space applications <--> ShieldNet DNS Proxy / VpnService TUN interface.
- **Trust Boundary 2**: ShieldNet Service <--> External Upstream Resolvers (e.g. Quad9 `9.9.9.9`, Cloudflare `1.1.1.1`).
- **Trust Boundary 3**: ShieldNet Blocklist Manager <--> Public Blocklist Distribution CDNs.
- **Trust Boundary 4**: Local GUI client <--> Background Service IPC.

---

## 2. STRIDE Threat Analysis

| Category | Threat Scenario | Impact | Defensive Countermeasure |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates public blocklist repository during update. | Malicious rules injected; legitimate critical domains blocked (denial of service) or malicious domains whitelisted. | Strict HTTPS transport enforced. SHA-256 fingerprint verification. Content validation rejects HTML/error responses. Fallback to cached good list. |
| **Tampering** | Non-privileged process tampers with ShieldNet IPC socket to modify rules. | Unauthorized domains allowed or blocked. | IPC socket strictly binds to `127.0.0.1` (loopback only). On Windows, configuration directory permissions restrict access to the current user and Administrators. |
| **Repudiation** | User denies performing network rule modifications. | Auditing breakdown. | Audit logs recorded with local timestamps in circular buffer and Room DB. |
| **Information Disclosure** | Local application snoops on user query history. | Privacy breach revealing domains visited by the user. | Query logging is optional and disabled by default in high-security mode. Logs are stored exclusively in volatile memory or encrypted local app storage with zero telemetry export. |
| **Denial of Service** | Oversized or cyclic blocklist payload exhausts memory or CPU. | Service crash; internet connectivity loss for client device. | Download size enforced (max 25 MB). Stream processing. Fallback to last known-good rules if parsing or download fails. |
| **Elevation of Privilege** | Attacker exploits Windows service to execute arbitrary code with SYSTEM rights. | Full machine takeover. | Windows service does not execute arbitrary shell commands or dynamic code evaluation (`eval`). Uses explicit parameterized APIs. |

---

## 3. High-Risk Attack Scenarios & Mitigations

### 3.1 Open Resolver / Amplification Risk
- **Threat**: If the local DNS proxy binds to `0.0.0.0`, malicious external actors on the same LAN or WAN could use ShieldNet as an open recursive resolver or DNS amplification vector.
- **Mitigation**: The DNS proxy strictly binds to `127.0.0.1` (localhost loopback) on Windows and the virtual TUN interface (`10.255.0.1`) on Android. It never accepts incoming packets from external network interfaces.

### 3.2 DNS Cache Poisoning
- **Threat**: An attacker on the local network attempts to inject forged DNS responses for permitted queries.
- **Mitigation**: Upstream queries preserve random 16-bit Transaction IDs and source port randomization. ShieldNet supports upstream resolvers with DNSSEC validation (e.g., Quad9 `9.9.9.9`).

### 3.3 CDN Over-Blocking & Collateral Damage
- **Threat**: Aggressive blocklists blocking multi-tenant CDN domains (e.g., `cloudflare.com`, `akamaihd.net`, `fastly.net`) breaking unrelated legitimate websites.
- **Mitigation**: Strict allowlist precedence (`@@||domain^`). Vetted default lists (StevenBlack, OISD) that specifically curate against shared CDN domain blocks. One-click whitelist action in the live Activity log.

### 3.4 Antivirus & Windows Defender Compatibility
- **Policy**: ShieldNet never attempts to disable Windows Defender, disable Windows Firewall, modify SmartScreen settings, or tamper with system security software.
- Network changes are restricted to standard adapter DNS address assignment (`Set-DnsClientServerAddress` / `netsh`), and are cleanly reverted upon shutdown.
