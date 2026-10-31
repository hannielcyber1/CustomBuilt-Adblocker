# ShieldNet Blocklists Documentation

This directory contains reference blocklists and guidelines for domain list selection and syntax.

## Supported Formats

ShieldNet supports:
1. **Standard `/etc/hosts` format**:
   ```hosts
   0.0.0.0 doubleclick.net
   127.0.0.1 telemetry.microsoft.com
   ```
2. **Adblock Plus / AdGuard Domain Filter Syntax (Subset)**:
   ```adblock
   ||adserver.com^           # Blocks adserver.com and all subdomains
   ||tracker.org^$important  # Block rule with modifier
   @@||api.trusted.com^      # Allowlist rule (overrides block rules)
   ```
3. **Plain Domain Lists**:
   ```text
   badsite.com
   malware-endpoint.org
   ```

## Unsupported Rules (Ignored Safely at DNS Level)

ShieldNet acts strictly as a DNS resolver and does not inspect HTTPS payload content or inject web scripts.
The following rule formats are ignored and logged in parser diagnostics:
- Cosmetic element hiding rules (e.g. `##.banner`, `#?#`)
- Scriptlet injection rules (e.g. `#%#//scriptlet`)
- URL path-based rules (e.g. `/banners/ad*.gif`)
- Protocol-specific filters (e.g. `$websocket`, `$csp`)

## Verified Public Blocklist Sources

| Name | Primary Focus | Official URL | License |
| :--- | :--- | :--- | :--- |
| **StevenBlack Unified** | Adware, malware, tracking | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` | MIT |
| **AdGuard DNS Filter** | Ad-serving and privacy tracking | `https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt` | GPLv3 |
| **OISD Basic** | Low false-positive ad/telemetry | `https://small.oisd.nl/` | CC BY 4.0 |
