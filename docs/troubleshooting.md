# ShieldNet Diagnostics & Troubleshooting Guide

This guide provides step-by-step troubleshooting instructions for common connectivity, DNS, and filtering scenarios on Windows and Android.

---

## 1. Windows Troubleshooting

### 1.1 "Administrator permissions are required"
- **Cause**: Windows requires elevated privileges to modify network adapter DNS server addresses.
- **Resolution**: Right-click the ShieldNet application or shortcut and select **Run as administrator**.

### 1.2 "Port 53 is already in use"
- **Cause**: Another service (such as Windows Internet Connection Sharing, Acrylic DNS, or a local Docker container) is bound to UDP/TCP port 53 on `127.0.0.1`.
- **Diagnosis**:
  Open an elevated PowerShell prompt and run:
  ```powershell
  Get-NetUDPEndpoint -LocalPort 53 | Select-Object -Property LocalAddress, LocalPort, OwningProcess
  ```
  Or:
  ```cmd
  netstat -ano | findstr :53
  ```
- **Resolution**: Stop the conflicting service, or configure ShieldNet to run on an alternative local port and forward traffic via portproxy.

### 1.3 Emergency Internet Restoration (Windows)
If your computer abruptly crashed or lost power while ShieldNet was active and original DNS was not restored:
1. Run the included restoration script:
   ```cmd
   windows\installer\service_uninstall.bat
   ```
2. Or run this PowerShell command to reset all active network adapters to automatic DHCP DNS:
   ```powershell
   Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses }
   ipconfig /flushdns
   ```

---

## 2. Android Troubleshooting

### 2.1 Advertisements Still Appearing on Websites
1. **Check Private DNS**:
   - Go to **Android Settings** > **Network & Internet** > **Private DNS**.
   - If set to a specific provider (e.g. `dns.google`), Android bypasses local VPN DNS filters.
   - Set Private DNS to **Off** or **Automatic**.
2. **Clear Browser DNS Cache**:
   - In Chrome, navigate to `chrome://net-internals/#dns` and tap **Clear host cache**.
3. **Verify Protection Status**:
   - Ensure the ShieldNet persistent notification is visible in the status bar.

### 2.2 VPN Service Stops in Background / Screen Off
- **Cause**: Android aggressive battery optimization kills background services.
- **Resolution**:
  - Go to **Android Settings** > **Apps** > **ShieldNet** > **Battery**.
  - Change battery usage setting from "Optimized" to **Unrestricted**.

### 2.3 Conflict with Another VPN
- **Cause**: Android OS architecture enforces a strict limit: **only one VpnService can be active at any time**.
- **Resolution**: If you connect to an external corporate or privacy VPN, Android will automatically pause ShieldNet. Reconnect ShieldNet when the external VPN session ends.

---

## 3. Whitelisting a Broken Website

If a website or application experiences broken functionality due to an aggressive blocklist:
1. Open the **Query Activity** tab in ShieldNet.
2. Filter by `BLOCKED` and locate the domain called when the error occurred.
3. Tap or click **Allow Selected Domain**.
4. The domain is instantly added to your custom Allowlist and takes immediate precedence.
