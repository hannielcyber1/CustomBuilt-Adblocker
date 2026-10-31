@echo off
:: ShieldNet Windows Service Uninstallation & DNS Cleanup Script
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Administrator rights are required.
    echo Please right-click this script and select 'Run as administrator'.
    pause
    exit /b 1
)

echo [INFO] Restoring network adapter DNS settings to default...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses }"
ipconfig /flushdns

echo [INFO] Stopping and deleting ShieldNet Service...
set SERVICE_NAME=ShieldNetDNS
sc stop %SERVICE_NAME% >nul 2>&1
sc delete %SERVICE_NAME%

echo [SUCCESS] ShieldNet Service uninstalled and system DNS restored.
pause
