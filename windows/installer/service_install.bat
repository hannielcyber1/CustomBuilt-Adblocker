@echo off
:: ShieldNet Windows Service Registration Script
:: Requires Administrator Privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Administrator rights are required to install ShieldNet as a Windows Service.
    echo Please right-click this script and select 'Run as administrator'.
    pause
    exit /b 1
)

echo [INFO] Registering ShieldNet Background Service...
set SERVICE_NAME=ShieldNetDNS
set BIN_PATH="%~dp0..\service\daemon.py"

:: Register auto-starting background service
sc create %SERVICE_NAME% binPath= "python.exe \"%BIN_PATH%\"" start= auto DisplayName= "ShieldNet DNS Filtering Service"
sc description %SERVICE_NAME% "ShieldNet local DNS proxy protecting against ads, telemetry, and tracking."

echo [INFO] Starting ShieldNet Service...
sc start %SERVICE_NAME%

echo [SUCCESS] ShieldNet Service installed and running.
pause
