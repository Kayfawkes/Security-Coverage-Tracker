@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo This script must be run as Administrator.
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "if (-not (Get-NetFirewallRule -DisplayName 'Security Coverage Tracker TCP 7777' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName 'Security Coverage Tracker TCP 7777' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 7777 -Profile Domain,Private } else { Write-Host 'Firewall rule already exists.' }"

echo Port 7777 is allowed for Domain and Private network profiles.
pause
