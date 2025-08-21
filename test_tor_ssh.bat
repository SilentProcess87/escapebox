@echo off
echo ==================================================
echo     TOR & SSH TUNNEL TESTING
echo     XDR Detection Features
echo ==================================================
echo.
echo This test will trigger XDR detections for:
echo   - TOR network connections (REAL TCP connections to TOR nodes)
echo   - Suspicious API calls from TOR exit nodes (REAL HTTPS to Telegram/Discord/Pastebin)
echo   - Reverse SSH tunnels
echo   - Netcat/Socat relay networks
echo.
echo WARNING: This will generate REAL network traffic to external IPs/domains!
echo          All data sent is fake/harmless test data only.
echo.

REM Check if server is running
echo [1] Starting C2 server...
start /B escapebox.exe server
timeout /t 3 >nul

REM Start client
echo [2] Starting C2 client...
start /B escapebox.exe client 127.0.0.1 443
timeout /t 5 >nul

echo [3] Server is ready. Press these keys to test:
echo.
echo     === TOR & NETWORK TUNNEL TESTS ===
echo     Press 'T' - Test TOR connections and API calls
echo     Press 'N' - Test network tunnels (SSH/Netcat/Socat)
echo     Press '3' - Run full Defense Evasion phase (includes all)
echo.
echo [4] Monitor the activity log for XDR alerts:
echo.
echo Starting log monitor for TOR/SSH activity...
echo.
powershell -Command "Get-Content -Path 'C:\Windows\Temp\c2_activity_log.txt' -Tail 20 -Wait | Select-String -Pattern 'XDR_ALERT|CRITICAL|TOR|SSH|NETCAT|SOCAT|onion' | ForEach-Object { $_ -replace '^.*?\[', '[' } | ForEach-Object { if($_ -match 'XDR_ALERT|CRITICAL') { Write-Host $_ -ForegroundColor Red } else { Write-Host $_ -ForegroundColor Yellow } }"
