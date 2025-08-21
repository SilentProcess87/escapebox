@echo off
echo ==================================================
echo     C2 Server Test Script
echo ==================================================
echo.
echo This script will help you test the improved C2 server
echo with enhanced logging and automatic test execution.
echo.
echo [1] Build the project first:
echo     - Open escapebox.sln in Visual Studio
echo     - Build in Release mode
echo.
echo [2] Start the server:
start cmd /k "cd /d %~dp0 && escapebox\x64\Release\escapebox.exe server"
echo     Server started in new window...
echo.
timeout /t 3 >nul
echo [3] Start a client to connect:
start cmd /k "cd /d %~dp0 && escapebox\x64\Release\escapebox.exe client 127.0.0.1"
echo     Client started in new window...
echo.
echo ==================================================
echo WHAT TO EXPECT:
echo.
echo In the SERVER window, you should see:
echo - Color-coded dashboard refreshing every 15 seconds
echo - Control legend ALWAYS visible at the bottom
echo - Recent activity log showing all operations
echo - Test execution status for each connected client
echo - Clear descriptions of each attack phase being executed
echo.
echo Automated tests will run every 30 seconds including:
echo   Phase 0: Initial Compromise
echo   Phase 1: Establish Foothold
echo   Phase 2: Privilege Escalation
echo   Phase 3: Defense Evasion
echo   Phase 4: Surveillance
echo   Phase 5: Discovery
echo   Phase 6: Lateral Movement
echo   Phase 7: Collection
echo   Phase 8: Exfiltration
echo   Phase 9: Impact (Ransomware)
echo.
echo Press any key to exit this helper window...
pause >nul
