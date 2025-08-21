@echo off
echo ====================================================
echo     C2 WEBSOCKET DASHBOARD - REAL-TIME CONTROL
echo ====================================================
echo.
echo [*] This dashboard provides real-time updates via WebSocket
echo [*] Make sure escapebox.exe is running in server mode!
echo.

REM Check if escapebox is running
tasklist /FI "IMAGENAME eq escapebox.exe" 2>NUL | find /I /N "escapebox.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo [+] C2 server detected - Good!
) else (
    echo [!] WARNING: escapebox.exe not running!
    echo [!] Start the C2 server first: escapebox.exe
    echo.
)

echo [*] Installing required Python packages...
python.exe -m pip install websockets --quiet

echo.
echo [*] Starting WebSocket-enhanced dashboard...
echo [*] Dashboard will be available at: http://localhost:8080
echo [*] WebSocket server on: ws://localhost:8081
echo.

python.exe c2_websocket_server.py

pause
