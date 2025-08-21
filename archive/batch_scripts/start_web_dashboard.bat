@echo off
echo =====================================
echo    C2 WEB DASHBOARD LAUNCHER
echo =====================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python is not installed or not in PATH
    echo [!] Please install Python 3.x from python.org
    pause
    exit /b 1
)

echo [*] Starting C2 Web Dashboard Server...
echo [*] Dashboard will be available at: http://localhost:8080
echo [*] Make sure escapebox.exe server is running!
echo.
echo [*] Press Ctrl+C to stop the web server
echo =====================================
echo.

cd /d "%~dp0"
python quick_web_server.py

pause
