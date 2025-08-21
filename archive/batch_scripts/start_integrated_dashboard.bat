@echo off
echo =====================================
echo    C2 INTEGRATED WEB DASHBOARD
echo =====================================
echo.
echo [*] This dashboard integrates with your running C2 server
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

echo [*] Starting integrated web dashboard...
python.exe c2_integrated_web_server.py

pause
