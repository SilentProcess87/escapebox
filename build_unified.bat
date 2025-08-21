@echo off
echo ============================================
echo Unified C2 Server - Build Script
echo ============================================
echo.

REM Check if running from VS Developer Command Prompt
where msbuild >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] MSBuild not found!
    echo Please run this script from "Developer Command Prompt for VS 2022"
    echo.
    echo To open it:
    echo 1. Press Windows key
    echo 2. Type "Developer Command Prompt"
    echo 3. Select "Developer Command Prompt for VS 2022"
    echo.
    pause
    exit /b 1
)

echo [*] Cleaning previous builds...
if exist x64 rmdir /s /q x64
if exist Win32 rmdir /s /q Win32

echo.
echo [*] Building Unified C2 Server (Release x64)...
msbuild UnifiedC2Server.sln /p:Configuration=Release /p:Platform=x64 /m /nologo /verbosity:minimal

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo.
echo ============================================
echo BUILD SUCCESSFUL!
echo ============================================
echo.
echo Executable location: x64\Release\UnifiedC2Server.exe
echo.
echo To run the server:
echo   cd x64\Release
echo   UnifiedC2Server.exe
echo.
echo The server will start:
echo   - C2 Server on port 443
echo   - Web Dashboard on http://localhost:8080
echo   - WebSocket API on ws://localhost:8081
echo.
pause

