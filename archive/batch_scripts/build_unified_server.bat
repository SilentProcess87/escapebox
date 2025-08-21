@echo off
echo ================================================================
echo           BUILDING C2 UNIFIED SERVER - SINGLE EXE
echo ================================================================
echo.
echo This will create a single executable with all features embedded:
echo   ✓ C2 Server (port 443)
echo   ✓ Web Server (port 8080) 
echo   ✓ Dashboard (embedded HTML)
echo   ✓ Real data analytics
echo   ✓ Surveillance capabilities
echo   ✓ No external dependencies
echo.

REM Check for Visual Studio
where cl >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Visual Studio compiler (cl.exe) not found
    echo.
    echo Please install Visual Studio 2019/2022 with C++ support or run from:
    echo   - Developer Command Prompt for VS
    echo   - Visual Studio x64 Native Tools Command Prompt
    echo.
    pause
    exit /b 1
)

REM Check for required files
if not exist "c2_unified_server.cpp" (
    echo [ERROR] c2_unified_server.cpp not found
    echo Please ensure the unified server source file is in this directory
    pause
    exit /b 1
)

echo [*] Compiling C2 Unified Server...
echo.

REM Compile with all necessary libraries and optimizations
cl.exe /EHsc /O2 /MT /DNDEBUG ^
    c2_unified_server.cpp ^
    /link ^
    ws2_32.lib ^
    psapi.lib ^
    shell32.lib ^
    winhttp.lib ^
    gdiplus.lib ^
    strmiids.lib ^
    ole32.lib ^
    user32.lib ^
    gdi32.lib ^
    /OUT:c2_unified_server.exe ^
    /SUBSYSTEM:CONSOLE

if errorlevel 1 (
    echo.
    echo [ERROR] Compilation failed
    echo Check the error messages above
    pause
    exit /b 1
)

echo.
echo [SUCCESS] C2 Unified Server compiled successfully!
echo.

REM Clean up intermediate files
if exist "c2_unified_server.obj" del "c2_unified_server.obj"

REM Check file size
for %%A in (c2_unified_server.exe) do (
    set size=%%~zA
    set /a size_mb=!size!/1024/1024
)

echo Output file: c2_unified_server.exe
echo File size: %size% bytes (~%size_mb% MB)
echo.

REM Test if executable works
echo [*] Testing executable...
c2_unified_server.exe /? >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Executable test failed, but file was created
) else (
    echo [SUCCESS] Executable test passed
)

echo.
echo ================================================================
echo                 BUILD COMPLETED SUCCESSFULLY
echo ================================================================
echo.
echo Your single executable is ready: c2_unified_server.exe
echo.
echo To run the server:
echo   c2_unified_server.exe
echo.
echo Features included in this single EXE:
echo   ✓ Complete C2 server functionality
echo   ✓ Embedded web dashboard (no external HTML files needed)
echo   ✓ Real-time analytics and surveillance
echo   ✓ Client management and command execution
echo   ✓ All libraries statically linked
echo.
echo Dashboard will be available at: http://localhost:8080
echo C2 server will listen on: port 443
echo.
choice /C YN /M "Run the server now"
if errorlevel 2 goto :end

echo.
echo [*] Starting C2 Unified Server...
c2_unified_server.exe

:end
echo.
echo Build script completed.
pause