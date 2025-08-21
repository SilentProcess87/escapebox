@echo off
echo ===================================
echo Building Escapebox (Release x64)
echo ===================================
echo.

set MSBUILD_FOUND=0
set MSBUILD_PATH=

REM Try to find MSBuild in common locations
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
    set MSBUILD_FOUND=1
    goto :found
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
    set MSBUILD_FOUND=1
    goto :found
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    set MSBUILD_FOUND=1
    goto :found
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
    set MSBUILD_FOUND=1
    goto :found
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe"
    set MSBUILD_FOUND=1
    goto :found
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe" (
    set "MSBUILD_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    set MSBUILD_FOUND=1
    goto :found
)

:found
if %MSBUILD_FOUND%==0 (
    echo ERROR: MSBuild not found. Please install Visual Studio.
    echo.
    echo Alternatively, open escapebox.sln in Visual Studio and build manually.
    pause
    exit /b 1
)

echo Found MSBuild at: %MSBUILD_PATH%
echo.

REM Clean previous build
echo Cleaning previous build...
if exist "x64\Release\escapebox.exe" del "x64\Release\escapebox.exe"

REM Build the solution
echo Building solution...
"%MSBUILD_PATH%" escapebox.sln /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /m

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED!
    echo Please check the error messages above.
    pause
    exit /b 1
)

echo.
echo ===================================
echo BUILD SUCCESSFUL!
echo ===================================
echo.
echo Output file: x64\Release\escapebox.exe
echo.
echo You can now test the application:
echo   - Start server: escapebox.exe server
echo   - Start client: escapebox.exe client 127.0.0.1 443
echo.
echo Or run the test script:
echo   - test_c2_functions.bat
echo.
pause
