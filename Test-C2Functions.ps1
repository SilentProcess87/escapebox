# C2 Functions Testing Script
# This script provides comprehensive testing for C2 screenshot and keylogger functionality

param(
    [string]$ServerIP = "127.0.0.1",
    [int]$ServerPort = 443,
    [switch]$StartServer,
    [switch]$StartClient
)

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "     C2 COMPREHENSIVE FUNCTION TESTER" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

# Function to check if process is running
function Test-ProcessRunning {
    param([string]$ProcessName)
    $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    return $process -ne $null
}

# Function to monitor log file
function Monitor-LogFile {
    param([string]$LogPath, [string]$Pattern)
    
    if (Test-Path $LogPath) {
        $recent = Get-Content $LogPath -Tail 50 | Select-String -Pattern $Pattern
        if ($recent) {
            Write-Host "Recent log entries matching '$Pattern':" -ForegroundColor Yellow
            $recent | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
        }
    }
}

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "[WARNING] Not running as Administrator. Some features may not work properly." -ForegroundColor Yellow
    Write-Host ""
}

# 1. Check C2 Server Status
Write-Host "[1] Checking C2 Server Status..." -ForegroundColor Green
if (Test-ProcessRunning "escapebox") {
    Write-Host "    ✓ Escapebox process is running" -ForegroundColor Green
} else {
    Write-Host "    ✗ Escapebox process is NOT running" -ForegroundColor Red
    if ($StartServer) {
        Write-Host "    Starting C2 server..." -ForegroundColor Yellow
        Start-Process "escapebox.exe" -ArgumentList "server" -WindowStyle Hidden
        Start-Sleep -Seconds 3
    }
}

# 2. Test Network Connectivity
Write-Host "[2] Testing Network Connectivity..." -ForegroundColor Green
$tcpTest = Test-NetConnection -ComputerName $ServerIP -Port $ServerPort -WarningAction SilentlyContinue
if ($tcpTest.TcpTestSucceeded) {
    Write-Host "    ✓ Server is listening on ${ServerIP}:${ServerPort}" -ForegroundColor Green
} else {
    Write-Host "    ✗ Server is NOT listening on ${ServerIP}:${ServerPort}" -ForegroundColor Red
    Write-Host "    Check firewall settings or try running as Administrator" -ForegroundColor Yellow
}

# 3. Check Output Directories
Write-Host "[3] Checking Output Directories..." -ForegroundColor Green
$dirs = @(
    "C:\Windows\Temp\C2_Screenshots",
    "C:\Windows\Temp\C2_Keylogs"
)

foreach ($dir in $dirs) {
    if (Test-Path $dir) {
        $files = Get-ChildItem $dir -ErrorAction SilentlyContinue
        Write-Host "    ✓ $dir exists (${($files.Count)} files)" -ForegroundColor Green
    } else {
        Write-Host "    ✗ $dir does not exist" -ForegroundColor Yellow
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "      Created directory: $dir" -ForegroundColor Gray
    }
}

# 4. Check Activity Log
Write-Host "[4] Checking Activity Log..." -ForegroundColor Green
$logPath = "C:\Windows\Temp\c2_activity_log.txt"
if (Test-Path $logPath) {
    $logSize = (Get-Item $logPath).Length / 1KB
    Write-Host "    ✓ Activity log exists (${[math]::Round($logSize, 2)} KB)" -ForegroundColor Green
    
    # Check for recent errors
    Monitor-LogFile -LogPath $logPath -Pattern "ERROR|FAILED"
} else {
    Write-Host "    ✗ Activity log not found" -ForegroundColor Red
}

# 5. Start Client if requested
if ($StartClient) {
    Write-Host "[5] Starting C2 Client..." -ForegroundColor Green
    Start-Process "escapebox.exe" -ArgumentList "client", $ServerIP, $ServerPort -WindowStyle Minimized
    Write-Host "    Client started. Waiting for connection..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
}

# 6. Function Testing Instructions
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "     MANUAL TESTING INSTRUCTIONS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. SCREENSHOT TESTING:" -ForegroundColor Yellow
Write-Host "   - Press 'S' in the server window to trigger screenshots"
Write-Host "   - Check C:\Windows\Temp\C2_Screenshots\ for .bmp files"
Write-Host "   - Verify files are being created and have proper size"
Write-Host ""
Write-Host "2. KEYLOGGER TESTING:" -ForegroundColor Yellow
Write-Host "   - Press 'K' in the server window to start keylogger"
Write-Host "   - Type some text in any application"
Write-Host "   - Press 'D' in the server window to dump keylog data"
Write-Host "   - Check C:\Windows\Temp\C2_Keylogs\ for .txt files"
Write-Host ""
Write-Host "3. AUTOMATED PHASE TESTING:" -ForegroundColor Yellow
Write-Host "   - Press '1' for Phase 1 (Recon)"
Write-Host "   - Press '4' for Phase 4 (Surveillance - includes keylogger)"
Write-Host ""

# 7. Real-time monitoring
Write-Host "Starting real-time log monitoring..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop monitoring" -ForegroundColor Gray
Write-Host ""

# Monitor both screenshot and keylog activity
Get-Content $logPath -Tail 10 -Wait | Where-Object {
    $_ -match "SCREENSHOT|KEYLOG|ERROR|FAILED|CLIENT_DEBUG"
} | ForEach-Object {
    $timestamp = Get-Date -Format "HH:mm:ss"
    if ($_ -match "ERROR|FAILED") {
        Write-Host "[$timestamp] $_" -ForegroundColor Red
    } elseif ($_ -match "SCREENSHOT") {
        Write-Host "[$timestamp] $_" -ForegroundColor Cyan
    } elseif ($_ -match "KEYLOG") {
        Write-Host "[$timestamp] $_" -ForegroundColor Magenta
    } elseif ($_ -match "CLIENT_DEBUG") {
        Write-Host "[$timestamp] $_" -ForegroundColor Yellow
    } else {
        Write-Host "[$timestamp] $_" -ForegroundColor Gray
    }
}
