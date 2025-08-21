# Real vs Simulated Techniques - XDR Detection Analysis

## ✅ REAL Techniques That WILL Trigger XDR/EDR

### 1. **Process Injection (T1055.001)** - REAL
```cpp
// This ACTUALLY injects into processes
- VirtualAllocEx() - Allocates memory in target process
- WriteProcessMemory() - Writes to process memory
- CreateRemoteThread() - Creates thread in target process
```
**XDR Alert**: Process injection detected, suspicious cross-process activity

### 2. **Event Log Clearing (T1070.001)** - REAL
```cpp
// This ACTUALLY clears Windows logs
- wevtutil cl Security
- wevtutil cl System
- sc stop eventlog
```
**XDR Alert**: Security log cleared, anti-forensic activity detected

### 3. **Registry Persistence (T1547.001)** - REAL
```cpp
// This ACTUALLY modifies registry
- reg add HKLM\...\Run
- reg add HKCU\...\Run
```
**XDR Alert**: Registry Run key modification, persistence mechanism detected

### 4. **File Discovery (T1083)** - REAL
```cpp
// This ACTUALLY scans the file system
- FindFirstFile/FindNextFile
- Searches for *.doc*, *password*, etc.
```
**XDR Alert**: Suspicious file system enumeration, data discovery

### 5. **System Discovery (T1082)** - REAL
```cpp
// This ACTUALLY queries system info
- systeminfo
- wmic computersystem get *
- wmic process list
```
**XDR Alert**: Extensive system enumeration, reconnaissance activity

### 6. **Credential Access Attempts (T1110)** - REAL
```cpp
// This ACTUALLY attempts authentication
- net use \\localhost\IPC$ /user:x password
- RDP connection attempts
```
**XDR Alert**: Brute force attempts, failed authentication spike

### 7. **Process Masquerading (T1036.005)** - REAL
```cpp
// This ACTUALLY creates deceptive processes
- Copies exe to Windows dir
- Names it svchost.exe
- Starts the process
```
**XDR Alert**: Suspicious svchost.exe, process impersonation

## ⚠️ PARTIALLY Real (Safe Demonstrations)

### 1. **Ransomware Simulation (T1486)** - PARTIAL
```cpp
// Real Actions:
- Creates files in C:\Windows\Temp\RansomTest
- Renames files to .ENCRYPTED
- Creates ransom note
// Simulated:
- No actual encryption
- No real data destruction
```
**XDR Alert**: File mass-renaming, ransomware behavior pattern

### 2. **DLL Hijacking (T1574.001)** - PARTIAL
```cpp
// Real Actions:
- Creates fake DLL files
- Starts legitimate processes
// Simulated:
- DLL contains no malicious code
- Just triggers the detection
```
**XDR Alert**: DLL search order hijacking attempt

## ❌ Techniques We Should Make MORE Real

### Current Implementation Issues:
1. **LSASS Dump** - Currently using commands, should use direct API
2. **Browser Credential Theft** - Currently copies files, should use DPAPI
3. **Process Hollowing** - Current implementation needs enhancement

## 🔧 Making Them More Real

Let me show you how to make the critical ones TRULY real:
