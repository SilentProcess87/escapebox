# XDR High/Medium Detection Functions - Key 8

## Overview
The XDR high/medium detection functions (bound to key '8') implement 10 specific behaviors designed to trigger high and medium severity XDR alerts. Each function performs real actions that match known malicious patterns.

## Implementation Details

### 1. Copy Process Memory File (dd utility)
- **Action**: Creates dd.exe and simulates memory dumping
- **Commands**: 
  - `dd.exe if=/proc/self/mem of=C:\Windows\Temp\memory.dmp`
  - `dd.exe if=\Device\PhysicalMemory of=C:\Windows\Temp\proc_mem.dmp`
- **Detection**: Process memory dumping using dd utility

### 2. PowerShell Removing Mailbox Export Logs
- **Action**: Exchange-specific PowerShell commands to remove export logs
- **Commands**:
  - `Remove-MailboxExportRequest -Confirm:$false`
  - `Get-MailboxExportRequest | Remove-MailboxExportRequest`
  - `Clear-Content -Path 'C:\Program Files\Microsoft\Exchange Server\V15\Logging\*export*.log'`
- **Detection**: Cleanup of Exchange mailbox export evidence

### 3. API Call from Tor Exit Node
- **Action**: Simulates API calls from known Tor exit node IPs
- **IPs Used**: 185.220.101.45, 23.129.64.190, 198.98.51.104, 45.142.114.231
- **Headers**: X-Forwarded-For, X-Originating-IP with Tor exit IPs
- **Detection**: Network traffic from known Tor infrastructure

### 4. Rundll32 with No Arguments
- **Action**: Executes rundll32.exe without any command-line parameters
- **Pattern**: Cobalt Strike default configuration behavior
- **Detection**: Anomalous rundll32 execution pattern

### 5. Credential Dumping via LaZagne
- **Action**: Creates and executes LaZagne.py credential dumper
- **Commands**:
  - `python.exe C:\Windows\Temp\LaZagne.py all`
  - Creates LaZagne.py file with stub content
- **Detection**: Known credential dumping tool execution

### 6. Delete Windows Shadow Copies
- **Action**: Multiple methods to delete VSS shadow copies
- **Commands**:
  - `vssadmin.exe delete shadows /all /quiet`
  - `wmic.exe shadowcopy delete`
  - `vssadmin.exe delete shadows /for=C: /all`
- **Detection**: Ransomware/wiper behavior pattern

### 7. EventLog Service Disabled
- **Action**: Disables Windows EventLog service via registry
- **Registry**: `HKLM\SYSTEM\CurrentControlSet\Services\EventLog`
- **Value**: Start=4 (Disabled)
- **Detection**: Defense evasion by disabling logging

### 8. Encoded VBScript Execution
- **Action**: Creates and executes encoded VBScript (.vbe)
- **File**: Creates malicious.vbe with encoded header
- **Commands**:
  - `wscript.exe C:\Windows\Temp\malicious.vbe //B //NoLogo`
  - `cscript.exe //E:vbscript.encode C:\Windows\Temp\malicious.vbe`
- **Detection**: Obfuscated script execution

### 9. Suspicious Executable in .NET Directory
- **Action**: cmd.exe creates executables in .NET Framework directories
- **Locations**:
  - `C:\Windows\Microsoft.NET\Framework\v4.0.30319\evil.exe`
  - `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\update.exe`
- **Detection**: PowerLessShell technique pattern

### 10. Windows Logon Text Changed
- **Action**: Modifies Windows logon legal notice (ransomware pattern)
- **Registry**: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
- **Values**:
  - LegalNoticeCaption: "SYSTEM COMPROMISED"
  - LegalNoticeText: "Your files have been encrypted! Contact evil@ransom.com"
- **Detection**: Ransomware notification behavior

## Evidence Collection
All activities are logged to:
- Console output with numbered progress indicators [1/10] through [10/10]
- Client logs: `C:\rat\logs\client.log`
- Evidence file: `C:\evidance\[hostname]\xdr_high_medium\evidance_[session].txt`

## Expected Severity Levels
- **High Severity (7 alerts)**: #1, #2, #3, #5, #6, #7, #8, #9
- **Medium Severity (3 alerts)**: #4, #10

## Usage
1. Start the C2 server
2. Connect a client
3. Press '8' on the server console
4. All 10 high/medium detection functions will execute automatically
5. Check XDR console for triggered alerts

## Differences from Key 7
- Key 7: Focuses on general XDR detection patterns (15 alerts)
- Key 8: Focuses on high/medium severity patterns (10 alerts)
- Key 8 includes more advanced techniques like memory dumping, Tor exit nodes, and Exchange-specific attacks

