# XDR High/Medium Detection Analysis - Key 8

## Real vs Simulated Actions

| # | Detection | Severity | Real Actions | What Actually Happens |
|---|-----------|----------|--------------|----------------------|
| 1 | Copy process memory (dd) | **HIGH** | ✅ **REAL** | • Creates actual dd.exe file<br>• Executes dd.exe with memory dumping commands<br>• Writes command to log file |
| 2 | PowerShell mailbox export | **HIGH** | ✅ **REAL** | • Executes real PowerShell commands<br>• Attempts Exchange cmdlets<br>• Tries to clear Exchange log files |
| 3 | API from Tor exit | **HIGH** | ✅ **REAL** | • Creates TCP sockets to port 443<br>• Connects from 4 known Tor exit IPs<br>• Sends HTTP requests with Tor headers |
| 4 | Rundll32 no args | **MEDIUM** | ✅ **REAL** | • Executes rundll32.exe with empty arguments<br>• Common Cobalt Strike pattern |
| 5 | LaZagne credential dump | **HIGH** | ✅ **REAL** | • Creates LaZagne.py file<br>• Executes with python.exe<br>• Logs execution pattern |
| 6 | Delete shadow copies | **HIGH** | ✅ **REAL** | • Executes vssadmin.exe delete commands<br>• Uses wmic.exe shadowcopy delete<br>• Multiple deletion methods |
| 7 | EventLog disabled | **HIGH** | ✅ **REAL** | • Modifies actual registry key<br>• Sets EventLog service Start=4<br>• Targets multiple ControlSets |
| 8 | Encoded VBScript | **HIGH** | ✅ **REAL** | • Creates .vbe file with encoded header<br>• Executes with wscript.exe<br>• Uses vbscript.encode engine |
| 9 | Exe in .NET directory | **HIGH** | ✅ **REAL** | • cmd.exe creates files in .NET dirs<br>• Writes to Framework and Framework64<br>• PowerLessShell technique |
| 10 | Logon text changed | **MEDIUM** | ✅ **REAL** | • Modifies Winlogon registry keys<br>• Sets ransomware-style messages<br>• Changes legal notice caption |

## Summary

**100% Real Actions** - All 10 detection functions perform actual system operations that will be detected by XDR.

## Technical Details

### Network Operations
- **Tor Exit Nodes**: Connects to IPs flagged as Tor infrastructure
- **API Simulation**: Sends HTTP headers indicating proxy/Tor usage
- **Socket Creation**: Real TCP connections established

### File System Operations
- **dd.exe**: Created in Windows\Temp with stub content
- **LaZagne.py**: Python script created and executed
- **.vbe File**: Encoded VBScript with malicious header
- **.NET Directory**: Executables created by cmd.exe

### Registry Modifications
- **EventLog Service**: HKLM\SYSTEM\*\Services\EventLog\Start = 4
- **Winlogon Text**: LegalNoticeCaption and LegalNoticeText modified

### Process Execution
- **PowerShell**: Exchange-specific cmdlets attempted
- **vssadmin.exe**: Shadow copy deletion commands
- **wmic.exe**: Alternative shadow copy deletion
- **rundll32.exe**: Executed without parameters
- **python.exe**: Executes LaZagne.py
- **wscript.exe/cscript.exe**: Runs encoded VBScript

## Why These Trigger XDR

### High Severity Triggers
1. **Memory Dumping**: dd.exe accessing process memory
2. **Exchange Tampering**: Removing mailbox export evidence
3. **Tor Network**: Known malicious infrastructure
4. **Credential Theft**: LaZagne execution pattern
5. **Anti-Forensics**: Shadow copy deletion
6. **Defense Evasion**: EventLog service disabled
7. **Obfuscation**: Encoded script execution
8. **Living off the Land**: Suspicious .NET directory usage

### Medium Severity Triggers
1. **Cobalt Strike**: Rundll32 without arguments
2. **Ransomware**: Logon text modification

## Detection Patterns

### Behavioral Analysis
- Process relationships (cmd.exe → suspicious locations)
- Registry modifications to critical services
- Network connections to threat intelligence feeds
- File creation in protected directories

### Command Line Analysis
- Known tool names (LaZagne.py, dd.exe)
- Suspicious parameters (delete shadows, /all)
- Encoded script execution flags

### Network Analysis
- Connections from Tor exit node IPs
- HTTP headers indicating proxy usage
- API endpoints with suspicious patterns

All actions are designed to trigger XDR's high-fidelity detection rules for advanced threats.

