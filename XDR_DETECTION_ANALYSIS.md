# XDR Detection Functions Analysis

## Real vs Simulated Actions

| # | Detection | Real Actions | What Actually Happens |
|---|-----------|--------------|----------------------|
| 1 | PowerShell from temp | ✅ **REAL** | • Creates actual .ps1 file in C:\Windows\Temp\<br>• Executes PowerShell with encoded command<br>• Uses -ExecutionPolicy Bypass -WindowStyle Hidden flags |
| 2 | Firewall disabled | ✅ **REAL** | • Attempts to modify actual registry keys<br>• Sets EnableFirewall=0 in FirewallPolicy keys<br>• May fail without admin but triggers detection |
| 3 | Clear audit policies | ✅ **REAL** | • Executes actual auditpol.exe /clear command<br>• Attempts to clear Windows audit policies |
| 4 | Service enum from public IP | ✅ **REAL** | • Creates real TCP sockets<br>• Connects to ports 445, 139, 135<br>• Source appears as public IP (8.8.8.8) |
| 5 | Rundll32 spawns cmd | ✅ **REAL** | • Executes rundll32.exe<br>• Uses ShellExec_RunDLL to spawn cmd.exe<br>• Creates batch file that launches cmd |
| 6 | Document discovery | ✅ **REAL** | • Executes Windows find.exe command<br>• Searches for *.pdf*, *.doc*, *.xls* files<br>• Searches for "password" string |
| 7 | Registry hive save | ✅ **REAL** | • Executes reg.exe save commands<br>• Attempts to save SAM, SECURITY, SYSTEM hives<br>• Targets C:\Windows\Temp\ for output |
| 8 | PowerShell reverse shell | ✅ **REAL** | • Executes PowerShell command<br>• Creates TCP socket to port 4444<br>• Uses Net.Sockets.TcpClient |
| 9 | Rundll32 ordinal | ✅ **REAL** | • Executes rundll32.exe<br>• Uses ordinal number (#61) instead of function name<br>• References shell32.dll |
| 10 | Netcat to TOR | ✅ **REAL** | • Creates nc.exe file if not present<br>• Executes nc.exe malware.onion 80<br>• Connection will fail but command executes |
| 11 | UAC bypass | ✅ **REAL** | • Creates registry key in HKCU\Software\Classes\mscfile<br>• Executes eventvwr.exe<br>• Should spawn cmd.exe instead of mmc.exe |
| 12 | Multiple RDP | ✅ **REAL** | • Modifies actual Terminal Server registry<br>• Sets fSingleSessionPerUser=0<br>• Enables multiple RDP sessions |
| 13 | Rundll32 main | ✅ **REAL** | • Executes rundll32.exe kernel32.dll,main<br>• Uses suspicious 'main' entry point |
| 14 | Procdump lsass | ✅ **REAL** | • Downloads procdump.zip from Sysinternals<br>• Executes procdump.exe targeting lsass.exe<br>• Attempts memory dump to C:\Windows\Temp\ |
| 15 | Add admin user | ✅ **REAL** | • Creates actual user account (XDRTestUser)<br>• Executes PowerShell Add-LocalGroupMember<br>• Cleans up by deleting test user |

## Summary

**100% Real Actions** - All 15 detection functions perform actual system operations:
- Execute real processes with suspicious command lines
- Modify actual registry keys
- Create real network connections
- Access sensitive system resources
- Download and execute tools

## Why These Trigger XDR

1. **Process Behavior**: Suspicious parent-child relationships (rundll32→cmd)
2. **Command Line Analysis**: Known malicious patterns and encoded commands
3. **Registry Monitoring**: Modifications to security-critical keys
4. **Network Analysis**: Connections to suspicious ports and domains
5. **File System**: Access to sensitive files and temp directory execution
6. **API Calls**: Security-sensitive Windows API usage patterns

## Tools Downloaded/Created

- **nc.exe**: Created as stub file in System32
- **procdump.zip**: Downloaded from Sysinternals
- **PowerShell scripts**: Created in Windows\Temp
- **Batch files**: Created for rundll32 execution

All actions are designed to be detected by XDR behavioral analysis engines.
