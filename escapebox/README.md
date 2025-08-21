# C2 Command & Control System - Palo Alto Networks Escape Room

## Overview
This is a demonstration C2 (Command & Control) system designed for the Palo Alto Networks Escape Room to trigger comprehensive XDR alerts. It consists of both server and client components that can be run from the same executable.

**WARNING**: This is for isolated lab environments only. Do NOT use on production systems.

## Features Fixed
1. **Display Issues** - Replaced box-drawing characters with ASCII characters for better console compatibility
2. **Server Controls** - Added keyboard controls to execute commands on all connected bots
3. **Connection Diagnostics** - Enhanced error reporting for troubleshooting connection issues
4. **Automatic Port Fallback** - Server tries port 443 first, then 8443 if unavailable
5. **Privilege Escalation** - Client includes multiple UAC bypass and privilege escalation techniques

## Usage

### Running the Server
```
escapebox.exe server
```

The server will:
- Bind to port 443 (or 8443 if 443 is unavailable)
- Display a dashboard showing connected bots
- Accept keyboard controls for remote command execution

### Running the Client
```
escapebox.exe client <server_ip> [port] [--no-auto-elevate]
```

Examples:
- `escapebox.exe client 192.168.1.100` - Connect to server at 192.168.1.100:443
- `escapebox.exe client 192.168.1.100 8443` - Connect to server at 192.168.1.100:8443
- `escapebox.exe client 192.168.1.100 443 --no-auto-elevate` - Connect without auto privilege escalation

### Server Controls

Once the server is running and clients are connected, use these keyboard controls:

| Key | Action | Description |
|-----|--------|-------------|
| ESC | Shutdown | Gracefully shutdown the C2 server |
| 1 | Phase 1 | Execute Recon & Collection on all bots |
| 2 | Phase 2 | Execute Privilege Escalation on all bots |
| 3 | Phase 3 | Execute Defense Evasion on all bots |
| 4 | Phase 4 | Execute Credential Access & Surveillance on all bots |
| 5 | Phase 5 | Execute Lateral Movement & Persistence on all bots |
| R | Ransomware | Trigger ransomware simulation on all bots |
| E | Exfiltration | Execute data exfiltration on all bots |
| P | Persistence | Install persistence mechanisms on all bots |
| C | Clear Logs | Clear Windows event logs on all bots |
| S | Screenshot | Take screenshots from all bots |
| K | Keylogger | Start keylogger on all bots |
| D | Dump Keylogs | Dump captured keylogger data from all bots |

## Connection Troubleshooting

If clients cannot connect to the server:

1. **Check Firewall** - Windows Firewall may block the connection
   ```
   netsh advfirewall set allprofiles state off
   ```
   (Run as Administrator)

2. **Verify Server is Listening**
   ```
   netstat -ano | findstr :443
   netstat -ano | findstr :8443
   ```

3. **Check Network Connectivity**
   - Ensure client can ping the server
   - Verify no network ACLs are blocking the ports

4. **Review Error Messages**
   - The client now shows specific error codes:
     - 10061 (WSAECONNREFUSED) - Server not running or port closed
     - 10060 (WSAETIMEDOUT) - Server unreachable
     - 10051 (WSAENETUNREACH) - Network unreachable
     - 10013 (WSAEACCES) - Permission denied (firewall)

## Dashboard Display

The server dashboard shows:
```
+==============================================================+
|         C2 COMMAND & CONTROL DASHBOARD - ESCAPE ROOM         |
+==============================================================+
| Active Bots: X  |  Elevated: Y  |  Beacons: Z |
+--------------------------------------------------------------+
|                        CONNECTED BOTS                        |
+--------------------------------------------------------------+
| HOSTNAME        | IP ADDRESS      | USER         | Up: Xm | LS: Ys |
+==============================================================+
|                     ATTACK INDICATORS                        |
+--------------------------------------------------------------+
| [ACTIVE] Credential Harvesting    | [ACTIVE] Lateral Movement|
| [ACTIVE] Data Exfiltration       | [ACTIVE] Persistence      |
| [ACTIVE] Process Injection       | [READY]  Ransomware       |
+==============================================================+
```

## Logs

Attack logs are saved to:
- `C:\temp\c2_server_detailed.log` - Detailed server activity
- `C:\temp\attack_timeline.log` - Timeline of attack simulation

## Building from Source

Requirements:
- Visual Studio 2022
- Windows SDK
- C++17 support

Build command:
```
msbuild escapebox.vcxproj /p:Configuration=Release /p:Platform=x64
```

## Security Notice

This tool is designed to generate realistic attack patterns for security testing and training purposes only. It should only be used in isolated lab environments with proper authorization.
