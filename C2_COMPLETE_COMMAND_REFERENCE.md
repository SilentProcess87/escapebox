# C2 Server - Complete Command Reference

## Overview
This document provides a comprehensive reference for all available commands in the C2 (Command and Control) server system. Commands can be executed through:
1. **CLI Keyboard Shortcuts** - Direct keyboard input in the server console
2. **Web Dashboard** - HTTP API at `http://localhost:9999/c2_dashboard_complete.html`
3. **Direct Socket Commands** - For programmatic access

## Quick Access

### Web Dashboard URLs
- **Complete Dashboard**: `http://localhost:9999/c2_dashboard_complete.html`
- **Classic Dashboard**: `http://localhost:9999/c2_dashboard.html`
- **API Endpoint**: `http://localhost:9999/api/command`

### Help Menu
Press `H` in the server console to display keyboard shortcuts.

## Command Categories

### 1. Discovery & Reconnaissance

| Command | Hex Code | CLI Key | Web Command | Description |
|---------|----------|---------|-------------|-------------|
| System Info | 0x10 | F1 | SYSINFO | Collects comprehensive system information |
| Process List | 0x11 | F1 | PROCESS_LIST | Lists all running processes |
| Network Config | 0x12 | F1 | NETWORK_CONFIG | Enumerates network interfaces and connections |
| User Enumeration | 0x13 | F1 | USER_ENUM | Lists local and domain users |
| Domain Info | 0x14 | F1 | DOMAIN_INFO | Gathers Active Directory information |
| Software Inventory | 0x15 | F1 | SOFTWARE_ENUM | Lists installed software |

### 2. Collection & Surveillance

| Command | Hex Code | CLI Key | Web Command | Description |
|---------|----------|---------|-------------|-------------|
| Screenshot | 0x20 | S | SCREENSHOT | Captures desktop screenshot |
| Keylogger Start | 0x21 | K | KEYLOG:START | Starts keystroke logging |
| Keylogger Dump | 0x22 | D | KEYLOG:DUMP | Retrieves captured keystrokes |
| Clipboard | 0x23 | F4 | CLIPBOARD | Captures clipboard contents |
| Browser Credentials | 0x24 | B | BROWSER_CREDS | Extracts saved browser passwords |
| File Search | 0x25 | F5 | FILE_SEARCH | Searches for sensitive files |
| Webcam Capture | 0x26 | W | WEBCAM:CAPTURE | Takes webcam snapshot |
| Microphone Record | 0x27 | F3 | MIC:RECORD:START | Records audio from microphone |
| Screen Recording | 0x28 | F6 | SCREEN_RECORD | Records desktop activity |

### 3. Command Execution

| Command | Hex Code | CLI Key | Web Command | Description |
|---------|----------|---------|-------------|-------------|
| Shell Execute | 0x30 | - | SHELL_EXEC | Executes system commands |
| PowerShell | 0x31 | - | POWERSHELL | Runs PowerShell commands |
| Process Injection | 0x32 | F2 | INJECT_PROCESS | Injects code into processes |
| Load Module | 0x33 | - | - | Loads additional payloads |
| Process Migration | 0x34 | - | - | Migrates to another process |
| Reverse Shell | 0x35 | - | REVERSE_SHELL | Establishes reverse shell |
| Remote Desktop | 0x36 | F12 | REMOTE_DESKTOP | Enables RDP access |

### 4. Persistence Mechanisms

| Command | Hex Code | CLI Key | Web Command | Description |
|---------|----------|---------|-------------|-------------|
| Install Service | 0x40 | P | INSTALL_SERVICE | Creates malicious service |
| Registry Persistence | 0x41 | P | REGISTRY_PERSIST | Adds registry autostart |
| Scheduled Task | 0x42 | P | SCHEDULED_TASK | Creates scheduled task |
| WMI Persistence | 0x43 | - | WMI_PERSIST | WMI event subscription |
| Startup Folder | 0x44 | - | STARTUP_FOLDER | Adds to startup folder |
| Bootkit Install | 0x45 | - | BOOTKIT_INSTALL | Installs boot-level persistence |

### 5. Lateral Movement

| Command | Hex Code | CLI Key | Web Command | Description |
|---------|----------|---------|-------------|-------------|
| Port Scan | 0x50 | L | PORT_SCAN | Scans internal network |
| SMB Scan | 0x51 | L | SMB_SCAN | Enumerates SMB shares |
| PsExec | 0x52 | L | PSEXEC | Remote execution via PsExec |
| WMI Exec | 0x53 | - | WMI_EXEC | WMI-based remote execution |
| RDP Exec | 0x54 | - | RDP_EXEC | RDP-based lateral movement |
| Pass the Hash | 0x55 | - | PASS_THE_HASH | PTH authentication attack |
| Mimikatz | 0x56 | M | MIMIKATZ | Credential extraction |

### 6. Privilege Escalation

| Command | Hex Code | CLI Key | Web Command | Description |
|---------|----------|---------|-------------|-------------|
| UAC Bypass | 0x60 | 2 | UAC_BYPASS | Bypasses User Account Control |
| Token Stealing | 0x61 | F7 | TOKEN_STEAL | Steals security tokens |
| Exploit Suggester | 0x62 | - | EXPLOIT_SUGGESTER | Suggests privilege escalation |
| LSASS Dump | 0x63 | M | LSASS_DUMP | Dumps LSASS memory |
| SAM Dump | 0x64 | F8 | SAM_DUMP | Extracts SAM database |

### 7. Defense Evasion

| Command | Hex Code | CLI Key | Web Command | Description |
|---------|----------|---------|-------------|-------------|
| Disable AV | 0x70 | A | DISABLE_AV | Disables antivirus |
| Clear Logs | 0x71 | C | CLEAR_LOGS | Clears event logs |
| Timestomp | 0x72 | - | TIMESTOMP | Modifies file timestamps |
| Process Hollowing | 0x73 | F2 | PROCESS_HOLLOW | Process hollowing technique |
| Rootkit Install | 0x74 | F9 | ROOTKIT_INSTALL | Installs kernel rootkit |
| AMSI Bypass | 0x75 | A | AMSI_BYPASS | Bypasses AMSI scanning |
| ETW Disable | 0x76 | A | ETW_DISABLE | Disables ETW logging |

### 8. Data Exfiltration

| Command | Hex Code | CLI Key | Web Command | Description |
|---------|----------|---------|-------------|-------------|
| Stage Files | 0x80 | E | STAGE_FILES | Prepares files for exfil |
| Compress Data | 0x81 | E | COMPRESS_DATA | Compresses staged data |
| Exfil HTTP | 0x82 | E | EXFIL_HTTP | Exfiltrates via HTTP |
| Exfil DNS | 0x83 | E | EXFIL_DNS | DNS tunneling exfiltration |
| Exfil ICMP | 0x84 | - | EXFIL_ICMP | ICMP tunneling |
| Exfil Email | 0x85 | - | EXFIL_EMAIL | Email-based exfiltration |
| Cloud Upload | 0x86 | F11 | CLOUD_UPLOAD | Uploads to cloud storage |

### 9. Impact

| Command | Hex Code | CLI Key | Web Command | Description |
|---------|----------|---------|-------------|-------------|
| Ransomware | 0x90 | R | RANSOMWARE | Deploys ransomware simulation |
| Wipe Disk | 0x91 | - | WIPE_DISK | Disk wiping simulation |
| Corrupt Boot | 0x92 | - | CORRUPT_BOOT | Boot sector corruption |
| Crypto Miner | 0x93 | F10 | CRYPTO_MINER | Deploys cryptocurrency miner |

### 10. Advanced Network Evasion (XDR Detection)

| Command | Hex Code | CLI Key | Web Command | Description |
|---------|----------|---------|-------------|-------------|
| TOR Connect | 0xA0 | T | TOR_CONNECT | Establishes TOR connections |
| TOR API Call | 0xA1 | T | TOR_API_CALL | API calls via TOR exit nodes |
| Reverse SSH | 0xA2 | N | REVERSE_SSH | Creates reverse SSH tunnels |
| Netcat Tunnel | 0xA3 | N | NETCAT_TUNNEL | Netcat-based tunneling |
| Socat Relay | 0xA4 | N | SOCAT_RELAY | Socat relay connections |

## Attack Phases

The server supports automated attack phases that execute multiple commands in sequence:

### Phase 1: Reconnaissance (Key: 1)
- System Information
- Process List
- Network Configuration
- File Search

### Phase 2: Privilege Escalation (Key: 2)
- UAC Bypass
- Token Stealing
- Exploit Suggester

### Phase 3: Defense Evasion (Key: 3)
- Disable AV
- AMSI Bypass
- ETW Disable
- Clear Logs
- Timestomp
- TOR connections

### Phase 4: Surveillance (Key: 4)
- Screenshot
- Keylogger Start
- Browser Credentials
- Webcam Capture

### Phase 5: Discovery (Key: 5)
- User Enumeration
- Domain Information
- Software Enumeration

### Phase 6: Lateral Movement
- Port Scan
- SMB Scan
- PsExec

### Phase 7: Collection
- Screenshot
- Keylogger Dump
- File Search

### Phase 8: Exfiltration
- Compress Data
- Exfil HTTP
- Exfil DNS

### Phase 9: Impact
- Ransomware
- Crypto Miner

## Web API Usage

### Send Command to All Bots
```bash
curl -X POST http://localhost:9999/api/command \
  -H "Content-Type: application/json" \
  -d '{"clientId": "all", "command": "SCREENSHOT"}'
```

### Send Command to Specific Bot
```bash
curl -X POST http://localhost:9999/api/command \
  -H "Content-Type: application/json" \
  -d '{"clientId": "BOT-001", "command": "SYSINFO"}'
```

### Get Status
```bash
curl http://localhost:9999/api/status
```

### Get Activity Log
```bash
curl http://localhost:9999/api/activity
```

## Special Features

### Real Network Traffic (XDR Detection)
The following commands generate **real network traffic** with fake data to trigger XDR detections:
- **TOR_CONNECT**: Actual TCP connections to TOR nodes
- **TOR_API_CALL**: Real HTTP/HTTPS requests to Telegram, Discord, Pastebin APIs with fake data

### Keyboard Shortcuts Summary
- **ESC**: Shutdown server
- **H**: Show help menu
- **1-5**: Execute attack phases
- **A-Z**: Individual commands (see tables above)
- **F1-F12**: Special functions

## Security Notice

⚠️ **WARNING**: This system is designed for isolated lab environments only. It will generate comprehensive security alerts and should never be used in production environments.

## Troubleshooting

### Commands Not Working
1. Ensure the server is running: `escapebox.exe server`
2. Check if clients are connected: Look for "NEW_BOT" entries in logs
3. Verify the web dashboard is accessible at port 9999
4. For TOR commands, ensure outbound connections are allowed

### Web Dashboard Issues
1. Check if port 9999 is available
2. Try the direct API endpoints instead of the dashboard
3. Check browser console for JavaScript errors

### Client Connection Issues
1. Verify firewall settings allow port 443/8443
2. Run server with admin privileges for full functionality
3. Check if another process is using the C2 ports
