# EscapeBox C2 System

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows-blue" alt="Platform">
  <img src="https://img.shields.io/badge/Language-C++-orange" alt="Language">
  <img src="https://img.shields.io/badge/Purpose-Red%20Team%20%2F%20XDR%20Testing-red" alt="Purpose">
  <img src="https://img.shields.io/badge/XDR%20Alerts-25+-green" alt="XDR Alerts">
</p>

## ⚠️ Disclaimer

**This project is designed exclusively for authorized security testing, red team exercises, and XDR detection validation in controlled lab environments. Unauthorized use of this software is illegal and unethical.**

---

## 📋 Overview

EscapeBox is a Command & Control (C2) system specifically designed to trigger **Cortex XDR** detection alerts. It serves as a comprehensive testing tool for security teams to validate their XDR configurations, detection rules, and incident response procedures.

### Key Features

- **Single Executable Architecture** - Combined client/server in one EXE with no external dependencies
- **25+ XDR Detection Triggers** - Comprehensive coverage of behavioral analytics
- **Real-Time Dashboard** - Web-based monitoring interface with cyberpunk theme
- **Multi-Client Management** - Control multiple endpoints simultaneously
- **Evidence Collection** - Detailed logging for post-analysis
- **MITRE ATT&CK Mapping** - Techniques mapped to ATT&CK framework

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        EscapeBox C2 System                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐         Port 443          ┌──────────────────┐   │
│  │   C2 Server  │◄─────────────────────────►│   C2 Client(s)   │   │
│  │              │   Encrypted Protocol      │                  │   │
│  │  - Commands  │                           │  - Execution     │   │
│  │  - Dashboard │                           │  - XDR Triggers  │   │
│  │  - Logging   │                           │  - Evidence      │   │
│  └──────┬───────┘                           └──────────────────┘   │
│         │                                                           │
│         │ Port 8080                                                 │
│         ▼                                                           │
│  ┌──────────────┐                                                   │
│  │ Web Dashboard│                                                   │
│  │  - Real-time │                                                   │
│  │  - Analytics │                                                   │
│  └──────────────┘                                                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Cortex XDR Analytics Detection Coverage

EscapeBox is designed to trigger a comprehensive range of Cortex XDR behavioral analytics. The detections are organized into two main categories activated by keyboard shortcuts.

### Key 7 - Standard XDR Detection Functions (15 Alerts)

| # | Detection | MITRE ATT&CK | Description |
|---|-----------|--------------|-------------|
| 1 | **PowerShell from Temp Directory** | T1059.001 | PowerShell execution with encoded commands from `C:\Windows\Temp\` |
| 2 | **Windows Firewall Disabled** | T1562.004 | Registry modification to disable Windows Firewall |
| 3 | **Audit Policy Cleared** | T1070.001 | Execution of `auditpol.exe /clear /y` |
| 4 | **Service Enumeration from Public IP** | T1046 | Socket connections from external IP to service ports (445, 139, 135) |
| 5 | **Rundll32 Spawning Processes** | T1218.011 | Rundll32.exe spawning cmd.exe or other LOLBINs |
| 6 | **Document Discovery** | T1083 | Using `find` command to search for sensitive documents |
| 7 | **Registry Hive Extraction** | T1003.002 | Saving SAM, SECURITY, and SYSTEM hives |
| 8 | **PowerShell Reverse Shell** | T1059.001 | TCP connection to port 4444 (Metasploit default) |
| 9 | **Rundll32 with Ordinals** | T1218.011 | Rundll32 using ordinal numbers (e.g., `shell32.dll,#61`) |
| 10 | **Netcat to TOR Domains** | T1071.001 | Network tool connecting to .onion addresses |
| 11 | **UAC Bypass (Event Viewer)** | T1548.002 | Registry hijacking via mscfile association |
| 12 | **RDP Session Manipulation** | T1563.002 | Registry modification for multiple RDP sessions |
| 13 | **Rundll32 Main EntryPoint** | T1218.011 | Suspicious 'main' entry point usage |
| 14 | **LSASS Memory Dump** | T1003.001 | Using procdump to dump lsass.exe memory |
| 15 | **Admin Group Modification** | T1136.001 | PowerShell adding users to Administrators group |

### Key 8 - High/Medium Severity XDR Detection Functions (10 Alerts)

| # | Detection | Severity | MITRE ATT&CK | Description |
|---|-----------|----------|--------------|-------------|
| 1 | **Process Memory Dump (dd)** | 🔴 HIGH | T1003 | Memory dumping using dd utility |
| 2 | **Exchange Mailbox Export Cleanup** | 🔴 HIGH | T1070.001 | PowerShell removing Exchange export logs |
| 3 | **API Call from Tor Exit Node** | 🔴 HIGH | T1090.003 | Connections from known Tor exit node IPs |
| 4 | **Rundll32 No Arguments** | 🟡 MEDIUM | T1218.011 | Cobalt Strike default beacon pattern |
| 5 | **LaZagne Credential Dump** | 🔴 HIGH | T1003 | LaZagne.py execution pattern |
| 6 | **Shadow Copy Deletion** | 🔴 HIGH | T1490 | vssadmin/wmic shadow copy deletion |
| 7 | **EventLog Service Disabled** | 🔴 HIGH | T1562.002 | Registry modification to disable logging |
| 8 | **Encoded VBScript Execution** | 🔴 HIGH | T1059.005 | Execution of .vbe encoded scripts |
| 9 | **Exe in .NET Directory** | 🔴 HIGH | T1036.005 | PowerLessShell technique pattern |
| 10 | **Logon Text Changed** | 🟡 MEDIUM | T1491.001 | Ransomware-style logon message modification |

---

## 📊 Additional XDR Detection Triggers

Beyond the keyboard-activated functions, EscapeBox implements numerous real-world attack techniques:

### Credential Access
- Browser credential database extraction (Chrome, Edge, Firefox)
- WiFi password extraction via `netsh wlan export profile`
- Clipboard monitoring and capture
- LSASS memory dumping

### Persistence Mechanisms
- Registry Run key modifications
- Scheduled task creation
- Startup folder additions
- Service installation patterns

### Defense Evasion
- AMSI bypass techniques
- ETW bypass patterns
- Windows Defender disabling
- Event log clearing

### Surveillance Capabilities
- Real screenshot capture (Windows GDI)
- Keylogger with file saves
- Webcam detection
- Microphone recording patterns

### Lateral Movement
- PSExec execution patterns
- WMI remote execution
- RDP session manipulation
- SMB scanning activity

### Data Exfiltration
- HTTP-based data transfer
- DNS tunneling patterns
- File compression behavior
- Cloud upload simulation

---

## 🖥️ System Requirements

### Build Requirements
- **OS**: Windows 10/11 or Windows Server 2016+
- **Compiler**: Visual Studio 2019/2022 with C++ support
- **SDK**: Windows SDK (included with Visual Studio)

### Runtime Requirements
- **OS**: Windows 10/11 or Windows Server 2016+
- **Privileges**: Administrator (for full functionality)
- **Network**: TCP ports 443 (C2) and 8080 (Dashboard)

---

## 🚀 Quick Start Guide

### Building the Project

1. **Open Developer Command Prompt** for Visual Studio
2. Navigate to the project directory
3. Build using the provided solution:

```batch
# Using MSBuild
msbuild escapebox.sln /p:Configuration=Release /p:Platform=x64

# Or use the build script
build_all.bat
```

### Running the Server

```batch
# Start the C2 server with web dashboard
escapebox.exe server

# Dashboard accessible at http://localhost:8080
```

### Running the Client

```batch
# Connect to C2 server
escapebox.exe client <server_ip> [port]

# Example
escapebox.exe client 192.168.1.100 443

# With auto-elevation disabled
escapebox.exe client 192.168.1.100 443 --no-auto-elevate
```

---

## ⌨️ Server Keyboard Controls

Once the server is running, use these keyboard shortcuts to trigger XDR detections:

### XDR Detection Triggers
| Key | Function | Alerts |
|-----|----------|--------|
| `7` | XDR Detection Functions | 15 alerts |
| `8` | XDR High/Medium Alerts | 10 alerts |

### Attack Phase Commands
| Key | Function |
|-----|----------|
| `1` | Phase 1 - Reconnaissance |
| `2` | Phase 2 - Initial Access |
| `3` | Phase 3 - Privilege Escalation |
| `4` | Phase 4 - Lateral Movement |
| `5` | Phase 5 - Data Collection |

### Individual Commands
| Key | Function |
|-----|----------|
| `S` | Take Screenshot |
| `K` | Start Keylogger |
| `D` | Dump Keylogger Data |
| `C` | Cached Credentials |
| `U` | UAC Bypass |
| `T` | TOR Connect |
| `W` | Webcam Capture |
| `B` | Browser Credentials |
| `M` | Mimikatz/LSASS |
| `P` | Install Persistence |
| `L` | Lateral Movement |
| `E` | Exfiltrate Data |
| `R` | Ransomware Simulation |
| `N` | SSH/Netcat/Socat |

### Function Keys
| Key | Function | Key | Function |
|-----|----------|-----|----------|
| `F1` | Full System Info | `F7` | Token Stealing |
| `F2` | Process Hollowing | `F8` | SAM Dump |
| `F3` | Network Discovery | `F9` | Rootkit Install |
| `F4` | Registry Persistence | `F10` | Pass-the-Hash |
| `F5` | AMSI Bypass | `F11` | Remote Desktop |
| `F6` | ETW Bypass | `F12` | SMB Scanning |

### Utility Keys
| Key | Function |
|-----|----------|
| `H` | Display Help |
| `C` | Clear All Logs |
| `ESC` | Shutdown Server |

---

## 📁 Directory Structure

```
escapebox/
├── escapebox/
│   ├── escapebox.cpp          # Main combined client/server code
│   ├── unified_c2_server.cpp  # Standalone server implementation
│   └── c2_client.cpp          # Enhanced client module
├── archive/
│   ├── old_documentation/     # Legacy documentation
│   ├── python_servers/        # Old Python-based components
│   ├── batch_scripts/         # Startup scripts
│   └── html_dashboards/       # Old web dashboards
├── XDR_DETECTION_SUMMARY.md   # Key 7 documentation
├── XDR_HIGH_MEDIUM_SUMMARY.md # Key 8 documentation
├── XDR_DETECTION_ANALYSIS.md  # Technical analysis
├── XDR_HIGH_MEDIUM_ANALYSIS.md # High/Medium analysis
├── PROJECT_STRUCTURE.md       # Project organization
├── escapebox.sln              # Visual Studio solution
├── UnifiedC2Server.sln        # Standalone server solution
├── build_all.bat              # Build script
└── README.md                  # This file
```

---

## 📝 Log Files

All activities are logged for evidence collection and post-analysis:

| Log File | Location | Purpose |
|----------|----------|---------|
| Server Log | `C:\rat\logs\server.log` | Server activity and commands |
| Client Log | `C:\rat\logs\client.log` | Client execution details |
| Command Log | `C:\temp\c2_command_log.txt` | Command tracking |
| Attack Timeline | `C:\temp\attack_timeline.log` | XDR correlation data |
| Server Status | `C:\temp\c2_server_status.txt` | Real-time status |
| Evidence Files | `C:\evidance\[hostname]\` | Per-host evidence |

### Evidence Directory Structure
```
C:\evidance\[hostname]\
├── xdr_detection\
│   └── evidance_[session].txt    # Key 7 evidence
├── xdr_high_medium\
│   └── evidance_[session].txt    # Key 8 evidence
└── [other categories]\
```

---

## 🔍 XDR Detection Patterns Explained

### Behavioral Analysis
- **Process Relationships**: Suspicious parent-child relationships (e.g., `rundll32.exe` → `cmd.exe`)
- **Command Line Analysis**: Known malicious patterns and encoded commands
- **File System Activity**: Access to sensitive files, temp directory execution

### Network Analysis
- **Tor Exit Nodes**: Connections from known Tor infrastructure IPs
- **C2 Communication**: Encrypted protocol patterns on port 443
- **DNS Tunneling**: DGA (Domain Generation Algorithm) patterns

### Registry Monitoring
- **Security-Critical Keys**: Firewall, EventLog, Terminal Server settings
- **Persistence Locations**: Run keys, services, scheduled tasks

### Credential Access Patterns
- **LSASS Access**: Memory reading from credential process
- **Registry Hive Extraction**: SAM, SECURITY, SYSTEM saves
- **Browser Databases**: Access to Chrome, Edge, Firefox credential stores

---

## 🛡️ Security Considerations

### For Defenders
1. Ensure Cortex XDR agent is installed and running before testing
2. Configure appropriate alert thresholds
3. Review generated alerts in XDR console
4. Use evidence logs for correlation

### For Red Teams
1. Only use in authorized environments
2. Document all activities
3. Coordinate with blue team for detection validation
4. Use `--no-auto-elevate` flag when elevation is not needed

---

## 📈 Implementation Status

### ✅ Fully Implemented (33 Features)
- System Information Gathering
- Process Listing & Hollowing
- Network Configuration & Port Scanning
- Registry/Scheduled Task/Startup Persistence
- UAC Bypass & Token Stealing
- LSASS Dumping
- Windows Defender Disabling
- Event Log Clearing
- AMSI/ETW Bypass
- Keylogger with File Saves
- Browser Credential Theft
- WiFi Password Extraction
- And more...

### ⚠️ Simulated Features (16 Features)
- WMI Persistence (structure only)
- Mimikatz (returns simulated output)
- SAM Dump (pattern without extraction)
- Ransomware (simulation only)
- And others for safety reasons...

---

## 📚 Additional Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Cortex XDR Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xdr)
- [Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/)

---

## 📄 License

This project is intended for authorized security testing and educational purposes only. Use responsibly and in compliance with all applicable laws and regulations.

---

## 🤝 Contributing

Contributions to improve detection coverage or add new XDR trigger patterns are welcome. Please ensure all additions are:
- Documented with MITRE ATT&CK mappings
- Safe for use in controlled environments
- Include appropriate severity ratings

---

<p align="center">
  <strong>Built for Security Testing | Use Responsibly</strong>
</p>
