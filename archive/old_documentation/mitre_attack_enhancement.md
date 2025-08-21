# MITRE ATT&CK Enhancement Plan

## Overview
Additional MITRE ATT&CK techniques to implement for comprehensive XDR/EDR detection demonstration.

## Current Coverage vs. Proposed Additions

### 🎯 Tactics & Techniques to Add

#### 1. **Initial Access (TA0001)**
```cpp
// T1566.001 - Spearphishing Attachment
CMD_PHISHING_SIMULATE     // Simulate malicious document execution
CMD_MACRO_EXEC           // Execute VBA macro simulation

// T1078 - Valid Accounts
CMD_STOLEN_CREDS         // Attempt login with harvested credentials
CMD_PASS_SPRAY           // Password spraying attack

// T1133 - External Remote Services
CMD_VPN_ABUSE            // Simulate VPN credential abuse
```

#### 2. **Execution (TA0002)**
```cpp
// T1059.003 - Windows Command Shell (enhance existing)
CMD_CMD_OBFUSCATION      // Obfuscated cmd.exe commands

// T1106 - Native API
CMD_NATIVE_API           // Direct Windows API calls

// T1053.005 - Scheduled Task (enhance)
CMD_HIDDEN_SCHTASK       // Create hidden scheduled tasks

// T1569.002 - Service Execution
CMD_SERVICE_EXEC         // Execute via Windows service
```

#### 3. **Persistence (TA0003)**
```cpp
// T1547.001 - Registry Run Keys (expand)
CMD_HKCU_RUN            // HKEY_CURRENT_USER\...\Run
CMD_HKLM_RUN            // HKEY_LOCAL_MACHINE\...\Run
CMD_RUNONCE             // RunOnce keys

// T1543.003 - Windows Service
CMD_SERVICE_PERSIST      // Create malicious service

// T1546.003 - WMI Event Subscription
CMD_WMI_PERSIST         // WMI persistence

// T1137 - Office Application Startup
CMD_OFFICE_PERSIST      // Office startup persistence
```

#### 4. **Privilege Escalation (TA0004)**
```cpp
// T1055.001 - DLL Injection
CMD_DLL_INJECT          // Classic DLL injection

// T1134 - Access Token Manipulation
CMD_TOKEN_IMPERSONATE   // Token impersonation

// T1068 - Exploitation for Privilege Escalation
CMD_EXPLOIT_PRIVESC     // Simulate known exploit

// T1574.001 - DLL Search Order Hijacking
CMD_DLL_HIJACK          // DLL hijacking
```

#### 5. **Defense Evasion (TA0005)**
```cpp
// T1070.001 - Clear Windows Event Logs (enhance)
CMD_SELECTIVE_LOG_CLEAR  // Clear specific event IDs

// T1036 - Masquerading
CMD_PROCESS_MASQUERADE   // Rename to svchost.exe, etc.

// T1140 - Deobfuscate/Decode Files
CMD_DECODE_PAYLOAD       // Decode embedded payloads

// T1497 - Virtualization/Sandbox Evasion
CMD_VM_DETECT           // Detect VM/Sandbox
CMD_SLEEP_BYPASS        // Time-based evasion

// T1562.001 - Disable Windows Defender (enhance)
CMD_DEFENDER_EXCLUSION   // Add exclusions
CMD_DEFENDER_TAMPER     // Tamper Protection bypass

// T1112 - Modify Registry
CMD_REGISTRY_HIDE       // Hide registry keys
```

#### 6. **Credential Access (TA0006)**
```cpp
// T1003.001 - LSASS Memory (enhance)
CMD_LSASS_MINIDUMP      // Multiple dump methods

// T1555.003 - Credentials from Web Browsers (enhance)
CMD_BROWSER_COOKIES     // Steal session cookies
CMD_BROWSER_HISTORY     // Exfiltrate browsing history

// T1552.001 - Credentials In Files
CMD_CRED_FILES          // Search for credential files

// T1110 - Brute Force
CMD_RDP_BRUTE           // RDP brute force
CMD_SMB_BRUTE           // SMB brute force
```

#### 7. **Discovery (TA0007)**
```cpp
// T1082 - System Information Discovery (enhance)
CMD_DETAILED_SYSINFO    // Comprehensive system profiling

// T1083 - File and Directory Discovery
CMD_FILE_SEARCH         // Search for specific files
CMD_DIR_ENUM            // Enumerate directories

// T1012 - Query Registry
CMD_REG_ENUM            // Registry enumeration

// T1016 - System Network Configuration Discovery
CMD_NETCONFIG           // Network adapter info
CMD_ROUTE_TABLE         // Routing table

// T1049 - System Network Connections Discovery
CMD_NETSTAT             // Active connections

// T1135 - Network Share Discovery
CMD_SHARE_ENUM          // Enumerate network shares
```

#### 8. **Lateral Movement (TA0008)**
```cpp
// T1021.006 - Windows Remote Management
CMD_WINRM_EXEC          // WinRM execution

// T1021.002 - SMB/Windows Admin Shares
CMD_ADMIN_SHARE         // C$, ADMIN$ access

// T1570 - Lateral Tool Transfer
CMD_TOOL_TRANSFER       // Copy tools to remote systems

// T1080 - Taint Shared Content
CMD_SHARE_BACKDOOR      // Backdoor shared folders
```

#### 9. **Collection (TA0009)**
```cpp
// T1005 - Data from Local System
CMD_DOC_HARVEST         // Harvest documents
CMD_DB_SEARCH           // Search databases

// T1025 - Data from Removable Media
CMD_USB_COLLECT         // Collect from USB drives

// T1074 - Data Staged
CMD_STAGE_DATA          // Stage data for exfil

// T1560 - Archive Collected Data
CMD_ZIP_DATA            // Compress collected data
CMD_RAR_DATA            // RAR with password
```

#### 10. **Command and Control (TA0011)**
```cpp
// T1071.001 - Web Protocols (enhance)
CMD_HTTPS_C2            // HTTPS with cert pinning

// T1132 - Data Encoding
CMD_BASE64_C2           // Base64 encoded comms
CMD_XOR_C2              // XOR encrypted comms

// T1573 - Encrypted Channel
CMD_AES_C2              // AES encrypted C2

// T1105 - Ingress Tool Transfer
CMD_DOWNLOAD_TOOL       // Download additional tools

// T1104 - Multi-Stage Channels
CMD_MULTI_C2            // Multiple C2 channels
```

#### 11. **Exfiltration (TA0010)**
```cpp
// T1048 - Exfiltration Over Alternative Protocol
CMD_ICMP_EXFIL          // ICMP tunneling
CMD_DNS_TXT_EXFIL       // DNS TXT records

// T1567 - Exfiltration Over Web Service
CMD_CLOUD_EXFIL         // Upload to cloud services
CMD_PASTEBIN_EXFIL      // Exfiltrate to pastebin

// T1029 - Scheduled Transfer
CMD_TIMED_EXFIL         // Scheduled exfiltration
```

#### 12. **Impact (TA0040)**
```cpp
// T1486 - Data Encrypted for Impact
CMD_RANSOMWARE_SIM      // Ransomware simulation
CMD_WALLPAPER_CHANGE    // Change wallpaper

// T1490 - Inhibit System Recovery
CMD_SHADOW_DELETE       // Delete shadow copies
CMD_RECOVERY_DISABLE    // Disable recovery options

// T1489 - Service Stop
CMD_SERVICE_STOP        // Stop critical services
CMD_PROCESS_KILL        // Kill security processes

// T1529 - System Shutdown/Reboot
CMD_SHUTDOWN            // Shutdown with message
```

## Implementation Priority

### High Priority (Maximum Detection Value)
1. **T1055** - Process Injection techniques
2. **T1003** - Credential Dumping variations
3. **T1486** - Ransomware simulation
4. **T1070** - Log clearing and anti-forensics
5. **T1036** - Process masquerading
6. **T1083** - File discovery and enumeration
7. **T1567** - Cloud exfiltration

### Medium Priority (Common in Real Attacks)
1. **T1547** - Additional persistence methods
2. **T1082** - Enhanced system discovery
3. **T1110** - Brute force attacks
4. **T1021** - Additional lateral movement
5. **T1074** - Data staging
6. **T1132** - C2 encoding techniques

### Low Priority (Good for Completeness)
1. **T1497** - VM/Sandbox detection
2. **T1137** - Office persistence
3. **T1025** - USB collection
4. **T1104** - Multi-stage C2

## Dashboard Integration

### MITRE ATT&CK Matrix View
Create a new dashboard page showing:
- Full MITRE ATT&CK matrix
- Techniques light up in real-time as they're executed
- Color coding: 
  - 🟢 Green: Attempted
  - 🟡 Yellow: In Progress  
  - 🔴 Red: Successfully Executed
  - ⚫ Gray: Not Attempted

### Technique Details Panel
When clicking on a technique:
- Show execution timestamp
- Display which bot executed it
- Show detection status
- Link to relevant logs/artifacts

## Code Structure

```cpp
// New command categories in escapebox.cpp
enum AdvancedCommands {
    // Process Manipulation
    CMD_DLL_INJECT = 0x100,
    CMD_PROCESS_HOLLOW_ADVANCED,
    CMD_PROCESS_DOPPELGANG,
    
    // Advanced Persistence
    CMD_COM_HIJACK = 0x110,
    CMD_SIP_PROVIDER,
    CMD_APPINIT_DLL,
    
    // Anti-Forensics
    CMD_TIMESTOMP = 0x120,
    CMD_USN_DELETE,
    CMD_PREFETCH_DELETE,
    
    // Advanced Discovery
    CMD_LDAP_ENUM = 0x130,
    CMD_BLOODHOUND_SIM,
    CMD_AD_ENUM,
    
    // Ransomware Simulation
    CMD_RANSOM_PREP = 0x140,
    CMD_RANSOM_ENCRYPT,
    CMD_RANSOM_NOTE
};
```

## Expected Detection Results

With these additions, you should trigger alerts in:
- **EDR**: Process injection, API hooking, abnormal process behavior
- **SIEM**: Unusual network patterns, authentication anomalies
- **XDR**: Cross-domain correlation of tactics
- **UEBA**: Behavioral anomalies in user actions
- **DLP**: Data staging and exfiltration attempts

## Safety Considerations

All implementations should:
1. Use simulation/demonstration code only
2. Create reversible changes
3. Log all actions for analysis
4. Include safeguards against accidental damage
5. Require explicit confirmation for destructive actions

This enhancement would provide comprehensive coverage of the MITRE ATT&CK framework and truly make it "light up like a Christmas tree" in any modern security platform!
