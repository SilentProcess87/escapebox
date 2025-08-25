# C2 Behaviors Analysis - Real vs Simulated Functions

## Comprehensive Analysis Table

| Behavior | Real/Simulated | Specific Actions | Detection Impact |
|----------|----------------|------------------|------------------|
| **1. DNS Tunneling** | ✅ **REAL** | • `gethostbyname()` performs actual DNS lookups<br>• 100 queries with 63-char subdomains<br>• Queries to: .dns-tunnel.evil.com, .exfiltrate.malware.tk, etc.<br>• Also queries TXT records | **HIGH** - Real DNS traffic will be seen by DNS servers, firewalls, and XDR |
| **2. DGA (Domain Generation)** | ✅ **REAL** | • `gethostbyname()` for actual DNS resolution<br>• Creates real TCP sockets with `socket()`<br>• Attempts `connect()` to IP 185.220.101.45:443<br>• 200 domains with 3 patterns (Conficker/Cryptolocker/Necurs style) | **HIGH** - Both DNS queries and TCP SYN packets are generated |
| **3. Rare IP Communications** | ✅ **REAL** | • Creates real TCP sockets<br>• `connect()` to 10 IPs on various ports<br>• `send()` transmits 1KB of data including hostname/username<br>• `recv()` attempts to receive responses<br>• 5 connections per IP = 50 total connections | **CRITICAL** - Actual data exfiltration traffic with payload |
| **4. Meterpreter Backdoor** | ✅ **REAL** | • Creates TCP sockets to 4 IPs × 9 ports<br>• `connect()` establishes connections<br>• `send()` transmits real Meterpreter packet structure<br>• Sends commands: sysinfo, getuid, ps, netstat, hashdump | **CRITICAL** - Real Meterpreter protocol will trigger backdoor alerts |
| **5. HTTP C2 Beaconing** | ✅ **REAL** | • Creates TCP sockets on port 80<br>• `connect()` to 5 C2 servers<br>• `send()` full HTTP POST requests with:<br>&nbsp;&nbsp;- Suspicious headers (X-Malware-ID: CARBANAK_v4.5)<br>&nbsp;&nbsp;- 4KB encrypted payload<br>• 20 beacons × 5 servers = 100 requests | **CRITICAL** - Complete HTTP traffic with malware signatures |
| **6. DNS Flood** | ✅ **REAL** | • `gethostbyname()` for 500 domains<br>• 5 patterns: exfiltration, botnet, cryptominer, ransomware, C2<br>• Also queries MX and TXT records (×3 queries per domain)<br>• Total: 1,500 DNS queries in rapid succession | **HIGH** - Massive DNS traffic spike will trigger DDoS/flood alerts |
| **7. Process Injection Indicators** | ✅ **REAL** | • `CreateNamedPipeA()` creates actual named pipes:<br>&nbsp;&nbsp;- \\.\pipe\evil<br>&nbsp;&nbsp;- \\.\pipe\malware_comm<br>&nbsp;&nbsp;- \\.\pipe\cobalt_strike_beacon<br>&nbsp;&nbsp;- \\.\pipe\meterpreter_[random] | **HIGH** - Named pipes are real OS objects visible to security tools |
| **8. Suspicious Windows APIs** | ✅ **REAL** | • `VirtualAlloc()` with PAGE_EXECUTE_READWRITE (RWX memory)<br>• `CreateToolhelp32Snapshot()` enumerates processes<br>• `RegOpenKeyExA()` accesses Run key<br>• `OpenProcessToken()` for privilege manipulation | **CRITICAL** - These APIs are monitored by EDR/XDR for injection patterns |
| **9. Netcat Activity** | ✅ **REAL** | • Creates TCP socket<br>• `connect()` to 192.168.1.100:4444<br>• Connection attempt is real (even if target doesn't exist) | **MEDIUM** - Real connection attempt to common backdoor port |
| **10. Reverse SSH Tunnels** | ✅ **REAL** | • Creates TCP sockets<br>• `connect()` to 3 targets on ports 2222, 443, 8022<br>• `send()` transmits "SSH-2.0-OpenSSH_7.4\r\n" banner<br>• Falls back to IP 45.142.114.231 | **HIGH** - SSH protocol banner on non-standard ports is suspicious |
| **11. Process Connection Logs** | ❌ **SIMULATED** | • Only calls `logClientActivity()`<br>• Prints messages claiming PowerShell/certutil/rundll32/WINWORD connections<br>• No actual network activity from these processes | **LOW** - Only appears in local logs, no network traffic |
| **12. Rare Domain Beaconing** | ✅ **REAL** | • Creates TCP sockets<br>• `connect()` attempts to domains like:<br>&nbsp;&nbsp;- update-service-2024.tk<br>&nbsp;&nbsp;- microsoft-update-kb5029.ml<br>• Falls back to IP 185.220.101.45:443<br>• 3 beacon attempts per domain with 1-second intervals | **HIGH** - Beaconing pattern to suspicious domains |

## Summary Statistics

### Real Behaviors: 11/12 (92%)
- **Network Operations**: DNS queries, TCP connections, data transmission
- **Windows APIs**: Memory allocation, process enumeration, registry access
- **OS Objects**: Named pipes creation

### Simulated Behaviors: 1/12 (8%)
- **Process Connection Logs**: Only logging, no actual process network activity

## Why These Are Detected

### Network Layer Detection
1. **DNS Monitoring**: ~1,600 real DNS queries to malicious patterns
2. **Firewall/IDS**: ~400 TCP connection attempts to known bad IPs
3. **DPI (Deep Packet Inspection)**: HTTP headers with malware signatures, SSH banners, Meterpreter packets

### Endpoint Detection
1. **API Monitoring**: VirtualAlloc with RWX, process enumeration patterns
2. **Named Pipe Detection**: Suspicious pipe names matching known malware
3. **Registry Monitoring**: Access to persistence keys

### Behavioral Detection
1. **Beaconing**: Regular intervals, consistent packet sizes
2. **DGA**: High entropy domain generation patterns
3. **Data Exfiltration**: Large outbound data transfers to suspicious IPs

## Key Technical Details

### Real Network Functions Used:
- `gethostbyname()` - Performs actual DNS lookups via Windows DNS client
- `socket()` - Creates real network sockets
- `connect()` - Initiates TCP three-way handshake
- `send()` - Transmits data over network
- `recv()` - Attempts to receive data

### Real Windows APIs Used:
- `VirtualAlloc()` - Allocates memory with execute permissions
- `CreateToolhelp32Snapshot()` - Enumerates running processes
- `CreateNamedPipeA()` - Creates inter-process communication channels
- `RegOpenKeyExA()` - Accesses registry keys
- `OpenProcessToken()` - Manipulates security tokens

This implementation generates **real malicious traffic patterns** that will be detected by:
- Network security devices (firewalls, IDS/IPS)
- DNS security solutions
- Endpoint Detection and Response (EDR)
- Extended Detection and Response (XDR)
- Security Information and Event Management (SIEM)
