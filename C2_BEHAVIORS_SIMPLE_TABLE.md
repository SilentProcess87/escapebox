# C2 Behaviors - Simple Technical Breakdown

## Quick Reference Table

| # | Behavior | Real? | What It Actually Does | What XDR Sees |
|---|----------|-------|----------------------|---------------|
| 1 | **DNS Tunneling** | ✅ YES | Calls `gethostbyname()` 100 times with 63-character subdomains like:<br>`YmFzZTY0ZW5jb2RlZGRhdGE...tunnel.malware-c2.com` | High-entropy DNS queries, abnormal query length, suspicious domains |
| 2 | **DGA Domains** | ✅ YES | • Generates 200 random domains<br>• Calls `gethostbyname()` for each<br>• Opens TCP socket to 185.220.101.45:443 | Mass DNS queries to non-existent domains, DGA patterns |
| 3 | **Rare IP Connections** | ✅ YES | • Opens sockets to 10 IPs (45.142.114.231, etc.)<br>• Sends "EXFIL::hostname::USERNAME=..." + 1KB data<br>• 5 connections per IP | Direct IP connections bypassing DNS, data exfiltration |
| 4 | **Meterpreter** | ✅ YES | • Connects to ports 4444,5555,8080,8443,9999,31337<br>• Sends byte sequence: `00 00 00 54 52 45 43 56...`<br>• Sends commands: "sysinfo", "getuid", "hashdump" | Meterpreter protocol signature, default backdoor ports |
| 5 | **HTTP C2** | ✅ YES | Sends HTTP requests with:<br>`X-Malware-ID: CARBANAK_v4.5`<br>`Cookie: infected=true`<br>`User-Agent: MALWARE/1.0`<br>+ 4KB payload | Malicious HTTP headers, beaconing pattern, suspicious User-Agents |
| 6 | **DNS Flood** | ✅ YES | 500 domains × 3 queries each (A, MX, TXT) = 1,500 queries<br>Patterns: `.exfil.data.malware-c2.tk`<br>`.zombie.botnet.cc`<br>`.pool.monero.crypto.miner.tk` | DNS flood attack, cryptominer/botnet/ransomware patterns |
| 7 | **Named Pipes** | ✅ YES | Creates Windows named pipes:<br>`\\.\pipe\evil`<br>`\\.\pipe\cobalt_strike_beacon`<br>`\\.\pipe\meterpreter_12345` | Process injection indicators, malware IPC channels |
| 8 | **Suspicious APIs** | ✅ YES | • `VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE)`<br>• `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`<br>• Opens registry key `...\CurrentVersion\Run` | Shellcode injection pattern, process enumeration, persistence |
| 9 | **Netcat** | ✅ YES | Opens socket to 192.168.1.100:4444 | Backdoor port connection |
| 10 | **SSH Tunnels** | ✅ YES | • Connects to port 2222, 443, 8022<br>• Sends: `SSH-2.0-OpenSSH_7.4\r\n` | SSH on non-standard ports, reverse tunnel pattern |
| 11 | **Process Logs** | ❌ NO | Just prints: "PowerShell.exe connecting..."<br>No actual PowerShell activity | Nothing (only local logs) |
| 12 | **Rare Domains** | ✅ YES | Connects to:<br>`update-service-2024.tk`<br>`microsoft-update-kb5029.ml`<br>3 beacons at 1-second intervals | Typosquatting, suspicious TLDs, beaconing |

## The Most Detectable Behaviors

### 🚨 **CRITICAL** (Will definitely trigger alerts)
1. **Meterpreter** - Sends actual Meterpreter protocol packets
2. **HTTP C2** - Header literally says "X-Malware-ID: CARBANAK"
3. **Suspicious APIs** - VirtualAlloc with RWX = classic injection

### ⚠️ **HIGH** (Very likely to trigger)
1. **DNS Tunneling** - 63-char subdomains are extremely abnormal
2. **DNS Flood** - 1,500 queries in seconds = obvious attack
3. **Named Pipes** - "\\.\pipe\cobalt_strike_beacon" is a dead giveaway

### 📊 **By The Numbers**
- **Total DNS Queries**: ~1,600
- **Total TCP Connections**: ~400
- **Data Sent**: ~500KB
- **Unique Bad IPs**: 14
- **Named Pipes Created**: 5
- **Suspicious API Calls**: 4

## Code Examples

### DNS Tunneling (Simplified)
```cpp
// Generates: "YmFzZTY0ZW5jb2RlZGRhdGE...tunnel.malware-c2.com"
gethostbyname(dnsQuery.c_str());  // Real DNS query
```

### Meterpreter Packet
```cpp
unsigned char metPacket[] = {
    0x00, 0x00, 0x00, 0x54,  // Length
    'R', 'E', 'C', 'V',      // Meterpreter header
    // ... more bytes
};
send(metSocket, (char*)metPacket, sizeof(metPacket), 0);
```

### Suspicious API
```cpp
// This pattern = shellcode injection
LPVOID mem = VirtualAlloc(NULL, 4096, 
    MEM_COMMIT | MEM_RESERVE, 
    PAGE_EXECUTE_READWRITE);  // RWX memory!
```
