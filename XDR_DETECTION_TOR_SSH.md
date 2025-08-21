# XDR Detection Features: TOR & SSH Tunneling

## Overview
This document describes the new advanced network evasion features added to trigger XDR detections for TOR connectivity and SSH tunneling.

## New Features Added

### 1. **TOR Network Connections**
Simulates connections to TOR network nodes and hidden services (.onion domains).

**What it does:**
- Connects to known TOR entry nodes
- Creates TOR circuit simulations
- Generates TOR traffic patterns
- Creates TOR configuration files

**XDR Detection Triggers:**
- Connections to known TOR nodes (ports 9001, 9050, 443)
- TOR handshake patterns
- .onion domain resolution attempts
- TOR configuration file creation

### 2. **Suspicious API Calls from TOR Exit Nodes**
Simulates API calls originating from known TOR exit nodes.

**What it does:**
- Makes HTTP requests with TOR exit node IPs in headers
- Targets suspicious API endpoints (Telegram, Discord, Pastebin)
- Simulates data exfiltration via TOR
- Uses X-Forwarded-For headers with TOR exit IPs

**XDR Detection Triggers:**
- API calls from known TOR exit node IPs
- Suspicious API endpoints accessed via TOR
- Data exfiltration to .onion domains
- HTTP headers indicating TOR usage

### 3. **Reverse SSH Tunnels**
Creates persistent reverse SSH tunnels to external domains/IPs.

**What it does:**
- Establishes SSH reverse tunnels to suspicious hosts
- Uses non-standard SSH ports (2222, 8022, 443)
- Creates SSH persistence scripts
- Configures SSH with StrictHostKeyChecking=no

**XDR Detection Triggers:**
- SSH connections to suspicious IPs/domains
- Reverse tunnel creation (ssh -R)
- SSH on non-standard ports
- Persistent SSH tunnel scripts

### 4. **Netcat Tunnels to TOR**
Uses netcat to connect to TOR hidden services.

**What it does:**
- Downloads/uses netcat (nc.exe)
- Connects to .onion domains
- Creates reverse shells via netcat
- Transfers data through netcat tunnels

**XDR Detection Triggers:**
- Netcat process execution
- Connections to .onion domains
- Reverse shell creation (nc.exe -e cmd.exe)
- Data transfer via netcat

### 5. **Socat Relay Networks**
Creates encrypted relay networks using socat.

**What it does:**
- Downloads/uses socat for Windows
- Creates TCP relays to TOR network
- Establishes SOCKS proxies to .onion sites
- Creates OpenSSL encrypted tunnels

**XDR Detection Triggers:**
- Socat process execution
- SOCKS proxy creation
- Encrypted relay to suspicious domains
- Persistent socat relay scripts

## Command Types

```cpp
// New command types added
CMD_TOR_CONNECT = 0xA0,      // Establish TOR connections
CMD_TOR_API_CALL = 0xA1,     // Make API calls via TOR
CMD_REVERSE_SSH = 0xA2,      // Create reverse SSH tunnels
CMD_NETCAT_TUNNEL = 0xA3,    // Netcat tunnel to TOR
CMD_SOCAT_RELAY = 0xA4       // Socat relay network
```

## Testing Instructions

### Manual Testing (Keyboard Shortcuts)

When the C2 server is running, use these keyboard shortcuts:

- **`T`** - Trigger TOR connections and API calls
- **`N`** - Create network tunnels (SSH/Netcat/Socat)
- **`3`** - Run Phase 3 which includes all network evasion techniques

### Automated Testing

The features are automatically included in Phase 3 (Defense Evasion) of the attack simulation:

```batch
# Start server
escapebox.exe server

# Start client
escapebox.exe client 127.0.0.1 443

# Press '3' to run Defense Evasion phase
```

### PowerShell Testing

```powershell
# Monitor specific TOR/SSH activity
Get-Content "C:\Windows\Temp\c2_activity_log.txt" -Tail 50 -Wait | Select-String "TOR|SSH|NETCAT|SOCAT"
```

## Expected XDR Alerts

### TOR Detection
```
*** XDR_ALERT *** [TOR_DETECTED] TOR network connection established from CLIENT_ID
*** XDR_ALERT *** [TOR_NODE_CONNECT] Attempting connection to TOR node: 62.210.105.116:9001
*** XDR_ALERT *** [TOR_API_DETECTED] Suspicious API call to https://api.telegram.org from TOR exit node 185.220.101.34
*** CRITICAL *** [TOR_EXFILTRATION] Data exfiltration detected via TOR network from CLIENT_ID
```

### SSH Tunnel Detection
```
*** XDR_ALERT *** [SSH_TUNNEL] Reverse SSH tunnel established to malware-c2.dynamic.io:22
*** CRITICAL *** [SSH_PERSISTENCE] Persistent reverse SSH tunnel configured on CLIENT_ID
```

### Netcat Detection
```
*** XDR_ALERT *** [NETCAT_TOR] Netcat connection to TOR service: 3g2upl4pq3kufc4m.onion:80
*** CRITICAL *** [NETCAT_SHELL] Netcat reverse shell established from CLIENT_ID
```

### Socat Detection
```
*** XDR_ALERT *** [SOCAT_RELAY] Socat relay created: TCP4-LISTEN:8888,fork TCP4:torproject.org:9050
*** CRITICAL *** [SOCAT_TUNNEL] Encrypted socat tunnel to TOR network from CLIENT_ID
```

## Network Indicators

### TOR Entry/Exit Nodes
- 62.210.105.116:9001 (France)
- 199.87.154.255:443 (Canada)
- 193.11.114.43:9001 (Sweden)
- 185.220.101.34 (Exit node)
- 104.244.76.13 (Exit node)

### Suspicious Domains
- malware-c2.dynamic.io
- ssh.exploit-db.net
- tunnel.darkweb.link
- 3g2upl4pq3kufc4m.onion (DuckDuckGo)
- torc2server.onion
- darknetmarket.onion

### Non-Standard Ports
- SSH: 2222, 8022, 443 (instead of 22)
- TOR: 9001, 9050
- Socat relays: 8888, 9999, 7777, 6666, 31337

## Files Created

### Configuration Files
- `%APPDATA%\tor\torrc` - TOR configuration
- `~\.ssh\config` - SSH tunnel configuration

### Persistence Scripts
- `%TEMP%\ssh_tunnel.bat` - SSH tunnel persistence
- `%TEMP%\socat_relay.bat` - Socat relay persistence
- `C:\Windows\Temp\relay.bat` - Network relay script

### Downloaded Tools
- `C:\Windows\Temp\nc.exe` - Netcat for Windows
- `C:\Windows\Temp\socat.exe` - Socat for Windows

## Security Notes

**This is demonstration malware for educational purposes only.**

These features simulate real malware behaviors that should trigger XDR/EDR solutions:
- TOR usage is commonly associated with malware C2 and data exfiltration
- Reverse SSH tunnels are used for persistent backdoor access
- Netcat and socat are often used by attackers for tunneling and pivoting
- Connections to .onion domains indicate TOR usage
- Non-standard ports for common services indicate evasion attempts

All network connections are simulated and don't actually establish real TOR circuits or SSH tunnels to external servers.
