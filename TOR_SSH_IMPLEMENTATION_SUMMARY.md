# TOR & SSH Implementation Summary

## What Was Added

I've successfully implemented advanced network evasion capabilities that will trigger XDR detections for:

### 1. **Socat/Netcat Connections to TOR Domains**
- Simulates connections to TOR entry nodes and hidden services (.onion domains)
- Uses netcat to connect to darknet sites like `3g2upl4pq3kufc4m.onion`
- Creates socat relays to TOR network with commands like:
  ```
  socat TCP4-LISTEN:8888,fork TCP4:torproject.org:9050
  socat TCP4-LISTEN:9999,fork SOCKS4A:127.0.0.1:darknet.onion:80,socksport=9050
  ```

### 2. **Suspicious API Calls from TOR Exit Nodes**
- Simulates HTTP requests with TOR exit node IPs in headers
- Makes API calls to suspicious endpoints:
  - Telegram Bot API
  - Discord Webhooks
  - Pastebin API
  - Blockchain APIs
- Uses known TOR exit node IPs like:
  - 185.220.101.34
  - 104.244.76.13
  - 23.129.64.142

### 3. **Uncommon Reverse SSH Tunnels**
- Creates reverse SSH tunnels to external domains/IPs
- Uses non-standard SSH ports (2222, 8022, 443)
- Targets suspicious domains:
  - malware-c2.dynamic.io
  - ssh.exploit-db.net
  - tunnel.darkweb.link
- Creates persistent SSH tunnel scripts

## Files Modified

1. **`escapebox.cpp`** (Server):
   - Added new command types (CMD_TOR_CONNECT, CMD_TOR_API_CALL, etc.)
   - Implemented server-side handlers for TOR/SSH commands
   - Added keyboard shortcuts (T for TOR, N for Network tunnels)
   - Updated Phase 3 to include these features

2. **`c2_client.cpp`** (Client):
   - Added client-side implementations for all new commands
   - Simulates actual TOR/SSH/Netcat/Socat behavior
   - Creates persistence scripts and configuration files

## How to Test

### Quick Test:
```batch
# Run the dedicated test script
test_tor_ssh.bat
```

### Manual Test:
1. Start server: `escapebox.exe server`
2. Start client: `escapebox.exe client 127.0.0.1 443`
3. Press keyboard shortcuts:
   - `T` - Test TOR connections
   - `N` - Test network tunnels
   - `3` - Run full Defense Evasion phase

### Monitor Activity:
```powershell
# Watch for XDR alerts
Get-Content "C:\Windows\Temp\c2_activity_log.txt" -Tail 50 -Wait | Select-String "XDR_ALERT|TOR|SSH"
```

## Expected XDR Detections

The implementation will generate these types of alerts:

1. **TOR Network Activity**:
   - Connections to known TOR nodes
   - .onion domain resolution attempts
   - TOR configuration file creation

2. **Suspicious Network Tunnels**:
   - Reverse SSH tunnels to external IPs
   - Netcat reverse shells
   - Socat encrypted relays

3. **Data Exfiltration Indicators**:
   - API calls from TOR exit nodes
   - Data transfer to .onion domains
   - Encrypted tunnel creation

## Build Instructions

The code is ready to compile:

```batch
# Use the build script
build_release.bat

# Or build in Visual Studio
# Open escapebox.sln and build in Release x64 mode
```

## Security Notes

This is demonstration malware for educational/testing purposes only. The implementation:
- Simulates real malware behavior patterns
- Doesn't actually connect to real TOR nodes or external servers
- All network activity is logged locally
- Designed specifically to trigger XDR/EDR detections

## Integration with Existing Features

These new features are integrated with:
- The existing command & control framework
- Attack phase automation (Phase 3: Defense Evasion)
- Activity logging system
- Web dashboard status updates

All new commands follow the same patterns as existing ones and are fully compatible with the C2 infrastructure.
