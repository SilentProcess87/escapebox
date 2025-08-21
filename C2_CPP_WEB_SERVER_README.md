# C++ Web Server Implementation for C2

## Overview
The C2 server now includes a native C++ web server implementation, eliminating the need for Python scripts or external dependencies. The web dashboard is fully embedded within the executable.

## Features

### Native C++ Web Server
- **Port**: 8080 (HTTP)
- **No external dependencies** - everything runs from the single executable
- **Multi-threaded** - handles multiple simultaneous connections
- **Embedded HTML/CSS/JavaScript** - dashboard code is compiled into the executable

### Web Dashboard Features
- **Real-time monitoring** of connected clients
- **Command execution** interface
- **Activity log viewer**
- **Auto-refresh** every 5 seconds
- **RESTful API endpoints**

## API Endpoints

### `GET /` or `GET /index.html`
Returns the main dashboard HTML page with embedded CSS and JavaScript.

### `GET /api/status`
Returns JSON data with current server status:
```json
{
  "activeClients": 2,
  "totalCommands": 45,
  "clients": [
    {
      "hostname": "DESKTOP-ABC123",
      "ip": "192.168.1.100",
      "username": "john.doe",
      "os": "Windows 10",
      "lastSeen": "5 beacons ago"
    }
  ],
  "logs": [
    "[2025-08-19 21:53:36] [C2] [NEW_CONNECTION] New bot connected from 192.168.1.100:55867"
  ]
}
```

### `POST /api/command`
Executes commands on all connected clients. Supported commands:
- `screenshot` - Capture screenshots from all clients
- `sysinfo` - Gather system information
- `persist` - Install persistence mechanisms

## How It Works

1. **Startup**: When `startWebServer()` is called, it:
   - Creates a socket on port 8080
   - Starts a dedicated thread for accepting connections
   - Logs the dashboard URL: http://localhost:8080

2. **Request Handling**: Each incoming HTTP request:
   - Is handled in a separate thread
   - Parsed to determine the endpoint
   - Responded to with appropriate content

3. **Data Integration**: The web server:
   - Accesses the same `connectedClients` map as the C2 server
   - Reads from the `activityLog` vector for recent events
   - Uses mutexes to ensure thread safety

## Implementation Details

### Key Components
- `webServerSocket` - The main listening socket
- `webServerRunning` - Atomic flag for graceful shutdown
- `handleHTTPClient()` - Processes individual HTTP requests
- `activityLog` - Vector storing recent log entries

### Thread Safety
- Uses `std::lock_guard` for accessing shared data
- Separate mutexes for clients (`clientsMutex`) and logs (`logMutex`)

## Usage

The web server starts automatically when the C2 server launches. No additional configuration needed.

Access the dashboard at: **http://localhost:8080**

## Benefits Over Python Implementation

1. **Single Executable** - No need to install Python or manage scripts
2. **Better Performance** - Native C++ is faster than Python
3. **Tighter Integration** - Direct access to C2 server data structures
4. **No Dependencies** - Works on any Windows system
5. **Embedded Assets** - HTML/CSS/JS compiled into the binary

## Security Note

The web server currently:
- Binds to all interfaces (0.0.0.0)
- Has no authentication
- Uses HTTP (not HTTPS)

For production use, consider adding:
- Authentication mechanisms
- HTTPS support
- IP whitelisting
- Rate limiting

