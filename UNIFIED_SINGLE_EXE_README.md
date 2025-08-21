# Unified C2 Server - Single Executable Solution

## Overview
This is a completely unified C2 server that runs as a **single executable** with no external dependencies. Everything is embedded in one EXE file:
- C2 Command & Control Server
- Web Dashboard Server
- WebSocket API Server
- Embedded HTML/CSS/JS Dashboard

## Building in Visual Studio 2022

### Method 1: Open the Solution
1. Open Visual Studio 2022
2. File → Open → Project/Solution
3. Navigate to your project folder and select `UnifiedC2Server.sln`
4. Build → Build Solution (or press F7)

### Method 2: Command Line Build
```powershell
# Open Developer Command Prompt for VS 2022
# Navigate to your project directory
cd D:\Development\escape_box\escapebox

# Build the solution
msbuild UnifiedC2Server.sln /p:Configuration=Release /p:Platform=x64
```

## Running the Server

After building successfully, run the executable:
```powershell
# From the build output directory
.\x64\Release\UnifiedC2Server.exe
```

The single executable will start:
- **C2 Server** on port 443
- **Web Dashboard** on http://localhost:8080
- **WebSocket API** on ws://localhost:8081

## Features

### No External Dependencies
- No Python scripts needed
- No batch files required
- No separate web server processes
- Everything runs from one EXE

### Embedded Dashboard
- Modern, responsive web interface
- Real-time updates via WebSocket
- Client management
- Command execution
- Activity logging

### Console Commands
When the server is running, you can use these commands:
- `help` - Show available commands
- `status` - Display server statistics
- `list` - List connected clients
- `exec <client_id> <command>` - Execute command on specific client
- `shutdown` - Stop the server

## Architecture

The unified server contains:
1. **C2 Server Thread** - Handles client connections and commands
2. **Web Server Thread** - Serves the embedded dashboard
3. **WebSocket Thread** - Provides real-time updates to the dashboard
4. **Console Handler** - Interactive command line interface

All components run in parallel within the single process.

## Troubleshooting

### Build Issues
- Ensure you have Visual Studio 2022 with C++ development tools installed
- The project uses C++17 standard
- All required Windows libraries are linked automatically

### Runtime Issues
- Run as Administrator if binding to port 443 fails
- Check Windows Firewall settings
- Ensure no other services are using ports 443, 8080, or 8081

## Security Note
This is designed for educational/testing purposes in isolated lab environments only.

