# EscapeBox C2 System - Project Structure

## Overview
This project contains a C2 (Command & Control) system with integrated debug logging. The system consists of multiple components that can be built separately to avoid header conflicts.

## Components

### 1. **escapebox.exe** (Combined Client/Server)
- **Source**: `escapebox/escapebox.cpp`
- **Project**: `escapebox.sln`
- **Description**: A combined executable that can function as either a C2 client or server based on command-line arguments
- **Debug Logs**: Uses integrated debug logging to `c:\rat\logs\`

### 2. **UnifiedC2Server.exe** (Standalone Server)
- **Source**: `escapebox/unified_c2_server.cpp`
- **Project**: `UnifiedC2Server.sln`
- **Description**: A dedicated C2 server with web dashboard and WebSocket support
- **Debug Logs**: Writes to `c:\rat\logs\server.log`

### 3. **C2 Client Module** (Not compiled separately)
- **Source**: `escapebox/c2_client.cpp`
- **Description**: Enhanced C2 client implementation with debug logging
- **Debug Logs**: Writes to `c:\rat\logs\client.log`
- **Note**: This file contains client-specific functionality but is not meant to be compiled as a standalone executable

## Important Build Notes

⚠️ **DO NOT** include multiple .cpp files with Winsock headers in the same project, as this will cause redefinition errors.

Each component should be built separately:
- Use `escapebox.sln` to build the combined client/server
- Use `UnifiedC2Server.sln` to build the standalone server

## Debug Logging

All components now include comprehensive debug logging with the following features:
- 5 log levels: NONE, ERROR, WARNING, INFO, VERBOSE
- Millisecond precision timestamps
- Categorized logging for easy filtering
- Automatic directory creation
- Logs written to `c:\rat\logs\`

## Building

Run `build_all.bat` to build all components automatically.

## Usage

### Standalone Server
```
UnifiedC2Server.exe
```

### Combined Executable
```
# As server
escapebox.exe server

# As client
escapebox.exe client <server_ip> [port]
```
