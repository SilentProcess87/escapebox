# Web C2 Server Setup Guide

## Overview
The new web-based C2 server provides a cyberpunk-themed web interface for controlling multiple bots with real-time analytics and command execution.

## Requirements
The web server requires additional libraries:
1. **nlohmann/json** - For JSON parsing
2. **cpp-httplib** - For HTTP server functionality

## Installation

### Option 1: Manual Installation
1. Download nlohmann/json:
   ```
   https://github.com/nlohmann/json/releases/download/v3.11.3/jon.hpps
   ```
   Place in project directory as `nlohmann/json.hpp`

2. Download cpp-httplib:
   ```
   https://github.com/yhirose/cpp-httplib/releases/download/v0.15.3/httplib.h
   ```
   Place in project directory as `httplib.h`

### Option 2: Using vcpkg (Recommended)
```powershell
# Install vcpkg if not already installed
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install

# Install dependencies
.\vcpkg install nlohmann-json:x64-windows
.\vcpkg install cpp-httplib:x64-windows
```

## Building

### For now, use the simplified version without external dependencies:
We'll create a simplified version that uses only Windows APIs.

## Features
- **Real-time Dashboard**: Monitor all connected bots
- **Cyberpunk Theme**: Neon green on black with glitch effects
- **Command Interface**: Send commands to individual or all bots
- **Analytics**: Track screenshots, keylogs, data exfiltration
- **WebSocket Support**: Real-time updates without polling

## Usage
1. Start the server: `escapebox.exe server`
2. Open browser to: `http://localhost:8080`
3. Monitor bots and send commands through the web interface

## Security Note
This is for demonstration purposes only in controlled environments.
