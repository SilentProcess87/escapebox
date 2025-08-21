# Manual Control Mode Update

## Changes Made

### 1. Fixed Remote Desktop (F12) Function
**Problem**: Client was responding with "UNSUPPORTED:COMMAND:54" when F12 was pressed
**Solution**: 
- Added `case CMD_REMOTE_DESKTOP:` handler in client's `processCommand` function
- Implemented `executeRemoteDesktop()` function that:
  - Enables RDP in Windows registry
  - Configures firewall rules
  - Starts Remote Desktop services
  - Creates temporary RDP user with credentials
  - Lists existing RDP sessions

### 2. Disabled Automatic Attack Execution
**Problem**: Server was automatically executing attack phases without user control
**Solution**:
- Disabled automatic attack phase execution in `handleClient` function
- Changed client connection message from "INITIALIZING AUTOMATED TESTS" to "MANUAL CONTROL MODE"
- Set automatic execution condition to `if (false)` to prevent it from running
- Now all commands must be manually triggered by the user

### 3. Enhanced Command Visibility
**Problem**: Commands being sent weren't clearly visible
**Solution**:
- Added console output for every command sent: `[!] SENDING COMMAND: <name> (ID: <id>) to <client>`
- Commands now show both the command name and numeric ID
- Each command is logged with full details

### 4. Improved Help Menu
**Problem**: Help menu was basic and didn't show all options clearly
**Solution**:
- Created comprehensive help menu with clear categories:
  - Attack Phases (1-5)
  - Individual Commands (A-W)
  - Function Keys (F1-F12)
  - Control keys (H, ESC)
- Added descriptions for each command
- Marked real network commands with [REAL PROCESSES] and [REAL NETWORK TRAFFIC]

## How to Use Manual Control

1. **Start the server**:
   ```
   escapebox.exe server
   ```

2. **Start client(s)**:
   ```
   escapebox.exe client <server_ip>
   ```

3. **View available commands**:
   - Press `H` to show the comprehensive help menu

4. **Execute commands manually**:
   - Press any key shown in the help menu
   - Commands are sent to ALL connected clients
   - Watch the console for `[!] SENDING COMMAND:` messages

5. **Monitor responses**:
   - Client responses appear in the server console
   - Check for successful execution or errors

## Command Categories

### Basic Operations
- **S** - Screenshot
- **K** - Keylogger Start
- **D** - Keylogger Dump
- **W** - Webcam Capture

### Credential Theft
- **B** - Browser Credentials
- **M** - Mimikatz/LSASS Dump
- **F8** - SAM Database Dump

### Network Operations (Real)
- **N** - SSH/Netcat/Socat (creates real processes)
- **T** - TOR connections (real network traffic)
- **L** - Lateral Movement

### Persistence
- **P** - Registry/Scheduled Task
- **F9** - Rootkit/Bootkit

### Defense Evasion
- **A** - Disable AV/AMSI/ETW
- **C** - Clear Event Logs

### Remote Access
- **F12** - Enable RDP & Create User

## Benefits of Manual Control

1. **Full Control**: You decide exactly when each command runs
2. **Better Testing**: Can test individual functions without running full attack sequence
3. **Debugging**: Easier to identify which commands succeed or fail
4. **Safety**: No automatic execution means less chance of unintended actions
5. **Visibility**: Every command sent is clearly shown

## Web Dashboard

The web dashboard is also available at http://localhost:8080/ for graphical control of all functions.
