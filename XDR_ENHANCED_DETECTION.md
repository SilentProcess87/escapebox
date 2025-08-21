# Enhanced XDR Detection Implementation

## Changes Made to Trigger More XDR Alerts

### 1. SSH Reverse Tunnel (executeReverseSSH)
**Previous**: Only created batch files and sent simulated responses
**Enhanced**:
- Creates real SSH key files in `~/.ssh/` directory
- Downloads and executes `plink.exe` (PuTTY SSH client)
- Creates actual SSH processes with reverse tunnel arguments
- Attempts connections to suspicious IPs and domains
- Creates registry persistence entries
- Each process gets a unique PID that's logged

### 2. Netcat Tunnel (executeNetcatTunnel)
**Previous**: Only sent simulated responses
**Enhanced**:
- Downloads real netcat binary from official source
- Creates actual `nc.exe` processes for:
  - Port scanning (internal and external IPs)
  - Connection attempts to suspicious domains
  - Reverse shell creation with `-e cmd.exe`
- Each netcat process runs briefly then terminates
- Generates network traffic that XDR can detect

### 3. Socat Relay (executeSocatRelay)
**Previous**: Only sent simulated responses
**Enhanced**:
- Downloads real socat binary from GitHub
- Creates actual socat processes with various relay configurations:
  - TCP to TOR networks
  - SOCKS proxy tunnels
  - Port forwarding to suspicious IPs
- Creates scheduled task for persistence
- Each relay process runs for 3 seconds before termination

## Expected XDR Detections

With these enhancements, you should now see alerts for:

1. **TOR Network Activity**
   - Direct TCP connections to TOR nodes ✓
   - TOR configuration file creation ✓
   - Network traffic to .onion addresses ✓

2. **SSH Tunneling**
   - SSH client download (plink.exe)
   - SSH reverse tunnel processes
   - SSH key file creation
   - Outbound SSH connections to suspicious IPs

3. **Netcat Activity**
   - Netcat binary download
   - Port scanning activity
   - Reverse shell creation
   - Command execution via netcat

4. **Socat Tunneling**
   - Socat binary download
   - Network relay creation
   - SOCKS proxy setup
   - Scheduled task persistence

5. **Process Creation Alerts**
   - PowerShell hidden window executions
   - Suspicious command line arguments
   - Network tool executions from Temp directory

## Additional Detections Still Available

The following attacks are already implemented and should trigger alerts:
- LSASS memory dumps ✓
- Mimikatz execution ✓
- Registry persistence ✓
- Event log clearing ✓
- Token manipulation ✓
- Process injection ✓
- Credential harvesting ✓
- Port scanning ✓
- Browser credential theft
- Webcam/microphone access
- Ransomware simulation
- Bootkit/rootkit installation

## Testing Instructions

1. Build the project:
   ```
   .\build_release.bat
   ```

2. Start the server:
   ```
   escapebox.exe server
   ```

3. Start the client:
   ```
   escapebox.exe client <server_ip>
   ```

4. Trigger network attacks:
   - Press `N` - Network tunnels (SSH/Netcat/Socat)
   - Press `T` - TOR connections and API calls
   
5. Monitor XDR alerts for:
   - Process creation with suspicious arguments
   - Network connections to known bad IPs
   - Download and execution of hacking tools
   - Persistence mechanism creation

## Safety Notes

- All processes are terminated after a few seconds
- Connections to malicious domains will fail (they're fake)
- No actual data is exfiltrated
- Tools are downloaded to Temp and can be easily cleaned up
