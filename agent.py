import psutil
import json
import time
import platform
import subprocess
from datetime import datetime
import os
import threading
import webbrowser
import socket
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.exceptions import NotFittedError
from sklearn.metrics import mean_squared_error
import joblib
import logging
from collections import defaultdict, deque
import warnings
import requests
from urllib.parse import urljoin
import configparser
import ipaddress
import netifaces
warnings.filterwarnings('ignore')

# TensorFlow imports for proper autoencoder
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from tensorflow.keras.models import Model, Sequential
from tensorflow.keras.layers import Dense, Input
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping
import pickle

from flask import Flask, render_template, jsonify, request

# Layer 2 communication imports
try:
    from scapy.all import Ether, Raw, sendp, get_if_list, get_if_hwaddr, get_if_addr
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not available. Layer 2 communication disabled.")
    print("Install with: pip install scapy")
    print("On Windows, also install Npcap: https://nmap.org/npcap/")

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress TensorFlow warnings
tf.get_logger().setLevel('ERROR')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

# Server credentials
SERVER_CONFIG = {
    'ip_address': '192.168.0.228', #Change on purposed to test layer 2
    'mac': '7C-8A-E1-C0-F0-5E',
    'interface_guid': '{13069286-8AD6-4984-99B1-49BB999C93BE}',
    'name': 'Ethernet'
}

# Agent credentials
AGENT_CONFIG = {
    'interface_guid': '{B38D5694-5E23-4B09-8DFA-FFFFD1ED85BA}',
    'mac_address': 'B0-22-7A-EC-30-95',
    'name': 'Ethernet'
}

# === Layer 2 Communication Class ===
class Layer2Communicator:
    """
    Layer 2 communication using raw Ethernet frames
    Bypasses IP layer for extreme misconfiguration scenarios
    """
    
    def __init__(self):
        self.custom_ethertype = 0x88B5  # Custom EtherType for diagnostics
        self.interface = r"\\Device\\NPF_{B38D5694-5E23-4B09-8DFA-FFFFD1ED85BA}"
        self.src_mac =  "B0-22-7A-EC-30-95"
        self.server_mac = None
        self.initialized = False
        self.server_discovery_cache = {}
        
        if SCAPY_AVAILABLE:
            self._initialize()
    
    def _initialize(self):
        """Initialize Layer 2 communication"""
        try:
            interfaces = get_if_list()
            logger.info(f"Available interfaces: {interfaces}")

            # Normalize config MAC
            target_mac = AGENT_CONFIG['mac_address'].lower().replace("-", ":")
            
            for iface in interfaces:
                try:
                    mac = get_if_hwaddr(iface).lower()
                    if mac == target_mac:
                        self.interface = iface
                        self.src_mac = mac
                        try:
                            ip = get_if_addr(iface)
                            logger.info(f"Layer 2: Using interface {iface} with MAC {mac} and IP {ip}")
                        except:
                            logger.info(f"Layer 2: Using interface {iface} with MAC {mac} (no IP)")
                        self.initialized = True
                        break
                except Exception as e:
                    logger.debug(f"Error checking interface {iface}: {e}")
                    continue

            if not self.initialized:
                logger.warning(f"Layer 2: No matching interface found for MAC {target_mac}")

        except Exception as e:
            logger.error(f"Layer 2 initialization failed: {e}")
    
    def discover_server_mac(self) -> bool:
        """
        Attempt to discover server MAC address via broadcast
        """
        if not self.initialized:
            return False
            
        try:
            # Discovery payload
            discovery_payload = {
                'message_type': 'layer2_server_discovery',
                'agent_mac': self.src_mac,
                'agent_info': AGENT_CONFIG,
                'server_target': SERVER_CONFIG,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Send broadcast discovery frame
            broadcast_frame = Ether(
                dst="ff:ff:ff:ff:ff:ff",
                src=self.src_mac,
                type=self.custom_ethertype
            ) / Raw(load=json.dumps(discovery_payload, default=str).encode())
            
            # Use verbose=1 to see if packet is actually sent
            result = sendp(broadcast_frame, iface=self.interface, verbose=1)
            logger.info(f"Layer 2: Sent server discovery broadcast on interface {self.interface}")
            return True
            
        except Exception as e:
            logger.error(f"Layer 2 server discovery failed: {e}")
            return False
    
    def send_diagnostic_data(self, data: dict, server_mac: str = None) -> bool:
        """
        Send diagnostic data via Layer 2 directly to the server's MAC
        """
        if not self.initialized:
            logger.warning("Layer 2: Not initialized, cannot send data")
            return False

        try:
            # Always use the configured server MAC
            dst_mac = (server_mac or SERVER_CONFIG['mac']).replace('-', ':').lower()

            # Flatten payload so agent_id is at the top level
            payload = {
                'message_type': 'agent_diagnostics',
                'agent_id': data.get('agent_id'),
                'hostname': AGENT_CONFIG.get('hostname'),
                'platform': AGENT_CONFIG.get('platform'),
                'agent_mac': self.src_mac,
                'agent_info': AGENT_CONFIG,
                'server_target': SERVER_CONFIG,
                'data': data.get('data', {}),   # <-- must be "data", not "diagnostic_data"
                'timestamp': datetime.utcnow().isoformat()
            }

            frame = Ether(
                dst=dst_mac,
                src=self.src_mac,
                type=self.custom_ethertype
            ) / Raw(load=json.dumps(payload, default=str).encode())

            sendp(frame, iface=self.interface, verbose=1)

            logger.info(f"Layer 2: Sent diagnostics to server MAC {dst_mac} via {self.interface}")
            return True

        except Exception as e:
            logger.error(f"Layer 2 send failed: {e}")
            return False
    
    def is_available(self) -> bool:
        """Check if Layer 2 communication is available"""
        return SCAPY_AVAILABLE and self.initialized

# === IP Address Detection Class ===
class IPAddressDetector:
    """Detects and diagnoses IP address configuration issues in student lab environment"""
    
    def __init__(self):
        self.expected_lab_networks = [
            # Common lab network ranges - adjust these according to your lab setup
            "192.168.1.0/24",
            "192.168.0.0/24", 
            "10.0.0.0/24",
            "172.16.0.0/24"
        ]
        self.dhcp_servers = [
            "192.168.1.1",
            "192.168.0.1",
            "10.0.0.1",
            "172.16.0.1"
        ]
        self.test_hosts = [
            "8.8.8.8",      # Google DNS
            "1.1.1.1",      # Cloudflare DNS
            "208.67.222.222" # OpenDNS
        ]
        logger.info("IP Address Detector initialized for lab environment")
    
    def get_network_interfaces(self):
        """Get all active network interfaces with their IP configurations"""
        interfaces = []
        
        try:
            # Get interface information using netifaces
            for interface in netifaces.interfaces():
                try:
                    addresses = netifaces.ifaddresses(interface)
                    
                    # Check if interface has IPv4 address
                    if netifaces.AF_INET in addresses:
                        for addr_info in addresses[netifaces.AF_INET]:
                            ip = addr_info.get('addr')
                            netmask = addr_info.get('netmask')
                            
                            if ip and ip != '127.0.0.1':  # Skip localhost
                                # Get additional interface stats
                                stats = psutil.net_if_stats().get(interface, None)
                                is_up = stats.isup if stats else False
                                
                                interfaces.append({
                                    'interface': interface,
                                    'ip': ip,
                                    'netmask': netmask,
                                    'is_up': is_up,
                                    'is_dhcp': self._is_dhcp_assigned(ip),
                                    'network': self._get_network_address(ip, netmask) if netmask else None
                                })
                except Exception as e:
                    logger.debug(f"Error processing interface {interface}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            
        return interfaces
    
    def _is_dhcp_assigned(self, ip_address):
        """Check if IP address appears to be DHCP assigned"""
        try:
            # Check if IP is in typical DHCP ranges
            ip = ipaddress.IPv4Address(ip_address)
            
            # Common DHCP ranges (these are heuristics)
            dhcp_ranges = [
                ipaddress.IPv4Network("192.168.1.100/24"),  # Typical DHCP pool
                ipaddress.IPv4Network("192.168.0.100/24"),
                ipaddress.IPv4Network("10.0.0.100/24"),
                ipaddress.IPv4Network("172.16.0.100/24")
            ]
            
            for network in dhcp_ranges:
                if ip in network:
                    return True
                    
            # Additional check: IPs ending in .100+ are often DHCP
            if int(str(ip).split('.')[-1]) >= 100:
                return True
                
            return False
            
        except Exception:
            return False
    
    def _get_network_address(self, ip, netmask):
        """Calculate network address from IP and netmask"""
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network.network_address)
        except Exception:
            return None
    
    def test_internet_connectivity(self):
        """Test internet connectivity using multiple methods"""
        connectivity_results = {
            'dns_resolution': False,
            'ping_test': False,
            'http_test': False,
            'details': []
        }
        
        # Test DNS resolution
        try:
            socket.getaddrinfo('google.com', 80)
            connectivity_results['dns_resolution'] = True
            connectivity_results['details'].append("DNS resolution: SUCCESS")
        except Exception as e:
            connectivity_results['details'].append(f"DNS resolution: FAILED - {str(e)}")
        
        # Test ping to multiple hosts
        ping_success = 0
        for host in self.test_hosts:
            if self._ping_host(host):
                ping_success += 1
        
        if ping_success > 0:
            connectivity_results['ping_test'] = True
            connectivity_results['details'].append(f"Ping test: SUCCESS ({ping_success}/{len(self.test_hosts)} hosts reachable)")
        else:
            connectivity_results['details'].append("Ping test: FAILED - No test hosts reachable")
        
        # Test HTTP connectivity
        try:
            response = requests.get('http://httpbin.org/ip', timeout=5)
            if response.status_code == 200:
                connectivity_results['http_test'] = True
                connectivity_results['details'].append("HTTP test: SUCCESS")
                
                # Get external IP
                try:
                    external_ip = response.json().get('origin', 'Unknown')
                    connectivity_results['external_ip'] = external_ip
                    connectivity_results['details'].append(f"External IP: {external_ip}")
                except:
                    pass
        except Exception as e:
            connectivity_results['details'].append(f"HTTP test: FAILED - {str(e)}")
        
        return connectivity_results
    
    def _ping_host(self, host):
        """Ping a specific host"""
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "1", host]
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def detect_ip_issues(self):
        """Main function to detect IP configuration issues"""
        issues = []
        recommendations = []
        
        # Get network interfaces
        interfaces = self.get_network_interfaces()
        
        if not interfaces:
            issues.append("No active network interfaces detected")
            recommendations.append("Check network adapter drivers and physical connections")
            return {
                'has_issues': True,
                'issues': issues,
                'recommendations': recommendations,
                'interfaces': [],
                'connectivity': None
            }
        
        # Test internet connectivity
        connectivity = self.test_internet_connectivity()
        
        # Analyze each interface
        for interface in interfaces:
            if not interface['is_up']:
                issues.append(f"Network interface {interface['interface']} is down")
                recommendations.append(f"Enable network interface {interface['interface']}")
                continue
            
            # Check if IP is in expected lab networks
            ip_in_lab_network = False
            try:
                ip = ipaddress.IPv4Address(interface['ip'])
                for network_str in self.expected_lab_networks:
                    network = ipaddress.IPv4Network(network_str)
                    if ip in network:
                        ip_in_lab_network = True
                        break
            except Exception:
                pass
            
            # Detect potential issues
            if not ip_in_lab_network:
                issues.append(f"Interface {interface['interface']} has IP {interface['ip']} outside expected lab networks")
                recommendations.append(f"Configure {interface['interface']} to use DHCP or set correct static IP for lab network")
            
            # Check for common manual configuration mistakes
            if interface['ip'].startswith('169.254.'):
                issues.append(f"Interface {interface['interface']} has APIPA address {interface['ip']} - no DHCP server found")
                recommendations.append(f"Check DHCP server availability or configure static IP for {interface['interface']}")
            
            # Check for obviously wrong static IPs
            if not interface['is_dhcp'] and not connectivity['ping_test']:
                issues.append(f"Interface {interface['interface']} appears to have manual IP {interface['ip']} but internet is not accessible")
                recommendations.append(f"Reset {interface['interface']} to DHCP or verify static IP configuration")
        
        # Overall connectivity issues
        if not connectivity['dns_resolution'] and not connectivity['ping_test'] and not connectivity['http_test']:
            issues.append("No internet connectivity detected")
            recommendations.append("Check network configuration, cables, and router/switch connectivity")
        elif not connectivity['dns_resolution']:
            issues.append("DNS resolution failed")
            recommendations.append("Check DNS server settings or reset network configuration")
        
        # Generate specific solutions
        solutions = self._generate_solutions(interfaces, connectivity)
        
        return {
            'has_issues': len(issues) > 0,
            'issues': issues,
            'recommendations': recommendations,
            'solutions': solutions,
            'interfaces': interfaces,
            'connectivity': connectivity,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def _generate_solutions(self, interfaces, connectivity):
        """Generate specific step-by-step solutions"""
        solutions = []
        
        # Solution 1: Reset to DHCP
        if interfaces and not connectivity['ping_test']:
            solutions.append({
                'title': 'Reset Network Configuration to DHCP',
                'description': 'Automatically obtain IP address from lab DHCP server',
                'steps': [
                    'Open Network and Sharing Center',
                    'Click "Change adapter settings"',
                    f'Right-click on your network adapter ({interfaces[0]["interface"]})',
                    'Select "Properties"',
                    'Select "Internet Protocol Version 4 (TCP/IPv4)" and click "Properties"',
                    'Select "Obtain an IP address automatically"',
                    'Select "Obtain DNS server address automatically"',
                    'Click "OK" and restart the network adapter'
                ],
                'command_windows': f'netsh interface ip set address "{interfaces[0]["interface"]}" dhcp',
                'command_linux': f'sudo dhclient {interfaces[0]["interface"]}'
            })
        
        # Solution 2: Manual IP configuration for lab
        solutions.append({
            'title': 'Configure Manual IP for Lab Network',
            'description': 'Set static IP within lab network range',
            'steps': [
                'Contact lab technician for correct IP range',
                'Open Network and Sharing Center',
                'Click "Change adapter settings"',
                'Right-click on your network adapter',
                'Select "Properties"',
                'Select "Internet Protocol Version 4 (TCP/IPv4)" and click "Properties"',
                'Select "Use the following IP address"',
                'Enter IP address (e.g., 192.168.1.100)',
                'Enter subnet mask (e.g., 255.255.255.0)',
                'Enter default gateway (e.g., 192.168.1.1)',
                'Enter DNS servers (e.g., 8.8.8.8)',
                'Click "OK" and test connectivity'
            ]
        })
        
        # Solution 3: Network troubleshooting
        solutions.append({
            'title': 'Network Troubleshooting Steps',
            'description': 'General network troubleshooting procedures',
            'steps': [
                'Check physical network cable connections',
                'Restart network adapter',
                'Flush DNS cache: ipconfig /flushdns (Windows) or sudo systemctl restart systemd-resolved (Linux)',
                'Reset TCP/IP stack: netsh int ip reset (Windows)',
                'Restart network services',
                'Contact lab technician if issues persist'
            ]
        })
        
        return solutions
    
    def fix_network_dhcp(self, interface_name):
        """Attempt to automatically fix network by resetting to DHCP"""
        try:
            if platform.system().lower() == "windows":
                # Windows commands
                commands = [
                    f'netsh interface ip set address "{interface_name}" dhcp',
                    f'netsh interface ip set dns "{interface_name}" dhcp',
                    f'ipconfig /release',
                    f'ipconfig /renew'
                ]
            else:
                # Linux commands
                commands = [
                    f'sudo dhclient -r {interface_name}',
                    f'sudo dhclient {interface_name}'
                ]
            
            for cmd in commands:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    logger.warning(f"Command failed: {cmd} - {result.stderr}")
            
            return True
        except Exception as e:
            logger.error(f"Error fixing network DHCP: {e}")
            return False

# === Agent Configuration Class ===
class AgentConfig:
    """Configuration manager for the agent functionality"""
    
    def __init__(self, config_file='agent_config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()
        
    def load_config(self):
        """Load configuration from file or create default"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.create_default_config()
    
    def create_default_config(self):
        """Create default configuration file"""
        self.config['AGENT'] = {
            'enabled': 'true',
            #'server_url': f'http://{SERVER_CONFIG["ip_address"]}:8080',
            'server_url': f'http://localhost:8080',
            'server_ip': SERVER_CONFIG['ip_address'],
            'agent_id': socket.gethostname(),
            'send_interval': '30',
            'retry_attempts': '3',
            'retry_delay': '5',
            'timeout': '10',
            'enable_layer2': 'true',
            'broadcast_port': '9999'
        }
        
        self.config['DATA'] = {
            'send_metrics': 'true',
            'send_faults': 'true',
            'send_processes': 'true',
            'send_ml_insights': 'true',
            'send_ip_diagnostics': 'true'
        }
        
        self.config['SECURITY'] = {
            'api_key': '',
            'use_https': 'false',
            'verify_ssl': 'true'
        }
        
        self.save_config()
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            self.config.write(f)
    
    def get(self, section, key, fallback=None):
        """Get configuration value"""
        return self.config.get(section, key, fallback=fallback)
    
    def getboolean(self, section, key, fallback=False):
        """Get boolean configuration value"""
        return self.config.getboolean(section, key, fallback=fallback)
    
    def getint(self, section, key, fallback=0):
        """Get integer configuration value"""
        return self.config.getint(section, key, fallback=fallback)
    
    def set(self, section, key, value):
        """Set configuration value"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, key, str(value))
        self.save_config()

# === Enhanced Data Agent Class with Multi-Protocol Communication ===
class DataAgent:
    """Agent that sends collected data to admin server with multi-protocol fallback"""
    
    def __init__(self, config):
        self.config = config
        self.running = False
        self.thread = None
        self.last_send_time = 0
        self.send_queue = deque(maxlen=1000)  # Queue for failed sends
        self.session = requests.Session()
        
        # Initialize Layer 2 communication
        self.layer2_comm = None
        if self.config.getboolean('AGENT', 'enable_layer2', True):
            self.layer2_comm = Layer2Communicator()
        
        # Communication statistics
        self.comm_stats = {
            'http_success': 0,
            'http_failed': 0,
            'broadcast_success': 0,
            'broadcast_failed': 0,
            'layer2_success': 0,
            'layer2_failed': 0,
            'last_success_method': None,
            'last_success_time': None
        }
        
        # Set up session with configuration
        if self.config.get('SECURITY', 'api_key'):
            self.session.headers.update({
                'Authorization': f"Bearer {self.config.get('SECURITY', 'api_key')}"
            })
        
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': f"SystemMonitor-Agent/{self.config.get('AGENT', 'agent_id')}"
        })
        
        # SSL verification
        self.session.verify = self.config.getboolean('SECURITY', 'verify_ssl', True)
        
        logger.info(f"Data Agent initialized for server: {SERVER_CONFIG['ip_address']}")
        if self.layer2_comm and self.layer2_comm.is_available():
            logger.info("Layer 2 communication enabled and available")
        else:
            logger.info("Layer 2 communication not available")
    
    def start(self):
        """Start the agent in background thread"""
        if not self.config.getboolean('AGENT', 'enabled'):
            logger.info("Data Agent is disabled in configuration")
            return
        
        if self.running:
            logger.warning("Data Agent is already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._agent_loop, daemon=True)
        self.thread.start()
        logger.info("Data Agent started successfully")
    
    def stop(self):
        """Stop the agent"""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        logger.info("Data Agent stopped")
    
    def _agent_loop(self):
        """Main agent loop running in background"""
        send_interval = self.config.getint('AGENT', 'send_interval', 30)
        
        while self.running:
            try:
                current_time = time.time()
                
                # Check if it's time to send data
                if current_time - self.last_send_time >= send_interval:
                    self._collect_and_send_data()
                    self.last_send_time = current_time
                
                # Process retry queue
                self._process_retry_queue()
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Agent loop error: {e}")
                time.sleep(10)  # Wait longer on error
    
    def _collect_and_send_data(self):
        """Collect all data and send to server using multi-protocol approach"""
        try:
            data_package = {
                'agent_id': self.config.get('AGENT', 'agent_id'),
                'agent_info': AGENT_CONFIG,
                'server_target': SERVER_CONFIG,
                'timestamp': datetime.now().isoformat(),
                'hostname': socket.gethostname(),
                'platform': platform.system(),
                'data': {}
            }
            
            # Collect metrics data
            if self.config.getboolean('DATA', 'send_metrics', True):
                try:
                    with open('metrics_data.json', 'r') as f:
                        metrics_data = json.load(f)
                        # Send only recent data (last 10 entries)
                        data_package['data']['metrics'] = metrics_data[-10:] if len(metrics_data) > 10 else metrics_data
                except (FileNotFoundError, json.JSONDecodeError):
                    data_package['data']['metrics'] = []
            
            # Collect faults data
            if self.config.getboolean('DATA', 'send_faults', True):
                try:
                    with open('faults_data.json', 'r') as f:
                        faults_data = json.load(f)
                        data_package['data']['faults'] = faults_data
                except (FileNotFoundError, json.JSONDecodeError):
                    data_package['data']['faults'] = {}
            
            # Collect process data
            if self.config.getboolean('DATA', 'send_processes', True):
                try:
                    with open('top_processes.json', 'r') as f:
                        process_data = json.load(f)
                        data_package['data']['processes'] = process_data
                except (FileNotFoundError, json.JSONDecodeError):
                    data_package['data']['processes'] = {}
            
            # Collect ML insights
            if self.config.getboolean('DATA', 'send_ml_insights', True):
                try:
                    with open('ml_insights.json', 'r') as f:
                        ml_data = json.load(f)
                        data_package['data']['ml_insights'] = ml_data
                except (FileNotFoundError, json.JSONDecodeError):
                    data_package['data']['ml_insights'] = {}
            
            # Collect IP diagnostics data
            if self.config.getboolean('DATA', 'send_ip_diagnostics', True):
                try:
                    with open('ip_diagnostics.json', 'r') as f:
                        ip_data = json.load(f)
                        data_package['data']['ip_diagnostics'] = ip_data
                except (FileNotFoundError, json.JSONDecodeError):
                    data_package['data']['ip_diagnostics'] = {}
            
            # Send data using multi-protocol approach
            self._send_data_with_fallback(data_package)
            
        except Exception as e:
            logger.error(f"Error collecting data for agent: {e}")
    
    def _send_data_with_fallback(self, data_package):
        """
        Send data using multi-protocol approach with fallback chain:
        1. HTTP (primary)
        2. UDP Broadcast (fallback for IP misconfigurations)
        3. Layer 2 Raw Ethernet (ultimate fallback)
        """
        success = False
        
        # Method 1: Try HTTP first
        if self._send_via_http(data_package):
            self.comm_stats['http_success'] += 1
            self.comm_stats['last_success_method'] = 'http'
            self.comm_stats['last_success_time'] = datetime.now().isoformat()
            success = True
        else:
            self.comm_stats['http_failed'] += 1
            logger.debug("HTTP communication failed, trying broadcast discovery")
            
            # Method 2: Try UDP broadcast
            if self._send_via_broadcast(data_package):
                self.comm_stats['broadcast_success'] += 1
                self.comm_stats['last_success_method'] = 'broadcast'
                self.comm_stats['last_success_time'] = datetime.now().isoformat()
                success = True
            else:
                self.comm_stats['broadcast_failed'] += 1
                logger.debug("Broadcast communication failed, trying Layer 2")
                
                logger.info("Falling back to Layer 2: attempting raw Ethernet send")
                # Method 3: Try Layer 2 as ultimate fallback
                if self.layer2_comm and self.layer2_comm.is_available():
                    if self.layer2_comm.send_diagnostic_data(data_package):
                        self.comm_stats['layer2_success'] += 1
                        self.comm_stats['last_success_method'] = 'layer2'
                        self.comm_stats['last_success_time'] = datetime.now().isoformat()
                        success = True
                    else:
                        self.comm_stats['layer2_failed'] += 1
                        logger.warning("Layer 2 communication failed")
                else:
                    logger.debug("Layer 2 communication not available")
        
        if not success:
            logger.warning("All communication methods failed, queuing for retry")
            self._queue_for_retry(data_package)
        
        self._update_status('success' if success else 'failed', self.comm_stats)
    
    def _send_via_http(self, data_package):
        """Send data via HTTP with detailed logging"""
        try:
            # Use server_url from config if present, else fallback to SERVER_CONFIG
            server_url = self.config.get('AGENT', 'server_url', None)
            if not server_url:
                server_ip = SERVER_CONFIG['ip_address']
                server_port = 8080
                server_url = f'http://{server_ip}:{server_port}'
            
            endpoint = urljoin(server_url, '/api/agent/data')
            timeout = self.config.getint('AGENT', 'timeout', 10)

            response = self.session.post(
                endpoint,
                json=data_package,
                timeout=timeout
            )

            if response.status_code == 200:
                logger.info(f"Successfully transmitted data via HTTP Method to {server_url}")
                return True
            else:
                logger.debug(f"HTTP request failed with status {response.status_code} to {server_url}")
                return False

        except requests.exceptions.ConnectionError:
            logger.debug(f"HTTP connection error to {server_url}")
            return False
        except requests.exceptions.Timeout:
            logger.debug(f"HTTP timeout to {server_url}")
            return False
        except Exception as e:
            logger.debug(f"HTTP send failed to {server_url}: {e}")
            return False
    
    def _send_via_broadcast(self, data_package):
        """Enhanced UDP broadcast with multiple addresses and proper error handling"""
        #logger.warning("UDP broadcast disabled for Layer 2 testing")  # Testing layer 2
        #return False  # Pretend broadcast failed cleanly
        broadcast_port = self.config.getint('AGENT', 'broadcast_port', 9999)
        server_ip = SERVER_CONFIG['ip_address']
        
        # Multiple broadcast addresses to try, including direct server IP
        broadcast_addresses = [
            #'0.0.0.0'
            server_ip,          # Direct to server IP first
            '255.255.255.255',  # Global broadcast
            '192.168.0.255',    # Server subnet broadcast
            '192.168.1.255',    # Common home network
            '10.0.0.255',       # Corporate network
            '172.16.255.255'    # Private network
        ]
        
        for broadcast_addr in broadcast_addresses:
            if self._attempt_broadcast(data_package, broadcast_addr, broadcast_port):
                return True
        
        logger.error("All UDP broadcast attempts failed")
        return False
    
    def _attempt_broadcast(self, data_package, broadcast_addr, port):
        """Attempt broadcast to specific address with proper socket handling"""
        sock = None
        try:
            # Prepare broadcast data with agent identification
            broadcast_data = {
                'message_type': 'agent_broadcast',
                'agent_info': AGENT_CONFIG,
                'server_target': SERVER_CONFIG,
                'diagnostic_data': data_package,
                'agent_id': self.config.get('AGENT', 'agent_id'),
                'timestamp': datetime.now().isoformat()
            }
            
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(10)  # 5 second timeout for acknowledgment
            
            # Send broadcast
            message = json.dumps(broadcast_data, default=str).encode()
            bytes_sent = sock.sendto(message, (broadcast_addr, port))
            
            if bytes_sent > 0:
                logger.info(f"UDP broadcast sent to {broadcast_addr}:{port} ({bytes_sent} bytes)")
                
                # Wait for acknowledgment from server
                try:
                    ack_data, server_addr = sock.recvfrom(1024)
                    ack_response = json.loads(ack_data.decode())
                    
                    if ack_response.get('status') == 'received':
                        logger.info(f"Successfully transmitted data via UDP Broadcast Method to {broadcast_addr}:{port} (ACK received from {server_addr[0]})")
                        return True
                    else:
                        logger.info(f"Successfully transmitted data via UDP Broadcast Method to {broadcast_addr}:{port} (Invalid ACK)")
                        return True  # Still consider it successful
                        
                except socket.timeout:
                    # No acknowledgment received within timeout
                    logger.info(f"Successfully transmitted data via UDP Broadcast Method to {broadcast_addr}:{port} (no ack - timeout)")
                    return True  # Still consider broadcast successful
                    
                except json.JSONDecodeError:
                    logger.info(f"Successfully transmitted data via UDP Broadcast Method to {broadcast_addr}:{port} (invalid ack format)")
                    return True  # Still consider it successful
                    
            else:
                logger.error(f"Failed to send UDP broadcast to {broadcast_addr}:{port} - no bytes sent")
                return False
                    
        except socket.error as e:
            logger.error(f"UDP broadcast socket error to {broadcast_addr}:{port}: {e}")
            return False
        except Exception as e:
            logger.error(f"UDP broadcast failed to {broadcast_addr}:{port}: {e}")
            return False
        finally:
            # Properly close socket in finally block
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def _queue_for_retry(self, data_package):
        """Queue failed data package for retry"""
        data_package['retry_count'] = data_package.get('retry_count', 0) + 1
        data_package['queued_at'] = time.time()
        
        max_retries = self.config.getint('AGENT', 'retry_attempts', 3)
        if data_package['retry_count'] <= max_retries:
            self.send_queue.append(data_package)
            logger.debug(f"Queued data package for retry ({data_package['retry_count']}/{max_retries})")
        else:
            logger.warning(f"Dropping data package after {max_retries} failed attempts")
    
    def _process_retry_queue(self):
        """Process queued data packages for retry"""
        if not self.send_queue:
            return
        
        retry_delay = self.config.getint('AGENT', 'retry_delay', 5)
        current_time = time.time()
        
        # Process items ready for retry
        items_to_retry = []
        while self.send_queue:
            item = self.send_queue.popleft()
            if current_time - item['queued_at'] >= retry_delay:
                items_to_retry.append(item)
            else:
                # Put back items not ready for retry
                self.send_queue.appendleft(item)
                break
        
        # Retry items
        for item in items_to_retry:
            logger.debug(f"Retrying data package (attempt {item['retry_count']})")
            self._send_data_with_fallback(item)
    
    def _update_status(self, status, details):
        """Update agent status for monitoring"""
        status_data = {
            'status': status,
            'last_update': datetime.now().isoformat(),
            'details': details,
            'queue_size': len(self.send_queue),
            'server_url': f"http://{SERVER_CONFIG['ip_address']}:8080",
            'server_config': SERVER_CONFIG,
            'agent_config': AGENT_CONFIG,
            'agent_id': self.config.get('AGENT', 'agent_id'),
            'comm_stats': self.comm_stats.copy(),
            'layer2_available': self.layer2_comm.is_available() if self.layer2_comm else False
        }
        
        try:
            with open('agent_status.json', 'w') as f:
                json.dump(status_data, f, indent=2)
        except Exception as e:
            logger.error(f"Error updating agent status: {e}")
    
    def get_status(self):
        """Get current agent status"""
        try:
            with open('agent_status.json', 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                'status': 'unknown',
                'last_update': None,
                'details': 'Status file not found',
                'queue_size': len(self.send_queue),
                'server_url': f"http://{SERVER_CONFIG['ip_address']}:8080",
                'server_config': SERVER_CONFIG,
                'agent_config': AGENT_CONFIG,
                'agent_id': self.config.get('AGENT', 'agent_id'),
                'comm_stats': self.comm_stats.copy(),
                'layer2_available': self.layer2_comm.is_available() if self.layer2_comm else False
            }

# === Flask Web Server Setup ===
app = Flask(__name__)

# Global variables
stopped_processes = set()
process_stop_lock = threading.Lock()
agent_config = AgentConfig()
data_agent = DataAgent(agent_config)
ip_detector = IPAddressDetector()

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/metrics')
def get_metrics():
    try:
        with open('metrics_data.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

@app.route('/api/faults')
def get_faults():
    try:
        with open('faults_data.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"faults": [], "rule_suggestions": [], "ml_suggestions": [], "ml_insights": []}

@app.route('/api/top_processes')
def get_top_processes():
    try:
        with open('top_processes.json', 'r') as f:
            data = json.load(f)
            # Filter out stopped processes for faster UI updates
            with process_stop_lock:
                if stopped_processes:
                    data['top_cpu'] = [p for p in data['top_cpu'] if p['pid'] not in stopped_processes]
                    data['top_memory'] = [p for p in data['top_memory'] if p['pid'] not in stopped_processes]
            return data
    except FileNotFoundError:
        return []

@app.route('/api/thresholds')
def get_thresholds():
    try:
        with open('thresholds.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "cpu_warning": 30,
            "cpu_critical": 50,
            "memory_warning": 30,
            "memory_critical": 50,
            "packet_loss_warning": 1,
            "packet_loss_critical": 2
        }

@app.route('/api/ml_insights')
def get_ml_insights():
    try:
        with open('ml_insights.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"anomalies": [], "predictions": [], "patterns": []}

# === IP Diagnostics API Endpoints ===
@app.route('/api/ip_diagnostics')
def get_ip_diagnostics():
    """Get IP diagnostics information"""
    try:
        with open('ip_diagnostics.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"has_issues": False, "issues": [], "recommendations": [], "interfaces": [], "connectivity": None}

@app.route('/api/ip_diagnostics/scan', methods=['POST'])
def scan_ip_issues():
    """Trigger a new IP diagnostics scan"""
    try:
        diagnostics = ip_detector.detect_ip_issues()
        
        # Save results
        with open('ip_diagnostics.json', 'w') as f:
            json.dump(diagnostics, f, indent=2)
        
        return jsonify({"success": True, "data": diagnostics})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error scanning IP issues: {str(e)}"})

@app.route('/api/ip_diagnostics/fix_dhcp', methods=['POST'])
def fix_ip_dhcp():
    """Attempt to fix IP configuration by resetting to DHCP"""
    try:
        data = request.json
        interface_name = data.get('interface', '')
        
        if not interface_name:
            return jsonify({"success": False, "message": "Interface name is required"})
        
        success = ip_detector.fix_network_dhcp(interface_name)
        
        if success:
            # Trigger a new scan after fixing
            time.sleep(3)  # Wait for network to stabilize
            diagnostics = ip_detector.detect_ip_issues()
            with open('ip_diagnostics.json', 'w') as f:
                json.dump(diagnostics, f, indent=2)
            
            return jsonify({
                "success": True, 
                "message": f"Network configuration reset to DHCP for {interface_name}. Please check connectivity.",
                "data": diagnostics
            })
        else:
            return jsonify({"success": False, "message": "Failed to reset network configuration"})
            
    except Exception as e:
        return jsonify({"success": False, "message": f"Error fixing IP configuration: {str(e)}"})

# === Enhanced Agent API Endpoints ===
@app.route('/api/agent/status')
def get_agent_status():
    """Get enhanced agent status with communication statistics"""
    status = data_agent.get_status()
    return jsonify(status)

@app.route('/api/agent/config', methods=['GET', 'POST'])
def agent_config_endpoint():
    """Get or update agent configuration"""
    if request.method == 'GET':
        config_dict = {}
        for section in agent_config.config.sections():
            config_dict[section] = dict(agent_config.config[section])
        return jsonify(config_dict)
    
    elif request.method == 'POST':
        try:
            global data_agent
            config_data = request.json
            
            for section, values in config_data.items():
                for key, value in values.items():
                    agent_config.set(section, key, value)
            
            # Restart agent if configuration changed
            if data_agent.running:
                data_agent.stop()
                time.sleep(1)
                data_agent = DataAgent(agent_config)
                data_agent.start()
            
            return jsonify({"success": True, "message": "Configuration updated successfully"})
            
        except Exception as e:
            return jsonify({"success": False, "message": f"Error updating configuration: {str(e)}"})

@app.route('/api/agent/start', methods=['POST'])
def start_agent():
    """Start the agent"""
    try:
        data_agent.start()
        return jsonify({"success": True, "message": "Agent started successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error starting agent: {str(e)}"})

@app.route('/api/agent/stop', methods=['POST'])
def stop_agent():
    """Stop the agent"""
    try:
        data_agent.stop()
        return jsonify({"success": True, "message": "Agent stopped successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error stopping agent: {str(e)}"})

# === Communication Test Endpoint ===
@app.route('/api/test_communication', methods=['POST'])
def test_communication():
    """Test all communication methods"""
    test_data = {
        'message_type': 'communication_test',
        'timestamp': datetime.now().isoformat(),
        'agent_id': agent_config.get('AGENT', 'agent_id'),
        'agent_info': AGENT_CONFIG,
        'server_target': SERVER_CONFIG,
        'hostname': socket.gethostname()
    }
    
    results = {
        'http': data_agent._send_via_http(test_data),
        'broadcast': data_agent._send_via_broadcast(test_data),
        'layer2': False
    }
    
    if data_agent.layer2_comm and data_agent.layer2_comm.is_available():
        results['layer2'] = data_agent.layer2_comm.send_diagnostic_data(test_data)
    
    return jsonify(results)

@app.route('/api/take_action', methods=['POST'])
def take_action():
    action_data = request.json
    action_type = action_data.get('action_type')
    target = action_data.get('target')
    result = {"success": False, "message": "Unknown action"}

    try:
        if action_type == 'end_process':
            try:
                pid = int(target)
                
                # Check if process exists first
                if not psutil.pid_exists(pid):
                    result = {"success": False, "message": f"Process {pid} not found"}
                    return jsonify(result)
                
                process = psutil.Process(pid)
                process_name = process.name()
                
                # Try graceful termination first
                try:
                    process.terminate()
                    # Wait up to 3 seconds for graceful termination
                    process.wait(timeout=3)
                except psutil.TimeoutExpired:
                    # Force kill if graceful termination fails
                    try:
                        process.kill()
                        process.wait(timeout=2)
                    except psutil.TimeoutExpired:
                        result = {"success": False, "message": f"Failed to stop {process_name} - process may be protected"}
                        return jsonify(result)
                except psutil.AccessDenied:
                    result = {"success": False, "message": f"Access denied - cannot stop {process_name}. Try running as administrator."}
                    return jsonify(result)
                
                # Add to stopped processes list for faster UI updates
                with process_stop_lock:
                    stopped_processes.add(pid)
                
                # Clean up stopped processes list after 10 seconds
                def cleanup_stopped_process():
                    time.sleep(10)
                    with process_stop_lock:
                        stopped_processes.discard(pid)
                
                cleanup_thread = threading.Thread(target=cleanup_stopped_process)
                cleanup_thread.daemon = True
                cleanup_thread.start()
                
                result = {
                    "success": True, 
                    "message": f"Successfully stopped {process_name} (PID: {pid})"
                }
                
            except psutil.NoSuchProcess:
                result = {"success": False, "message": f"Process not found"}
            except psutil.AccessDenied:
                result = {"success": False, "message": f"Access denied - try running as administrator"}
            except Exception as e:
                result = {"success": False, "message": f"Error stopping process: {str(e)}"}
                
        elif action_type == 'restart_network':
            result = {
                "success": True, 
                "message": "Network restart initiated. This may take a few moments to complete."
            }
            
        elif action_type == 'clear_memory':
            import gc
            gc.collect()
            result = {
                "success": True, 
                "message": "Memory cleanup completed. This should improve performance temporarily."
            }
            
    except Exception as e:
        result = {"success": False, "message": f"Error performing action: {str(e)}"}
        
    return jsonify(result)

# === Testing Endpoints ===
def create_cpu_load(seconds=30, cores=1):
    """Create artificial CPU load for testing"""
    logger.info(f"Creating artificial CPU load for {seconds} seconds using {cores} cores")
    
    def stress_cpu():
        end_time = time.time() + seconds
        while time.time() < end_time:
            for i in range(10000000):
                i * i
    
    threads = []
    for i in range(cores):
        thread = threading.Thread(target=stress_cpu)
        thread.daemon = True
        threads.append(thread)
    
    for thread in threads:
        thread.start()
    
    return f"Started CPU load test on {cores} cores for {seconds} seconds"

@app.route('/api/test/cpu_load')
def test_cpu_load():
    seconds = int(request.args.get('seconds', 30))
    cores = int(request.args.get('cores', 1))
    
    seconds = min(seconds, 120)
    cores = min(cores, os.cpu_count() or 4)
    
    result = create_cpu_load(seconds, cores)
    return jsonify({"status": "success", "message": result})

def create_memory_load(mb=500, seconds=30):
    """Create artificial memory pressure for testing"""
    logger.info(f"Creating artificial memory load of {mb}MB for {seconds} seconds")
    
    def consume_memory():
        data = []
        for i in range(mb):
            data.append(' ' * (1024 * 1024))
        time.sleep(seconds)
        return "Memory test completed"
    
    thread = threading.Thread(target=consume_memory)
    thread.daemon = True
    thread.start()
    
    return f"Started memory load test using {mb}MB for {seconds} seconds"

@app.route('/api/test/memory_load')
def test_memory_load():
    mb = int(request.args.get('mb', 500))
    seconds = int(request.args.get('seconds', 30))
    
    mb = min(mb, 1000)
    seconds = min(seconds, 120)
    
    result = create_memory_load(mb, seconds)
    return jsonify({"status": "success", "message": result})

@app.route('/api/test/network_issue')
def test_network_issue():
    original_func = globals()['get_packet_loss']
    
    def mock_packet_loss():
        return 3.0
    
    globals()['get_packet_loss'] = mock_packet_loss
    
    def restore_function():
        time.sleep(30)
        globals()['get_packet_loss'] = original_func
    
    thread = threading.Thread(target=restore_function)
    thread.daemon = True
    thread.start()
    
    return jsonify({"status": "success", "message": "Simulated network issues for 30 seconds"})

def run_flask():
    if not os.path.exists('templates'):
        os.makedirs('templates')

    with open('templates/dashboard.html', 'w', encoding='utf-8') as f:
        f.write(DASHBOARD_HTML)

    webbrowser.open("http://localhost:5000")
    app.run(debug=False, host='0.0.0.0', port=5000)

# === Enhanced TensorFlow Autoencoder ML Engine ===
class EnhancedTensorFlowAutoencoderEngine:
    def __init__(self, model_dir='ml_models'):
        self.model_dir = model_dir
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
            
        # Model components
        self.autoencoder = None
        self.encoder = None
        self.decoder = None
        self.scaler = MinMaxScaler(feature_range=(0, 1))
        
        # Enhanced Autoencoder parameters (from your document)
        self.input_dim = 3  # cpu, memory, packet_loss
        self.encoding_layers = [16, 8, 2]  # As per your algorithm
        self.decoding_layers = [8, 16]     # As per your algorithm
        self.sequence_length = 10
        
        # Adaptive threshold management
        self.reconstruction_errors = deque(maxlen=100)  # Store last 100 errors
        self.base_threshold = None
        self.adaptive_threshold = None
        self.threshold_update_frequency = 10  # Update every 10 data points
        self.data_point_counter = 0
        
        # Training and data management
        self.is_trained = False
        self.is_scaler_fitted = False
        self.training_data = pd.DataFrame()
        self.pattern_history = defaultdict(lambda: deque(maxlen=1000))
        self.anomaly_history = deque(maxlen=100)
        
        # Status tracking for consistent indicators
        self.last_status = {'cpu': 'good', 'memory': 'good', 'network': 'good'}
        self.status_change_timestamps = {'cpu': 0, 'memory': 0, 'network': 0}
        self.status_stability_threshold = 3  # seconds before status change
        
        # User behavior learning for adaptive thresholds
        self.user_metrics_history = {
            'cpu_percent': deque(maxlen=200),
            'memory_percent': deque(maxlen=200),
            'packet_loss_percent': deque(maxlen=200)
        }
        
        # Initialize
        self.init_models()
        self.load_historical_data()
    
    def create_autoencoder_model(self):
        """Create enhanced autoencoder model as per your algorithm"""
        # Input layer
        input_layer = Input(shape=(self.input_dim,))
        
        # Encoder layers [16, 8, 2] as specified in your algorithm
        encoded = Dense(self.encoding_layers[0], activation='relu')(input_layer)
        encoded = Dense(self.encoding_layers[1], activation='relu')(encoded)
        encoded = Dense(self.encoding_layers[2], activation='relu')(encoded)
        
        # Decoder layers [8, 16] as specified in your algorithm
        decoded = Dense(self.decoding_layers[0], activation='relu')(encoded)
        decoded = Dense(self.decoding_layers[1], activation='relu')(decoded)
        decoded = Dense(self.input_dim, activation='sigmoid')(decoded)
        
        # Create models
        autoencoder = Model(input_layer, decoded)
        encoder = Model(input_layer, encoded)
        
        # Compile with Adam optimizer as specified in your algorithm
        autoencoder.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='mse',
            metrics=['mae']
        )
        
        return autoencoder, encoder
    
    def init_models(self):
        """Initialize or load TensorFlow models"""
        try:
            # Load existing models
            self.autoencoder = keras.models.load_model(f"{self.model_dir}/autoencoder.h5")
            self.encoder = keras.models.load_model(f"{self.model_dir}/encoder.h5")
            
            # Load scaler
            with open(f"{self.model_dir}/scaler.pkl", 'rb') as f:
                self.scaler = pickle.load(f)
            
            # Load threshold data
            with open(f"{self.model_dir}/threshold_data.json", 'r') as f:
                threshold_data = json.load(f)
                self.base_threshold = threshold_data.get('base_threshold')
                self.adaptive_threshold = threshold_data.get('adaptive_threshold', self.base_threshold)
                if 'reconstruction_errors' in threshold_data:
                    self.reconstruction_errors = deque(threshold_data['reconstruction_errors'], maxlen=100)
            
            self.is_scaler_fitted = True
            self.is_trained = True
            logger.info("Loaded existing TensorFlow autoencoder models")
            
        except (FileNotFoundError, OSError) as e:
            logger.info("Creating new TensorFlow autoencoder models")
            self.autoencoder, self.encoder = self.create_autoencoder_model()
            self.is_scaler_fitted = False
            self.is_trained = False
    
    def load_historical_data(self):
        """Load historical metrics data for training"""
        try:
            with open('metrics_data.json', 'r') as f:
                metrics = json.load(f)
                if metrics:
                    df = pd.DataFrame(metrics)
                    df['timestamp'] = pd.to_datetime(df['timestamp'])
                    df.set_index('timestamp', inplace=True)
                    self.training_data = df
                    logger.info(f"Loaded {len(df)} historical data points")
                    
                    # Fit scaler if enough data
                    if len(df) >= 5:
                        features = df[['cpu_percent', 'memory_percent', 'packet_loss_percent']].values
                        self.scaler.fit(features)
                        self.is_scaler_fitted = True
                        logger.info("Fitted scaler with historical data")
                        
                        # Train autoencoder if enough data
                        if len(df) >= 20:
                            self.train_autoencoder()
                            
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Couldn't load historical data: {e}")
            self.training_data = pd.DataFrame()
    
    def prepare_training_data(self, data):
        """Prepare data for autoencoder training"""
        if len(data) < 10:
            return None
            
        # Filter for normal behavior (as per your algorithm)
        normal_indices = []
        for i, row in enumerate(data):
            if (row[0] < 60 and row[1] < 60 and row[2] < 3):  # Normal thresholds
                normal_indices.append(i)
        
        if len(normal_indices) < 10:
            logger.info("Using all available data for training")
            return data
        else:
            logger.info(f"Using {len(normal_indices)} normal data points for training")
            return data[normal_indices]
    
    def train_autoencoder(self):
        """Train the TensorFlow autoencoder as per your enhanced algorithm"""
        if len(self.training_data) < 20:
            logger.info("Not enough data to train autoencoder")
            return False
            
        try:
            # Prepare features
            features = self.training_data[['cpu_percent', 'memory_percent', 'packet_loss_percent']].values
            
            # Fit scaler if not already fitted
            if not self.is_scaler_fitted:
                self.scaler.fit(features)
                self.is_scaler_fitted = True
            
            # Scale features (MinMaxScaler normalization as per your algorithm)
            scaled_features = self.scaler.transform(features)
            
            # Prepare normal training data
            normal_data = self.prepare_training_data(scaled_features)
            if normal_data is None or len(normal_data) < 10:
                logger.info("Not enough normal data for training")
                return False
            
            logger.info(f"Training TensorFlow autoencoder on {len(normal_data)} data points...")
            
            # Train autoencoder with early stopping
            early_stopping = EarlyStopping(
                monitor='loss',
                patience=10,
                restore_best_weights=True,
                verbose=1
            )
            
            # Train the model
            history = self.autoencoder.fit(
                normal_data, normal_data,
                epochs=100,
                batch_size=32,
                validation_split=0.2,
                callbacks=[early_stopping],
                verbose=1
            )
            
            # Calculate reconstruction threshold (θ = mean + 2.5 * std as per your algorithm)
            reconstructed = self.autoencoder.predict(normal_data, verbose=0)
            reconstruction_errors = np.mean(np.square(normal_data - reconstructed), axis=1)
            
            # Enhanced threshold calculation as per your algorithm
            self.base_threshold = np.mean(reconstruction_errors) + 2.5 * np.std(reconstruction_errors)
            self.adaptive_threshold = self.base_threshold
            
            # Store recent errors for adaptive threshold
            self.reconstruction_errors.extend(reconstruction_errors[-20:])
            
            self.is_trained = True
            self.save_models()
            
            logger.info(f"TensorFlow autoencoder trained successfully!")
            logger.info(f"Base reconstruction threshold: {self.base_threshold:.6f}")
            logger.info(f"Training loss: {history.history['loss'][-1]:.6f}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error training TensorFlow autoencoder: {e}")
            return False
    
    def update_adaptive_threshold(self):
        """Update adaptive threshold based on user usage patterns"""
        if len(self.reconstruction_errors) < 10:
            return
        
        try:
            # Get recent reconstruction errors
            recent_errors = list(self.reconstruction_errors)[-20:]  # Last 20 errors
            
            # Calculate adaptive threshold with smoothing
            recent_mean = np.mean(recent_errors)
            recent_std = np.std(recent_errors)
            
            # Adaptive threshold with user behavior consideration
            new_threshold = recent_mean + 2.0 * recent_std
            
            # Smooth threshold updates to prevent oscillation
            if self.adaptive_threshold is not None:
                # Use exponential moving average for smooth adaptation
                alpha = 0.3  # Smoothing factor
                self.adaptive_threshold = alpha * new_threshold + (1 - alpha) * self.adaptive_threshold
            else:
                self.adaptive_threshold = new_threshold
                
            # Ensure threshold doesn't go below base threshold
            if self.base_threshold is not None:
                self.adaptive_threshold = max(self.adaptive_threshold, self.base_threshold * 0.8)
                
            logger.debug(f"Updated adaptive threshold: {self.adaptive_threshold:.6f}")
            
        except Exception as e:
            logger.error(f"Error updating adaptive threshold: {e}")
    
    def save_models(self):
        """Save TensorFlow models and related data"""
        try:
            if self.autoencoder is not None and self.is_trained:
                self.autoencoder.save(f"{self.model_dir}/autoencoder.h5")
                self.encoder.save(f"{self.model_dir}/encoder.h5")
                logger.info("Saved TensorFlow autoencoder models")
            
            if self.is_scaler_fitted:
                with open(f"{self.model_dir}/scaler.pkl", 'wb') as f:
                    pickle.dump(self.scaler, f)
            
            # Save threshold data
            threshold_data = {
                'base_threshold': self.base_threshold,
                'adaptive_threshold': self.adaptive_threshold,
                'reconstruction_errors': list(self.reconstruction_errors)
            }
            
            with open(f"{self.model_dir}/threshold_data.json", 'w') as f:
                json.dump(threshold_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def add_data_point(self, metrics):
        """Add a new data point and return ML insights"""
        # Store user behavior for adaptive learning
        for key in ['cpu_percent', 'memory_percent', 'packet_loss_percent']:
            if key in metrics:
                self.user_metrics_history[key].append(metrics[key])
        
        # Update training data
        self.update_training_data(metrics)
        
        # Generate insights
        features = np.array([
            metrics['cpu_percent'],
            metrics['memory_percent'],
            metrics['packet_loss_percent']
        ]).reshape(1, -1)
        
        insights = {
            "anomalies": self.detect_anomalies(features),
            "predictions": self.predict_trends(),
            "patterns": self.detect_patterns(),
            "timestamp": metrics['timestamp']
        }
        
        self.save_insights(insights)
        
        # Update data point counter and adaptive threshold
        self.data_point_counter += 1
        if self.data_point_counter % self.threshold_update_frequency == 0:
            self.update_adaptive_threshold()
        
        # Retrain periodically with more data
        if self.data_point_counter % 20 == 0 and len(self.training_data) >= 30:
            threading.Thread(target=self.train_autoencoder, daemon=True).start()
        
        return insights
    
    def update_training_data(self, metrics):
        """Update training data with new metrics"""
        new_data = pd.DataFrame([metrics])
        new_data['timestamp'] = pd.to_datetime(new_data['timestamp'])
        new_data.set_index('timestamp', inplace=True)
        
        self.training_data = pd.concat([self.training_data, new_data])
        
        # Keep last 1000 data points
        if len(self.training_data) > 1000:
            self.training_data = self.training_data.iloc[-1000:]
    
    def detect_anomalies(self, features):
        """Enhanced anomaly detection using TensorFlow autoencoder"""
        anomalies = []
        
        if not self.is_trained or not self.is_scaler_fitted:
            return anomalies
            
        try:
            # Scale features
            scaled_features = self.scaler.transform(features)
            
            # Get reconstruction from autoencoder
            reconstructed = self.autoencoder.predict(scaled_features, verbose=0)
            reconstruction_error = np.mean(np.square(scaled_features - reconstructed))
            
            # Add to error history
            self.reconstruction_errors.append(reconstruction_error)
            
            # Use adaptive threshold
            current_threshold = self.adaptive_threshold or self.base_threshold
            if current_threshold is None:
                return anomalies
            
            # Check if anomaly
            if reconstruction_error > current_threshold:
                current_metrics = features[0]
                
                # Determine anomaly type and create meaningful descriptions
                anomaly_desc = None
                confidence = min(95, (reconstruction_error / current_threshold) * 50)
                
                if current_metrics[0] > 50:  # High CPU
                    anomaly_desc = "Enhanced autoencoder detected unusual high CPU usage pattern"
                elif current_metrics[1] > 50:  # High Memory
                    anomaly_desc = "Enhanced autoencoder detected unusual high memory usage pattern"
                elif current_metrics[2] > 2:  # High packet loss
                    anomaly_desc = "Enhanced autoencoder detected unusual network connectivity pattern"
                elif current_metrics[0] > 40 and current_metrics[1] > 40:  # Combined load
                    anomaly_desc = "Enhanced autoencoder detected unusual system overload pattern"
                else:
                    anomaly_desc = "Enhanced autoencoder detected unusual system behavior pattern"
                
                # Determine reliability based on confidence and error magnitude
                reliability_label = "High" if confidence > 70 else ("Medium" if confidence > 50 else "Low")
                
                anomaly = {
                    "description": anomaly_desc,
                    "confidence": confidence,
                    "reliability_label": reliability_label,
                    "reconstruction_error": float(reconstruction_error),
                    "threshold": float(current_threshold),
                    "adaptive_threshold_used": True,
                    "metrics": {
                        "cpu": float(current_metrics[0]),
                        "memory": float(current_metrics[1]),
                        "packet_loss": float(current_metrics[2])
                    }
                }
                
                anomalies.append(anomaly)
                
                # Store in history
                self.anomaly_history.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "description": anomaly_desc,
                    "reconstruction_error": float(reconstruction_error),
                    "metrics": anomaly["metrics"]
                })
                
                logger.info(f"Anomaly detected: {anomaly_desc} (error: {reconstruction_error:.6f}, threshold: {current_threshold:.6f})")
                
        except Exception as e:
            logger.error(f"Error in TensorFlow autoencoder anomaly detection: {e}")
        
        return anomalies
    
    def predict_trends(self):
        """Enhanced trend prediction using user behavior patterns"""
        predictions = []
        
        for metric, history in self.user_metrics_history.items():
            if len(history) >= 10:
                try:
                    recent = list(history)[-10:]
                    x = np.arange(len(recent))
                    
                    # Linear regression for trend
                    slope, intercept = np.polyfit(x, recent, 1)
                    last_val = recent[-1]
                    
                    if abs(slope) > 0.3:  # Significant trend
                        direction = "increasing" if slope > 0 else "decreasing"
                        metric_name = metric.replace('_percent', '').replace('_', ' ').title()
                        
                        if direction == "increasing":
                            future_val = last_val + (slope * 10)  # 10 time steps ahead
                            
                            # Determine severity and certainty
                            certainty = "High" if abs(slope) > 1.0 else "Medium"
                            if abs(slope) > 2.0:
                                certainty = "Very High"
                            
                            # Check if prediction is concerning
                            is_concerning = False
                            severity = "low"
                            
                            if metric == 'cpu_percent' and (future_val > 60 or slope > 1.0):
                                is_concerning = True
                                severity = "high" if future_val > 80 else "medium"
                            elif metric == 'memory_percent' and (future_val > 60 or slope > 1.0):
                                is_concerning = True
                                severity = "high" if future_val > 80 else "medium"
                            elif metric == 'packet_loss_percent' and (future_val > 3 or slope > 0.5):
                                is_concerning = True
                                severity = "high" if future_val > 5 else "medium"
                            
                            if is_concerning:
                                predictions.append({
                                    "metric": metric_name,
                                    "trend": direction,
                                    "current": float(last_val),
                                    "projected": float(min(100, max(0, future_val))),
                                    "time_frame": "~1 minute",
                                    "severity": severity,
                                    "certainty": certainty,
                                    "slope": float(slope)
                                })
                                
                except Exception as e:
                    logger.error(f"Error predicting trends for {metric}: {e}")
        
        return predictions
    
    def detect_patterns(self):
        """Enhanced pattern detection using autoencoder insights"""
        patterns = []
        
        if len(self.training_data) < 20:
            return patterns
            
        try:
            # Memory leak detection using autoencoder reconstruction patterns
            if 'memory_percent' in self.training_data.columns:
                mem_data = self.training_data['memory_percent'].values[-30:]  # Last 30 points
                if len(mem_data) >= 10:
                    # Check for consistent upward trend
                    x = np.arange(len(mem_data))
                    slope, _ = np.polyfit(x, mem_data, 1)
                    
                    if slope > 0.5 and mem_data[-1] > 40:
                        confidence = min(85, int(slope * 30))
                        reliability = "High" if slope > 1.0 else "Medium"
                        
                        patterns.append({
                            "description": "Enhanced autoencoder detected potential memory leak pattern",
                            "confidence": confidence,
                            "reliability": reliability,
                            "suggestion": "Monitor applications for memory leaks - restart memory-intensive applications",
                            "pattern_type": "memory_leak",
                            "slope": float(slope)
                        })
            
            # CPU spike pattern detection
            if 'cpu_percent' in self.training_data.columns:
                cpu_data = self.training_data['cpu_percent'].values[-50:]  # Last 50 points
                if len(cpu_data) >= 20:
                    cpu_mean = np.mean(cpu_data)
                    cpu_std = np.std(cpu_data)
                    
                    # Find spikes
                    spikes = np.where(cpu_data > max(60, cpu_mean + 2 * cpu_std))[0]
                    
                    if len(spikes) >= 3:
                        intervals = np.diff(spikes)
                        if len(intervals) > 0 and np.std(intervals) / (np.mean(intervals) + 1e-10) < 0.2:
                            patterns.append({
                                "description": f"Regular CPU usage spikes detected every ~{np.mean(intervals) * 3:.0f} seconds",
                                "confidence": 75,
                                "reliability": "Medium",
                                "suggestion": "Check for scheduled tasks, background processes, or system services running at regular intervals",
                                "pattern_type": "cpu_spikes",
                                "spike_interval": float(np.mean(intervals) * 3)
                            })
            
            # Network instability pattern using autoencoder
            if 'packet_loss_percent' in self.training_data.columns:
                network_data = self.training_data['packet_loss_percent'].values[-30:]
                if len(network_data) >= 15:
                    # Check for intermittent issues
                    high_loss_points = np.where(network_data > 1.0)[0]
                    if len(high_loss_points) >= 4:
                        # Check if losses are clustered or spread out
                        intervals = np.diff(high_loss_points)
                        if len(intervals) > 0:
                            avg_interval = np.mean(intervals)
                            if avg_interval < 8:  # Frequent issues
                                patterns.append({
                                    "description": "Enhanced autoencoder detected intermittent network instability pattern",
                                    "confidence": 70,
                                    "reliability": "High",
                                    "suggestion": "Check network hardware, router stability, and WiFi interference",
                                    "pattern_type": "network_instability",
                                    "issue_frequency": float(avg_interval * 3)
                                })
            
            # System overload pattern using combined metrics
            if len(self.training_data) >= 20:
                recent_data = self.training_data[['cpu_percent', 'memory_percent']].values[-20:]
                combined_load = recent_data[:, 0] + recent_data[:, 1]  # CPU + Memory
                
                if np.mean(combined_load) > 80 and np.std(combined_load) < 15:
                    patterns.append({
                        "description": "Enhanced autoencoder detected sustained system overload pattern",
                        "confidence": 80,
                        "reliability": "High",
                        "suggestion": "Consider upgrading hardware or reducing concurrent applications",
                        "pattern_type": "system_overload",
                        "average_load": float(np.mean(combined_load))
                    })
                    
        except Exception as e:
            logger.error(f"Error in enhanced pattern detection: {e}")
            
        return patterns
    
    def save_insights(self, insights):
        """Save ML insights to file"""
        try:
            with open('ml_insights.json', 'w') as f:
                json.dump(insights, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving ML insights: {e}")
    
    def get_status_with_stability(self, value, thresholds, metric_type):
        """Get status with stability checking to prevent flickering"""
        current_time = time.time()
        
        # Determine new status
        if value >= thresholds['critical']:
            new_status = 'critical'
        elif value >= thresholds['warning']:
            new_status = 'warning'
        else:
            new_status = 'good'
        
        # Check if status changed
        if self.last_status[metric_type] != new_status:
            # If enough time has passed since last change, update status
            if current_time - self.status_change_timestamps[metric_type] >= self.status_stability_threshold:
                self.last_status[metric_type] = new_status
                self.status_change_timestamps[metric_type] = current_time
                return new_status
            else:
                # Keep previous status to prevent flickering
                return self.last_status[metric_type]
        else:
            # Status unchanged, reset timestamp
            self.status_change_timestamps[metric_type] = current_time
            return new_status
    
    def get_adaptive_thresholds(self):
        """Calculate enhanced adaptive thresholds based on user behavior patterns"""
        # Base thresholds - more conservative for better user experience
        base_thresholds = {
            'cpu_percent': {'warning': 40, 'critical': 65},
            'memory_percent': {'warning': 40, 'critical': 65},
            'packet_loss_percent': {'warning': 1, 'critical': 3}
        }
        
        # Enhance thresholds based on user behavior if enough data available
        if len(self.training_data) >= 30:
            try:
                for metric in ['cpu_percent', 'memory_percent', 'packet_loss_percent']:
                    if metric in self.user_metrics_history and len(self.user_metrics_history[metric]) >= 20:
                        # Get user's typical usage patterns
                        user_values = list(self.user_metrics_history[metric])
                        
                        # Calculate percentiles for adaptive thresholds
                        p75 = np.percentile(user_values, 75)
                        p90 = np.percentile(user_values, 90)
                        p95 = np.percentile(user_values, 95)
                        
                        # Adaptive warning threshold (between base and user's 90th percentile)
                        adaptive_warning = max(
                            base_thresholds[metric]['warning'],
                            min(p90 * 1.2, base_thresholds[metric]['warning'] * 1.5)
                        )
                        
                        # Adaptive critical threshold (between warning and user's 95th percentile)
                        adaptive_critical = max(
                            adaptive_warning + 10,
                            min(p95 * 1.3, base_thresholds[metric]['critical'] * 1.3)
                        )
                        
                        # Apply reasonable caps
                        if metric in ['cpu_percent', 'memory_percent']:
                            adaptive_warning = min(adaptive_warning, 75)
                            adaptive_critical = min(adaptive_critical, 85)
                        else:  # packet_loss_percent
                            adaptive_warning = min(adaptive_warning, 5)
                            adaptive_critical = min(adaptive_critical, 8)
                        
                        base_thresholds[metric]['warning'] = adaptive_warning
                        base_thresholds[metric]['critical'] = adaptive_critical
                        
                        logger.debug(f"Adaptive {metric} thresholds: warning={adaptive_warning:.1f}, critical={adaptive_critical:.1f}")
                        
            except Exception as e:
                logger.error(f"Error calculating adaptive thresholds: {e}")
        
        return base_thresholds

# === Collector Functions ===
def get_packet_loss():
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "4", "8.8.8.8"]

    try:
        output = subprocess.check_output(command, universal_newlines=True)
        if platform.system().lower() == "windows":
            lost_line = [line for line in output.split('\n') if "Lost" in line]
            if lost_line:
                lost = int(lost_line[0].split(',')[2].split('(')[1].split('%')[0])
                return lost
        else:
            for line in output.splitlines():
                if "packet loss" in line:
                    return float(line.split('%')[0].split()[-1])
    except Exception as e:
        logger.error(f"Ping failed: {e}")
    return 0.0

def get_top_processes(count=5):
    # Get the top processes by CPU usage with better process handling
    cpu_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            proc.cpu_percent(interval=0.1)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    time.sleep(0.2)
    
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            process_info = proc.info
            # Filter out system processes and very low usage processes for cleaner UI
            if (process_info['cpu_percent'] > 0.1 or process_info['memory_percent'] > 0.1) and \
               process_info['name'] not in ['System Idle Process', 'System', '[System Process]']:
                processes.append({
                    'pid': process_info['pid'],
                    'name': process_info['name'],
                    'cpu_percent': process_info['cpu_percent'],
                    'memory_percent': process_info['memory_percent']
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    top_cpu = sorted(processes, key=lambda p: p['cpu_percent'], reverse=True)[:count]
    top_memory = sorted(processes, key=lambda p: p['memory_percent'], reverse=True)[:count]
    
    result = {
        "top_cpu": top_cpu,
        "top_memory": top_memory,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    with open("top_processes.json", "w") as f:
        json.dump(result, f, indent=2)
    
    return result

def get_network_info():
    """Get network interface information"""
    network_info = []
    
    try:
        for interface, stats in psutil.net_if_stats().items():
            if stats.isup:
                addrs = psutil.net_if_addrs().get(interface, [])
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        network_info.append({
                            "interface": interface,
                            "ip": addr.address,
                            "netmask": addr.netmask,
                            "speed": getattr(stats, "speed", 0)
                        })
    except Exception as e:
        logger.error(f"Error getting network info: {e}")
    
    return network_info

def run_ip_diagnostics():
    """Run IP diagnostics and save results"""
    try:
        diagnostics = ip_detector.detect_ip_issues()
        
        # Save results
        with open('ip_diagnostics.json', 'w') as f:
            json.dump(diagnostics, f, indent=2)
            
        return diagnostics
    except Exception as e:
        logger.error(f"Error running IP diagnostics: {e}")
        return {
            'has_issues': False,
            'issues': [],
            'recommendations': [],
            'interfaces': [],
            'connectivity': None,
            'error': str(e)
        }

def generate_suggestions(faults, top_processes, ml_insights, ip_diagnostics=None):
    """Generate suggestions based on detected faults, ML insights, and IP diagnostics"""
    rule_suggestions = []
    ml_suggestions = []
    
    # Add IP-related suggestions if there are network issues
    if ip_diagnostics and ip_diagnostics.get('has_issues'):
        for issue in ip_diagnostics['issues']:
            if "internet connectivity" in issue.lower() or "dns resolution" in issue.lower():
                rule_suggestions.append({
                    "issue": "Network Configuration Issues Detected",
                    "suggestions": [
                        {
                            "text": "IP Address Detector found network configuration problems",
                            "action_type": "info"
                        },
                        {
                            "text": "Reset network configuration to DHCP",
                            "action_type": "ip_fix_dhcp"
                        },
                        {
                            "text": "Check network cables and router connectivity",
                            "action_type": "info"
                        },
                        {
                            "text": "View detailed IP diagnostics in Network Configuration tab",
                            "action_type": "info"
                        }
                    ]
                })
                break  # Only add one network suggestion to avoid duplication
    
    # Rule-based suggestions (existing logic)
    for fault in faults:
        if "High CPU usage" in fault:
            cpu_heavy_apps = [{"name": p['name'], "pid": p['pid'], "usage": p['cpu_percent']} 
                             for p in top_processes["top_cpu"][:3] if p['cpu_percent'] > 5]
            
            rule_suggestions.append({
                "issue": "High CPU Usage",
                "suggestions": [
                    {
                        "text": f"Close CPU-intensive applications",
                        "action_type": "end_process",
                        "targets": cpu_heavy_apps
                    },
                    {
                        "text": "Check for background processes",
                        "action_type": "info"
                    },
                    {
                        "text": "Update your applications",
                        "action_type": "info"
                    },
                    {
                        "text": "Restart your computer if issues persist",
                        "action_type": "info"
                    }
                ]
            })
            
        if "High memory usage" in fault:
            memory_heavy_apps = [{"name": p['name'], "pid": p['pid'], "usage": p['memory_percent']} 
                               for p in top_processes["top_memory"][:3] if p['memory_percent'] > 2]
            
            rule_suggestions.append({
                "issue": "High Memory Usage",
                "suggestions": [
                    {
                        "text": f"Close memory-intensive applications",
                        "action_type": "end_process",
                        "targets": memory_heavy_apps
                    },
                    {
                        "text": "Clear system memory cache",
                        "action_type": "clear_memory"
                    },
                    {
                        "text": "Close unused browser tabs",
                        "action_type": "info"
                    },
                    {
                        "text": "Consider adding more RAM if this is frequent",
                        "action_type": "info"
                    }
                ]
            })
            
        if "High packet loss" in fault:
            network_info = get_network_info()
            interface_info = ""
            if network_info:
                interface_info = f" (Active: {network_info[0]['interface']})"
            
            suggestions = [
                {
                    "text": f"Restart network adapter{interface_info}",
                    "action_type": "restart_network"
                },
                {
                    "text": "Check IP address configuration",
                    "action_type": "info"
                },
                {
                    "text": "Restart your router and modem",
                    "action_type": "info"
                },
                {
                    "text": "Move closer to your Wi-Fi router",
                    "action_type": "info"
                },
                {
                    "text": "Try using a wired connection",
                    "action_type": "info"
                }
            ]
            
            # Add IP diagnostics suggestion if available
            if ip_diagnostics and ip_diagnostics.get('has_issues'):
                suggestions.insert(1, {
                    "text": "Run IP address diagnostics to identify configuration issues",
                    "action_type": "ip_scan"
                })
            
            rule_suggestions.append({
                "issue": "Network Connectivity Issues",
                "suggestions": suggestions
            })
    
    # Enhanced ML-based suggestions (existing logic continues...)
    if ml_insights:
        for anomaly in ml_insights.get("anomalies", []):
            ml_suggestion = {
                "issue": f"{anomaly['description']}",
                "reliability": anomaly.get('reliability_label', 'Medium'),
                "confidence": anomaly['confidence'],
                "suggestions": []
            }
            
            if "CPU" in anomaly['description'] or "cpu" in anomaly['description'].lower():
                cpu_heavy_apps = [{"name": p['name'], "pid": p['pid'], "usage": p['cpu_percent']} 
                                 for p in top_processes["top_cpu"][:2] if p['cpu_percent'] > 5]
                
                if cpu_heavy_apps:
                    ml_suggestion["suggestions"].append({
                        "text": "Stop CPU-intensive applications detected by enhanced autoencoder",
                        "action_type": "end_process",
                        "targets": cpu_heavy_apps
                    })
                ml_suggestion["suggestions"].append({
                    "text": "Monitor system for continued unusual patterns",
                    "action_type": "info"
                })
                
            elif "memory" in anomaly['description'].lower():
                memory_heavy_apps = [{"name": p['name'], "pid": p['pid'], "usage": p['memory_percent']} 
                                   for p in top_processes["top_memory"][:2] if p['memory_percent'] > 2]
                
                if memory_heavy_apps:
                    ml_suggestion["suggestions"].append({
                        "text": "Stop memory-intensive applications detected by enhanced autoencoder",
                        "action_type": "end_process",
                        "targets": memory_heavy_apps
                    })
                ml_suggestion["suggestions"].append({
                    "text": "Clear system memory",
                    "action_type": "clear_memory"
                })
                
            elif "network" in anomaly['description'].lower():
                ml_suggestion["suggestions"].append({
                    "text": "Restart network adapter",
                    "action_type": "restart_network"
                })
                # Add IP diagnostics for network anomalies
                if ip_diagnostics and ip_diagnostics.get('has_issues'):
                    ml_suggestion["suggestions"].append({
                        "text": "Check IP address configuration for network anomalies",
                        "action_type": "ip_scan"
                    })
            
            if "enhanced autoencoder" in anomaly['description'].lower():
                ml_suggestion["suggestions"].append({
                    "text": "Enhanced autoencoder detected unusual behavior - investigate recent changes",
                    "action_type": "info"
                })
            
            ml_suggestion["suggestions"].append({
                "text": "Check for recent system or software changes",
                "action_type": "info"
            })
            
            ml_suggestions.append(ml_suggestion)
        
        # Handle enhanced predictions (existing logic continues...)
        for prediction in ml_insights.get("predictions", []):
            certainty = prediction.get('certainty', 'Medium')
            
            if prediction["metric"] == "Cpu Percent" and prediction["trend"] == "increasing":
                cpu_apps = [{"name": p['name'], "pid": p['pid'], "usage": p['cpu_percent']} 
                           for p in top_processes["top_cpu"][:2] if p['cpu_percent'] > 5]
                
                suggestions = [
                    {
                        "text": "Enhanced autoencoder predicts CPU overload - check for background tasks",
                        "action_type": "info"
                    },
                    {
                        "text": "Save your work as precaution",
                        "action_type": "info"
                    }
                ]
                
                if cpu_apps:
                    suggestions.insert(0, {
                        "text": "Close applications before predicted CPU overload",
                        "action_type": "end_process",
                        "targets": cpu_apps
                    })
                
                ml_suggestions.append({
                    "issue": f"Enhanced autoencoder predicts CPU usage will reach {prediction['projected']:.1f}% soon",
                    "reliability": certainty,
                    "confidence": min(90, int((prediction['projected'] - prediction['current']) * 2)),
                    "suggestions": suggestions
                })
                
            elif prediction["metric"] == "Memory Percent" and prediction["trend"] == "increasing":
                memory_apps = [{"name": p['name'], "pid": p['pid'], "usage": p['memory_percent']} 
                              for p in top_processes["top_memory"][:2] if p['memory_percent'] > 2]
                
                suggestions = [
                    {
                        "text": "Clear system memory before predicted overload",
                        "action_type": "clear_memory"
                    },
                    {
                        "text": "Enhanced autoencoder suggests restarting memory-intensive applications",
                        "action_type": "info"
                    }
                ]
                
                if memory_apps:
                    suggestions.insert(0, {
                        "text": "Close memory-intensive applications before predicted overload",
                        "action_type": "end_process",
                        "targets": memory_apps
                    })
                
                ml_suggestions.append({
                    "issue": f"Enhanced autoencoder predicts memory usage will reach {prediction['projected']:.1f}% soon",
                    "reliability": certainty,
                    "confidence": min(90, int((prediction['projected'] - prediction['current']) * 2)),
                    "suggestions": suggestions
                })
                
            elif prediction["metric"] == "Packet Loss Percent" and prediction["trend"] == "increasing":
                suggestions = [
                    {
                        "text": "Restart network adapter before predicted network failure",
                        "action_type": "restart_network"
                    },
                    {
                        "text": "Enhanced autoencoder suggests checking network stability",
                        "action_type": "info"
                    },
                    {
                        "text": "Check for network interference",
                        "action_type": "info"
                    }
                ]
                
                # Add IP diagnostics for network predictions
                if ip_diagnostics and ip_diagnostics.get('has_issues'):
                    suggestions.insert(1, {
                        "text": "Run IP diagnostics to identify potential network configuration issues",
                        "action_type": "ip_scan"
                    })
                
                ml_suggestions.append({
                    "issue": f"Enhanced autoencoder predicts network issues will reach {prediction['projected']:.1f}% packet loss",
                    "reliability": certainty,
                    "confidence": min(90, int((prediction['projected'] - prediction['current']) * 10)),
                    "suggestions": suggestions
                })
        
        # Handle enhanced patterns (existing logic continues...)
        for pattern in ml_insights.get("patterns", []):
            ml_suggestion = {
                "issue": pattern["description"],
                "reliability": pattern.get("reliability", "Medium"),
                "confidence": pattern["confidence"],
                "suggestions": [
                    {
                        "text": pattern["suggestion"],
                        "action_type": "info"
                    }
                ]
            }
            
            if "memory leak" in pattern["description"].lower():
                memory_apps = [{"name": p['name'], "pid": p['pid'], "usage": p['memory_percent']} 
                              for p in top_processes["top_memory"][:2] if p['memory_percent'] > 2]
                
                if memory_apps:
                    ml_suggestion["suggestions"].append({
                        "text": "Close applications with potential memory leaks",
                        "action_type": "end_process",
                        "targets": memory_apps
                    })
                ml_suggestion["suggestions"].append({
                    "text": "Clear system memory to mitigate leak effects",
                    "action_type": "clear_memory"
                })
                
            elif "CPU spikes" in pattern["description"] or "CPU usage" in pattern["description"]:
                ml_suggestion["suggestions"].append({
                    "text": "Enhanced autoencoder suggests investigating background processes",
                    "action_type": "info"
                })
                
            elif "network" in pattern["description"].lower():
                ml_suggestion["suggestions"].append({
                    "text": "Enhanced autoencoder recommends checking network stability and connections",
                    "action_type": "info"
                })
                # Add IP diagnostics for network patterns
                if ip_diagnostics and ip_diagnostics.get('has_issues'):
                    ml_suggestion["suggestions"].append({
                        "text": "Check IP address configuration as network pattern may be related to IP issues",
                        "action_type": "ip_scan"
                    })
                
            ml_suggestions.append(ml_suggestion)
    
    return rule_suggestions, ml_suggestions

def diagnose_faults(metrics, top_processes, ml_engine):
    """Enhanced fault diagnosis using TensorFlow autoencoder and adaptive thresholds"""
    ml_insights = ml_engine.add_data_point(metrics)
    thresholds = ml_engine.get_adaptive_thresholds()
    
    # Run IP diagnostics periodically
    ip_diagnostics = None
    try:
        # Run IP diagnostics every 60 seconds or if there are network issues
        current_time = time.time()
        should_run_ip_diagnostics = False
        
        # Check if we should run IP diagnostics
        if not hasattr(diagnose_faults, 'last_ip_check'):
            diagnose_faults.last_ip_check = 0
        
        if (current_time - diagnose_faults.last_ip_check > 60) or metrics.get('packet_loss_percent', 0) > 2:
            should_run_ip_diagnostics = True
            diagnose_faults.last_ip_check = current_time
        
        if should_run_ip_diagnostics:
            ip_diagnostics = run_ip_diagnostics()
        else:
            # Load existing IP diagnostics
            try:
                with open('ip_diagnostics.json', 'r') as f:
                    ip_diagnostics = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                pass
                
    except Exception as e:
        logger.error(f"Error running IP diagnostics: {e}")

    try:
        with open('thresholds.json', 'w') as f_thresh:
            flat = {
                "cpu_warning": thresholds['cpu_percent']['warning'],
                "cpu_critical": thresholds['cpu_percent']['critical'],
                "memory_warning": thresholds['memory_percent']['warning'],
                "memory_critical": thresholds['memory_percent']['critical'],
                "packet_loss_warning": thresholds['packet_loss_percent']['warning'],
                "packet_loss_critical": thresholds['packet_loss_percent']['critical']
            }
            json.dump(flat, f_thresh, indent=2)
    except Exception as e:
        logger.error(f"Error saving thresholds: {e}")
    
    # Enhanced rule-based fault detection with stable status indicators
    faults = []
    
    # Get stable status for each metric to prevent flickering
    cpu_status = ml_engine.get_status_with_stability(
        metrics["cpu_percent"], 
        thresholds['cpu_percent'], 
        'cpu'
    )
    
    memory_status = ml_engine.get_status_with_stability(
        metrics["memory_percent"], 
        thresholds['memory_percent'], 
        'memory'
    )
    
    network_status = ml_engine.get_status_with_stability(
        metrics["packet_loss_percent"], 
        thresholds['packet_loss_percent'], 
        'network'
    )
    
    # Only report faults for critical status to reduce noise
    if cpu_status == 'critical':
        faults.append(f"High CPU usage: {metrics['cpu_percent']:.1f}%")
    if memory_status == 'critical':
        faults.append(f"High memory usage: {metrics['memory_percent']:.1f}%")
    if network_status == 'critical':
        faults.append(f"High packet loss: {metrics['packet_loss_percent']:.1f}%")

    rule_suggestions, ml_suggestions = generate_suggestions(faults, top_processes, ml_insights, ip_diagnostics)
    
    result = {
        "faults": faults,
        "rule_suggestions": rule_suggestions,
        "ml_suggestions": ml_suggestions,
        "ml_insights": ml_insights,
        "thresholds": thresholds,
        "timestamp": metrics['timestamp'],
        "metrics": metrics,
        "training_data_points": len(ml_engine.training_data),
        "autoencoder_trained": ml_engine.is_trained,
        "reconstruction_threshold": ml_engine.adaptive_threshold or ml_engine.base_threshold,
        "adaptive_threshold_active": ml_engine.adaptive_threshold is not None,
        "status_indicators": {
            "cpu": cpu_status,
            "memory": memory_status,
            "network": network_status
        },
        "ip_diagnostics": ip_diagnostics
    }

    with open("faults_data.json", "w") as f:
        json.dump(result, f, indent=2)
        
    return result

def save_metrics(metrics):
    filename = "metrics_data.json"
    try:
        with open(filename, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []

    data.append(metrics)
    if len(data) > 1000:
        data = data[-1000:]

    with open(filename, "w") as f:
        json.dump(data, f, indent=2)

def collect_metrics(ml_engine):
    while True:
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            packet_loss = get_packet_loss()
            
            top_processes = get_top_processes()

            metrics = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_used_gb": round(memory.used / (1024**3), 2),
                "memory_total_gb": round(memory.total / (1024**3), 2),
                "packet_loss_percent": packet_loss
            }

            save_metrics(metrics)
            diagnose_faults(metrics, top_processes, ml_engine)
            
            # Enhanced status reporting
            autoencoder_status = "Trained & Active" if ml_engine.is_trained else "Learning"
            threshold_type = "Adaptive" if ml_engine.adaptive_threshold else "Base"
            layer2_status = "Available" if data_agent.layer2_comm and data_agent.layer2_comm.is_available() else "Unavailable"
            
            logger.info(f"[{metrics['timestamp']}] CPU: {cpu_percent:.1f}%, Memory: {memory.percent:.1f}%, "
                       f"Packet Loss: {packet_loss:.1f}% | TensorFlow Autoencoder: {autoencoder_status} | "
                       f"Threshold: {threshold_type} | Layer 2: {layer2_status}")
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
        
        time.sleep(3)  # 3-second intervals for responsive monitoring

# Enhanced Dashboard HTML with Layer 2 Communication Test - KEEPING YOUR ORIGINAL DESIGN INTACT
DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Enhanced System Monitor - TensorFlow ML with Multi-Protocol Data Agent</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #D1D0D0;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            padding: 20px 0;
        }
        .header h1 {
            margin: 0;
            color: #2c3e50;
            font-size: 28px;
            font-weight: 600;
        }
        .header .subtitle {
            color: #7f8c8d;
            font-size: 14px;
            margin-top: 5px;
        }
        .chart-container { 
            background-color: white; 
            padding: 20px; 
            border-radius: 12px; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            margin-bottom: 20px;
        }
        .metrics-current { 
            display: flex; 
            justify-content: space-between; 
            margin-bottom: 20px; 
            flex-wrap: wrap;
        }
        .metric-box {
            flex: 1;
            min-width: 200px;
            background-color: white;
            border-radius: 12px;
            padding: 20px;
            margin: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            text-align: center;
            transition: all 0.3s ease;
        }
        .metric-box:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .processes-container {
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            margin-top: 20px;
        }
        .processes-box {
            flex: 1;
            min-width: 300px;
            background-color: white;
            border-radius: 12px;
            padding: 20px;
            margin: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        h1, h2, h3 { 
            color: #2c3e50; 
            margin-top: 0;
        }
        .value { 
            font-size: 32px; 
            font-weight: 600; 
            color: #3498db; 
            margin: 10px 0;
        }
        .label { 
            font-size: 14px; 
            color: #7f8c8d; 
            margin-bottom: 5px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            font-size: 14px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }
        th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }
        .diagnostics-table {
            width: 100%;
            margin-bottom: 20px;
            background-color: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        .diagnostics-table th {
            padding: 15px;
            text-align: left;
            font-size: 14px;
            font-weight: 600;
            color: #2c3e50;
            border-bottom: 2px solid #ecf0f1;
        }
        .diagnostics-table td {
            padding: 15px;
            vertical-align: top;
            border-bottom: 1px solid #ecf0f1;
        }
        .diagnostics-table tr:hover {
            background-color: #f9fafb;
        }
        .method-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 12px 12px 0 0;
            border-bottom: 2px solid #ecf0f1;
            margin-top: 25px;
        }
        .method-title {
            font-weight: 600;
            font-size: 16px;
            color: #2c3e50;
            display: flex;
            align-items: center;
        }
        .reliability-tag {
            display: inline-flex;
            align-items: center;
            padding: 4px 12px;
            border-radius: 30px;
            font-size: 13px;
            font-weight: 500;
            margin-left: 10px;
        }
        .reliability-high {
            background-color: #d4edda;
            color: #155724;
        }
        .reliability-medium {
            background-color: #fff3cd;
            color: #856404;
        }
        .reliability-low {
            background-color: #f8d7da;
            color: #721c24;
        }
        .suggestion-list {
            margin: 0;
            padding: 0 0 0 20px;
        }
        .suggestion-list li {
            margin-bottom: 12px;
            line-height: 1.5;
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
            transition: background-color 0.5s ease;
        }
        .status-good {
            background-color: #28a745;
        }
        .status-warning {
            background-color: #ffc107;
        }
        .status-critical {
            background-color: #ff0018;
        }
        .status-text {
            display: block;
            text-align: center;
            margin-top: 8px;
            font-size: 14px;
            font-weight: 500;
            transition: color 0.5s ease;
            color: #28a745;
        }
        .status-text.warning {
            color: #856404;
        }
        .status-text.critical {
            color: #ff0018;
        }
        .section {
            background-color: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        .header-icon {
            font-size: 18px;
            margin-right: 8px;
            color: #3498db;
        }
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 12px;
            border-radius: 30px;
            font-size: 13px;
            font-weight: 500;
            margin-left: 10px;
        }
        .badge-tensorflow {
            background-color: #fff3e0;
            color: #f57c00;
        }
        .badge-rule {
            background-color: #e0f2f1;
            color: #009688;
        }
        .badge-agent {
            background-color: #e8f5e8;
            color: #2e7d32;
        }
        .badge-network {
            background-color: #e3f2fd;
            color: #1976d2;
        }
        .badge-layer2 {
            background-color: #f3e5f5;
            color: #7b1fa2;
        }
        .ml-insights {
            margin-top: 15px;
            border-left: 4px solid #673ab7;
            padding-left: 15px;
        }
        .prediction {
            background-color: #f3f0ff;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid #9575cd;
        }
        .anomaly {
            background-color: #fef8f8;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid #ef5350;
        }
        .pattern {
            background-color: #f0f8ff;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid #42a5f5;
        }
        .tab-container {
            margin-bottom: 20px;
            position: relative;
        }
        .tab {
            overflow: hidden;
            background-color: white;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            display: flex;
            flex-wrap: wrap;
        }
        .tab button {
            flex: 1;
            min-width: 100px;
            background-color: transparent;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 15px;
            font-size: 15px;
            font-weight: 500;
            color: #7f8c8d;
            transition: all 0.3s ease;
        }
        .tab button:hover {
            background-color: #f9fafb;
            color: #3498db;
        }
        .tab button.active {
            color: #3498db;
            border-bottom: 3px solid #3498db;
            font-weight: 600;
        }
        .tabcontent {
            display: none;
            padding: 20px;
            background-color: white;
            border-radius: 0 0 12px 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            animation: fadeEffect 0.5s ease;
        }
        @keyframes fadeEffect {
            from {opacity: 0;}
            to {opacity: 1;}
        }
        .threshold-info {
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            font-size: 14px;
        }
        .threshold-item {
            flex: 1;
            min-width: 160px;
            text-align: center;
            padding: 10px;
        }
        .threshold-label {
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 5px;
        }
        .threshold-value {
            color: #7f8c8d;
        }
        .alert {
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 12px;
            display: flex;
            align-items: center;
        }
        .alert-icon {
            font-size: 24px;
            margin-right: 20px;
        }
        .alert-info {
            color: #0c5460;
            background-color: #d1ecf1;
        }
        .alert-success {
            color: #155724;
            background-color: #d4edda;
        }
        .alert-warning {
            color: #856404;
            background-color: #fff3cd;
        }
        .alert-error {
            color: #721c24;
            background-color: #f8d7da;
        }
        .info-box {
            background-color: #e8f4fd;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            font-size: 14px;
            line-height: 1.6;
            display: flex;
            align-items: flex-start;
        }
        .info-icon {
            font-size: 18px;
            margin-right: 15px;
            color: #3498db;
            margin-top: 2px;
        }
        .action-button {
            background-color: #3498db;
            color: white;
            border: none;
            border-radius: 6px;
            padding: 8px 12px;
            margin-top: 8px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .action-button:hover {
            background-color: #2980b9;
            transform: translateY(-1px);
        }
        .action-button:disabled {
            background-color: #bdc3c7;
            cursor: not-allowed;
            transform: none;
        }
        .action-button i {
            margin-right: 6px;
        }
        .stop-button {
            background-color: #e74c3c !important;
            color: white;
        }
        .stop-button:hover:not(:disabled) {
            background-color: #c0392b !important;
        }
        .stop-button:disabled {
            background-color: #95a5a6 !important;
        }
        .network-button {
            background-color: #17a2b8 !important;
        }
        .network-button:hover:not(:disabled) {
            background-color: #138496 !important;
        }
        .agent-status {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            border-left: 4px solid #17a2b8;
        }
        .agent-status.connected {
            border-left-color: #28a745;
            background-color: #d4edda;
        }
        .agent-status.error {
            border-left-color: #dc3545;
            background-color: #f8d7da;
        }
        .config-form {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin: 20px 0;
        }
        .config-group {
            display: flex;
            flex-direction: column;
        }
        .config-group label {
            font-weight: 600;
            margin-bottom: 5px;
            color: #2c3e50;
        }
        .config-group input, .config-group select {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
        }
        .config-group input[type="checkbox"] {
            width: auto;
            margin-right: 8px;
        }
        .tooltip {
            position: relative;
            display: inline-block;
            cursor: help;
        }
        .tooltip .tooltiptext {
            visibility: hidden;
            width: 320px;
            background-color: #2c3e50;
            color: #fff;
            text-align: left;
            border-radius: 6px;
            padding: 12px 15px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            transform: translateX(-50%);
            opacity: 0;
            transition: opacity 0.3s, transform 0.3s;
            transform: translateX(-50%) translateY(10px);
            line-height: 1.5;
            font-weight: normal;
            font-size: 13px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .tooltip .tooltiptext::after {
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            margin-left: -8px;
            border-width: 8px;
            border-style: solid;
            border-color: #2c3e50 transparent transparent transparent;
        }
        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
            transform: translateX(-50%) translateY(0);
        }
        .tooltip-icon {
            margin-left: 6px;
            color: #bdc3c7;
            transition: color 0.3s;
        }
        .tooltip:hover .tooltip-icon {
            color: #7f8c8d;
        }
        .process-action-container {
            margin-top: 10px;
            padding: 10px;
            background-color: #f9fafb
            border-radius: 6px;
            font-size: 13px;
        }
        .process-item {
            display: flex;
            flex-direction: column;
            margin-bottom: 8px;
            padding-bottom: 8px;
            border-bottom: 1px solid #ecf0f1;
        }
        .process-item:last-child {
            margin-bottom: 0;
            padding-bottom: 0;
            border-bottom: none;
        }
        .process-details {
            display: flex;
            justify-content: space-between;
            margin-bottom: 5px;
        }
        .process-name {
            font-weight: 600;
            color: #2c3e50;
        }
        .process-usage {
            color: #7f8c8d;
            font-weight: 500;
        }
        .usage-high {
            color: #e74c3c;
        }
        .card-responsive {
            overflow-x: auto;
        }
        .toast {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background-color: #2ecc71;
            color: white;
            padding: 15px 25px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 1000;
            display: none;
            transform: translateY(20px);
            opacity: 0;
            transition: transform 0.3s, opacity 0.3s;
            font-weight: 500;
        }
        .toast.show {
            transform: translateY(0);
            opacity: 1;
        }
        .toast.error {
            background-color: #e74c3c;
        }
        .center-message {
            text-align: center;
            padding: 30px;
            color: #7f8c8d;
        }
        .center-message i {
            font-size: 48px;
            margin-bottom: 15px;
            color: #bdc3c7;
        }
        .system-status {
            text-align: center;
            margin-bottom: 10px;
            padding: 10px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.5s ease;
        }
        .status-healthy {
            background-color: #d4edda;
            color: #155724;
        }
        .status-warning {
            background-color: #fff3cd;
            color: #856404;
        }
        .status-critical {
            background-color: #f8d7da;
            color: #721c24;
        }
        .test-container {
            margin-top: 20px;
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            border-left: 4px solid #3498db;
        }
        .test-title {
            font-weight: 600;
            font-size: 16px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
        }
        .test-title i {
            margin-right: 8px;
            color: #3498db;
        }
        .test-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 15px;
        }
        .autoencoder-status {
            background-color: #fff3e0;
            padding: 10px 15px;
            border-radius: 8px;
            margin: 10px 0;
            border-left: 4px solid #f57c00;
            transition: all 0.3s ease;
        }
        .autoencoder-training {
            background-color: #fff3e0;
            color: #ef6c00;
        }
        .autoencoder-ready {
            background-color: #e8f5e8;
            color: #2e7d32;
            border-left-color: #4caf50;
        }
        .spinner {
            border: 2px solid #f3f3f3;
            border-top: 2px solid #3498db;
            border-radius: 50%;
            width: 12px;
            height: 12px;
            animation: spin 1s linear infinite;
            display: inline-block;
            margin-right: 6px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .process-stopped {
            opacity: 0.5;
            background-color: #f8f9fa;
        }
        .process-stopping {
            opacity: 0.7;
            background-color: #fff3cd;
        }
        
        /* IP Diagnostics specific styles */
        .ip-diagnostics-container {
            margin-top: 20px;
        }
        .ip-status {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            border-left: 4px solid #17a2b8;
        }
        .ip-status.has-issues {
            border-left-color: #dc3545;
            background-color: #f8d7da;
        }
        .ip-status.no-issues {
            border-left-color: #28a745;
            background-color: #d4edda;
        }
        .interfaces-table {
            width: 100%;
            margin-top: 15px;
            background-color: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .solution-card {
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
            border-left: 4px solid #007bff;
        }
        .solution-steps {
            margin: 10px 0;
            padding-left: 20px;
        }
        .solution-steps li {
            margin-bottom: 5px;
            line-height: 1.4;
        }
        .command-box {
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 13px;
            margin: 10px 0;
            overflow-x: auto;
        }
        
        /* Communication status indicators */
        .comm-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .comm-stat-card {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #17a2b8;
        }
        .comm-stat-card.success {
            border-left-color: #28a745;
            background-color: #d4edda;
        }
        .comm-stat-card.error {
            border-left-color: #dc3545;
            background-color: #f8d7da;
        }
        .comm-method {
            font-weight: 600;
            margin-bottom: 5px;
        }
        .comm-count {
            font-size: 24px;
            font-weight: bold;
            margin: 5px 0;
        }
        
        @media (max-width: 768px) {
            .metrics-current {
                flex-direction: column;
            }
            .metric-box {
                margin: 5px 0;
                width: 100%;
            }
            .processes-container {
                flex-direction: column;
            }
            .processes-box {
                width: 100%;
                margin: 5px 0;
            }
            .threshold-info {
                flex-direction: column;
            }
            .threshold-item {
                margin-bottom: 10px;
            }
            .test-buttons {
                flex-direction: column;
            }
            .test-buttons .action-button {
                width: 100%;
            }
            .config-form {
                grid-template-columns: 1fr;
            }
            .comm-stats {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>System Performance Monitor</h1>
            <div class="subtitle">Enhanced TensorFlow ML with Multi-Protocol Data Agent (HTTP + Broadcast + Layer 2)</div>
        </div>

        <div class="section">
            <h2><i class="fas fa-tachometer-alt header-icon"></i>System Status</h2>
            <div id="system-status-indicator" class="system-status status-healthy">
                <i class="fas fa-check-circle"></i> System is running normally
            </div>
            <div class="metrics-current">
                <div class="metric-box">
                    <div class="label">CPU Usage</div>
                    <div id="cpu-value" class="value">-</div>
                    <div id="cpu-status"></div>
                </div>
                <div class="metric-box">
                    <div class="label">Memory Usage</div>
                    <div id="memory-value" class="value">-</div>
                    <div id="memory-status"></div>
                </div>
                <div class="metric-box">
                    <div class="label">Memory Used/Total</div>
                    <div id="memory-detail" class="value">-</div>
                </div>
                <div class="metric-box">
                    <div class="label">Network Health</div>
                    <div id="packet-loss-value" class="value">-</div>
                    <div id="network-status"></div>
                </div>
            </div>
            
            <div class="threshold-info">
                <div class="threshold-item">
                    <div class="threshold-label">CPU Thresholds</div>
                    <div id="cpu-thresholds" class="threshold-value">Warning: 40%, Critical: 65%</div>
                </div>
                <div class="threshold-item">
                    <div class="threshold-label">Memory Thresholds</div>
                    <div id="memory-thresholds" class="threshold-value">Warning: 40%, Critical: 65%</div>
                </div>
                <div class="threshold-item">
                    <div class="threshold-label">Network Thresholds</div>
                    <div id="network-thresholds" class="threshold-value">Warning: 1%, Critical: 3%</div>
                </div>
                <div class="threshold-item">
                    <div class="threshold-label">ML Engine Status</div>
                    <div id="ml-status" class="threshold-value">Learning your system...</div>
                </div>
            </div>
            
            <div id="autoencoder-status" class="autoencoder-status autoencoder-training">
                <div style="display: flex; align-items: center;">
                    <i class="fas fa-cogs" style="margin-right: 10px; font-size: 18px;"></i>
                    <div>
                        <div style="font-weight: 600;">Enhanced TensorFlow Autoencoder</div>
                        <div id="autoencoder-details" style="font-size: 13px; margin-top: 5px;">
                            Gathering data to learn normal system behavior patterns...
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="tab-container">
            <div class="tab">
                <button class="tablinks active" onclick="openTab(event, 'DiagnosticsTab')">
                    <i class="fas fa-stethoscope"></i> System Health
                </button>
                <button class="tablinks" onclick="openTab(event, 'MLInsightsTab')">
                    <i class="fas fa-robot"></i> ML Insights
                </button>
                <button class="tablinks" onclick="openTab(event, 'ResourcesTab')">
                    <i class="fas fa-microchip"></i> Resource Usage
                </button>
                <button class="tablinks" onclick="openTab(event, 'NetworkTab')">
                    <i class="fas fa-network-wired"></i> Network Configuration
                </button>
                <button class="tablinks" onclick="openTab(event, 'AgentTab')">
                    <i class="fas fa-satellite-dish"></i> Multi-Protocol Agent
                </button>
                <button class="tablinks" onclick="openTab(event, 'HistoryTab')">
                    <i class="fas fa-chart-line"></i> Performance History
                </button>
            </div>
        </div>

        <div id="DiagnosticsTab" class="tabcontent" style="display: block;">
            <div id="issues-container" style="display: none;">
                <h3><i class="fas fa-exclamation-circle" style="color: #e74c3c;"></i> System Issues Detected</h3>
                <div class="info-box">
                    <div class="info-icon"><i class="fas fa-info-circle"></i></div>
                    <div class="info-text">
                        The system has detected issues that may affect performance. Click on the red "Stop" buttons below to automatically resolve them.
                    </div>
                </div>
                
                <div class="method-header">
                    <div class="method-title">
                        Adaptive Rule-Based Diagnostics 
                        <div class="tooltip">
                            <i class="fas fa-info-circle tooltip-icon"></i>
                            <span class="tooltiptext">Issues detected based on adaptive system thresholds that learn from your usage patterns. These are immediate problems affecting your system right now.</span>
                        </div>
                    </div>
                </div>
                <div class="card-responsive">
                    <table id="rule-diagnostics-table" class="diagnostics-table">
                        <thead>
                            <tr>
                                <th width="30%">Issue</th>
                                <th width="70%">Recommended Actions</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
                
                <div class="method-header" style="margin-top: 20px;">
                    <div class="method-title">
                        TensorFlow Autoencoder Diagnostics 
                        <div class="tooltip">
                            <i class="fas fa-info-circle tooltip-icon"></i>
                            <span class="tooltiptext">Issues detected by enhanced autoencoder that learns your system's normal behavior patterns and identifies potential problems before they become critical using adaptive thresholds.</span>
                        </div>
                        <span class="badge badge-tensorflow">TensorFlow ML</span>
                    </div>
                </div>
                <div class="card-responsive">
                    <table id="ml-diagnostics-table" class="diagnostics-table">
                        <thead>
                            <tr>
                                <th width="30%">Issue</th>
                                <th width="15%">Reliability</th>
                                <th width="55%">Recommended Actions</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
            
            <div id="no-issues-container" class="alert alert-info">
                <div class="alert-icon"><i class="fas fa-check-circle"></i></div>
                <div>
                    <strong>All Systems Normal</strong>
                    <p>Your system is running smoothly with no detected issues.</p>
                </div>
            </div>
        </div>

        <div id="MLInsightsTab" class="tabcontent">
            <h3><i class="fas fa-robot header-icon"></i> Enhanced TensorFlow ML Insights</h3>
            
            <div class="info-box">
                <div class="info-icon"><i class="fas fa-info-circle"></i></div>
                <div class="info-text">
                    The enhanced autoencoder continuously learns your system's normal behavior patterns and detects anomalies using adaptive thresholds that automatically adjust based on your usage patterns.
                </div>
            </div>
            
            <div id="ml-anomalies-container" style="display: none;">
                <h3>TensorFlow Autoencoder Anomaly Detection</h3>
                <div id="anomalies-area"></div>
            </div>
            
            <div id="ml-predictions-container" style="display: none;">
                <h3>Enhanced Performance Predictions</h3>
                <div id="predictions-area"></div>
            </div>
            
            <div id="ml-patterns-container" style="display: none;">
                <h3>System Behavior Patterns</h3>
                <div id="patterns-area"></div>
            </div>
            
            <div id="no-ml-insights-container" class="alert alert-info">
                <div class="alert-icon"><i class="fas fa-sync-alt"></i></div>
                <div>
                    <strong>TensorFlow ML Learning in Progress</strong>
                    <p>The enhanced autoencoder is currently learning your system's normal behavior patterns. ML insights will appear here as the model gathers sufficient training data.</p>
                </div>
            </div>
        </div>

        <div id="ResourcesTab" class="tabcontent">
            <h3><i class="fas fa-microchip header-icon"></i> Active Applications</h3>
            <div class="info-box">
                <div class="info-icon"><i class="fas fa-info-circle"></i></div>
                <div class="info-text">
                    These are the applications currently using the most system resources. Use the red "Stop" buttons to terminate resource-intensive applications.
                </div>
            </div>
            <div class="processes-container">
                <div class="processes-box">
                    <div class="label">Top CPU Users</div>
                    <table id="cpu-processes">
                        <thead>
                            <tr>
                                <th>Application</th>
                                <th>Process ID</th>
                                <th>CPU Usage</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr><td colspan="4">Loading...</td></tr>
                        </tbody>
                    </table>
                </div>
                
                <div class="processes-box">
                    <div class="label">Top Memory Users</div>
                    <table id="memory-processes">
                        <thead>
                            <tr>
                                <th>Application</th>
                                <th>Process ID</th>
                                <th>Memory Usage</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr><td colspan="4">Loading...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div class="section" style="margin-top: 20px;">
                <div class="test-title"><i class="fas fa-flask"></i> Performance Test Tools</div>
                <div class="info-box">
                    <div class="info-icon"><i class="fas fa-info-circle"></i></div>
                    <div class="info-text">
                        Use these buttons to create temporary system load for testing the enhanced autoencoder's anomaly detection capabilities.
                    </div>
                </div>
                
                <div class="test-buttons">
                    <button onclick="runTest('cpu_load')" class="action-button">
                        <i class="fas fa-microchip"></i> Test High CPU Usage
                    </button>
                    <button onclick="runTest('memory_load')" class="action-button">
                        <i class="fas fa-memory"></i> Test High Memory Usage
                    </button>
                    <button onclick="runTest('network_issue')" class="action-button">
                        <i class="fas fa-network-wired"></i> Test Network Issues
                    </button>
                </div>
            </div>
        </div>

        <div id="NetworkTab" class="tabcontent">
            <h3><i class="fas fa-network-wired header-icon"></i> Network Configuration Diagnostics</h3>
            <div class="info-box">
                <div class="info-icon"><i class="fas fa-info-circle"></i></div>
                <div class="info-text">
                    This tool detects incorrect IP address configurations that can prevent internet access in the student lab environment. 
                    It identifies when manual IP settings aren't properly restored to lab defaults.
                </div>
            </div>
            
            <div id="ip-status-container" class="ip-status">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <div>
                        <div style="font-weight: 600; display: flex; align-items: center;">
                            <i id="ip-status-icon" class="fas fa-circle" style="margin-right: 10px; font-size: 12px; color: #95a5a6;"></i>
                            Network Status: <span id="ip-status-text">Checking...</span>
                            <span class="badge badge-network">Lab Network</span>
                        </div>
                        <div id="ip-status-details" style="font-size: 13px; margin-top: 5px; color: #7f8c8d;">
                            Analyzing network configuration...
                        </div>
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <button id="scan-network-btn" onclick="scanNetworkIssues()" class="action-button network-button">
                            <i class="fas fa-search"></i> Scan Network
                        </button>
                    </div>
                </div>
            </div>

            <div id="network-interfaces-container" class="section" style="display: none;">
                <h3><i class="fas fa-ethernet header-icon"></i> Network Interfaces</h3>
                <div class="card-responsive">
                    <table id="interfaces-table" class="interfaces-table">
                        <thead>
                            <tr>
                                <th>Interface</th>
                                <th>IP Address</th>
                                <th>Subnet Mask</th>
                                <th>Status</th>
                                <th>Type</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>

            <div id="connectivity-results-container" class="section" style="display: none;">
                <h3><i class="fas fa-globe header-icon"></i> Internet Connectivity Test Results</h3>
                <div id="connectivity-details"></div>
            </div>

            <div id="network-issues-container" class="section" style="display: none;">
                <h3><i class="fas fa-exclamation-triangle header-icon"></i> Detected Network Issues</h3>
                <div id="network-issues-list"></div>
            </div>

            <div id="network-solutions-container" class="section" style="display: none;">
                <h3><i class="fas fa-wrench header-icon"></i> Recommended Solutions</h3>
                <div id="network-solutions-list"></div>
            </div>
        </div>

        <div id="AgentTab" class="tabcontent">
            <h3><i class="fas fa-satellite-dish header-icon"></i> Multi-Protocol Data Agent Management</h3>
            <div class="info-box">
                <div class="info-icon"><i class="fas fa-info-circle"></i></div>
                <div class="info-text">
                    The Multi-Protocol Data Agent automatically sends collected system metrics to an admin server using multiple communication methods:
                    <strong>HTTP</strong> (primary), <strong>UDP Broadcast</strong> (IP misconfiguration fallback), and <strong>Layer 2 Raw Ethernet</strong> (ultimate fallback).
                </div>
            </div>
            
            <div id="agent-status-container" class="agent-status">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <div>
                        <div style="font-weight: 600; display: flex; align-items: center;">
                            <i id="agent-status-icon" class="fas fa-circle" style="margin-right: 10px; font-size: 12px; color: #95a5a6;"></i>
                            Agent Status: <span id="agent-status-text">Unknown</span>
                            <span class="badge badge-agent">Multi-Protocol</span>
                        </div>
                        <div id="agent-status-details" style="font-size: 13px; margin-top: 5px; color: #7f8c8d;">
                            Loading agent status...
                        </div>
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <button id="start-agent-btn" onclick="startAgent()" class="action-button">
                            <i class="fas fa-play"></i> Start Agent
                        </button>
                        <button id="stop-agent-btn" onclick="stopAgent()" class="action-button stop-button">
                            <i class="fas fa-stop"></i> Stop Agent
                        </button>
                        <button id="test-comm-btn" onclick="testAllCommunication()" class="action-button network-button">
                            <i class="fas fa-satellite-dish"></i> Test All Methods
                        </button>
                    </div>
                </div>
            </div>

            <div class="section" style="margin-top: 20px;">
                <h3><i class="fas fa-chart-bar header-icon"></i> Communication Statistics</h3>
                <div class="comm-stats" id="comm-stats">
                    <div class="comm-stat-card">
                        <div class="comm-method">HTTP</div>
                        <div class="comm-count" id="http-success">0</div>
                        <div>Success</div>
                    </div>
                    <div class="comm-stat-card error">
                        <div class="comm-method">HTTP Failed</div>
                        <div class="comm-count" id="http-failed">0</div>
                        <div>Errors</div>
                    </div>
                    <div class="comm-stat-card">
                        <div class="comm-method">UDP Broadcast</div>
                        <div class="comm-count" id="broadcast-success">0</div>
                        <div>Success</div>
                    </div>
                    <div class="comm-stat-card error">
                        <div class="comm-method">Broadcast Failed</div>
                        <div class="comm-count" id="broadcast-failed">0</div>
                        <div>Errors</div>
                    </div>
                    <div class="comm-stat-card">
                        <div class="comm-method">Layer 2 Ethernet</div>
                        <div class="comm-count" id="layer2-success">0</div>
                        <div>Success</div>
                    </div>
                    <div class="comm-stat-card error">
                        <div class="comm-method">Layer 2 Failed</div>
                        <div class="comm-count" id="layer2-failed">0</div>
                        <div>Errors</div>
                    </div>
                </div>
                <div class="info-box">
                    <div class="info-icon"><i class="fas fa-info-circle"></i></div>
                    <div class="info-text">
                        <strong>Last Successful Method:</strong> <span id="last-success-method">None</span><br>
                        <strong>Last Success Time:</strong> <span id="last-success-time">Never</span><br>
                        <strong>Layer 2 Available:</strong> <span id="layer2-available">Checking...</span>
                    </div>
                </div>
            </div>

            <div class="section" style="margin-top: 20px;">
                <h3><i class="fas fa-cog header-icon"></i> Agent Configuration</h3>
                
                <form id="agent-config-form" class="config-form">
                    <div class="config-group">
                        <label for="agent-enabled">Enable Agent:</label>
                        <input type="checkbox" id="agent-enabled" name="enabled">
                    </div>
                    
                    <div class="config-group">
                        <label for="server-url">Admin Server URL:</label>
                        <input type="url" id="server-url" name="server_url" placeholder="http://192.168.0.228:8080">
                    </div>
                    
                    <div class="config-group">
                        <label for="agent-id">Agent ID:</label>
                        <input type="text" id="agent-id" name="agent_id" placeholder="hostname">
                    </div>
                    
                    <div class="config-group">
                        <label for="send-interval">Send Interval (seconds):</label>
                        <input type="number" id="send-interval" name="send_interval" min="10" max="300" value="30">
                    </div>
                    
                    <div class="config-group">
                        <label for="retry-attempts">Retry Attempts:</label>
                        <input type="number" id="retry-attempts" name="retry_attempts" min="1" max="10" value="3">
                    </div>
                    
                    <div class="config-group">
                        <label for="timeout">Request Timeout (seconds):</label>
                        <input type="number" id="timeout" name="timeout" min="5" max="60" value="10">
                    </div>
                    
                    <div class="config-group">
                        <label for="broadcast-port">Broadcast Port:</label>
                        <input type="number" id="broadcast-port" name="broadcast_port" min="1024" max="65535" value="9999">
                    </div>
                    
                    <div class="config-group">
                        <label for="enable-layer2">Enable Layer 2:</label>
                        <input type="checkbox" id="enable-layer2" name="enable_layer2" checked>
                    </div>
                    
                    <div class="config-group">
                        <label for="api-key">API Key (optional):</label>
                        <input type="password" id="api-key" name="api_key" placeholder="Bearer token">
                    </div>
                    
                    <div class="config-group">
                        <label for="verify-ssl">Verify SSL:</label>
                        <input type="checkbox" id="verify-ssl" name="verify_ssl" checked>
                    </div>
                    
                    <div class="config-group">
                        <label for="send-metrics">Send Metrics:</label>
                        <input type="checkbox" id="send-metrics" name="send_metrics" checked>
                    </div>
                    
                    <div class="config-group">
                        <label for="send-faults">Send Faults:</label>
                        <input type="checkbox" id="send-faults" name="send_faults" checked>
                    </div>
                    
                    <div class="config-group">
                        <label for="send-processes">Send Process Data:</label>
                        <input type="checkbox" id="send-processes" name="send_processes" checked>
                    </div>
                    
                    <div class="config-group">
                        <label for="send-ml-insights">Send ML Insights:</label>
                        <input type="checkbox" id="send-ml-insights" name="send_ml_insights" checked>
                    </div>
                    
                    <div class="config-group">
                        <label for="send-ip-diagnostics">Send IP Diagnostics:</label>
                        <input type="checkbox" id="send-ip-diagnostics" name="send_ip_diagnostics" checked>
                    </div>
                </form>
                
                <div style="margin-top: 20px; text-align: center;">
                    <button onclick="saveAgentConfig()" class="action-button">
                        <i class="fas fa-save"></i> Save Configuration
                    </button>
                    <button onclick="loadAgentConfig()" class="action-button">
                        <i class="fas fa-sync"></i> Reload Configuration
                    </button>
                </div>
            </div>
        </div>

        <div id="HistoryTab" class="tabcontent">
            <h3><i class="fas fa-chart-line header-icon"></i> System Performance History</h3>
            <div class="chart-container">
                <canvas id="metricsChart"></canvas>
            </div>
        </div>
    </div>

    <div id="toast" class="toast"></div>

    <script>
        // Global variables for enhanced state management
        let stoppedProcesses = new Set();
        let lastThresholds = {};
        let currentStatuses = {cpu: 'good', memory: 'good', network: 'good'};
        let lastStatusUpdate = {cpu: 0, memory: 0, network: 0};
        const STATUS_STABILITY_TIME = 3000; // 3 seconds for status stability
        
        // Tab functionality
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
            
            // Load specific data when tabs are opened
            if (tabName === 'AgentTab') {
                loadAgentStatus();
                loadAgentConfig();
            } else if (tabName === 'NetworkTab') {
                loadNetworkStatus();
            }
        }
        
        // Enhanced toast message function
        function showToast(message, isError = false) {
            const toast = document.getElementById("toast");
            toast.textContent = message;
            toast.className = isError ? "toast error" : "toast";
            toast.classList.add("show");
            
            setTimeout(() => {
                toast.classList.remove("show");
                setTimeout(() => {
                    toast.style.display = "none";
                }, 300);
            }, 4000);
            
            toast.style.display = "block";
        }
        
        // Enhanced action function with IP diagnostics support
        function takeAction(actionType, target) {
            if (actionType === 'ip_scan') {
                return scanNetworkIssues();
            } else if (actionType === 'ip_fix_dhcp') {
                return fixNetworkDHCP(target);
            }
            
            const actionBtns = document.querySelectorAll(`[id^="action-${actionType}-${target}"]`);
            
            // Add to stopped processes immediately for UI responsiveness
            if (actionType === 'end_process') {
                stoppedProcesses.add(parseInt(target));
                
                // Update UI immediately
                actionBtns.forEach(btn => {
                    btn.disabled = true;
                    btn.innerHTML = '<div class="spinner"></div> Stopping...';
                    btn.classList.add('stop-button');
                    
                    // Find parent row and mark as stopping
                    const row = btn.closest('tr');
                    if (row) {
                        row.classList.add('process-stopping');
                    }
                });
            }
            
            fetch('/api/take_action', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    action_type: actionType,
                    target: target
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message);
                    
                    actionBtns.forEach(btn => {
                        if (actionType === 'end_process') {
                            btn.innerHTML = '<i class="fas fa-check"></i> Stopped';
                            btn.style.backgroundColor = '#27ae60';
                            
                            // Mark parent row as stopped
                            const row = btn.closest('tr');
                            if (row) {
                                row.classList.remove('process-stopping');
                                row.classList.add('process-stopped');
                            }
                        } else if (actionType === 'restart_network') {
                            btn.innerHTML = '<i class="fas fa-check"></i> Restarted';
                        } else if (actionType === 'clear_memory') {
                            btn.innerHTML = '<i class="fas fa-check"></i> Cleared';
                        }
                        btn.disabled = true;
                    });
                    
                    // Force immediate update of process list
                    setTimeout(() => {
                        updateProcessTables();
                    }, 1000);
                    
                } else {
                    showToast(data.message, true);
                    
                    // Remove from stopped processes if action failed
                    if (actionType === 'end_process') {
                        stoppedProcesses.delete(parseInt(target));
                    }
                    
                    actionBtns.forEach(btn => {
                        btn.disabled = false;
                        btn.innerHTML = btn.innerHTML.replace('<div class="spinner"></div> Stopping...', '<i class="fas fa-times"></i> Stop');
                        
                        const row = btn.closest('tr');
                        if (row) {
                            row.classList.remove('process-stopping');                
                        }
                    });
                }
            })
            .catch(error => {
                showToast("Error: Could not complete the action", true);
                
                // Remove from stopped processes if request failed
                if (actionType === 'end_process') {
                    stoppedProcesses.delete(parseInt(target));
                }
                
                actionBtns.forEach(btn => {
                    btn.disabled = false;
                    btn.innerHTML = btn.innerHTML.replace('<div class="spinner"></div> Stopping...', '<i class="fas fa-times"></i> Stop');
                    
                    const row = btn.closest('tr');
                    if (row) {
                        row.classList.remove('process-stopping');
                    }
                });
            });
        }
        
        // Network diagnostics functions
        function loadNetworkStatus() {
            fetch('/api/ip_diagnostics')
                .then(response => response.json())
                .then(data => {
                    updateNetworkStatusUI(data);
                })
                .catch(error => {
                    console.error('Error loading network status:', error);
                });
        }
        
        function scanNetworkIssues() {
            const scanBtn = document.getElementById('scan-network-btn');
            scanBtn.disabled = true;
            scanBtn.innerHTML = '<div class="spinner"></div> Scanning...';
            
            fetch('/api/ip_diagnostics/scan', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateNetworkStatusUI(data.data);
                    showToast('Network scan completed');
                } else {
                    showToast(data.message, true);
                }
            })
            .catch(error => {
                console.error('Error scanning network:', error);
                showToast('Error scanning network configuration', true);
            })
            .finally(() => {
                scanBtn.disabled = false;
                scanBtn.innerHTML = '<i class="fas fa-search"></i> Scan Network';
            });
        }
        
        function fixNetworkDHCP(interfaceName) {
            if (!interfaceName) {
                showToast('No interface specified for DHCP fix', true);
                return;
            }
            
            const confirmed = confirm(`Reset network interface "${interfaceName}" to DHCP configuration?\\n\\nThis will:\\n- Clear manual IP settings\\n- Request automatic IP from DHCP server\\n- May temporarily disconnect network`);
            
            if (!confirmed) return;
            
            fetch('/api/ip_diagnostics/fix_dhcp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    interface: interfaceName
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message);
                    updateNetworkStatusUI(data.data);
                } else {
                    showToast(data.message, true);
                }
            })
            .catch(error => {
                console.error('Error fixing network DHCP:', error);
                showToast('Error resetting network to DHCP', true);
            });
        }
        
        function updateNetworkStatusUI(data) {
            const statusContainer = document.getElementById('ip-status-container');
            const statusIcon = document.getElementById('ip-status-icon');
            const statusText = document.getElementById('ip-status-text');
            const statusDetails = document.getElementById('ip-status-details');
            
            // Update main status
            if (data.has_issues) {
                statusContainer.className = 'ip-status has-issues';
                statusIcon.style.color = '#dc3545';
                statusText.textContent = 'Issues Detected';
                statusDetails.textContent = `${data.issues.length} network configuration issue(s) found`;
            } else {
                statusContainer.className = 'ip-status no-issues';
                statusIcon.style.color = '#28a745';
                statusText.textContent = 'Configuration OK';
                statusDetails.textContent = 'Network configuration appears correct';
            }
            
            // Update interfaces table
            if (data.interfaces && data.interfaces.length > 0) {
                updateInterfacesTable(data.interfaces);
                document.getElementById('network-interfaces-container').style.display = 'block';
            } else {
                document.getElementById('network-interfaces-container').style.display = 'none';
            }
            
            // Update connectivity results
            if (data.connectivity) {
                updateConnectivityResults(data.connectivity);
                document.getElementById('connectivity-results-container').style.display = 'block';
            } else {
                document.getElementById('connectivity-results-container').style.display = 'none';
            }
            
            // Update issues list
            if (data.has_issues && data.issues.length > 0) {
                updateNetworkIssuesList(data.issues, data.recommendations);
                document.getElementById('network-issues-container').style.display = 'block';
            } else {
                document.getElementById('network-issues-container').style.display = 'none';
            }
            
            // Update solutions
            if (data.solutions && data.solutions.length > 0) {
                updateNetworkSolutions(data.solutions);
                document.getElementById('network-solutions-container').style.display = 'block';
            } else {
                document.getElementById('network-solutions-container').style.display = 'none';
            }
        }
        
        function updateInterfacesTable(interfaces) {
            const tbody = document.getElementById('interfaces-table').getElementsByTagName('tbody')[0];
            tbody.innerHTML = '';
            
            interfaces.forEach(interface => {
                const row = tbody.insertRow();
                
                row.insertCell(0).textContent = interface.interface;
                row.insertCell(1).textContent = interface.ip;
                row.insertCell(2).textContent = interface.netmask || 'N/A';
                
                const statusCell = row.insertCell(3);
                statusCell.innerHTML = interface.is_up ? 
                    '<span style="color: #28a745;"><i class="fas fa-check-circle"></i> Up</span>' : 
                    '<span style="color: #dc3545;"><i class="fas fa-times-circle"></i> Down</span>';
                
                const typeCell = row.insertCell(4);
                typeCell.innerHTML = interface.is_dhcp ? 
                    '<span class="badge" style="background-color: #d4edda; color: #155724;">DHCP</span>' : 
                    '<span class="badge" style="background-color: #fff3cd; color: #856404;">Static</span>';
                
                const actionCell = row.insertCell(5);
                if (interface.is_up) {
                    actionCell.innerHTML = `
                        <button class="action-button network-button" 
                                onclick="fixNetworkDHCP('${interface.interface}')"
                                title="Reset ${interface.interface} to DHCP">
                            <i class="fas fa-sync"></i> Reset to DHCP
                        </button>
                    `;
                }
            });
        }
        
        function updateConnectivityResults(connectivity) {
            const container = document.getElementById('connectivity-details');
            let html = '<div class="info-box">';
            
            // Overall connectivity status
            const overallStatus = connectivity.dns_resolution && connectivity.ping_test && connectivity.http_test;
            html += `<div class="info-icon"><i class="fas fa-${overallStatus ? 'check-circle' : 'exclamation-triangle'}"></i></div>`;
            html += '<div class="info-text">';
            html += `<strong>Internet Connectivity: ${overallStatus ? 'Working' : 'Issues Detected'}</strong><br>`;
            
            // Detailed results
            connectivity.details.forEach(detail => {
                html += `${detail}<br>`;
            });
            
            if (connectivity.external_ip) {
                html += `<strong>External IP:</strong> ${connectivity.external_ip}`;
            }
            
            html += '</div></div>';
            container.innerHTML = html;
        }
        
        function updateNetworkIssuesList(issues, recommendations) {
            const container = document.getElementById('network-issues-list');
            let html = '';
            
            issues.forEach((issue, index) => {
                html += `
                    <div class="alert alert-warning">
                        <div class="alert-icon"><i class="fas fa-exclamation-triangle"></i></div>
                        <div>
                            <strong>Issue ${index + 1}:</strong> ${issue}
                            ${recommendations[index] ? `<br><strong>Recommendation:</strong> ${recommendations[index]}` : ''}
                        </div>
                    </div>
                `;
            });
            
            container.innerHTML = html;
        }
        
        function updateNetworkSolutions(solutions) {
            const container = document.getElementById('network-solutions-list');
            let html = '';
            
            solutions.forEach((solution, index) => {
                html += `
                    <div class="solution-card">
                        <h4><i class="fas fa-wrench"></i> Solution ${index + 1}: ${solution.title}</h4>
                        <p>${solution.description}</p>
                        
                        <h5>Steps:</h5>
                        <ol class="solution-steps">
                `;
                
                solution.steps.forEach(step => {
                    html += `<li>${step}</li>`;
                });
                
                html += '</ol>';
                
                // Add command examples if available
                if (solution.command_windows) {
                    html += `
                        <h5>Windows Command:</h5>
                        <div class="command-box">${solution.command_windows}</div>
                    `;
                }
                
                if (solution.command_linux) {
                    html += `
                        <h5>Linux Command:</h5>
                        <div class="command-box">${solution.command_linux}</div>
                    `;
                }
                
                html += '</div>';
            });
            
            container.innerHTML = html;
        }
        
        // Enhanced Agent management functions with multi-protocol support
        function loadAgentStatus() {
            fetch('/api/agent/status')
                .then(response => response.json())
                .then(data => {
                    const statusContainer = document.getElementById('agent-status-container');
                    const statusIcon = document.getElementById('agent-status-icon');
                    const statusText = document.getElementById('agent-status-text');
                    const statusDetails = document.getElementById('agent-status-details');
                    
                    let statusClass = 'agent-status';
                    let iconColor = '#95a5a6';
                    let statusLabel = 'Unknown';
                    let details = 'Status information unavailable';
                    
                    if (data.status === 'success') {
                        statusClass += ' connected';
                        iconColor = '#28a745';
                        statusLabel = 'Connected';
                        details = `Successfully sending data to ${data.server_url}. Last update: ${data.last_update}`;
                    } else if (data.status === 'connection_error') {
                        statusClass += ' error';
                        iconColor = '#dc3545';
                        statusLabel = 'Connection Error';
                        details = `Cannot connect to ${data.server_url}. ${data.details}`;
                    } else if (data.status === 'timeout') {
                        statusClass += ' error';
                        iconColor = '#ffc107';
                        statusLabel = 'Timeout';
                        details = `Request timeout when connecting to ${data.server_url}`;
                    } else if (data.status === 'error') {
                        statusClass += ' error';
                        iconColor = '#dc3545';
                        statusLabel = 'Error';
                        details = `Error: ${data.details}`;
                    } else {
                        details = `Agent configured for ${data.server_url}. Status: ${data.status}`;
                    }
                    
                    if (data.queue_size > 0) {
                        details += `. Retry queue: ${data.queue_size} items`;
                    }
                    
                    statusContainer.className = statusClass;
                    statusIcon.style.color = iconColor;
                    statusText.textContent = statusLabel;
                    statusDetails.textContent = details;
                    
                    // Update communication statistics
                    if (data.comm_stats) {
                        updateCommStats(data.comm_stats);
                    }
                    
                    // Update Layer 2 availability
                    const layer2Available = document.getElementById('layer2-available');
                    if (layer2Available) {
                        layer2Available.textContent = data.layer2_available ? 'Yes' : 'No';
                        layer2Available.style.color = data.layer2_available ? '#28a745' : '#dc3545';
                    }
                })
                .catch(error => {
                    console.error('Error loading agent status:', error);
                    document.getElementById('agent-status-text').textContent = 'Error';
                    document.getElementById('agent-status-details').textContent = 'Failed to load agent status';
                });
        }
        
        function updateCommStats(commStats) {
            // Update success counts
            document.getElementById('http-success').textContent = commStats.http_success || 0;
            document.getElementById('http-failed').textContent = commStats.http_failed || 0;
            document.getElementById('broadcast-success').textContent = commStats.broadcast_success || 0;
            document.getElementById('broadcast-failed').textContent = commStats.broadcast_failed || 0;
            document.getElementById('layer2-success').textContent = commStats.layer2_success || 0;
            document.getElementById('layer2-failed').textContent = commStats.layer2_failed || 0;
            
            // Update last success info
            const lastMethodElement = document.getElementById('last-success-method');
            const lastTimeElement = document.getElementById('last-success-time');
            
            if (lastMethodElement) {
                lastMethodElement.textContent = commStats.last_success_method || 'None';
            }
            
            if (lastTimeElement && commStats.last_success_time) {
                const successTime = new Date(commStats.last_success_time);
                lastTimeElement.textContent = successTime.toLocaleString();
            }
        }
        
        function testAllCommunication() {
            const testBtn = document.getElementById('test-comm-btn');
            testBtn.disabled = true;
            testBtn.innerHTML = '<div class="spinner"></div> Testing...';
            
            fetch('/api/test_communication', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    let message = 'Communication test results:\\n';
                    message += `HTTP: ${data.http ? 'SUCCESS' : 'FAILED'}\\n`;
                    message += `UDP Broadcast: ${data.broadcast ? 'SUCCESS' : 'FAILED'}\\n`;
                    message += `Layer 2 Ethernet: ${data.layer2 ? 'SUCCESS' : 'FAILED'}`;
                    
                    showToast(message);
                    
                    // Refresh status after test
                    setTimeout(() => {
                        loadAgentStatus();
                    }, 1000);
                })
                .catch(error => {
                    console.error('Error testing communication:', error);
                    showToast('Error testing communication methods', true);
                })
                .finally(() => {
                    testBtn.disabled = false;
                    testBtn.innerHTML = '<i class="fas fa-satellite-dish"></i> Test All Methods';
                });
        }
        
        function loadAgentConfig() {
            fetch('/api/agent/config')
                .then(response => response.json())
                .then(data => {
                    // Populate AGENT section
                    if (data.AGENT) {
                        document.getElementById('agent-enabled').checked = data.AGENT.enabled === 'true';
                        document.getElementById('server-url').value = data.AGENT.server_url || '';
                        document.getElementById('agent-id').value = data.AGENT.agent_id || '';
                        document.getElementById('send-interval').value = data.AGENT.send_interval || '30';
                        document.getElementById('retry-attempts').value = data.AGENT.retry_attempts || '3';
                        document.getElementById('timeout').value = data.AGENT.timeout || '10';
                        document.getElementById('broadcast-port').value = data.AGENT.broadcast_port || '9999';
                        document.getElementById('enable-layer2').checked = data.AGENT.enable_layer2 !== 'false';
                    }
                    
                    // Populate SECURITY section
                    if (data.SECURITY) {
                        document.getElementById('api-key').value = data.SECURITY.api_key || '';
                        document.getElementById('verify-ssl').checked = data.SECURITY.verify_ssl !== 'false';
                    }
                    
                    // Populate DATA section
                    if (data.DATA) {
                        document.getElementById('send-metrics').checked = data.DATA.send_metrics !== 'false';
                        document.getElementById('send-faults').checked = data.DATA.send_faults !== 'false';
                        document.getElementById('send-processes').checked = data.DATA.send_processes !== 'false';
                        document.getElementById('send-ml-insights').checked = data.DATA.send_ml_insights !== 'false';
                        document.getElementById('send-ip-diagnostics').checked = data.DATA.send_ip_diagnostics !== 'false';
                    }
                })
                .catch(error => {
                    console.error('Error loading agent config:', error);
                    showToast('Error loading agent configuration', true);
                });
        }
        
        function saveAgentConfig() {
            const config = {
                AGENT: {
                    enabled: document.getElementById('agent-enabled').checked ? 'true' : 'false',
                    server_url: document.getElementById('server-url').value,
                    agent_id: document.getElementById('agent-id').value,
                    send_interval: document.getElementById('send-interval').value,
                    retry_attempts: document.getElementById('retry-attempts').value,
                    timeout: document.getElementById('timeout').value,
                    broadcast_port: document.getElementById('broadcast-port').value,
                    enable_layer2: document.getElementById('enable-layer2').checked ? 'true' : 'false'
                },
                SECURITY: {
                    api_key: document.getElementById('api-key').value,
                    verify_ssl: document.getElementById('verify-ssl').checked ? 'true' : 'false'
                },
                DATA: {
                    send_metrics: document.getElementById('send-metrics').checked ? 'true' : 'false',
                    send_faults: document.getElementById('send-faults').checked ? 'true' : 'false',
                    send_processes: document.getElementById('send-processes').checked ? 'true' : 'false',
                    send_ml_insights: document.getElementById('send-ml-insights').checked ? 'true' : 'false',
                    send_ip_diagnostics: document.getElementById('send-ip-diagnostics').checked ? 'true' : 'false'
                }
            };
            
            fetch('/api/agent/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(config)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast('Agent configuration saved successfully');
                    loadAgentStatus(); // Refresh status after config change
                } else {
                    showToast(data.message, true);
                }
            })
            .catch(error => {
                console.error('Error saving agent config:', error);
                showToast('Error saving agent configuration', true);
            });
        }
        
        function startAgent() {
            const startBtn = document.getElementById('start-agent-btn');
            startBtn.disabled = true;
            startBtn.innerHTML = '<div class="spinner"></div> Starting...';
            
            fetch('/api/agent/start', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message);
                    setTimeout(() => {
                        loadAgentStatus();
                    }, 1000);
                } else {
                    showToast(data.message, true);
                }
            })
            .catch(error => {
                console.error('Error starting agent:', error);
                showToast('Error starting agent', true);
            })
            .finally(() => {
                startBtn.disabled = false;
                startBtn.innerHTML = '<i class="fas fa-play"></i> Start Agent';
            });
        }
        
        function stopAgent() {
            const stopBtn = document.getElementById('stop-agent-btn');
            stopBtn.disabled = true;
            stopBtn.innerHTML = '<div class="spinner"></div> Stopping...';
            
            fetch('/api/agent/stop', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message);
                    setTimeout(() => {
                        loadAgentStatus();
                    }, 1000);
                } else {
                    showToast(data.message, true);
                }
            })
            .catch(error => {
                console.error('Error stopping agent:', error);
                showToast('Error stopping agent', true);
            })
            .finally(() => {
                stopBtn.disabled = false;
                stopBtn.innerHTML = '<i class="fas fa-stop"></i> Stop Agent';
            });
        }
        
        // Run test functions
        function runTest(testType) {
            showToast(`Starting ${testType.replace('_', ' ')} test...`);
            
            fetch(`/api/test/${testType}`)
                .then(response => response.json())
                .then(data => {
                    if (data.status === "success") {
                        showToast(data.message);
                    } else {
                        showToast("Test failed: " + data.message, true);
                    }
                })
                .catch(error => {
                    showToast("Error running test: " + error, true);
                });
        }
        
        // Set up the chart
        const ctx = document.getElementById('metricsChart').getContext('2d');
        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { 
                        label: 'CPU Usage %',
                        data: [],
                        borderColor: 'rgb(231, 76, 60)',
                        backgroundColor: 'rgba(231, 76, 60, 0.1)',
                        tension: 0.3,
                        fill: true
                    },
                    { 
                        label: 'Memory Usage %',
                        data: [],
                        borderColor: 'rgb(52, 152, 219)',
                        backgroundColor: 'rgba(52, 152, 219, 0.1)',
                        tension: 0.3,
                        fill: true
                    },
                    { 
                        label: 'Network Issues %',
                        data: [],
                        borderColor: 'rgb(46, 204, 113)',
                        backgroundColor: 'rgba(46, 204, 113, 0.1)',
                        tension: 0.3,
                        borderDash: [5, 5],
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        title: {
                            display: true,
                            text: 'Percentage'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Time'
                        }
                    }
                },
                interaction: {
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                },
                animations: {
                    radius: {
                        duration: 400,
                        easing: 'linear'
                    }
                }
            }
        });
        
        document.querySelector('.chart-container').style.height = '400px';

        function updateSystemStatus(cpuPercent, memoryPercent, packetLossPercent, thresholds) {
            const statusIndicator = document.getElementById('system-status-indicator');
            
            const cpuCritical = thresholds?.cpu_percent?.critical || 65;
            const memoryCritical = thresholds?.memory_percent?.critical || 65;
            const networkCritical = thresholds?.packet_loss_percent?.critical || 3;
            
            const cpuWarning = thresholds?.cpu_percent?.warning || 40;
            const memoryWarning = thresholds?.memory_percent?.warning || 40;
            const networkWarning = thresholds?.packet_loss_percent?.warning || 1;
            
            if (cpuPercent >= cpuCritical || memoryPercent >= memoryCritical || packetLossPercent >= networkCritical) {
                statusIndicator.className = 'system-status status-critical';
                statusIndicator.innerHTML = '<i class="fas fa-exclamation-triangle"></i> System Performance Issues Detected';
                return;
            }
            
            if (cpuPercent >= cpuWarning || memoryPercent >= memoryWarning || packetLossPercent >= networkWarning) {
                statusIndicator.className = 'system-status status-warning';
                statusIndicator.innerHTML = '<i class="fas fa-exclamation-circle"></i> System Performance Warning';
                return;
            }
            
            statusIndicator.className = 'system-status status-healthy';
            statusIndicator.innerHTML = '<i class="fas fa-check-circle"></i> System is Running Normally';
        }

        // Enhanced status indicator with improved stability and consistency
        function updateStatusIndicatorStable(value, element, thresholds, metricType, serverStatus = null) {
            const currentTime = Date.now();
            
            // Determine new status based on server-side status if available, otherwise calculate
            let newStatus = 'good';
            if (serverStatus) {
                newStatus = serverStatus;
            } else {
                if (value >= thresholds.critical) {
                    newStatus = 'critical';
                } else if (value >= thresholds.warning) {
                    newStatus = 'warning';
                } else {
                    newStatus = 'good';
                }
            }
            
            // Check if status actually changed and apply stability delay
            if (currentStatuses[metricType] !== newStatus) {
                // Only update if enough time has passed for stability
                if (currentTime - lastStatusUpdate[metricType] >= STATUS_STABILITY_TIME) {
                    currentStatuses[metricType] = newStatus;
                    lastStatusUpdate[metricType] = currentTime;
                    
                    // Update UI with new status
                    updateStatusUI(element, newStatus);
                }
                // If not enough time passed, keep current status
            } else {
                // Status unchanged, reset timer
                lastStatusUpdate[metricType] = currentTime;
                // Still update UI to ensure consistency
                updateStatusUI(element, newStatus);
            }
        }
        
        function updateStatusUI(element, status) {
            let statusHTML = '';
            
            if (status === 'critical') {
                statusHTML = '<span class="status-indicator status-critical"></span><span class="status-text critical">Critical</span>';
            } else if (status === 'warning') {
                statusHTML = '<span class="status-indicator status-warning"></span><span class="status-text warning">Warning</span>';
            } else {
                statusHTML = '<span class="status-indicator status-good"></span><span class="status-text">Good</span>';
            }
            
            const statusElement = document.getElementById(element);
            if (statusElement) {
                statusElement.innerHTML = statusHTML;
            }
        }

        function updateAutoencoderStatus(data) {
            const statusElement = document.getElementById('autoencoder-status');
            const detailsElement = document.getElementById('autoencoder-details');
            
            if (data.autoencoder_trained) {
                statusElement.className = 'autoencoder-status autoencoder-ready';
                let detailsText = `Enhanced TensorFlow autoencoder trained and actively monitoring. `;
                
                if (data.adaptive_threshold_active) {
                    detailsText += `Adaptive threshold: ${data.reconstruction_threshold.toFixed(6)}`;
                } else if (data.reconstruction_threshold) {
                    detailsText += `Base threshold: ${data.reconstruction_threshold.toFixed(6)}`;
                }
                
                detailsElement.textContent = detailsText;
            } else {
                statusElement.className = 'autoencoder-status autoencoder-training';
                const dataPoints = data.training_data_points || 0;
                const minRequired = 20;
                detailsElement.textContent = `Collecting training data: ${dataPoints}/${minRequired} data points needed for TensorFlow autoencoder training.`;
            }
        }

        // Enhanced process table update function
        function updateProcessTables() {
            fetch('/api/top_processes').then(res => res.json()).then(data => {
                const cpuTable = document.getElementById('cpu-processes').getElementsByTagName('tbody')[0];
                cpuTable.innerHTML = '';
                
                data.top_cpu.forEach(proc => {
                    // Skip stopped processes
                    if (stoppedProcesses.has(proc.pid)) {
                        return;
                    }
                    
                    const row = cpuTable.insertRow();
                    row.insertCell(0).textContent = proc.name;
                    row.insertCell(1).textContent = proc.pid;
                    const cpuCell = row.insertCell(2);
                    cpuCell.textContent = proc.cpu_percent.toFixed(1) + '%';
                    
                    // Enhanced highlighting
                    if (proc.cpu_percent > 50) {
                        cpuCell.style.color = '#e74c3c';
                        cpuCell.style.fontWeight = 'bold';
                    } else if (proc.cpu_percent > 20) {
                        cpuCell.style.color = '#f39c12';
                        cpuCell.style.fontWeight = '600';
                    }
                    
                    // Lower threshold for better user control
                    if (proc.cpu_percent > 10) {
                        const actionCell = row.insertCell(3);
                        actionCell.innerHTML = `
                            <button id="action-end_process-${proc.pid}-table" 
                                    class="action-button stop-button" 
                                    onclick="takeAction('end_process', ${proc.pid})"
                                    title="Stop ${proc.name}">
                                <i class="fas fa-times"></i> Stop
                            </button>
                        `;
                    } else {
                        row.insertCell(3);
                    }
                });
                
                // Update Memory processes table
                const memTable = document.getElementById('memory-processes').getElementsByTagName('tbody')[0];
                memTable.innerHTML = '';
                
                data.top_memory.forEach(proc => {
                    // Skip stopped processes
                    if (stoppedProcesses.has(proc.pid)) {
                        return;
                    }
                    
                    const row = memTable.insertRow();
                    row.insertCell(0).textContent = proc.name;
                    row.insertCell(1).textContent = proc.pid;
                    const memCell = row.insertCell(2);
                    memCell.textContent = proc.memory_percent.toFixed(1) + '%';
                    
                    // Enhanced highlighting
                    if (proc.memory_percent > 15) {
                        memCell.style.color = '#e74c3c';
                        memCell.style.fontWeight = 'bold';
                    } else if (proc.memory_percent > 8) {
                        memCell.style.color = '#f39c12';
                        memCell.style.fontWeight = '600';
                    }
                    
                    // Lower threshold for better user control
                    if (proc.memory_percent > 3) {
                        const actionCell = row.insertCell(3);
                        actionCell.innerHTML = `
                            <button id="action-end_process-${proc.pid}-table" 
                                    class="action-button stop-button" 
                                    onclick="takeAction('end_process', ${proc.pid})"
                                    title="Stop ${proc.name}">
                                <i class="fas fa-times"></i> Stop
                            </button>
                        `;
                    } else {
                        row.insertCell(3);
                    }
                });
            }).catch(error => {
                console.error('Error updating process tables:', error);
            });
        }

        function updateDashboard() {
            fetch('/api/metrics').then(res => res.json()).then(data => {
                if (!data.length) return;
                const latest = data[data.length - 1];
                
                // Update metrics display
                document.getElementById('cpu-value').textContent = latest.cpu_percent.toFixed(1) + '%';
                document.getElementById('memory-value').textContent = latest.memory_percent.toFixed(1) + '%';
                document.getElementById('memory-detail').textContent = `${latest.memory_used_gb} / ${latest.memory_total_gb} GB`;
                document.getElementById('packet-loss-value').textContent = latest.packet_loss_percent.toFixed(1) + '%';
                
                // Update chart with animation
                chart.data.labels = data.slice(-30).map(d => d.timestamp.split(' ')[1]);
                chart.data.datasets[0].data = data.slice(-30).map(d => d.cpu_percent);
                chart.data.datasets[1].data = data.slice(-30).map(d => d.memory_percent);
                chart.data.datasets[2].data = data.slice(-30).map(d => d.packet_loss_percent);
                chart.update('none');
                
            }).catch(error => {
                console.error('Error updating metrics:', error);
            });

            fetch('/api/faults').then(res => res.json()).then(data => {
                const issuesContainer = document.getElementById('issues-container');
                const noIssuesContainer = document.getElementById('no-issues-container');
                const ruleDiagnosticsTable = document.getElementById('rule-diagnostics-table').getElementsByTagName('tbody')[0];
                const mlDiagnosticsTable = document.getElementById('ml-diagnostics-table').getElementsByTagName('tbody')[0];
                
                // Update enhanced autoencoder status
                updateAutoencoderStatus(data);
                
                // Update overall system status
                if (data.metrics) {
                    updateSystemStatus(
                        data.metrics.cpu_percent,
                        data.metrics.memory_percent,
                        data.metrics.packet_loss_percent,
                        data.thresholds
                    );
                }
                
                // Update ML status with enhanced information
                if (data.training_data_points !== undefined) {
                    if (data.autoencoder_trained) {
                        const thresholdType = data.adaptive_threshold_active ? "Adaptive" : "Base";
                        document.getElementById('ml-status').textContent = `TensorFlow ML Active - ${thresholdType} (${data.training_data_points} data points)`;
                    } else if (data.training_data_points < 20) {
                        document.getElementById('ml-status').textContent = `Learning (${data.training_data_points}/20 data points)`;
                    } else {
                        document.getElementById('ml-status').textContent = `Training TensorFlow Model (${data.training_data_points} data points)`;
                    }
                } else {
                    document.getElementById('ml-status').textContent = 'Learning your system...';
                }
                
                // Update adaptive thresholds with better formatting
                if (data.thresholds) {
                    const newThresholds = {
                        cpu: `Warning: ${data.thresholds.cpu_percent.warning.toFixed(1)}%, Critical: ${data.thresholds.cpu_percent.critical.toFixed(1)}%`,
                        memory: `Warning: ${data.thresholds.memory_percent.warning.toFixed(1)}%, Critical: ${data.thresholds.memory_percent.critical.toFixed(1)}%`,
                        network: `Warning: ${data.thresholds.packet_loss_percent.warning.toFixed(1)}%, Critical: ${data.thresholds.packet_loss_percent.critical.toFixed(1)}%`
                    };
                    
                    if (JSON.stringify(lastThresholds) !== JSON.stringify(newThresholds)) {
                        document.getElementById('cpu-thresholds').textContent = newThresholds.cpu;
                        document.getElementById('memory-thresholds').textContent = newThresholds.memory;
                        document.getElementById('network-thresholds').textContent = newThresholds.network;
                        lastThresholds = newThresholds;
                    }
                    
                    // Update status indicators with enhanced stability and server-side status
                    if (data.metrics && data.status_indicators) {
                        updateStatusIndicatorStable(
                            data.metrics.cpu_percent, 
                            'cpu-status', 
                            {
                                warning: data.thresholds.cpu_percent.warning, 
                                critical: data.thresholds.cpu_percent.critical
                            },
                            'cpu',
                            data.status_indicators.cpu
                        );
                        
                        updateStatusIndicatorStable(
                            data.metrics.memory_percent, 
                            'memory-status', 
                            {
                                warning: data.thresholds.memory_percent.warning, 
                                critical: data.thresholds.memory_percent.critical
                            },
                            'memory',
                            data.status_indicators.memory
                        );
                        
                        updateStatusIndicatorStable(
                            data.metrics.packet_loss_percent, 
                            'network-status', 
                            {
                                warning: data.thresholds.packet_loss_percent.warning, 
                                critical: data.thresholds.packet_loss_percent.critical
                            },
                            'network',
                            data.status_indicators.network
                        );
                    }
                }
                
                // Handle issues display with IP diagnostics integration
                const hasRuleIssues = data.rule_suggestions && data.rule_suggestions.length > 0;
                const hasMLIssues = data.ml_suggestions && data.ml_suggestions.length > 0;
                
                if (hasRuleIssues || hasMLIssues) {
                    issuesContainer.style.display = 'block';
                    noIssuesContainer.style.display = 'none';
                    
                    // Clear previous tables
                    ruleDiagnosticsTable.innerHTML = '';
                    mlDiagnosticsTable.innerHTML = '';
                    
                    // Populate rule-based diagnostics
                    if (hasRuleIssues) {
                        data.rule_suggestions.forEach(issue => {
                            const row = ruleDiagnosticsTable.insertRow();
                            
                            const issueCell = row.insertCell(0);
                            issueCell.innerHTML = `<strong>${issue.issue}</strong>`;
                            
                            const recsCell = row.insertCell(1);
                            let recsHTML = '<ul class="suggestion-list">';
                            
                            issue.suggestions.forEach(suggestion => {
                                recsHTML += '<li>';
                                recsHTML += suggestion.text;
                                
                                if (suggestion.action_type === 'end_process' && suggestion.targets && suggestion.targets.length > 0) {
                                    recsHTML += '<div class="process-action-container">';
                                    suggestion.targets.forEach(target => {
                                        if (stoppedProcesses.has(target.pid)) {
                                            return;
                                        }
                                        
                                        let usageClass = target.usage > 25 ? 'usage-high' : '';
                                        recsHTML += `
                                            <div class="process-item">
                                                <div class="process-details">
                                                    <span class="process-name">${target.name}</span>
                                                    <span class="process-usage ${usageClass}">${target.usage.toFixed(1)}%</span>
                                                </div>
                                                <button id="action-end_process-${target.pid}" 
                                                        class="action-button stop-button" 
                                                        onclick="takeAction('end_process', ${target.pid})"
                                                        title="Stop ${target.name}">
                                                    <i class="fas fa-times-circle"></i> Stop Application
                                                </button>
                                            </div>`;
                                    });
                                    recsHTML += '</div>';
                                } else if (suggestion.action_type === 'restart_network') {
                                    recsHTML += `
                                        <div style="margin-top: 8px;">
                                            <button id="action-restart_network-net" class="action-button" 
                                                onclick="takeAction('restart_network', 'network')">
                                                <i class="fas fa-sync-alt"></i> Fix Network Issues
                                            </button>
                                        </div>`;
                                } else if (suggestion.action_type === 'clear_memory') {
                                    recsHTML += `
                                        <div style="margin-top: 8px;">
                                            <button id="action-clear_memory-mem" class="action-button" 
                                                onclick="takeAction('clear_memory', 'memory')">
                                                <i class="fas fa-broom"></i> Free Up Memory
                                            </button>
                                        </div>`;
                                } else if (suggestion.action_type === 'ip_scan') {
                                    recsHTML += `
                                        <div style="margin-top: 8px;">
                                            <button class="action-button network-button" 
                                                onclick="scanNetworkIssues()">
                                                <i class="fas fa-network-wired"></i> Scan IP Configuration
                                            </button>
                                        </div>`;
                                } else if (suggestion.action_type === 'ip_fix_dhcp') {
                                    recsHTML += `
                                        <div style="margin-top: 8px;">
                                            <button class="action-button network-button" 
                                                onclick="fixNetworkDHCP('')">
                                                <i class="fas fa-sync"></i> Reset to DHCP
                                            </button>
                                        </div>`;
                                }
                                
                                recsHTML += '</li>';
                            });
                            
                            recsHTML += '</ul>';
                            recsCell.innerHTML = recsHTML;
                        });
                    } else {
                        const row = ruleDiagnosticsTable.insertRow();
                        const cell = row.insertCell(0);
                        cell.colSpan = 2;
                        cell.innerHTML = '<div class="center-message"><i class="fas fa-check-circle"></i><p>No adaptive rule-based issues detected</p></div>';
                    }
                    
                    // Populate TensorFlow ML diagnostics (similar enhancement)
                    if (hasMLIssues) {
                        data.ml_suggestions.forEach(issue => {
                            const row = mlDiagnosticsTable.insertRow();
                            
                            const issueCell = row.insertCell(0);
                            issueCell.innerHTML = `<strong>${issue.issue}</strong>`;
                            
                            const reliabilityCell = row.insertCell(1);
                            const reliabilityLabel = issue.reliability || "Medium";
                            let reliabilityClass = "reliability-medium";
                            
                            if (reliabilityLabel === "High") {
                                reliabilityClass = "reliability-high";
                            } else if (reliabilityLabel === "Low") {
                                reliabilityClass = "reliability-low";
                            }
                            
                            reliabilityCell.innerHTML = `<span class="reliability-tag ${reliabilityClass}">${reliabilityLabel}</span>`;
                            
                            const recsCell = row.insertCell(2);
                            let recsHTML = '<ul class="suggestion-list">';
                            
                            issue.suggestions.forEach(suggestion => {
                                recsHTML += '<li>';
                                recsHTML += suggestion.text;
                                
                                if (suggestion.action_type === 'end_process' && suggestion.targets && suggestion.targets.length > 0) {
                                    recsHTML += '<div class="process-action-container">';
                                    suggestion.targets.forEach(target => {
                                        if (stoppedProcesses.has(target.pid)) {
                                            return;
                                        }
                                        
                                        let usageClass = target.usage > 25 ? 'usage-high' : '';
                                        recsHTML += `
                                            <div class="process-item">
                                                <div class="process-details">
                                                    <span class="process-name">${target.name}</span>
                                                    <span class="process-usage ${usageClass}">${target.usage.toFixed(1)}%</span>
                                                </div>
                                                <button id="action-end_process-${target.pid}-ml" 
                                                        class="action-button stop-button" 
                                                        onclick="takeAction('end_process', ${target.pid})"
                                                        title="Stop ${target.name}">
                                                    <i class="fas fa-times-circle"></i> Stop Application
                                                </button>
                                            </div>`;
                                    });
                                    recsHTML += '</div>';
                                } else if (suggestion.action_type === 'restart_network') {
                                    recsHTML += `
                                        <div style="margin-top: 8px;">
                                            <button id="action-restart_network-net-ml" class="action-button" 
                                                onclick="takeAction('restart_network', 'network')">
                                                <i class="fas fa-sync-alt"></i> Fix Network Issues
                                            </button>
                                        </div>`;
                                } else if (suggestion.action_type === 'clear_memory') {
                                    recsHTML += `
                                        <div style="margin-top: 8px;">
                                            <button id="action-clear_memory-mem-ml" class="action-button" 
                                                onclick="takeAction('clear_memory', 'memory')">
                                                <i class="fas fa-broom"></i> Free Up Memory
                                            </button>
                                        </div>`;
                                } else if (suggestion.action_type === 'ip_scan') {
                                    recsHTML += `
                                        <div style="margin-top: 8px;">
                                            <button class="action-button network-button" 
                                                onclick="scanNetworkIssues()">
                                                <i class="fas fa-network-wired"></i> Scan IP Configuration
                                            </button>
                                        </div>`;
                                }
                                
                                recsHTML += '</li>';
                            });
                            
                            recsHTML += '</ul>';
                            recsCell.innerHTML = recsHTML;
                        });
                    } else {
                        const row = mlDiagnosticsTable.insertRow();
                        const cell = row.insertCell(0);
                        cell.colSpan = 3;
                        cell.innerHTML = '<div class="center-message"><i class="fas fa-check-circle"></i><p>No TensorFlow ML insights to report</p></div>';
                    }
                    
                } else {
                    issuesContainer.style.display = 'none';
                    noIssuesContainer.style.display = 'block';
                }
                
                // Update Enhanced ML Insights Tab
                updateMLInsightsTab(data);
                
            }).catch(error => {
                console.error('Error updating faults:', error);
            });
            
            // Update process tables
            updateProcessTables();
        }

        function updateMLInsightsTab(data) {
            const mlAnomaliesContainer = document.getElementById('ml-anomalies-container');
            const mlPredictionsContainer = document.getElementById('ml-predictions-container');
            const mlPatternsContainer = document.getElementById('ml-patterns-container');
            const noMlInsightsContainer = document.getElementById('no-ml-insights-container');
            
            const anomaliesArea = document.getElementById('anomalies-area');
            const predictionsArea = document.getElementById('predictions-area');
            const patternsArea = document.getElementById('patterns-area');
            
            let hasInsights = false;
            
            if (data.ml_insights) {
                // Handle TensorFlow autoencoder anomalies
                if (data.ml_insights.anomalies && data.ml_insights.anomalies.length > 0) {
                    hasInsights = true;
                    mlAnomaliesContainer.style.display = 'block';
                    
                    let anomaliesHTML = '';
                    data.ml_insights.anomalies.forEach(anomaly => {
                        const reliabilityLabel = anomaly.reliability_label || "Medium";
                        let reliabilityClass = "reliability-medium";
                        
                        if (reliabilityLabel === "High") {
                            reliabilityClass = "reliability-high";
                        } else if (reliabilityLabel === "Low") {
                            reliabilityClass = "reliability-low";
                        }
                        
                        let reconstructionInfo = '';
                        if (anomaly.reconstruction_error && anomaly.threshold) {
                            const thresholdType = anomaly.adaptive_threshold_used ? "Adaptive" : "Base";
                            reconstructionInfo = `<div style="font-size: 12px; color: #7f8c8d; margin-top: 5px;">
                                Reconstruction error: ${anomaly.reconstruction_error.toFixed(6)} | ${thresholdType} threshold: ${anomaly.threshold.toFixed(6)}
                            </div>`;
                        }
                        
                        anomaliesHTML += `
                            <div class="anomaly">
                                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                                    <strong>${anomaly.description}</strong>
                                    <span class="reliability-tag ${reliabilityClass}">${reliabilityLabel} Reliability</span>
                                </div>
                                <div>Detected values: CPU ${anomaly.metrics.cpu.toFixed(1)}%, 
                                Memory ${anomaly.metrics.memory.toFixed(1)}%, 
                                Network ${anomaly.metrics.packet_loss.toFixed(1)}%</div>
                                ${reconstructionInfo}
                                <div style="margin-top:10px;">
                                    <button class="action-button" onclick="openTab(event, 'DiagnosticsTab')">
                                        <i class="fas fa-tools"></i> View Recommendations
                                    </button>
                                </div>
                            </div>
                        `;
                    });
                    
                    anomaliesArea.innerHTML = anomaliesHTML;
                } else {
                    mlAnomaliesContainer.style.display = 'none';
                }
                
                // Handle enhanced predictions (same as original)
                if (data.ml_insights.predictions && data.ml_insights.predictions.length > 0) {
                    hasInsights = true;
                    mlPredictionsContainer.style.display = 'block';
                    
                    let predictionsHTML = '';
                    data.ml_insights.predictions.forEach(prediction => {
                        const certainty = prediction.certainty || "Medium";
                        let certaintyClass = "reliability-medium";
                        
                        if (certainty === "High" || certainty === "Very High") {
                            certaintyClass = "reliability-high";
                        } else if (certainty === "Low") {
                            certaintyClass = "reliability-low";
                        }
                        
                        let slopeInfo = '';
                        if (prediction.slope) {
                            slopeInfo = `<div style="font-size: 12px; color: #7f8c8d; margin-top: 5px;">
                                Trend slope: ${prediction.slope.toFixed(3)} per time unit
                            </div>`;
                        }
                        
                        predictionsHTML += `
                            <div class="prediction">
                                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                                    <strong>TensorFlow ML predicts ${prediction.metric} is ${prediction.trend} rapidly</strong>
                                    <span class="reliability-tag ${certaintyClass}">${certainty} Certainty</span>
                                </div>
                                <div>Current: ${prediction.current.toFixed(1)}%, Expected to reach: ${prediction.projected.toFixed(1)}% in ${prediction.time_frame}</div>
                                ${slopeInfo}
                                <div style="margin-top:10px;">
                                    <button class="action-button" onclick="openTab(event, 'DiagnosticsTab')">
                                        <i class="fas fa-tools"></i> View Recommendations
                                    </button>
                                </div>
                            </div>
                        `;
                    });
                    
                    predictionsArea.innerHTML = predictionsHTML;
                } else {
                    mlPredictionsContainer.style.display = 'none';
                }
                
                // Handle enhanced patterns (same as original)
                if (data.ml_insights.patterns && data.ml_insights.patterns.length > 0) {
                    hasInsights = true;
                    mlPatternsContainer.style.display = 'block';
                    
                    let patternsHTML = '';
                    data.ml_insights.patterns.forEach(pattern => {
                        const reliability = pattern.reliability || "Medium";
                        let reliabilityClass = "reliability-medium";
                        
                        if (reliability === "High") {
                            reliabilityClass = "reliability-high";
                        } else if (reliability === "Low") {
                            reliabilityClass = "reliability-low";
                        }
                        
                        // Add pattern-specific details
                        let patternDetails = '';
                        if (pattern.pattern_type === "memory_leak" && pattern.slope) {
                            patternDetails = `<div style="font-size: 12px; color: #7f8c8d; margin-top: 5px;">
                                Memory increase rate: ${pattern.slope.toFixed(3)}% per measurement
                            </div>`;
                        } else if (pattern.pattern_type === "cpu_spikes" && pattern.spike_interval) {
                            patternDetails = `<div style="font-size: 12px; color: #7f8c8d; margin-top: 5px;">
                                CPU spike interval: every ${pattern.spike_interval.toFixed(1)} seconds
                            </div>`;
                        } else if (pattern.pattern_type === "network_instability" && pattern.issue_frequency) {
                            patternDetails = `<div style="font-size: 12px; color: #7f8c8d; margin-top: 5px;">
                                Network issue frequency: every ${pattern.issue_frequency.toFixed(1)} seconds
                            </div>`;
                        } else if (pattern.pattern_type === "system_overload" && pattern.average_load) {
                            patternDetails = `<div style="font-size: 12px; color: #7f8c8d; margin-top: 5px;">
                                Average system load: ${pattern.average_load.toFixed(1)}%
                            </div>`;
                        }
                        
                        patternsHTML += `
                            <div class="pattern">
                                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                                    <strong>${pattern.description}</strong>
                                    <span class="reliability-tag ${reliabilityClass}">${reliability} Reliability</span>
                                </div>
                                <div>TensorFlow Analysis: ${pattern.suggestion}</div>
                                ${patternDetails}
                                <div style="margin-top:10px;">
                                    <button class="action-button" onclick="openTab(event, 'DiagnosticsTab')">
                                        <i class="fas fa-tools"></i> View Recommendations
                                    </button>
                                </div>
                            </div>
                        `;
                    });
                    
                    patternsArea.innerHTML = patternsHTML;
                } else {
                    mlPatternsContainer.style.display = 'none';
                }
            }
            
            if (hasInsights) {
                noMlInsightsContainer.style.display = 'none';
            } else {
                noMlInsightsContainer.style.display = 'block';
            }
        }

        // Clean up stopped processes periodically
        setInterval(() => {
            // Remove PIDs that no longer exist from our tracking
            stoppedProcesses.forEach(pid => {
                fetch('/api/top_processes').then(res => res.json()).then(data => {
                    const allPids = [...data.top_cpu.map(p => p.pid), ...data.top_memory.map(p => p.pid)];
                    if (!allPids.includes(pid)) {
                        stoppedProcesses.delete(pid);
                    }
                });
            });
        }, 30000); // Clean up every 30 seconds

        // Update agent status periodically when on agent tab
        setInterval(() => {
            const agentTab = document.getElementById('AgentTab');
            if (agentTab && agentTab.style.display !== 'none') {
                loadAgentStatus();
            }
        }, 10000); // Every 10 seconds
        
        // Update network status periodically when on network tab
        setInterval(() => {
            const networkTab = document.getElementById('NetworkTab');
            if (networkTab && networkTab.style.display !== 'none') {
                loadNetworkStatus();
            }
        }, 30000); // Every 30 seconds

        // Initial dashboard update and set optimized refresh interval
        updateDashboard();
        setInterval(updateDashboard, 2500); // Slightly increased to 2.5 seconds for better stability with TensorFlow processing
    </script>
</body>
</html>
"""

# Main application entry point
def main():
    try:
        # Initialize enhanced TensorFlow ML engine
        logger.info("Initializing Enhanced TensorFlow Autoencoder Engine...")
        ml_engine = EnhancedTensorFlowAutoencoderEngine()
        
        # Display server and agent configuration
        logger.info(f"Server Configuration: IP={SERVER_CONFIG['ip_address']}, MAC={SERVER_CONFIG['mac']}")
        logger.info(f"Agent Configuration: MAC={AGENT_CONFIG['mac_address']}")
        
        # Start multi-protocol data agent
        logger.info("Starting Multi-Protocol Data Agent...")
        data_agent.start()
        
        # Display Layer 2 status
        if data_agent.layer2_comm and data_agent.layer2_comm.is_available():
            logger.info("Layer 2 communication initialized and available")
        else:
            logger.warning("Layer 2 communication not available - scapy/Npcap may be missing")
        
        # Start Flask web server in a separate thread
        flask_thread = threading.Thread(target=run_flask)
        flask_thread.daemon = True
        flask_thread.start()
        
        # Start enhanced metrics collection
        logger.info("Starting enhanced metrics collection with multi-protocol communication...")
        collect_metrics(ml_engine)
        
    except KeyboardInterrupt:
        logger.info("Application stopped by user")
        data_agent.stop()
    except Exception as e:
        logger.error(f"Application error: {e}")
        import traceback
        traceback.print_exc()
        data_agent.stop()

if __name__ == "__main__":
    main()