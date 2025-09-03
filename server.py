import json
import time
import sqlite3
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging
import os
import statistics
import socket
import struct
import platform
from flask import Flask, render_template, jsonify, request, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import plotly.graph_objs as go
import plotly.utils

# Try to import scapy for Layer 2 support
try:
    from scapy.all import Ether, Raw, sniff, get_if_list, get_if_hwaddr, get_if_addr, conf, sendp
    SCAPY_AVAILABLE = True
    print("Scapy available - Layer 2 support enabled")
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not available - Layer 2 support disabled. Install with: pip install scapy")

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Custom EtherType for our diagnostics protocol
CUSTOM_ETHERTYPE = 0x88B5

# Communication method tracking constants
COMM_METHOD_HTTP = 'HTTP'
COMM_METHOD_UDP = 'UDP_BROADCAST'  
COMM_METHOD_LAYER2 = 'LAYER2_RAW'

# Manual MAC address configuration for Layer 2
MANUAL_MAC_ADDRESS = None  # Set this to override automatic detection (e.g., "aa:bb:cc:dd:ee:ff")

# === Enhanced Layer 2 Ethernet Frame Handler ===
class Layer2DiagnosticsServer:
    def __init__(self):
        self.running = False
        self.server_mac = None
        self.db_manager = None
        self.thread = None
        self.interface = None
        self.packet_count = 0
        self.error_count = 0
        
    def set_db_manager(self, db_manager):
        """Set database manager reference"""
        self.db_manager = db_manager
    
    def set_manual_mac(self, mac_address):
        """Set manual MAC address for Layer 2 interface"""
        global MANUAL_MAC_ADDRESS
        MANUAL_MAC_ADDRESS = mac_address
        logger.info(f"Manual MAC address set to: {mac_address}")
    
    def get_best_interface(self):
        """Find the best network interface for Layer 2 communication"""
        if not SCAPY_AVAILABLE:
            return None, None
            
        try:
            interfaces = get_if_list()
            logger.info(f"Available interfaces: {interfaces}")
            
            # If manual MAC is set, find interface with that MAC
            if MANUAL_MAC_ADDRESS:
                for iface in interfaces:
                    try:
                        mac = get_if_hwaddr(iface)
                        if mac and mac.lower() == MANUAL_MAC_ADDRESS.lower():
                            try:
                                ip = get_if_addr(iface)
                            except:
                                ip = "N/A"
                            logger.info(f"Found interface with manual MAC: {iface}, MAC: {mac}, IP: {ip}")
                            return iface, mac
                    except Exception as e:
                        logger.debug(f"Error checking interface {iface}: {e}")
                        continue
                
                logger.warning(f"Manual MAC address {MANUAL_MAC_ADDRESS} not found on any interface")
                # Use manual MAC anyway with first active interface
                for iface in interfaces:
                    try:
                        if 'loopback' not in iface.lower() and 'vmware' not in iface.lower():
                            logger.info(f"Using interface {iface} with manual MAC: {MANUAL_MAC_ADDRESS}")
                            return iface, MANUAL_MAC_ADDRESS
                    except:
                        continue
            
            # Look for active interfaces with IP addresses
            for iface in interfaces:
                try:
                    # Skip loopback and virtual interfaces
                    if 'loopback' in iface.lower() or 'vmware' in iface.lower() or 'virtualbox' in iface.lower():
                        continue
                    
                    mac = get_if_hwaddr(iface)
                    try:
                        ip = get_if_addr(iface)
                    except:
                        ip = "N/A"
                    
                    if mac and mac != "00:00:00:00:00:00":
                        logger.info(f"Selected interface: {iface}, MAC: {mac}, IP: {ip}")
                        return iface, mac
                        
                except Exception as e:
                    logger.debug(f"Error checking interface {iface}: {e}")
                    continue
                    
            # Fallback to first non-loopback interface
            for iface in interfaces:
                if 'loopback' not in iface.lower():
                    try:
                        mac = get_if_hwaddr(iface)
                        if mac and mac != "00:00:00:00:00:00":
                            logger.info(f"Fallback interface: {iface}, MAC: {mac}")
                            return iface, mac
                    except:
                        continue
                        
        except Exception as e:
            logger.error(f"Error finding network interface: {e}")
            
        return None, None
    
    def is_for_us(self, eth_dst):
        """Check if the packet is addressed to us"""
        if not self.server_mac:
            return False
        
        # Check if it's broadcast
        if eth_dst.lower() == "ff:ff:ff:ff:ff:ff":
            return True
        
        # Check if it's for our MAC
        if eth_dst.lower() == self.server_mac.lower():
            return True
        
        # Check manual MAC if set
        if MANUAL_MAC_ADDRESS and eth_dst.lower() == MANUAL_MAC_ADDRESS.lower():
            return True
            
        return False
    
    def process_layer2_packet(self, packet):
        """Enhanced Layer 2 diagnostic packet processor"""
        try:
            self.packet_count += 1
            
            # Basic packet validation
            if not packet or not packet.haslayer(Ether):
                return
                
            eth = packet[Ether]
            
            # Check EtherType first for efficiency
            if eth.type != CUSTOM_ETHERTYPE:
                return
                
            logger.info(f"Received Layer 2 packet from {eth.src} with custom EtherType 0x{eth.type:04X}")
            
            # Check if packet is for us (broadcast or our MAC)
            if not self.is_for_us(eth.dst):
                logger.debug(f"Packet not for us: dst={eth.dst}, our_mac={self.server_mac}")
                return
                
            # Extract payload
            if not packet.haslayer(Raw):
                logger.debug("No Raw payload in packet")
                return
                
            try:
                payload = packet[Raw].load
                
                # Handle different payload encodings
                payload_str = None
                if isinstance(payload, bytes):
                    try:
                        payload_str = payload.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            payload_str = payload.decode('latin-1')
                        except UnicodeDecodeError:
                            logger.error(f"Could not decode payload from {eth.src}")
                            return
                else:
                    payload_str = str(payload)
                
                logger.info(f"Received Layer 2 data from {eth.src}: {len(payload)} bytes [METHOD: {COMM_METHOD_LAYER2}]")
                
                # Parse JSON payload
                try:
                    data_package = json.loads(payload_str)
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in Layer 2 packet from {eth.src}: {e}")
                    return
                
                # Process the agent data package
                self.process_agent_data_package(data_package, eth.src)
                    
            except Exception as e:
                logger.error(f"Error processing Layer 2 payload from {eth.src}: {e}")
                
        except Exception as e:
            self.error_count += 1
            logger.error(f"Error in Layer 2 packet processing: {e}")
    
    def process_agent_data_package(self, data_package, source_mac):
        """Process agent data package received via Layer 2"""
        try:
            agent_id = data_package.get('agent_id')
            hostname = data_package.get('hostname', 'unknown')
            platform = data_package.get('platform', 'unknown')
            
            if not agent_id or not self.db_manager:
                logger.warning(f"Missing agent_id or db_manager in Layer 2 data")
                return
                
            logger.info(f"Processing Layer 2 data package from agent {agent_id} (MAC: {source_mac}) [METHOD: {COMM_METHOD_LAYER2}]")
            
            # Register/update agent with MAC address as IP placeholder and communication method
            self.db_manager.register_agent(agent_id, hostname, platform, f"L2:{source_mac}", COMM_METHOD_LAYER2)
            
            # Process data from the package
            data = data_package.get('data', {})
            
            # Process metrics if present
            if data.get('metrics'):
                self.db_manager.insert_metrics(agent_id, data['metrics'])
            
            # Process faults if present
            if data.get('faults'):
                self.db_manager.insert_faults(agent_id, data['faults'])
            
            # Process ML insights if present
            if data.get('ml_insights'):
                self.db_manager.insert_ml_insights(agent_id, data['ml_insights'])
            
            # Process IP diagnostics if present
            if data.get('ip_diagnostics'):
                logger.info(f"Processing IP diagnostics for agent {agent_id} via Layer 2")
                self.db_manager.insert_ip_diagnostics(agent_id, data['ip_diagnostics'])
            
            # Process processes if present
            if data.get('processes'):
                # Handle processes data if needed
                pass
            
            # Log successful Layer 2 data reception
            self.db_manager.log_event(agent_id, 'layer2_data_received', 'info', 
                                   f"Successfully received data from {hostname} via Layer 2 (MAC: {source_mac})")
            
            logger.info(f"Successfully processed Layer 2 data for agent {agent_id} [METHOD: {COMM_METHOD_LAYER2}]")
            
        except Exception as e:
            logger.error(f"Error processing Layer 2 data package: {e}")
            import traceback
            traceback.print_exc()
    
    def start(self):
        """Start Layer 2 diagnostic server with enhanced error handling"""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available - Layer 2 support disabled")
            return False
            
        try:
            self.interface, self.server_mac = self.get_best_interface()
            
            if not self.interface or not self.server_mac:
                logger.error("Could not find suitable network interface for Layer 2 communication")
                return False
                
            logger.info(f"Starting Layer 2 Diagnostics Server on {self.interface} (MAC: {self.server_mac})")
            logger.info(f"Listening for custom EtherType: 0x{CUSTOM_ETHERTYPE:04X}")
            
            self.running = True
            self.packet_count = 0
            self.error_count = 0
            
            # Start packet capture in separate thread
            self.thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.thread.start()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Layer 2 diagnostics server: {e}")
            return False
    
    def _capture_loop(self):
        """Enhanced packet capture loop with better error handling"""
        try:
            logger.info(f"Starting packet capture on interface: {self.interface}")

            if SCAPY_AVAILABLE:
                logger.info("Starting packet sniffing...")

                while self.running:
                    logger.info(f"Layer2 server listening on iface={self.interface}, MAC={self.server_mac}")

                    sniff(
                        iface=self.interface,
                        prn=self.process_layer2_packet,
                        #stop_filter=lambda x: not self.running,
                        store=0,
                        timeout=3,  # run in 1s chunks so we can check self.running
                        promisc=True
                    )

            logger.info("Layer 2 packet capture loop ended")

        except Exception as e:
            logger.error(f"Critical error in Layer 2 capture loop: {e}")
        finally:
            logger.info(f"Layer 2 capture statistics: {self.packet_count} packets processed, {self.error_count} errors")
    
    def stop(self):
        """Stop Layer 2 diagnostic server"""
        logger.info("Stopping Layer 2 diagnostic server...")
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        logger.info(f"Layer 2 server stopped. Final stats: packets={self.packet_count}, errors={self.error_count}")
            
    def get_server_info(self):
        """Get server MAC address for agents"""
        return {
            'mac_address': self.server_mac,
            'interface': self.interface,
            'ethertype': f"0x{CUSTOM_ETHERTYPE:04X}",
            'manual_mac': MANUAL_MAC_ADDRESS
        }
    
    def get_statistics(self):
        """Get Layer 2 server statistics"""
        return {
            'running': self.running,
            'interface': self.interface,
            'server_mac': self.server_mac,
            'manual_mac': MANUAL_MAC_ADDRESS,
            'packet_count': self.packet_count,
            'error_count': self.error_count,
            'success_rate': (self.packet_count - self.error_count) / max(self.packet_count, 1) * 100
        }

# === Enhanced Broadcast Discovery Server ===
class BroadcastDiscoveryServer:
    def __init__(self, port=9999):
        self.port = port
        self.server_socket = None
        self.running = False
        self.server_ip = self.get_server_ip()
        self.server_port = 8080  # Flask server port
        self.db_manager = None  # Will be set after initialization
        self.layer2_server = None  # Reference to Layer 2 server
        
    def set_db_manager(self, db_manager):
        """Set database manager reference"""
        self.db_manager = db_manager
        
    def set_layer2_server(self, layer2_server):
        """Set Layer 2 server reference"""
        self.layer2_server = layer2_server
        
    def get_server_ip(self):
        """Get the server's IP address"""
        try:
            # Connect to a remote address to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def process_agent_data_package(self, data_package, agent_addr):
        """Process agent data package received via UDP broadcast"""
        try:
            agent_id = data_package.get('agent_id')
            hostname = data_package.get('hostname', 'unknown')
            platform = data_package.get('platform', 'unknown')
            
            if not agent_id or not self.db_manager:
                return
            
            logger.info(f"Processing UDP broadcast data package from agent {agent_id} at {agent_addr} [METHOD: {COMM_METHOD_UDP}]")
            
            # Register/update agent with broadcast source IP and communication method
            self.db_manager.register_agent(agent_id, hostname, platform, agent_addr, COMM_METHOD_UDP)
            
            # Process data from the package
            data = data_package.get('data') or data_package.get('diagnostic_data', {})
            
            # Process metrics if present
            if data.get('metrics'):
                self.db_manager.insert_metrics(agent_id, data['metrics'])
            
            # Process faults if present
            if data.get('faults'):
                self.db_manager.insert_faults(agent_id, data['faults'])
            
            # Process ML insights if present
            if data.get('ml_insights'):
                self.db_manager.insert_ml_insights(agent_id, data['ml_insights'])
            
            # Process IP diagnostics if present
            if data.get('ip_diagnostics'):
                logger.info(f"Processing IP diagnostics for agent {agent_id} via UDP broadcast")
                self.db_manager.insert_ip_diagnostics(agent_id, data['ip_diagnostics'])
            
            # Process processes if present
            if data.get('processes'):
                # Handle processes data if needed
                pass
            
            # Log successful broadcast data reception
            self.db_manager.log_event(agent_id, 'broadcast_data_received', 'info', 
                                   f"Received data via broadcast from {hostname} at {agent_addr}")
            
        except Exception as e:
            logger.error(f"Error processing broadcast data package: {e}")
    
    def start(self):
        """Start the broadcast discovery server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.server_socket.bind(('', self.port))
            self.server_socket.settimeout(1.0)  # 1 second timeout for clean shutdown
            self.running = True
            
            logger.info(f"Broadcast Discovery Server started on port {self.port}")
            logger.info(f"Server IP: {self.server_ip}, Server Port: {self.server_port}")
            
            while self.running:
                try:
                    data, addr = self.server_socket.recvfrom(65536)  # Increased buffer size
                    message = data.decode('utf-8')
                    
                    logger.info(f"Received UDP broadcast message from {addr[0]}: {len(message)} bytes [METHOD: {COMM_METHOD_UDP}]")
                    
                    # Handle JSON broadcast format from agent
                    try:
                        data_package = json.loads(message)
                        
                        # Process the agent data package directly
                        self.process_agent_data_package(data_package, addr[0])
                        
                        # Send acknowledgment back to agent
                        ack_response = {
                            'status': 'received', 'timestamp': datetime.now().isoformat()
                        }
                        
                        response_json = json.dumps(ack_response)
                        self.server_socket.sendto(response_json.encode('utf-8'), addr)
                        logger.info(f"Sent acknowledgment to agent at {addr[0]}")
                    
                    except json.JSONDecodeError:
                        logger.warning(f"Received non-JSON broadcast message from {addr[0]}: {message[:50]}...")
                
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Error in broadcast discovery server: {e}")
                        
        except Exception as e:
            logger.error(f"Failed to start broadcast discovery server: {e}")
    
    def stop(self):
        """Stop the broadcast discovery server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()

# Initialize servers
layer2_server = Layer2DiagnosticsServer()
broadcast_server = BroadcastDiscoveryServer()

def start_communication_servers():
    """Start both Layer 2 and broadcast discovery servers"""
    # Start Layer 2 server
    layer2_success = layer2_server.start()
    
    # Start broadcast discovery server
    broadcast_server.set_layer2_server(layer2_server)
    discovery_thread = threading.Thread(target=broadcast_server.start, daemon=True)
    discovery_thread.start()
    
    return layer2_success

# Enhanced helper function to parse diagnostic issues with detailed technical information
def parse_diagnostic_issues(issues_data, connectivity_data=None):
    """Parse IP diagnostic issues to show specific technical problem descriptions for technicians"""
    if not issues_data:
        return "No Issues"
    
    try:
        if isinstance(issues_data, str):
            issues = json.loads(issues_data)
        else:
            issues = issues_data
    except (json.JSONDecodeError, TypeError):
        issues = []
    
    if not issues or len(issues) == 0:
        return "No Issues"
    
    # Extract detailed technical issue descriptions
    detailed_descriptions = []
    for issue in issues:
        if isinstance(issue, dict):
            issue_type = issue.get('type', '')
            description = issue.get('description', '')
            severity = issue.get('severity', 'medium')
            
            # Enhanced technical categorization for technicians
            if issue_type == 'network_connectivity':
                if 'DNS' in description:
                    if 'timeout' in description.lower():
                        detailed_descriptions.append("🔴 DNS Resolution Timeout - DNS servers unresponsive or unreachable")
                    elif 'nxdomain' in description.lower():
                        detailed_descriptions.append("🔴 DNS Resolution Failed - Domain not found (NXDOMAIN)")
                    else:
                        detailed_descriptions.append("🔴 DNS Resolution Failed - Check DNS server configuration")
                elif 'gateway' in description.lower():
                    if 'unreachable' in description.lower():
                        detailed_descriptions.append("🔴 Default Gateway Unreachable - Network routing issue or gateway down")
                    elif 'timeout' in description.lower():
                        detailed_descriptions.append("🔴 Gateway Ping Timeout - Possible network congestion or firewall blocking")
                    else:
                        detailed_descriptions.append("🔴 Gateway Connectivity Issue - Check network cable and switch ports")
                elif 'HTTP' in description:
                    if '404' in description:
                        detailed_descriptions.append("🟡 HTTP Test Failed - Target URL not found (404)")
                    elif 'timeout' in description.lower():
                        detailed_descriptions.append("🔴 HTTP Connectivity Timeout - Internet access blocked or slow")
                    else:
                        detailed_descriptions.append("🔴 HTTP Connectivity Failed - Internet access unavailable")
                else:
                    detailed_descriptions.append(f"🔴 Network Connectivity Issue - {description}")
                    
            elif issue_type == 'ip_configuration':
                if 'DHCP' in description:
                    if 'lease' in description.lower():
                        detailed_descriptions.append("🔴 DHCP Lease Expired - Renew IP address lease from DHCP server")
                    elif 'server' in description.lower():
                        detailed_descriptions.append("🔴 DHCP Server Unavailable - Check DHCP server status and network connectivity")
                    elif 'timeout' in description.lower():
                        detailed_descriptions.append("🔴 DHCP Request Timeout - DHCP server not responding")
                    else:
                        detailed_descriptions.append("🔴 DHCP Configuration Problem - Check DHCP server and network settings")
                elif 'subnet' in description.lower():
                    if 'mismatch' in description.lower():
                        detailed_descriptions.append("🔴 Subnet Mismatch - IP address not in correct network range")
                    else:
                        detailed_descriptions.append("🔴 Subnet Configuration Error - Check network mask and IP range")
                elif 'duplicate' in description.lower() or 'conflict' in description.lower():
                    detailed_descriptions.append("🔴 IP Address Conflict - Another device using same IP address")
                elif 'APIPA' in description or '169.254' in description:
                    detailed_descriptions.append("🟡 APIPA Address Detected - No DHCP server found, using auto-assigned IP")
                else:
                    detailed_descriptions.append(f"🔴 IP Configuration Issue - {description}")
                    
            elif issue_type == 'interface':
                if 'down' in description.lower():
                    detailed_descriptions.append("🔴 Network Interface Down - Check network cable connection")
                elif 'disabled' in description.lower():
                    detailed_descriptions.append("🟡 Network Interface Disabled - Enable network adapter in system settings")
                elif 'speed' in description.lower():
                    detailed_descriptions.append("🟡 Network Speed Issue - Check cable quality and switch port settings")
                else:
                    detailed_descriptions.append(f"🔴 Network Interface Problem - {description}")
                    
            elif issue_type == 'dns':
                if 'server' in description.lower():
                    detailed_descriptions.append("🔴 DNS Server Configuration Error - Check DNS server settings")
                elif 'cache' in description.lower():
                    detailed_descriptions.append("🟡 DNS Cache Issue - Clear DNS cache and retry")
                else:
                    detailed_descriptions.append(f"🔴 DNS Configuration Issue - {description}")
                    
            elif issue_type == 'routing':
                if 'default' in description.lower():
                    detailed_descriptions.append("🔴 Default Route Missing - No default gateway configured")
                elif 'table' in description.lower():
                    detailed_descriptions.append("🔴 Routing Table Error - Check routing configuration")
                else:
                    detailed_descriptions.append(f"🔴 Routing Issue - {description}")
                    
            else:
                # Use severity indicators and provide actionable information
                severity_icon = "🔴" if severity == "high" else "🟡" if severity == "medium" else "🟢"
                detailed_descriptions.append(f"{severity_icon} {description if description else 'Network Issue Detected'}")
                
        elif isinstance(issue, str):
            # Handle simple string issues with basic categorization
            if 'dns' in issue.lower():
                detailed_descriptions.append("🔴 DNS Issue - Check DNS configuration")
            elif 'gateway' in issue.lower():
                detailed_descriptions.append("🔴 Gateway Issue - Check network routing")
            elif 'dhcp' in issue.lower():
                detailed_descriptions.append("🔴 DHCP Issue - Check DHCP server")
            else:
                detailed_descriptions.append(f"🔴 {issue}")
    
    # Join descriptions with line breaks for better readability
    return "; ".join(detailed_descriptions) if detailed_descriptions else "Issues Detected"

# === Enhanced Database Manager with Communication Method Tracking ===
class DatabaseManager:
    def __init__(self, db_path='nms_server.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables with enhanced communication method tracking"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Enhanced Agents table with communication method tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    hostname TEXT,
                    platform TEXT,
                    last_seen TIMESTAMP,
                    status TEXT DEFAULT 'online',
                    ip_address TEXT,
                    communication_method TEXT DEFAULT 'HTTP',
                    last_communication_method TEXT,
                    method_fallback_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Add communication method columns if they don't exist (for existing databases)
            try:
                cursor.execute('ALTER TABLE agents ADD COLUMN communication_method TEXT DEFAULT "HTTP"')
            except sqlite3.OperationalError:
                pass  # Column already exists
            
            try:
                cursor.execute('ALTER TABLE agents ADD COLUMN last_communication_method TEXT')
            except sqlite3.OperationalError:
                pass
                
            try:
                cursor.execute('ALTER TABLE agents ADD COLUMN method_fallback_count INTEGER DEFAULT 0')
            except sqlite3.OperationalError:
                pass
            
            # Metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT,
                    timestamp TIMESTAMP,
                    cpu_percent REAL,
                    memory_percent REAL,
                    memory_used_gb REAL,
                    memory_total_gb REAL,
                    packet_loss_percent REAL,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
                )
            ''')
            
            # Faults table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS faults (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT,
                    timestamp TIMESTAMP,
                    fault_type TEXT,
                    severity TEXT,
                    description TEXT,
                    status TEXT DEFAULT 'active',
                    resolved_at TIMESTAMP,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
                )
            ''')
            
            # ML Insights table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ml_insights (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT,
                    timestamp TIMESTAMP,
                    insight_type TEXT,
                    confidence REAL,
                    reliability TEXT,
                    description TEXT,
                    details TEXT,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
                )
            ''')
            
            # IP Diagnostics table - Enhanced
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_diagnostics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT,
                    timestamp TIMESTAMP,
                    has_issues BOOLEAN,
                    issues_count INTEGER,
                    connectivity_dns BOOLEAN,
                    connectivity_ping BOOLEAN,
                    connectivity_http BOOLEAN,
                    external_ip TEXT,
                    interfaces_data TEXT,
                    issues_data TEXT,
                    solutions_data TEXT,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
                )
            ''')
            
            # Network Interfaces table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_interfaces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT,
                    interface_name TEXT,
                    ip_address TEXT,
                    netmask TEXT,
                    is_up BOOLEAN,
                    is_dhcp BOOLEAN,
                    network_address TEXT,
                    timestamp TIMESTAMP,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
                )
            ''')
            
            # Events table for audit trail
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT,
                    event_type TEXT,
                    severity TEXT,
                    message TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
                )
            ''')
            
            conn.commit()
            logger.info("Database initialized successfully with communication method tracking")
    
    def register_agent(self, agent_id, hostname, platform, ip_address, communication_method=COMM_METHOD_HTTP):
        """Register or update agent information with communication method tracking"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Check if agent exists and get current method info
            cursor.execute('SELECT communication_method, method_fallback_count FROM agents WHERE agent_id = ?', (agent_id,))
            existing_agent = cursor.fetchone()
            
            method_fallback_count = 0
            if existing_agent:
                current_method = existing_agent[0]
                current_fallback_count = existing_agent[1] or 0
                
                # Increment fallback count if method changed to a fallback method
                if current_method != communication_method:
                    if communication_method in [COMM_METHOD_UDP, COMM_METHOD_LAYER2]:
                        method_fallback_count = current_fallback_count + 1
                    else:
                        method_fallback_count = current_fallback_count
                else:
                    method_fallback_count = current_fallback_count
            
            cursor.execute('''
                INSERT OR REPLACE INTO agents 
                (agent_id, hostname, platform, last_seen, status, ip_address, 
                 communication_method, last_communication_method, method_fallback_count)
                VALUES (?, ?, ?, ?, 'online', ?, ?, ?, ?)
            ''', (agent_id, hostname, platform, datetime.now(), ip_address, 
                  communication_method, communication_method, method_fallback_count))
            conn.commit()
            
            # Log communication method change if different
            if existing_agent and existing_agent[0] != communication_method:
                logger.info(f"Agent {agent_id} communication method changed: {existing_agent[0]} -> {communication_method}")
    
    def update_agent_status(self, agent_id, status='online'):
        """Update agent last seen and status"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE agents SET last_seen = ?, status = ? WHERE agent_id = ?
            ''', (datetime.now(), status, agent_id))
            conn.commit()
    
    def insert_metrics(self, agent_id, metrics_data):
        """Insert metrics data for an agent"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for metric in metrics_data:
                cursor.execute('''
                    INSERT INTO metrics 
                    (agent_id, timestamp, cpu_percent, memory_percent, memory_used_gb, memory_total_gb, packet_loss_percent)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    agent_id,
                    datetime.fromisoformat(metric['timestamp'].replace('Z', '+00:00')) if 'T' in metric['timestamp'] else datetime.strptime(metric['timestamp'], '%Y-%m-%d %H:%M:%S'),
                    metric.get('cpu_percent', 0),
                    metric.get('memory_percent', 0),
                    metric.get('memory_used_gb', 0),
                    metric.get('memory_total_gb', 0),
                    metric.get('packet_loss_percent', 0)
                ))
            conn.commit()
    
    def insert_faults(self, agent_id, faults_data):
        """Insert fault data for an agent"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Insert from rule suggestions
            for suggestion in faults_data.get('rule_suggestions', []):
                cursor.execute('''
                    INSERT INTO faults (agent_id, timestamp, fault_type, severity, description)
                    VALUES (?, ?, 'rule_based', 'warning', ?)
                ''', (agent_id, datetime.now(), suggestion['issue']))
            
            # Insert from ML suggestions
            for suggestion in faults_data.get('ml_suggestions', []):
                severity = suggestion.get('reliability', 'medium').lower()
                cursor.execute('''
                    INSERT INTO faults (agent_id, timestamp, fault_type, severity, description)
                    VALUES (?, ?, 'ml_based', ?, ?)
                ''', (agent_id, datetime.now(), severity, suggestion['issue']))
            
            conn.commit()
    
    def insert_ml_insights(self, agent_id, ml_data):
        """Insert ML insights for an agent - FIXED VERSION"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Insert anomalies
            for anomaly in ml_data.get('anomalies', []):
                cursor.execute('''
                    INSERT INTO ml_insights 
                    (agent_id, timestamp, insight_type, confidence, reliability, description, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    agent_id, 
                    datetime.now(), 
                    'anomaly',
                    anomaly.get('confidence', 0),
                    anomaly.get('reliability_label', 'medium'),
                    anomaly.get('description', ''),
                    json.dumps(anomaly.get('metrics', {}))
                ))
            
            # Insert predictions
            for prediction in ml_data.get('predictions', []):
                cursor.execute('''
                    INSERT INTO ml_insights 
                    (agent_id, timestamp, insight_type, confidence, reliability, description, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    agent_id, 
                    datetime.now(), 
                    'prediction',
                    70,  # Default confidence for predictions
                    prediction.get('certainty', 'medium'),
                    f"{prediction.get('metric', '')} trending {prediction.get('trend', '')}",
                    json.dumps(prediction)
                ))
            
            # Insert patterns
            for pattern in ml_data.get('patterns', []):
                cursor.execute('''
                    INSERT INTO ml_insights 
                    (agent_id, timestamp, insight_type, confidence, reliability, description, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    agent_id, 
                    datetime.now(), 
                    'pattern',
                    pattern.get('confidence', 50),
                    pattern.get('reliability', 'medium'),
                    pattern.get('description', ''),
                    json.dumps({'suggestion': pattern.get('suggestion', ''), 'pattern_type': pattern.get('pattern_type', '')})
                ))
            
            conn.commit()
    
    def insert_ip_diagnostics(self, agent_id, ip_data):
        """Insert IP diagnostics data for an agent"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            try:
                # Log the received IP data for debugging
                logger.info(f"Inserting IP diagnostics for agent {agent_id}: {json.dumps(ip_data, indent=2)}")
                
                # Insert main diagnostics record
                connectivity = ip_data.get('connectivity', {})
                timestamp = datetime.now()
                
                # Parse timestamp if provided
                if 'timestamp' in ip_data:
                    try:
                        if isinstance(ip_data['timestamp'], str):
                            if 'T' in ip_data['timestamp']:
                                timestamp = datetime.fromisoformat(ip_data['timestamp'].replace('Z', '+00:00'))
                            else:
                                timestamp = datetime.strptime(ip_data['timestamp'], '%Y-%m-%d %H:%M:%S')
                        else:
                            timestamp = ip_data['timestamp']
                    except Exception as e:
                        logger.warning(f"Could not parse timestamp {ip_data['timestamp']}: {e}")
                        timestamp = datetime.now()
                
                has_issues = bool(ip_data.get('has_issues', False))
                issues_count = len(ip_data.get('issues', []))
                
                # If there are issues but has_issues is False, set it to True
                if issues_count > 0 and not has_issues:
                    has_issues = True
                    logger.info(f"Auto-corrected has_issues to True for agent {agent_id} due to {issues_count} issues found")
                
                cursor.execute('''
                    INSERT INTO ip_diagnostics 
                    (agent_id, timestamp, has_issues, issues_count, connectivity_dns, connectivity_ping, connectivity_http, 
                     external_ip, interfaces_data, issues_data, solutions_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    agent_id,
                    timestamp,
                    has_issues,
                    issues_count,
                    connectivity.get('dns_resolution', False),
                    connectivity.get('ping_test', False),
                    connectivity.get('http_test', False),
                    connectivity.get('external_ip', ''),
                    json.dumps(ip_data.get('interfaces', [])),
                    json.dumps(ip_data.get('issues', [])),
                    json.dumps(ip_data.get('solutions', []))
                ))
                
                # Insert network interfaces data
                for interface in ip_data.get('interfaces', []):
                    cursor.execute('''
                        INSERT INTO network_interfaces 
                        (agent_id, interface_name, ip_address, netmask, is_up, is_dhcp, network_address, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        agent_id,
                        interface.get('interface', ''),
                        interface.get('ip', ''),
                        interface.get('netmask', ''),
                        interface.get('is_up', False),
                        interface.get('is_dhcp', False),
                        interface.get('network', ''),
                        timestamp
                    ))
                
                conn.commit()
                logger.info(f"Successfully inserted IP diagnostics for agent {agent_id}: has_issues={has_issues}, issues_count={issues_count}")
                
            except Exception as e:
                logger.error(f"Error inserting IP diagnostics for agent {agent_id}: {e}")
                logger.error(f"IP data: {json.dumps(ip_data, indent=2)}")
                raise
    
    def log_event(self, agent_id, event_type, severity, message):
        """Log system events"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO events (agent_id, event_type, severity, message)
                VALUES (?, ?, ?, ?)
            ''', (agent_id, event_type, severity, message))
            conn.commit()
    
    def get_agents_summary(self):
        """Get summary of all agents with communication method information"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT agent_id, hostname, platform, last_seen, status, ip_address, created_at,
                       communication_method, last_communication_method, method_fallback_count
                FROM agents ORDER BY last_seen DESC
            ''')
            agents = []
            for row in cursor.fetchall():
                last_seen = datetime.fromisoformat(row[3]) if row[3] else None
                status = 'offline' if last_seen and (datetime.now() - last_seen).seconds > 300 else row[4]
                
                agents.append({
                    'agent_id': row[0],
                    'hostname': row[1],
                    'platform': row[2],
                    'last_seen': last_seen.strftime('%Y-%m-%d %H:%M:%S') if last_seen else 'Never',
                    'status': status,
                    'ip_address': row[5],
                    'created_at': row[6],
                    'communication_method': row[7] if len(row) > 7 else 'HTTP',
                    'last_communication_method': row[8] if len(row) > 8 else None,
                    'method_fallback_count': row[9] if len(row) > 9 else 0
                })
            return agents
    
    def get_agent_metrics(self, agent_id=None, hours_back=24):
        """Get metrics for specific agent or all agents"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            since = datetime.now() - timedelta(hours=hours_back)
            
            if agent_id:
                cursor.execute('''
                    SELECT timestamp, cpu_percent, memory_percent, packet_loss_percent
                    FROM metrics WHERE agent_id = ? AND timestamp > ?
                    ORDER BY timestamp DESC LIMIT 1000
                ''', (agent_id, since))
            else:
                cursor.execute('''
                    SELECT agent_id, timestamp, cpu_percent, memory_percent, packet_loss_percent
                    FROM metrics WHERE timestamp > ?
                    ORDER BY timestamp DESC LIMIT 5000
                ''', (since,))
            
            return cursor.fetchall()
    
    def get_active_faults(self, agent_id=None):
        """Get active faults"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if agent_id:
                cursor.execute('''
                    SELECT id, fault_type, severity, description, timestamp
                    FROM faults WHERE agent_id = ? AND status = 'active'
                    ORDER BY timestamp DESC LIMIT 100
                ''', (agent_id,))
            else:
                cursor.execute('''
                    SELECT agent_id, fault_type, severity, description, timestamp
                    FROM faults WHERE status = 'active'
                    ORDER BY timestamp DESC LIMIT 500
                ''')
            
            return cursor.fetchall()
    
    def get_fault_distribution(self):
        """Get fault distribution by type for all agents with enhanced categorization"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 
                    CASE 
                        WHEN LOWER(description) LIKE '%memory%' 
                             OR LOWER(description) LIKE '%ram%' 
                             OR LOWER(description) LIKE '%out of memory%'
                             OR LOWER(description) LIKE '%memory usage%'
                             OR LOWER(description) LIKE '%memory leak%'
                             OR LOWER(description) LIKE '%swap%' THEN 'Memory Usage'
                        
                        WHEN LOWER(description) LIKE '%cpu%' 
                             OR LOWER(description) LIKE '%processor%' 
                             OR LOWER(description) LIKE '%high load%'
                             OR LOWER(description) LIKE '%cpu usage%'
                             OR LOWER(description) LIKE '%cpu spike%'
                             OR LOWER(description) LIKE '%load average%' THEN 'CPU Usage'
                        
                        WHEN LOWER(description) LIKE '%disk%' 
                             OR LOWER(description) LIKE '%storage%' 
                             OR LOWER(description) LIKE '%drive%'
                             OR LOWER(description) LIKE '%filesystem%'
                             OR LOWER(description) LIKE '%disk space%'
                             OR LOWER(description) LIKE '%disk full%'
                             OR LOWER(description) LIKE '%inode%' THEN 'Disk Issues'
                        
                        WHEN LOWER(description) LIKE '%network%' 
                             OR LOWER(description) LIKE '%connection%' 
                             OR LOWER(description) LIKE '%connectivity%'
                             OR LOWER(description) LIKE '%packet loss%'
                             OR LOWER(description) LIKE '%latency%'
                             OR LOWER(description) LIKE '%bandwidth%'
                             OR LOWER(description) LIKE '%timeout%'
                             OR LOWER(description) LIKE '%dns%'
                             OR LOWER(description) LIKE '%ping%'
                             OR LOWER(description) LIKE '%internet%' THEN 'Network Issues'
                        
                        WHEN LOWER(description) LIKE '%performance%' 
                             OR LOWER(description) LIKE '%slow%' 
                             OR LOWER(description) LIKE '%response time%'
                             OR LOWER(description) LIKE '%bottleneck%'
                             OR LOWER(description) LIKE '%throughput%' THEN 'Performance Issues'
                        
                        WHEN LOWER(description) LIKE '%service%' 
                             OR LOWER(description) LIKE '%process%' 
                             OR LOWER(description) LIKE '%daemon%'
                             OR LOWER(description) LIKE '%application%'
                             OR LOWER(description) LIKE '%crashed%'
                             OR LOWER(description) LIKE '%failed to start%' THEN 'Service Issues'
                        
                        WHEN LOWER(description) LIKE '%security%' 
                             OR LOWER(description) LIKE '%authentication%' 
                             OR LOWER(description) LIKE '%permission%'
                             OR LOWER(description) LIKE '%unauthorized%'
                             OR LOWER(description) LIKE '%breach%' THEN 'Security Issues'
                        
                        ELSE 'System Faults'
                    END as fault_category,
                    COUNT(*) as fault_count
                FROM faults 
                WHERE status = 'active'
                GROUP BY fault_category
                ORDER BY fault_count DESC
            ''')
            
            results = cursor.fetchall()
            logger.info(f"Fault distribution query returned: {results}")
            return results
    
    def get_ml_insights_summary(self, agent_id=None, hours_back=24):
        """Get ML insights summary"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            since = datetime.now() - timedelta(hours=hours_back)
            
            if agent_id:
                cursor.execute('''
                    SELECT insight_type, confidence, reliability, description, timestamp
                    FROM ml_insights WHERE agent_id = ? AND timestamp > ?
                    ORDER BY timestamp DESC LIMIT 100
                ''', (agent_id, since))
            else:
                cursor.execute('''
                    SELECT agent_id, insight_type, confidence, reliability, description, timestamp
                    FROM ml_insights WHERE timestamp > ?
                    ORDER BY timestamp DESC LIMIT 500
                ''', (since,))
            
            return cursor.fetchall()
    
    def get_ip_diagnostics_summary(self, agent_id=None, hours_back=24):
        """Get IP diagnostics summary"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            since = datetime.now() - timedelta(hours=hours_back)
            
            if agent_id:
                cursor.execute('''
                    SELECT timestamp, has_issues, issues_count, connectivity_dns, connectivity_ping, 
                           connectivity_http, external_ip, interfaces_data, issues_data
                    FROM ip_diagnostics WHERE agent_id = ? AND timestamp > ?
                    ORDER BY timestamp DESC LIMIT 50
                ''', (agent_id, since))
            else:
                cursor.execute('''
                    SELECT agent_id, timestamp, has_issues, issues_count, connectivity_dns, 
                           connectivity_ping, connectivity_http, external_ip
                    FROM ip_diagnostics WHERE timestamp > ?
                    ORDER BY timestamp DESC LIMIT 200
                ''', (since,))
            
            return cursor.fetchall()
    
    def get_network_interfaces_summary(self, agent_id=None):
        """Get network interfaces summary"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            if agent_id:
                cursor.execute('''
                    SELECT interface_name, ip_address, netmask, is_up, is_dhcp, network_address, timestamp
                    FROM network_interfaces WHERE agent_id = ?
                    ORDER BY timestamp DESC LIMIT 10
                ''', (agent_id,))
            else:
                cursor.execute('''
                    SELECT agent_id, interface_name, ip_address, netmask, is_up, is_dhcp, timestamp
                    FROM network_interfaces 
                    ORDER BY timestamp DESC LIMIT 100
                ''')
            
            return cursor.fetchall()
    
    def get_system_statistics(self):
        """Get overall system statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total agents
            cursor.execute('SELECT COUNT(*) FROM agents')
            total_agents = cursor.fetchone()[0]
            
            # Online agents (last seen within 5 minutes)
            five_minutes_ago = datetime.now() - timedelta(minutes=5)
            cursor.execute('SELECT COUNT(*) FROM agents WHERE last_seen > ?', (five_minutes_ago,))
            online_agents = cursor.fetchone()[0]
            
            # Active faults
            cursor.execute('SELECT COUNT(*) FROM faults WHERE status = "active"')
            active_faults = cursor.fetchone()[0]
            
            # ML insights today
            today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            cursor.execute('SELECT COUNT(*) FROM ml_insights WHERE timestamp > ?', (today,))
            ml_insights_today = cursor.fetchone()[0]
            
            # IP diagnostics issues today
            cursor.execute('''
                SELECT COUNT(DISTINCT agent_id) 
                FROM ip_diagnostics 
                WHERE timestamp > ? AND (has_issues = 1 OR issues_count > 0)
            ''', (today,))
            ip_issues_today = cursor.fetchone()[0]
            
            # Combined issues (faults + IP issues) - Combined count
            combined_issues = active_faults + ip_issues_today
            
            # Average metrics (last hour)
            one_hour_ago = datetime.now() - timedelta(hours=1)
            cursor.execute('''
                SELECT AVG(cpu_percent), AVG(memory_percent), AVG(packet_loss_percent)
                FROM metrics WHERE timestamp > ?
            ''', (one_hour_ago,))
            avg_metrics = cursor.fetchone()
            
            logger.info(f"System statistics - Total agents: {total_agents}, Active faults: {active_faults}, IP issues today: {ip_issues_today}, Combined issues: {combined_issues}")
            
            return {
                'total_agents': total_agents,
                'online_agents': online_agents,
                'offline_agents': total_agents - online_agents,
                'active_faults': active_faults,
                'ml_insights_today': ml_insights_today,
                'ip_issues_today': ip_issues_today,
                'combined_issues': combined_issues,  # Combined metric
                'avg_cpu': round(avg_metrics[0] or 0, 1),
                'avg_memory': round(avg_metrics[1] or 0, 1),
                'avg_packet_loss': round(avg_metrics[2] or 0, 1)
            }

# === Global instances ===
db_manager = DatabaseManager()
agent_data_cache = defaultdict(lambda: {'last_update': None, 'metrics': deque(maxlen=100)})

# Set database manager references
layer2_server.set_db_manager(db_manager)
broadcast_server.set_db_manager(db_manager)

# === Agent Status Monitor ===
class AgentStatusMonitor:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
    
    def _monitor_loop(self):
        """Monitor agent status and mark offline agents"""
        while self.running:
            try:
                agents = self.db_manager.get_agents_summary()
                current_time = datetime.now()
                
                for agent in agents:
                    if agent['last_seen'] != 'Never':
                        last_seen = datetime.strptime(agent['last_seen'], '%Y-%m-%d %H:%M:%S')
                        if (current_time - last_seen).seconds > 300:  # 5 minutes timeout
                            if agent['status'] != 'offline':
                                self.db_manager.update_agent_status(agent['agent_id'], 'offline')
                                self.db_manager.log_event(
                                    agent['agent_id'], 'status_change', 'warning',
                                    f"Agent {agent['agent_id']} went offline"
                                )
                
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Error in agent status monitor: {e}")
                time.sleep(60)

# Start status monitor
status_monitor = AgentStatusMonitor(db_manager)

# === Enhanced Flask Routes with Communication Method Tracking ===

@app.route('/')
def dashboard():
    """Main dashboard"""
    return render_template('server_dashboard.html')

@app.route('/api/agent/data', methods=['POST'])
def receive_agent_data():
    """Receive data from agents with communication method tracking - FIXED VERSION"""
    try:
        data_package = request.json
        if not data_package:
            logger.error("No JSON data received in HTTP request")
            return jsonify({'error': 'No data provided'}), 400
        
        agent_id = data_package.get('agent_id')
        hostname = data_package.get('hostname', 'unknown')
        platform = data_package.get('platform', 'unknown')
        ip_address = request.remote_addr
        
        if not agent_id:
            logger.error("No agent_id in HTTP request")
            return jsonify({'error': 'Agent ID required'}), 400
        
        logger.info(f"Received HTTP request from agent {agent_id} ({hostname}) [METHOD: {COMM_METHOD_HTTP}]")
        
        # Register/update agent with HTTP communication method
        db_manager.register_agent(agent_id, hostname, platform, ip_address, COMM_METHOD_HTTP)
        
        # Process data from the package
        agent_data = data_package.get('data', {})
        
        # Insert metrics
        if 'metrics' in agent_data and agent_data['metrics']:
            db_manager.insert_metrics(agent_id, agent_data['metrics'])
        
        # Insert faults
        if 'faults' in agent_data and agent_data['faults']:
            db_manager.insert_faults(agent_id, agent_data['faults'])
        
        # Insert ML insights
        if 'ml_insights' in agent_data and agent_data['ml_insights']:
            db_manager.insert_ml_insights(agent_id, agent_data['ml_insights'])
        
        # Insert IP diagnostics
        if 'ip_diagnostics' in agent_data and agent_data['ip_diagnostics']:
            logger.info(f"Processing IP diagnostics for agent {agent_id} via HTTP")
            db_manager.insert_ip_diagnostics(agent_id, agent_data['ip_diagnostics'])
        
        # Process processes if present
        if 'processes' in agent_data and agent_data['processes']:
            # Handle processes data if needed
            pass
        
        # Log successful data reception with communication method
        db_manager.log_event(agent_id, 'data_received', 'info', 
                           f"Received data package from {hostname} via {COMM_METHOD_HTTP}")
        
        # Update cache
        agent_data_cache[agent_id]['last_update'] = datetime.now()
        
        logger.info(f"Successfully processed HTTP data from agent {agent_id} ({hostname}) [METHOD: {COMM_METHOD_HTTP}]")
        return jsonify({'status': 'success', 'message': 'Data received successfully'})
        
    except Exception as e:
        logger.error(f"Error receiving HTTP agent data: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/dashboard/summary')
def get_dashboard_summary():
    """Get dashboard summary data with communication method information"""
    try:
        stats = db_manager.get_system_statistics()
        agents = db_manager.get_agents_summary()
        
        # Get recent faults by agent
        faults_by_agent = defaultdict(int)
        active_faults = db_manager.get_active_faults()
        for fault in active_faults:
            faults_by_agent[fault[0]] += 1
        
        # Agent status distribution
        status_counts = {'online': 0, 'offline': 0, 'warning': 0}
        for agent in agents:
            if agent['status'] in status_counts:
                status_counts[agent['status']] += 1
            else:
                status_counts['offline'] += 1
        
        # Communication method distribution
        method_counts = {COMM_METHOD_HTTP: 0, COMM_METHOD_UDP: 0, COMM_METHOD_LAYER2: 0}
        for agent in agents:
            method = agent.get('communication_method', COMM_METHOD_HTTP)
            if method in method_counts:
                method_counts[method] += 1
        
        return jsonify({
            'statistics': stats,
            'agents': agents[:10],  # Last 10 agents
            'agent_status_distribution': status_counts,
            'communication_method_distribution': method_counts,
            'faults_by_agent': dict(faults_by_agent),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting dashboard summary: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/agents')
def get_agents():
    """Get all agents with communication method information"""
    try:
        agents = db_manager.get_agents_summary()
        return jsonify(agents)
    except Exception as e:
        logger.error(f"Error getting agents: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/agent/<agent_id>/details')
def get_agent_details(agent_id):
    """Get detailed information for specific agent"""
    try:
        # Get agent basic info
        agents = db_manager.get_agents_summary()
        agent_info = next((a for a in agents if a['agent_id'] == agent_id), None)
        
        if not agent_info:
            return jsonify({'error': 'Agent not found'}), 404
        
        # Get recent metrics
        metrics = db_manager.get_agent_metrics(agent_id, hours_back=24)
        
        # Get active faults
        faults = db_manager.get_active_faults(agent_id)
        
        # Get ML insights
        ml_insights = db_manager.get_ml_insights_summary(agent_id, hours_back=24)
        
        # Get IP diagnostics with enhanced parsing
        ip_diagnostics = db_manager.get_ip_diagnostics_summary(agent_id, hours_back=24)
        
        # Get network interfaces
        network_interfaces = db_manager.get_network_interfaces_summary(agent_id)
        
        return jsonify({
            'agent_info': agent_info,
            'metrics': [
                {
                    'timestamp': m[0],
                    'cpu_percent': m[1],
                    'memory_percent': m[2],
                    'packet_loss_percent': m[3]
                } for m in metrics
            ],
            'faults': [
                {
                    'id': f[0],
                    'type': f[1],
                    'severity': f[2],
                    'description': f[3],
                    'timestamp': f[4]
                } for f in faults
            ],
            'ml_insights': [
                {
                    'type': m[0],
                    'confidence': m[1],
                    'reliability': m[2],
                    'description': m[3],
                    'timestamp': m[4]
                } for m in ml_insights
            ],
            'ip_diagnostics': [
                {
                    'timestamp': ip[0],
                    'has_issues': bool(ip[1]),
                    'issues_count': ip[2],
                    'connectivity_dns': bool(ip[3]),
                    'connectivity_ping': bool(ip[4]),
                    'connectivity_http': bool(ip[5]),
                    'external_ip': ip[6],
                    'interfaces_data': json.loads(ip[7]) if len(ip) > 7 and ip[7] else [],
                    'issues_data': json.loads(ip[8]) if len(ip) > 8 and ip[8] else [],
                    'parsed_issues': parse_diagnostic_issues(ip[8] if len(ip) > 8 else None)
                } for ip in ip_diagnostics
            ],
            'network_interfaces': [
                {
                    'interface_name': ni[0],
                    'ip_address': ni[1],
                    'netmask': ni[2],
                    'is_up': bool(ni[3]),
                    'is_dhcp': bool(ni[4]),
                    'network_address': ni[5],
                    'timestamp': ni[6]
                } for ni in network_interfaces
            ]
        })
    except Exception as e:
        logger.error(f"Error getting agent details: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/metrics/chart')
def get_metrics_chart():
    """Get metrics data for charts"""
    try:
        agent_id = request.args.get('agent_id')
        hours_back = int(request.args.get('hours', 24))
        
        metrics = db_manager.get_agent_metrics(agent_id, hours_back)
        
        if agent_id:
            # Single agent chart
            timestamps = [m[0] for m in metrics]
            cpu_data = [m[1] for m in metrics]
            memory_data = [m[2] for m in metrics]
            network_data = [m[3] for m in metrics]
            
            return jsonify({
                'timestamps': timestamps[-100:],  # Last 100 points
                'cpu_data': cpu_data[-100:],
                'memory_data': memory_data[-100:],
                'network_data': network_data[-100:]
            })
        else:
            # Multi-agent aggregated chart
            agent_metrics = defaultdict(list)
            for m in metrics:
                agent_metrics[m[0]].append({
                    'timestamp': m[1],
                    'cpu': m[2],
                    'memory': m[3],
                    'network': m[4]
                })
            
            # Calculate averages across all agents
            all_timestamps = []
            avg_cpu = []
            avg_memory = []
            avg_network = []
            
            # Group by time and calculate averages
            time_groups = defaultdict(list)
            for agent_id, metric_list in agent_metrics.items():
                for metric in metric_list:
                    time_key = metric['timestamp'][:16]  # Group by minute
                    time_groups[time_key].append(metric)
            
            for time_key in sorted(time_groups.keys())[-100:]:  # Last 100 time points
                metrics_at_time = time_groups[time_key]
                all_timestamps.append(time_key)
                avg_cpu.append(statistics.mean([m['cpu'] for m in metrics_at_time]))
                avg_memory.append(statistics.mean([m['memory'] for m in metrics_at_time]))
                avg_network.append(statistics.mean([m['network'] for m in metrics_at_time]))
            
            return jsonify({
                'timestamps': all_timestamps,
                'cpu_data': avg_cpu,
                'memory_data': avg_memory,
                'network_data': avg_network
            })
            
    except Exception as e:
        logger.error(f"Error getting metrics chart: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/fault-distribution')
def get_fault_distribution():
    """Get fault distribution data for the bar chart"""
    try:
        fault_distribution = db_manager.get_fault_distribution()
        
        categories = [f[0] for f in fault_distribution]
        counts = [f[1] for f in fault_distribution]
        
        logger.info(f"Fault distribution API returning: categories={categories}, counts={counts}")
        
        return jsonify({
            'categories': categories,
            'counts': counts
        })
    except Exception as e:
        logger.error(f"Error getting fault distribution: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/faults')
def get_faults():
    """Get active faults"""
    try:
        agent_id = request.args.get('agent_id')
        faults = db_manager.get_active_faults(agent_id)
        
        fault_list = []
        for fault in faults:
            if agent_id:
                fault_list.append({
                    'id': fault[0],
                    'type': fault[1],
                    'severity': fault[2],
                    'description': fault[3],
                    'timestamp': fault[4]
                })
            else:
                fault_list.append({
                    'agent_id': fault[0],
                    'type': fault[1],
                    'severity': fault[2],
                    'description': fault[3],
                    'timestamp': fault[4]
                })
        
        return jsonify(fault_list)
    except Exception as e:
        logger.error(f"Error getting faults: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/ml-insights')
def get_ml_insights():
    """Get ML insights"""
    try:
        agent_id = request.args.get('agent_id')
        hours_back = int(request.args.get('hours', 24))
        
        insights = db_manager.get_ml_insights_summary(agent_id, hours_back)
        
        insight_list = []
        for insight in insights:
            if agent_id:
                insight_list.append({
                    'type': insight[0],
                    'confidence': insight[1],
                    'reliability': insight[2],
                    'description': insight[3],
                    'timestamp': insight[4]
                })
            else:
                insight_list.append({
                    'agent_id': insight[0],
                    'type': insight[1],
                    'confidence': insight[2],
                    'reliability': insight[3],
                    'description': insight[4],
                    'timestamp': insight[5]
                })
        
        return jsonify(insight_list)
    except Exception as e:
        logger.error(f"Error getting ML insights: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/ip-diagnostics')
def get_ip_diagnostics():
    """Get IP diagnostics data with enhanced technical details"""
    try:
        agent_id = request.args.get('agent_id')
        hours_back = int(request.args.get('hours', 24))
        
        diagnostics = db_manager.get_ip_diagnostics_summary(agent_id, hours_back)
        
        diagnostics_list = []
        for diag in diagnostics:
            if agent_id:
                diagnostics_list.append({
                    'timestamp': diag[0],
                    'has_issues': bool(diag[1]),
                    'issues_count': diag[2],
                    'connectivity_dns': bool(diag[3]),
                    'connectivity_ping': bool(diag[4]),
                    'connectivity_http': bool(diag[5]),
                    'external_ip': diag[6],
                    'interfaces_data': json.loads(diag[7]) if len(diag) > 7 and diag[7] else [],
                    'issues_data': json.loads(diag[8]) if len(diag) > 8 and diag[8] else [],
                    'parsed_issues': parse_diagnostic_issues(diag[8] if len(diag) > 8 else None)
                })
            else:
                # Enhanced technical details for overview
                parsed_issues = parse_diagnostic_issues(None)  # Will get enhanced later
                if len(diag) > 7:
                    try:
                        # Try to get issues data for parsing
                        with sqlite3.connect(db_manager.db_path) as conn:
                            cursor = conn.cursor()
                            cursor.execute('SELECT issues_data FROM ip_diagnostics WHERE agent_id = ? AND timestamp = ?', 
                                         (diag[0], diag[1]))
                            issues_row = cursor.fetchone()
                            if issues_row and issues_row[0]:
                                parsed_issues = parse_diagnostic_issues(issues_row[0])
                    except:
                        parsed_issues = 'Issues Detected' if diag[2] else 'No Issues'
                
                diagnostics_list.append({
                    'agent_id': diag[0],
                    'timestamp': diag[1],
                    'has_issues': bool(diag[2]),
                    'issues_count': diag[3],
                    'connectivity_dns': bool(diag[4]),
                    'connectivity_ping': bool(diag[5]),
                    'connectivity_http': bool(diag[6]),
                    'external_ip': diag[7] if len(diag) > 7 else '',
                    'parsed_issues': parsed_issues
                })
        
        logger.info(f"IP diagnostics API returning {len(diagnostics_list)} records for agent_id={agent_id}")
        return jsonify(diagnostics_list)
    except Exception as e:
        logger.error(f"Error getting IP diagnostics: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/network-interfaces')
def get_network_interfaces():
    """Get network interfaces data"""
    try:
        agent_id = request.args.get('agent_id')
        interfaces = db_manager.get_network_interfaces_summary(agent_id)
        
        interface_list = []
        for interface in interfaces:
            if agent_id:
                interface_list.append({
                    'interface_name': interface[0],
                    'ip_address': interface[1],
                    'netmask': interface[2],
                    'is_up': bool(interface[3]),
                    'is_dhcp': bool(interface[4]),
                    'network_address': interface[5],
                    'timestamp': interface[6]
                })
            else:
                interface_list.append({
                    'agent_id': interface[0],
                    'interface_name': interface[1],
                    'ip_address': interface[2],
                    'netmask': interface[3],
                    'is_up': bool(interface[4]),
                    'is_dhcp': bool(interface[5]),
                    'timestamp': interface[6]
                })
        
        return jsonify(interface_list)
    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/agent/<agent_id>')
def agent_detail_page(agent_id):
    """Agent detail page"""
    return render_template('agent_detail.html', agent_id=agent_id)

# === Configuration Routes for Manual MAC Address ===
@app.route('/api/config/set-mac', methods=['POST'])
def set_manual_mac():
    """Set manual MAC address for Layer 2 interface"""
    try:
        data = request.json
        if not data or 'mac_address' not in data:
            return jsonify({'error': 'MAC address required'}), 400
        
        mac_address = data['mac_address'].strip()
        
        # Basic MAC address validation
        if not mac_address or len(mac_address.replace(':', '').replace('-', '')) != 12:
            return jsonify({'error': 'Invalid MAC address format'}), 400
        
        # Normalize MAC address format
        mac_clean = mac_address.replace('-', ':').lower()
        
        # Set the manual MAC address
        layer2_server.set_manual_mac(mac_clean)
        
        # Restart Layer 2 server if it's running
        if layer2_server.running:
            logger.info("Restarting Layer 2 server with new MAC address...")
            layer2_server.stop()
            time.sleep(2)  # Wait for clean shutdown
            layer2_server.start()
        
        return jsonify({
            'status': 'success', 
            'message': f'Manual MAC address set to {mac_clean}',
            'mac_address': mac_clean
        })
        
    except Exception as e:
        logger.error(f"Error setting manual MAC address: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/config/get-mac')
def get_current_mac():
    """Get current MAC address configuration"""
    try:
        return jsonify({
            'manual_mac': MANUAL_MAC_ADDRESS,
            'server_mac': layer2_server.server_mac,
            'interface': layer2_server.interface,
            'layer2_running': layer2_server.running
        })
    except Exception as e:
        logger.error(f"Error getting MAC configuration: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/layer2/stats')
def get_layer2_stats():
    """Get Layer 2 server statistics"""
    try:
        stats = layer2_server.get_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting Layer 2 statistics: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# === Debug Route for Testing ===
@app.route('/api/debug/create-test-faults')
def create_test_faults():
    """Create test faults for debugging fault distribution"""
    try:
        test_faults = [
            {'agent_id': 'test-agent-1', 'description': 'CPU usage is above 90%', 'severity': 'high'},
            {'agent_id': 'test-agent-1', 'description': 'Memory usage critical - out of memory', 'severity': 'critical'},
            {'agent_id': 'test-agent-2', 'description': 'Disk space running low on /var partition', 'severity': 'medium'},
            {'agent_id': 'test-agent-2', 'description': 'Network connectivity issues detected', 'severity': 'high'},
            {'agent_id': 'test-agent-3', 'description': 'Service performance degraded - slow response time', 'severity': 'medium'},
            {'agent_id': 'test-agent-3', 'description': 'Security alert: unauthorized access attempt', 'severity': 'high'},
        ]
        
        with sqlite3.connect(db_manager.db_path) as conn:
            cursor = conn.cursor()
            for fault in test_faults:
                cursor.execute('''
                    INSERT INTO faults (agent_id, timestamp, fault_type, severity, description)
                    VALUES (?, ?, 'test', ?, ?)
                ''', (fault['agent_id'], datetime.now(), fault['severity'], fault['description']))
            conn.commit()
        
        return jsonify({'status': 'success', 'message': f'Created {len(test_faults)} test faults'})
    except Exception as e:
        logger.error(f"Error creating test faults: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# === HTML Templates with Enhanced Communication Method Display ===
SERVER_DASHBOARD_HTML = '''<!DOCTYPE html>
<html>
<head>
    <title>Network Diagnostic System - Admin Server</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: #f5f6fa;
            color: #2c3e50;
            line-height: 1.6;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .header .subtitle {
            opacity: 0.9;
            font-size: 1.1rem;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            border-left: 4px solid #3498db;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }
        
        .stat-card.agents { border-left-color: #3498db; }
        .stat-card.issues { border-left-color: #e74c3c; }
        
        .stat-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .stat-icon {
            font-size: 2rem;
            opacity: 0.7;
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            color: #2c3e50;
        }
        
        .stat-label {
            color: #7f8c8d;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }
        
        .stat-change {
            font-size: 0.8rem;
            margin-top: 0.5rem;
        }
        
        .stat-change.positive { color: #27ae60; }
        .stat-change.negative { color: #e74c3c; }
        
        .main-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .chart-container {
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            margin-bottom: 1.5rem;
        }
        
        .chart-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .chart-title {
            font-size: 1.3rem;
            font-weight: 600;
            color: #2c3e50;
        }
        
        .chart-controls {
            display: flex;
            gap: 0.5rem;
        }
        
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 500;
            transition: all 0.2s;
        }
        
        .btn-primary {
            background-color: #3498db;
            color: white;
        }
        
        .btn-primary:hover {
            background-color: #2980b9;
        }
        
        .btn-secondary {
            background-color: #ecf0f1;
            color: #2c3e50;
        }
        
        .btn-secondary:hover {
            background-color: #d5dbdb;
        }
        
        .btn.active {
            background-color: #2c3e50;
            color: white;
        }
        
        .agents-panel {
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            overflow: hidden;
        }
        
        .panel-header {
            background-color: #f8f9fa;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .panel-title {
            font-size: 1.1rem;
            font-weight: 600;
            color: #2c3e50;
        }
        
        .agents-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .agent-item {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #ecf0f1;
            transition: background-color 0.2s;
            cursor: pointer;
        }
        
        .agent-item:hover {
            background-color: #f8f9fa;
        }
        
        .agent-item:last-child {
            border-bottom: none;
        }
        
        .agent-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        
        .agent-name {
            font-weight: 600;
            color: #2c3e50;
        }
        
        .agent-status {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 500;
        }
        
        .status-online {
            background-color: #d4edda;
            color: #155724;
        }
        
        .status-offline {
            background-color: #f8d7da;
            color: #721c24;
        }
        
        .status-warning {
            background-color: #fff3cd;
            color: #856404;
        }
        
        .agent-details {
            font-size: 0.9rem;
            color: #7f8c8d;
        }
        
        .agent-details span {
            margin-right: 1rem;
        }
        
        /* Communication method indicators */
        .comm-method {
            padding: 0.2rem 0.5rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 500;
            margin-left: 0.5rem;
        }
        
        .comm-http {
            background-color: #d4edda;
            color: #155724;
        }
        
        .comm-udp {
            background-color: #fff3cd;
            color: #856404;
        }
        
        .comm-layer2 {
            background-color: #f8d7da;
            color: #721c24;
        }
        
        .bottom-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 2rem;
        }
        
        .table-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            overflow: hidden;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .table th {
            background-color: #f8f9fa;
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            color: #2c3e50;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .table td {
            padding: 1rem;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .table tbody tr:hover {
            background-color: #f8f9fa;
        }
        
        .severity-high {
            color: #e74c3c;
            font-weight: 600;
        }
        
        .severity-medium {
            color: #f39c12;
            font-weight: 600;
        }
        
        .severity-low {
            color: #27ae60;
            font-weight: 600;
        }
        
        .timestamp {
            color: #7f8c8d;
            font-size: 0.9rem;
        }
        
        .loading {
            text-align: center;
            padding: 2rem;
            color: #7f8c8d;
        }
        
        .loading i {
            font-size: 2rem;
            margin-bottom: 1rem;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .no-data {
            text-align: center;
            padding: 2rem;
            color: #7f8c8d;
        }
        
        .refresh-indicator {
            position: fixed;
            top: 1rem;
            right: 1rem;
            background: rgba(52, 73, 94, 0.9);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.9rem;
            display: none;
            align-items: center;
            gap: 0.5rem;
        }
        
        .chart-placeholder {
            height: 350px;
            display: flex;
            align-items: center;
            justify-content: left;
            background-color: #f8f9fa;
            border-radius: 8px;
            color: #7f8c8d;
        }

        #fault-distribution-chart {
            height: 300px;
            width: 100%;
            min-height: 300px;
        }

        #performance-chart {
            height: 350px;
            width: 100%;
            min-height: 350px;
        }

        .chart-container {
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            overflow: hidden;
        }
        
        /* Network status indicators with tooltips */
        .network-status {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }
        
        .network-icon {
            font-size: 0.9rem;
            cursor: help;
            position: relative;
        }
        
        .network-good { color: #27ae60; }
        .network-warning { color: #f39c12; }
        .network-error { color: #e74c3c; }
        
        /* Custom tooltip styles */
        .tooltip-container {
            position: relative;
            display: inline-block;
        }
        
        .tooltip-text {
            visibility: hidden;
            width: 200px;
            background-color: #2c3e50;
            color: white;
            text-align: center;
            border-radius: 6px;
            padding: 8px;
            position: absolute;
            z-index: 1000;
            bottom: 125%;
            left: 50%;
            margin-left: -100px;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 0.8rem;
            line-height: 1.2;
        }
        
        .tooltip-text::after {
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            margin-left: -5px;
            border-width: 5px;
            border-style: solid;
            border-color: #2c3e50 transparent transparent transparent;
        }
        
        .tooltip-container:hover .tooltip-text {
            visibility: visible;
            opacity: 1;
        }
        
        /* Debug controls */
        .debug-controls {
            position: fixed;
            bottom: 1rem;
            left: 1rem;
            background: rgba(52, 73, 94, 0.9);
            color: white;
            padding: 0.5rem;
            border-radius: 6px;
            font-size: 0.8rem;
        }
        
        .debug-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            border: none;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8rem;
            margin-left: 0.5rem;
        }
        
        /* MAC Configuration controls */
        .config-controls {
            position: fixed;
            bottom: 4rem;
            left: 1rem;
            background: rgba(44, 62, 80, 0.9);
            color: white;
            padding: 0.5rem;
            border-radius: 6px;
            font-size: 0.8rem;
            min-width: 250px;
        }
        
        .config-input {
            width: 150px;
            padding: 0.25rem;
            margin: 0.25rem;
            border: none;
            border-radius: 4px;
            font-size: 0.8rem;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .main-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            }
        }

        /* IP Diagnostics specific styles */
        .ip-issues-column {
            max-width: 400px;
            word-wrap: break-word;
            line-height: 1.4;
        }
        
        .connectivity-icons {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .connectivity-icon {
            font-size: 1rem;
            cursor: help;
        }
        
        /* Enhanced technical issue styling */
        .technical-issue {
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.85rem;
            line-height: 1.3;
        }

        /* Layer 2 Stats display */
        .layer2-stats {
            position: fixed;
            bottom: 7rem;
            left: 1rem;
            background: rgba(44, 62, 80, 0.9);
            color: white;
            padding: 0.5rem;
            border-radius: 6px;
            font-size: 0.8rem;
            min-width: 250px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1><i class="fas fa-network-wired"></i> Enhanced Network Diagnostic System</h1>
        <div class="subtitle">Admin Dashboard - Multi-Protocol Support with Enhanced Layer 2 Raw Ethernet Reception</div>
    </div>
    
    <div class="refresh-indicator" id="refresh-indicator">
        <i class="fas fa-sync-alt fa-spin"></i>
        <span>Updating...</span>
    </div>
    
    <div class="debug-controls">
        Debug: 
        <button class="debug-btn" onclick="createTestFaults()">Create Test Faults</button>
        <button class="debug-btn" onclick="clearAllFaults()">Clear All Faults</button>
    </div>
    
    <div class="config-controls">
        Layer 2 MAC Config:
        <br>
        <input type="text" class="config-input" id="mac-input" placeholder="aa:bb:cc:dd:ee:ff">
        <button class="debug-btn" onclick="setManualMac()">Set MAC</button>
        <br>
        <small id="mac-status">Current: Auto-detect</small>
    </div>
    
    <div class="layer2-stats" id="layer2-stats">
        Layer 2 Server Stats:
        <br>
        <small id="layer2-status">Loading...</small>
    </div>
    
    <div class="container">
        <!-- Statistics Cards -->
        <div class="stats-grid">
            <div class="stat-card agents">
                <div class="stat-header">
                    <div>
                        <div class="stat-value" id="total-agents">-</div>
                        <div class="stat-label">Total Agents</div>
                    </div>
                    <i class="fas fa-desktop stat-icon"></i>
                </div>
                <div class="stat-change" id="agents-change">
                    <span id="online-agents">-</span> online, <span id="offline-agents">-</span> offline
                </div>
            </div>
            
            <div class="stat-card issues">
                <div class="stat-header">
                    <div>
                        <div class="stat-value" id="combined-issues">-</div>
                        <div class="stat-label">Active Issues</div>
                    </div>
                    <i class="fas fa-exclamation-triangle stat-icon"></i>
                </div>
                <div class="stat-change" id="issues-breakdown">
                    Combined faults and IP issues
                </div>
            </div>
        </div>
        
        <!-- Main Content Grid -->
        <div class="main-grid">
            <!-- Charts Column -->
            <div>
                <!-- Fault Distribution Chart -->
                <div class="chart-container">
                    <div class="chart-header">
                        <div class="chart-title">Fault Distribution by Type</div>
                    </div>
                    <div id="fault-distribution-chart" class="chart-placeholder">
                        <div>
                            <i class="fas fa-chart-bar fa-3x"></i>
                            <p>Loading fault distribution...</p>
                        </div>
                    </div>
                </div>
                
                <!-- Performance Chart -->
                <div class="chart-container">
                    <div class="chart-header">
                        <div class="chart-title">System Performance Overview</div>
                        <div class="chart-controls">
                            <button class="btn btn-secondary active" onclick="changeTimeRange(1)">1H</button>
                            <button class="btn btn-secondary" onclick="changeTimeRange(6)">6H</button>
                            <button class="btn btn-secondary" onclick="changeTimeRange(24)">24H</button>
                        </div>
                    </div>
                    <div id="performance-chart" class="chart-placeholder">
                        <div>
                            <i class="fas fa-chart-line fa-3x"></i>
                            <p>Loading performance data...</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Agents Panel with Communication Method Display -->
            <div class="agents-panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <i class="fas fa-desktop"></i> Connected Agents
                    </div>
                </div>
                <div class="agents-list" id="agents-list">
                    <div class="loading">
                        <i class="fas fa-spinner"></i>
                        <p>Loading agents...</p>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Bottom Tables Grid -->
        <div class="bottom-grid">
            <!-- IP Diagnostics History with Enhanced Technical Details -->
            <div class="table-container">
                <div class="panel-header">
                    <div class="panel-title">
                        <i class="fas fa-network-wired"></i> IP Diagnostics History - Enhanced Technical Details
                    </div>
                </div>
                <div style="overflow-x: auto;">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Agent</th>
                                <th>Timestamp</th>
                                <th>Connectivity</th>
                                <th>Technical Issues Detected</th>
                            </tr>
                        </thead>
                        <tbody id="ip-diagnostics-table">
                            <tr>
                                <td colspan="4" class="loading">
                                    <i class="fas fa-spinner"></i> Loading IP diagnostics...
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Active Faults -->
            <div class="table-container">
                <div class="panel-header">
                    <div class="panel-title">
                        <i class="fas fa-exclamation-circle"></i> Recent Faults
                    </div>
                </div>
                <div style="overflow-x: auto;">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Agent</th>
                                <th>Type</th>
                                <th>Severity</th>
                                <th>Description</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody id="faults-table">
                            <tr>
                                <td colspan="5" class="loading">
                                    <i class="fas fa-spinner"></i> Loading faults...
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let currentTimeRange = 1; // hours
        let performanceChart = null;
        let faultDistributionChart = null;
        
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            updateDashboard();
            loadMacConfig();
            loadLayer2Stats();
            setInterval(updateDashboard, 30000); // Update every 30 seconds
            setInterval(loadLayer2Stats, 10000); // Update Layer 2 stats every 10 seconds
        });
        
        function showRefreshIndicator() {
            document.getElementById('refresh-indicator').style.display = 'flex';
        }
        
        function hideRefreshIndicator() {
            document.getElementById('refresh-indicator').style.display = 'none';
        }
        
        function updateDashboard() {
            showRefreshIndicator();
            
            // Update summary statistics
            fetch('/api/dashboard/summary')
                .then(response => response.json())
                .then(data => {
                    updateStatistics(data.statistics);
                    updateAgentsList(data.agents);
                })
                .catch(error => {
                    console.error('Error updating dashboard:', error);
                });
            
            // Update fault distribution chart
            updateFaultDistributionChart();
            
            // Update performance chart
            updatePerformanceChart();
            
            // Update faults table
            updateFaultsTable();
            
            // Update IP diagnostics table
            updateIPDiagnosticsTable();
            
            setTimeout(hideRefreshIndicator, 1000);
        }
        
        function updateStatistics(stats) {
            document.getElementById('total-agents').textContent = stats.total_agents;
            document.getElementById('online-agents').textContent = stats.online_agents;
            document.getElementById('offline-agents').textContent = stats.offline_agents;
            document.getElementById('combined-issues').textContent = stats.combined_issues; // Combined issues
        }
        
        function getCommMethodDisplay(method) {
            switch(method) {
                case 'HTTP':
                    return '<span class="comm-method comm-http"><i class="fas fa-globe"></i> HTTP</span>';
                case 'UDP_BROADCAST':
                    return '<span class="comm-method comm-udp"><i class="fas fa-broadcast-tower"></i> UDP</span>';
                case 'LAYER2_RAW':
                    return '<span class="comm-method comm-layer2"><i class="fas fa-ethernet"></i> L2</span>';
                default:
                    return '<span class="comm-method comm-http"><i class="fas fa-globe"></i> HTTP</span>';
            }
        }
        
        function updateAgentsList(agents) {
            const agentsList = document.getElementById('agents-list');
            
            if (agents.length === 0) {
                agentsList.innerHTML = '<div class="no-data"><i class="fas fa-desktop"></i><p>No agents connected</p></div>';
                return;
            }
            
            const agentsHTML = agents.map(agent => `
                <div class="agent-item" onclick="viewAgentDetails('${agent.agent_id}')">
                    <div class="agent-header">
                        <div class="agent-name">${agent.hostname} (${agent.agent_id})</div>
                        <div>
                            <div class="agent-status status-${agent.status}">${agent.status}</div>
                            ${getCommMethodDisplay(agent.communication_method || 'HTTP')}
                        </div>
                    </div>
                    <div class="agent-details">
                        <span><i class="fas fa-desktop"></i> ${agent.platform}</span>
                        <span><i class="fas fa-network-wired"></i> ${agent.ip_address || 'N/A'}</span>
                        <span><i class="fas fa-clock"></i> ${agent.last_seen}</span>
                        ${agent.method_fallback_count > 0 ? `<span><i class="fas fa-exclamation-triangle" style="color: #f39c12;"></i> ${agent.method_fallback_count} fallbacks</span>` : ''}
                    </div>
                </div>
            `).join('');
            
            agentsList.innerHTML = agentsHTML;
        }
        
        function updateFaultDistributionChart() {
            fetch('/api/fault-distribution')
                .then(response => response.json())
                .then(data => {
                    console.log('Fault distribution data:', data);
                    if (data.categories && data.categories.length > 0) {
                        createFaultDistributionChart(data);
                    } else {
                        document.getElementById('fault-distribution-chart').innerHTML = `
                            <div class="no-data">
                                <i class="fas fa-chart-bar fa-3x"></i>
                                <p>No fault data available</p>
                                <small>Try creating some test faults using the debug button</small>
                            </div>
                        `;
                    }
                })
                .catch(error => {
                    console.error('Error updating fault distribution chart:', error);
                    document.getElementById('fault-distribution-chart').innerHTML = `
                        <div class="no-data">
                            <i class="fas fa-exclamation-triangle fa-3x"></i>
                            <p>Error loading fault distribution data</p>
                        </div>
                    `;
                });
        }
        
        function createFaultDistributionChart(data) {
            const trace = {
                x: data.categories,
                y: data.counts,
                type: 'bar',
                marker: {
                    color: ['#e74c3c', '#f39c12', '#3498db', '#2ecc71', '#9b59b6', '#95a5a6', '#e67e22'],
                    opacity: 0.8
                },
                text: data.counts,
                textposition: 'auto',
                hovertemplate: '<b>%{x}</b><br>Count: %{y}<extra></extra>'
            };
            
            const layout = {
                title: false,
                xaxis: {
                    title: 'Fault Type',
                    showgrid: false,
                    tickangle: -45,
                    automargin: true
                },
                yaxis: {
                    title: 'Number of Faults',
                    showgrid: true,
                    gridcolor: '#ecf0f1',
                    automargin: true
                },
                margin: { l: 50, r: 30, t: 30, b: 100 },
                plot_bgcolor: 'white',
                paper_bgcolor: 'white',
                showlegend: false,
                height: 300
            };
            
            const config = {
                responsive: true,
                displayModeBar: false
            };
            
            document.getElementById('fault-distribution-chart').innerHTML = '';
            
            Plotly.newPlot('fault-distribution-chart', [trace], layout, config);
            
            setTimeout(() => {
                Plotly.Plots.resize('fault-distribution-chart');
            }, 100);
        }
        
        function updatePerformanceChart() {
            fetch(`/api/metrics/chart?hours=${currentTimeRange}`)
                .then(response => response.json())
                .then(data => {
                    if (data.timestamps && data.timestamps.length > 0) {
                        createPerformanceChart(data);
                    } else {
                        document.getElementById('performance-chart').innerHTML = `
                            <div class="no-data">
                                <i class="fas fa-chart-line fa-3x"></i>
                                <p>No performance data available</p>
                            </div>
                        `;
                    }
                })
                .catch(error => {
                    console.error('Error updating performance chart:', error);
                    document.getElementById('performance-chart').innerHTML = `
                        <div class="no-data">
                            <i class="fas fa-exclamation-triangle fa-3x"></i>
                            <p>Error loading performance data</p>
                        </div>
                    `;
                });
        }
        
        function createPerformanceChart(data) {
            const traces = [
                {
                    x: data.timestamps,
                    y: data.cpu_data,
                    type: 'scatter',
                    mode: 'lines',
                    name: 'CPU Usage %',
                    line: { color: '#e74c3c', width: 2 }
                },
                {
                    x: data.timestamps,
                    y: data.memory_data,
                    type: 'scatter',
                    mode: 'lines',
                    name: 'Memory Usage %',
                    line: { color: '#3498db', width: 2 }
                },
                {
                    x: data.timestamps,  
                    y: data.network_data,
                    type: 'scatter',
                    mode: 'lines',
                    name: 'Network Issues %',
                    line: { color: '#2ecc71', width: 2 }
                }
            ];
            
            const layout = {
                title: false,
                xaxis: {
                    title: 'Time',
                    showgrid: true,
                    gridcolor: '#ecf0f1',
                    tickangle: -45,
                    automargin: true
                },
                yaxis: {
                    title: 'Percentage',
                    range: [0, 100],
                    showgrid: true,
                    gridcolor: '#ecf0f1',
                    automargin: true
                },
                margin: { l: 50, r: 30, t: 30, b: 80 },
                showlegend: true,
                legend: {
                    orientation: 'h',
                    x: 0,
                    y: -0.25,
                    xanchor: 'left',
                    yanchor: 'top'
                },
                plot_bgcolor: 'white',
                paper_bgcolor: 'white',
                autosize: true,
                height: 350
            };
            
            const config = {
                responsive: true,
                displayModeBar: false
            };
            
            document.getElementById('performance-chart').innerHTML = '';
            
            Plotly.newPlot('performance-chart', traces, layout, config);
            
            setTimeout(() => {
                Plotly.Plots.resize('performance-chart');
            }, 100);
        }
        
        function updateFaultsTable() {
            fetch('/api/faults')
                .then(response => response.json())
                .then(data => {
                    const faultsTable = document.getElementById('faults-table');
                    
                    if (data.length === 0) {
                        faultsTable.innerHTML = '<tr><td colspan="5" class="no-data">No active faults</td></tr>';
                        return;
                    }
                    
                    const faultsHTML = data.slice(0, 10).map(fault => `
                        <tr onclick="viewAgentDetails('${fault.agent_id}')">
                            <td>${fault.agent_id}</td>
                            <td>${fault.type}</td>
                            <td><span class="severity-${fault.severity}">${fault.severity}</span></td>
                            <td>${fault.description}</td>
                            <td class="timestamp">${new Date(fault.timestamp).toLocaleString()}</td>
                        </tr>
                    `).join('');
                    
                    faultsTable.innerHTML = faultsHTML;
                })
                .catch(error => {
                    console.error('Error updating faults:', error);
                });
        }
        
        function updateIPDiagnosticsTable() {
            fetch('/api/ip-diagnostics')
                .then(response => response.json())
                .then(data => {
                    const diagnosticsTable = document.getElementById('ip-diagnostics-table');
                    
                    if (data.length === 0) {
                        diagnosticsTable.innerHTML = '<tr><td colspan="4" class="no-data">No IP diagnostics data available</td></tr>';
                        return;
                    }
                    
                    const diagnosticsHTML = data.slice(0, 10).map(diag => {
                        // Create connectivity icons with enhanced tooltips
                        const dnsIcon = `
                            <div class="tooltip-container">
                                <i class="fas fa-globe connectivity-icon ${diag.connectivity_dns ? 'network-good' : 'network-error'}"></i>
                                <span class="tooltip-text">DNS Resolution: ${diag.connectivity_dns ? 'Working - Can resolve domain names to IP addresses' : 'Failed - Cannot resolve domain names'}</span>
                            </div>
                        `;
                        
                        const pingIcon = `
                            <div class="tooltip-container">
                                <i class="fas fa-satellite-dish connectivity-icon ${diag.connectivity_ping ? 'network-good' : 'network-error'}"></i>
                                <span class="tooltip-text">Gateway Ping: ${diag.connectivity_ping ? 'Successful - Can reach default gateway' : 'Failed - Cannot reach default gateway'}</span>
                            </div>
                        `;
                        
                        const httpIcon = `
                            <div class="tooltip-container">
                                <i class="fas fa-wifi connectivity-icon ${diag.connectivity_http ? 'network-good' : 'network-error'}"></i>
                                <span class="tooltip-text">HTTP Connectivity: ${diag.connectivity_http ? 'Working - Can access internet services' : 'Failed - Cannot access internet services'}</span>
                            </div>
                        `;
                        
                        const connectivityIcons = `<div class="connectivity-icons">${dnsIcon}${pingIcon}${httpIcon}</div>`;
                        
                        // Get enhanced technical issues description
                        const issuesText = diag.parsed_issues || (diag.has_issues ? 'Issues Detected' : 'No Issues');
                        const issuesClass = diag.has_issues ? 'network-error' : 'network-good';
                        
                        return `
                            <tr onclick="viewAgentDetails('${diag.agent_id}')">
                                <td>${diag.agent_id}</td>
                                <td class="timestamp">${new Date(diag.timestamp).toLocaleString()}</td>
                                <td>${connectivityIcons}</td>
                                <td class="ip-issues-column">
                                    <div class="${issuesClass} technical-issue">
                                        <i class="fas ${diag.has_issues ? 'fa-exclamation-triangle' : 'fa-check-circle'}"></i>
                                        ${issuesText}
                                    </div>
                                </td>
                            </tr>
                        `;
                    }).join('');
                    
                    diagnosticsTable.innerHTML = diagnosticsHTML;
                })
                .catch(error => {
                    console.error('Error updating IP diagnostics:', error);
                    document.getElementById('ip-diagnostics-table').innerHTML = 
                        '<tr><td colspan="4" class="no-data">Error loading IP diagnostics data</td></tr>';
                });
        }
        
        function changeTimeRange(hours) {
            currentTimeRange = hours;
            
            // Update button states
            document.querySelectorAll('.chart-controls .btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // Update chart
            updatePerformanceChart();
        }
        
        function viewAgentDetails(agentId) {
            window.open(`/agent/${agentId}`, '_blank');
        }
        
        // MAC Configuration functions
        function loadMacConfig() {
            fetch('/api/config/get-mac')
                .then(response => response.json())
                .then(data => {
                    const statusText = data.manual_mac ? 
                        `Manual: ${data.manual_mac}` : 
                        `Auto: ${data.server_mac || 'Not set'}`;
                    document.getElementById('mac-status').textContent = `Current: ${statusText}`;
                    if (data.manual_mac) {
                        document.getElementById('mac-input').value = data.manual_mac;
                    }
                })
                .catch(error => {
                    console.error('Error loading MAC config:', error);
                });
        }
        
        function setManualMac() {
            const macAddress = document.getElementById('mac-input').value.trim();
            
            if (!macAddress) {
                alert('Please enter a MAC address');
                return;
            }
            
            fetch('/api/config/set-mac', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    mac_address: macAddress
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    alert(`MAC address set to: ${data.mac_address}`);
                    loadMacConfig();
                } else {
                    alert(`Error: ${data.error}`);
                }
            })
            .catch(error => {
                console.error('Error setting MAC address:', error);
                alert('Error setting MAC address');
            });
        }
        
        // Layer 2 Statistics functions
        function loadLayer2Stats() {
            fetch('/api/layer2/stats')
                .then(response => response.json())
                .then(data => {
                    const statusElement = document.getElementById('layer2-status');
                    if (data.running) {
                        const successRate = data.success_rate ? data.success_rate.toFixed(1) : '0.0';
                        statusElement.innerHTML = `
                            <span style="color: #27ae60;">✅ Running</span><br>
                            Interface: ${data.interface || 'N/A'}<br>
                            MAC: ${data.server_mac || 'N/A'}<br>
                            Packets: ${data.packet_count || 0}<br>
                            Errors: ${data.error_count || 0}<br>
                            Success Rate: ${successRate}%
                        `;
                    } else {
                        statusElement.innerHTML = `
                            <span style="color: #e74c3c;">❌ Stopped</span><br>
                            Interface: ${data.interface || 'N/A'}<br>
                            MAC: ${data.server_mac || 'N/A'}
                        `;
                    }
                })
                .catch(error => {
                    console.error('Error loading Layer 2 stats:', error);
                    document.getElementById('layer2-status').innerHTML = 
                        '<span style="color: #e74c3c;">❌ Error loading stats</span>';
                });
        }
        
        // Debug functions
        function createTestFaults() {
            fetch('/api/debug/create-test-faults')
                .then(response => response.json())
                .then(data => {
                    console.log('Test faults created:', data);
                    alert('Test faults created successfully!');
                    updateDashboard(); // Refresh the dashboard
                })
                .catch(error => {
                    console.error('Error creating test faults:', error);
                    alert('Error creating test faults');
                });
        }
        
        function clearAllFaults() {
            if (confirm('Are you sure you want to clear all faults?')) {
                // This would need a backend endpoint to clear faults
                console.log('Clear all faults not implemented yet');
                alert('Clear all faults not implemented yet');
            }
        }
    </script>
</body>
</html>'''

# Enhanced Agent Detail HTML (keeping the same structure but updated for communication methods)
AGENT_DETAIL_HTML = '''<!DOCTYPE html>
<html>
<head>
    <title>Agent Details - {{agent_id}}</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: #f5f6fa;
            color: #2c3e50;
            line-height: 1.6;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            font-size: 1.5rem;
            font-weight: 600;
        }
        
        .back-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            cursor: pointer;
            text-decoration: none;
            transition: background-color 0.2s;
        }
        
        .back-btn:hover {
            background: rgba(255,255,255,0.3);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .agent-info {
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            margin-bottom: 2rem;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        
        .info-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .info-label {
            font-weight: 600;
            color: #7f8c8d;
        }
        
        .info-value {
            color: #2c3e50;
        }
        
        .status-online { color: #27ae60; }
        .status-offline { color: #e74c3c; }
        .status-warning { color: #f39c12; }
        
        /* Communication method indicators */
        .comm-method {
            padding: 0.2rem 0.5rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 500;
            margin-left: 0.5rem;
        }
        
        .comm-http {
            background-color: #d4edda;
            color: #155724;
        }
        
        .comm-udp {
            background-color: #fff3cd;
            color: #856404;
        }
        
        .comm-layer2 {
            background-color: #f8d7da;
            color: #721c24;
        }
        
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .chart-container {
            background: white;
            padding: 1rem 1rem 1rem 0.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            overflow: hidden;
        }
        
        .chart-title {
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: #2c3e50;
        }
        
        .tables-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 2rem;
        }
        
        .table-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            overflow: hidden;
        }
        
        .table-header {
            background-color: #f8f9fa;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #ecf0f1;
            font-weight: 600;
            color: #2c3e50;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .table th {
            background-color: #f8f9fa;
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            color: #2c3e50;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .table td {
            padding: 1rem;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .table tbody tr:hover {
            background-color: #f8f9fa;
        }
        
        .severity-high { color: #e74c3c; font-weight: 600; }
        .severity-medium { color: #f39c12; font-weight: 600; }
        .severity-low { color: #27ae60; font-weight: 600; }
        
        .loading {
            text-align: center;
            padding: 2rem;
            color: #7f8c8d;
        }
        
        .no-data {
            text-align: center;
            padding: 2rem;
            color: #7f8c8d;
        }
        
        .timestamp {
            color: #7f8c8d;
            font-size: 0.9rem;
        }
        
        /* IP Diagnostics specific styles */
        .network-status {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .network-good { color: #27ae60; }
        .network-warning { color: #f39c12; }
        .network-error { color: #e74c3c; }
        
        .ip-interface {
            font-family: monospace;
            background-color: #f8f9fa;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.9rem;
        }
        
        .dhcp-tag {
            background-color: #d4edda;
            color: #155724;
            padding: 0.2rem 0.5rem;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 500;
        }
        
        .static-tag {
            background-color: #fff3cd;
            color: #856404;
            padding: 0.2rem 0.5rem;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 500;
        }

        /* Enhanced connectivity icons with tooltips */
        .connectivity-icons {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .connectivity-icon {
            font-size: 1rem;
            cursor: help;
        }
        
        .tooltip-container {
            position: relative;
            display: inline-block;
        }
        
        .tooltip-text {
            visibility: hidden;
            width: 200px;
            background-color: #2c3e50;
            color: white;
            text-align: center;
            border-radius: 6px;
            padding: 8px;
            position: absolute;
            z-index: 1000;
            bottom: 125%;
            left: 50%;
            margin-left: -100px;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 0.8rem;
            line-height: 1.2;
        }
        
        .tooltip-text::after {
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            margin-left: -5px;
            border-width: 5px;
            border-style: solid;
            border-color: #2c3e50 transparent transparent transparent;
        }
        
        .tooltip-container:hover .tooltip-text {
            visibility: visible;
            opacity: 1;
        }
        
        /* Enhanced technical issue styling */
        .technical-issue {
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.85rem;
            line-height: 1.3;
            max-width: 400px;
            word-wrap: break-word;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1><i class="fas fa-desktop"></i> Agent Details: {{agent_id}}</h1>
        <a href="/" class="back-btn">
            <i class="fas fa-arrow-left"></i> Back to Dashboard
        </a>
    </div>
    
    <div class="container">
        <!-- Agent Information Card -->
        <div class="agent-info" id="agent-info">
            <div class="loading">
                <i class="fas fa-spinner fa-spin"></i>
                <p>Loading agent information...</p>
            </div>
        </div>
        
        <!-- Performance Chart -->
        <div class="charts-grid">
            <div class="chart-container">
                <div class="chart-title">Performance Metrics (24 Hours)</div>
                <div id="metrics-chart" style="height: 400px;"></div>
            </div>
        </div>
        
        <!-- Data Tables -->
        <div class="tables-grid">
            <!-- Active Faults -->
            <div class="table-container">
                <div class="table-header">
                    <i class="fas fa-exclamation-triangle"></i> Active Faults
                </div>
                <div style="overflow-x: auto; max-height: 400px; overflow-y: auto;">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Severity</th>
                                <th>Description</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody id="faults-table">
                            <tr>
                                <td colspan="4" class="loading">
                                    <i class="fas fa-spinner fa-spin"></i> Loading...
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- IP Diagnostics - ENHANCED -->
            <div class="table-container">
                <div class="table-header">
                    <i class="fas fa-network-wired"></i> IP Diagnostics History - Enhanced Technical Details
                </div>
                <div style="overflow-x: auto; max-height: 400px; overflow-y: auto;">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Status</th>
                                <th>Technical Issues</th>
                                <th>Connectivity</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody id="ip-diagnostics-table">
                            <tr>
                                <td colspan="4" class="loading">
                                    <i class="fas fa-spinner fa-spin"></i> Loading...
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Network Interfaces - NEW -->
            <div class="table-container">
                <div class="table-header">
                    <i class="fas fa-ethernet"></i> Network Interfaces
                </div>
                <div style="overflow-x: auto; max-height: 400px; overflow-y: auto;">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Interface</th>
                                <th>IP Address</th>
                                <th>Status</th>
                                <th>Type</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody id="network-interfaces-table">
                            <tr>
                                <td colspan="5" class="loading">
                                    <i class="fas fa-spinner fa-spin"></i> Loading...
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        const agentId = '{{agent_id}}';
        
        document.addEventListener('DOMContentLoaded', function() {
            loadAgentDetails();
            setInterval(loadAgentDetails, 30000); // Refresh every 30 seconds
        });
        
        function getCommMethodDisplay(method) {
            switch(method) {
                case 'HTTP':
                    return '<span class="comm-method comm-http"><i class="fas fa-globe"></i> HTTP</span>';
                case 'UDP_BROADCAST':
                    return '<span class="comm-method comm-udp"><i class="fas fa-broadcast-tower"></i> UDP Broadcast</span>';
                case 'LAYER2_RAW':
                    return '<span class="comm-method comm-layer2"><i class="fas fa-ethernet"></i> Layer 2 Raw</span>';
                default:
                    return '<span class="comm-method comm-http"><i class="fas fa-globe"></i> HTTP</span>';
            }
        }
        
        function loadAgentDetails() {
            fetch(`/api/agent/${agentId}/details`)
                .then(response => response.json())
                .then(data => {
                    updateAgentInfo(data.agent_info);
                    updateMetricsChart(data.metrics);
                    updateFaultsTable(data.faults);
                    updateIPDiagnosticsTable(data.ip_diagnostics || []);
                    updateNetworkInterfacesTable(data.network_interfaces || []);
                })
                .catch(error => {
                    console.error('Error loading agent details:', error);
                });
        }
        
        function updateAgentInfo(agentInfo) {
            const agentInfoDiv = document.getElementById('agent-info');
            
            const statusClass = `status-${agentInfo.status}`;
            const commMethodDisplay = getCommMethodDisplay(agentInfo.communication_method || 'HTTP');
            
            agentInfoDiv.innerHTML = `
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Status:</span>
                        <span class="info-value ${statusClass}">
                            <i class="fas fa-circle"></i> ${agentInfo.status.toUpperCase()}
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Hostname:</span>
                        <span class="info-value">${agentInfo.hostname}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Platform:</span>
                        <span class="info-value">${agentInfo.platform}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">IP Address:</span>
                        <span class="info-value">${agentInfo.ip_address || 'N/A'}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Communication Method:</span>
                        <span class="info-value">${commMethodDisplay}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Method Fallbacks:</span>
                        <span class="info-value">${agentInfo.method_fallback_count || 0}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Last Seen:</span>
                        <span class="info-value">${agentInfo.last_seen}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Created:</span>
                        <span class="info-value">${new Date(agentInfo.created_at).toLocaleString()}</span>
                    </div>
                </div>
            `;
        }
        
        function updateMetricsChart(metrics) {
            if (!metrics || metrics.length === 0) {
                document.getElementById('metrics-chart').innerHTML = `
                    <div class="no-data">
                        <i class="fas fa-chart-line fa-3x"></i>
                        <p>No metrics data available</p>
                    </div>
                `;
                return;
            }
            
            const traces = [
                {
                    x: metrics.map(m => m.timestamp),
                    y: metrics.map(m => m.cpu_percent),
                    type: 'scatter',
                    mode: 'lines',
                    name: 'CPU Usage %',
                    line: { color: '#e74c3c', width: 2 }
                },
                {
                    x: metrics.map(m => m.timestamp),
                    y: metrics.map(m => m.memory_percent),
                    type: 'scatter',
                    mode: 'lines',
                    name: 'Memory Usage %',
                    line: { color: '#3498db', width: 2 }
                },
                {
                    x: metrics.map(m => m.timestamp),
                    y: metrics.map(m => m.packet_loss_percent),
                    type: 'scatter',
                    mode: 'lines',
                    name: 'Network Issues %',
                    line: { color: '#2ecc71', width: 2 }
                }
            ];
            
            const layout = {
                title: false,
                xaxis: {
                    title: 'Time',
                    showgrid: true,
                    gridcolor: '#ecf0f1'
                },
                yaxis: {
                    title: 'Percentage',
                    range: [0, 100],
                    showgrid: true,
                    gridcolor: '#ecf0f1'
                },
                margin: { l: 50, r: 30, t: 30, b: 50 },
                showlegend: true,
                legend: {
                    orientation: 'h',
                    y: -0.2
                },
                plot_bgcolor: 'white',
                paper_bgcolor: 'white'
            };
            
            const config = {
                responsive: true,
                displayModeBar: false
            };
            
            Plotly.newPlot('metrics-chart', traces, layout, config);
        }
        
        function updateFaultsTable(faults) {
            const faultsTable = document.getElementById('faults-table');
            
            if (!faults || faults.length === 0) {
                faultsTable.innerHTML = '<tr><td colspan="4" class="no-data">No active faults</td></tr>';
                return;
            }
            
            const faultsHTML = faults.map(fault => `
                <tr>
                    <td>${fault.type}</td>
                    <td><span class="severity-${fault.severity}">${fault.severity}</span></td>
                    <td>${fault.description}</td>
                    <td class="timestamp">${new Date(fault.timestamp).toLocaleString()}</td>
                </tr>
            `).join('');
            
            faultsTable.innerHTML = faultsHTML;
        }
        
        function updateIPDiagnosticsTable(diagnostics) {
            const diagnosticsTable = document.getElementById('ip-diagnostics-table');
            
            if (!diagnostics || diagnostics.length === 0) {
                diagnosticsTable.innerHTML = '<tr><td colspan="4" class="no-data">No IP diagnostics data available</td></tr>';
                return;
            }
            
            const diagnosticsHTML = diagnostics.map(diag => {
                const statusClass = diag.has_issues ? 'network-error' : 'network-good';
                const statusText = diag.has_issues ? 'Issues Detected' : 'All Good';
                const statusIcon = diag.has_issues ? 'fas fa-exclamation-triangle' : 'fas fa-check-circle';
                
                // Enhanced connectivity status with tooltips
                const dnsIcon = `
                    <div class="tooltip-container">
                        <i class="fas fa-globe connectivity-icon ${diag.connectivity_dns ? 'network-good' : 'network-error'}"></i>
                        <span class="tooltip-text">DNS Resolution: ${diag.connectivity_dns ? 'Working - Can resolve domain names to IP addresses' : 'Failed - Cannot resolve domain names'}</span>
                    </div>
                `;
                
                const pingIcon = `
                    <div class="tooltip-container">
                        <i class="fas fa-satellite-dish connectivity-icon ${diag.connectivity_ping ? 'network-good' : 'network-error'}"></i>
                        <span class="tooltip-text">Gateway Ping: ${diag.connectivity_ping ? 'Successful - Can reach default gateway' : 'Failed - Cannot reach default gateway'}</span>
                    </div>
                `;
                
                const httpIcon = `
                    <div class="tooltip-container">
                        <i class="fas fa-wifi connectivity-icon ${diag.connectivity_http ? 'network-good' : 'network-error'}"></i>
                        <span class="tooltip-text">HTTP Connectivity: ${diag.connectivity_http ? 'Working - Can access internet services' : 'Failed - Cannot access internet services'}</span>
                    </div>
                `;
                
                const connectivityHTML = `<div class="connectivity-icons">${dnsIcon}${pingIcon}${httpIcon}</div>`;
                
                // Use enhanced parsed issues with technical details
                const issuesText = diag.parsed_issues || (diag.has_issues ? 'Issues Detected' : 'No Issues');
                
                return `
                    <tr>
                        <td><span class="${statusClass}"><i class="${statusIcon}"></i> ${statusText}</span></td>
                        <td class="technical-issue">${issuesText}</td>
                        <td>${connectivityHTML}</td>
                        <td class="timestamp">${new Date(diag.timestamp).toLocaleString()}</td>
                    </tr>
                `;
            }).join('');
            
            diagnosticsTable.innerHTML = diagnosticsHTML;
        }
        
        function updateNetworkInterfacesTable(interfaces) {
            const interfacesTable = document.getElementById('network-interfaces-table');
            
            if (!interfaces || interfaces.length === 0) {
                interfacesTable.innerHTML = '<tr><td colspan="5" class="no-data">No network interfaces data available</td></tr>';
                return;
            }
            
            const interfacesHTML = interfaces.map(iface => {
                const statusClass = iface.is_up ? 'network-good' : 'network-error';
                const statusText = iface.is_up ? 'Up' : 'Down';
                const statusIcon = iface.is_up ? 'fas fa-check-circle' : 'fas fa-times-circle';
                
                const typeClass = iface.is_dhcp ? 'dhcp-tag' : 'static-tag';
                const typeText = iface.is_dhcp ? 'DHCP' : 'Static';
                
                return `
                    <tr>
                        <td><span class="ip-interface">${iface.interface_name}</span></td>
                        <td>${iface.ip_address}${iface.netmask ? '/' + iface.netmask : ''}</td>
                        <td><span class="${statusClass}"><i class="${statusIcon}"></i> ${statusText}</span></td>
                        <td><span class="${typeClass}">${typeText}</span></td>
                        <td class="timestamp">${new Date(iface.timestamp).toLocaleString()}</td>
                    </tr>
                `;
            }).join('');
            
            interfacesTable.innerHTML = interfacesHTML;
        }
    </script>
</body>
</html>'''

def create_templates():
    """Create HTML templates"""
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    with open('templates/server_dashboard.html', 'w', encoding='utf-8') as f:
        f.write(SERVER_DASHBOARD_HTML)
    
    with open('templates/agent_detail.html', 'w', encoding='utf-8') as f:
        f.write(AGENT_DETAIL_HTML)

def main():
    """Main application entry point"""
    try:
        logger.info("Starting Network Management System Server...")
        
        # Create templates
        create_templates()
        
        # Start communication servers (Layer 2 + Broadcast)
        layer2_success = start_communication_servers()
        
        if layer2_success:
            logger.info("✅ Layer 2 diagnostics server started successfully")
        else:
            logger.warning("❌ Layer 2 diagnostics server failed to start (install scapy)")
        
        # Start Flask server
        logger.info("🌟 FEATURES ACTIVE:")
        logger.info("📡 HTTP POST endpoint: /api/agent/data - Receives agent data packages")
        logger.info("📡 UDP Broadcast server on port 9999 - Receives agent data via broadcast")
        logger.info("📡 Layer 2 Ethernet server - Receives agent data via raw Ethernet frames")
        logger.info("🔧 Communication method tracking - Tracks HTTP/UDP/Layer2 usage per agent")
        logger.info("📊 Enhanced IP diagnostics parsing with technical details")
        logger.info("🔍 Fault categorization by type (CPU, Memory, Network, etc.)")
        logger.info("📡 Server running on http://localhost:8080")
        logger.info("📡 Broadcast Discovery Server running on UDP port 9999")
        if layer2_success:
            logger.info(f"📡 Layer 2 Diagnostics Server running (EtherType 0x{CUSTOM_ETHERTYPE:04X})")
            logger.info(f"📡 Layer 2 Server MAC: {layer2_server.server_mac}")
            logger.info(f"📡 Layer 2 Interface: {layer2_server.interface}")
        logger.info("✅ Server ready to receive agent data via HTTP, UDP broadcast, and Layer 2 Ethernet!")
        
        app.run(host='0.0.0.0', port=8080, debug=False, threaded=True)
        
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        status_monitor.running = False
        broadcast_server.stop()
        layer2_server.stop()
    except Exception as e:
        logger.error(f"Server error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()