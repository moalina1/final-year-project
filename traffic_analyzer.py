import logging
import json
from datetime import datetime
from typing import Dict, List, Optional
import threading
import time
import os
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, DNS
import platform
from flask import Flask, render_template
from flask_socketio import SocketIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('traffic_analyzer.log'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)
socketio = SocketIO(app)

class TrafficAnalyzer:
    def __init__(self):
        self.traffic_data_file = 'traffic_data.json'
        self.alert_thresholds = {
            'syn_flood': 100,  # SYN packets per second
            'port_scan': 50,   # Connection attempts per minute
            'dns_amplification': 100,  # DNS responses per second
            'brute_force': 20  # Failed authentication attempts per minute
        }
        self.traffic_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'connections': defaultdict(int),
            'ports': defaultdict(int),
            'protocols': defaultdict(int)
        })
        self.alerts = deque(maxlen=1000)  # Keep last 1000 alerts
        self.is_running = False
        self.sniffer = None
        self.time_window = 5  # Default time window in minutes
        self.packet_count = 0
        self.last_update = time.time()

    def start_monitoring(self, interface: str = None):
        """Start monitoring network traffic"""
        try:
            self.is_running = True
            
            # Start monitoring thread
            monitor_thread = threading.Thread(target=self._monitor_traffic, args=(interface,))
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # Start analysis thread
            analysis_thread = threading.Thread(target=self._analyze_traffic)
            analysis_thread.daemon = True
            analysis_thread.start()
            
            # Start dashboard update thread
            update_thread = threading.Thread(target=self._update_dashboard)
            update_thread.daemon = True
            update_thread.start()
            
            logging.info("Starting network traffic monitoring...")
            return True
        except Exception as e:
            logging.error(f"Error starting traffic monitoring: {e}")
            return False

    def stop_monitoring(self):
        """Stop monitoring network traffic"""
        self.is_running = False
        if self.sniffer:
            self.sniffer.stop()
        logging.info("Stopped network traffic monitoring")

    def _update_dashboard(self):
        """Update dashboard with real-time data"""
        while self.is_running:
            try:
                current_time = time.time()
                if current_time - self.last_update >= 1:  # Update every second
                    self._send_traffic_update()
                    self.last_update = current_time
                time.sleep(0.1)
            except Exception as e:
                logging.error(f"Error updating dashboard: {e}")
                time.sleep(1)

    def _send_traffic_update(self):
        """Send traffic update to dashboard"""
        try:
            # Calculate packets per second
            pps = self.packet_count
            self.packet_count = 0

            # Get top IPs
            top_ips = sorted(
                [(ip, stats['packets']) for ip, stats in self.traffic_stats.items()],
                key=lambda x: x[1],
                reverse=True
            )[:5]

            # Get top ports
            port_usage = defaultdict(int)
            for stats in self.traffic_stats.values():
                for port, count in stats['ports'].items():
                    port_usage[port] += count

            top_ports = sorted(
                [(port, count) for port, count in port_usage.items()],
                key=lambda x: x[1],
                reverse=True
            )[:5]

            # Send update to dashboard
            socketio.emit('traffic_update', {
                'packets_per_second': pps,
                'top_ips': [{'address': ip, 'packets': count} for ip, count in top_ips],
                'port_usage': [{'port': port, 'count': count} for port, count in top_ports]
            })

        except Exception as e:
            logging.error(f"Error sending traffic update: {e}")

    def _packet_handler(self, packet):
        """Handle captured packets"""
        try:
            if IP in packet:
                self.packet_count += 1
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                
                # Update statistics
                self.traffic_stats[src_ip]['packets'] += 1
                self.traffic_stats[src_ip]['bytes'] += len(packet)
                self.traffic_stats[src_ip]['protocols'][protocol] += 1
                
                # Process TCP packets
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = packet[TCP].flags
                    
                    self.traffic_stats[src_ip]['ports'][dst_port] += 1
                    self.traffic_stats[src_ip]['connections'][(src_ip, src_port, dst_ip, dst_port)] += 1
                    
                    # Check for SYN flood
                    if flags & 0x02:  # SYN flag
                        self._check_syn_flood(src_ip)
                    
                    # Check for port scanning
                    if len(self.traffic_stats[src_ip]['ports']) > self.alert_thresholds['port_scan']:
                        self._add_alert('port_scan', src_ip, 
                                      f"Detected port scanning activity from {src_ip} to ports: {list(self.traffic_stats[src_ip]['ports'].keys())}")
                
                # Process UDP packets
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    
                    self.traffic_stats[src_ip]['ports'][dst_port] += 1
                    
                    # Check for DNS amplification
                    if dst_port == 53 and DNS in packet:
                        self._check_dns_amplification(src_ip)
        
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    def _monitor_traffic(self, interface: str = None):
        """Monitor network traffic and collect statistics"""
        try:
            # Start packet capture
            self.sniffer = sniff(
                prn=self._packet_handler,
                store=0,
                iface=interface,
                stop_filter=lambda _: not self.is_running
            )
        except Exception as e:
            logging.error(f"Error in traffic monitoring: {e}")

    def _analyze_traffic(self):
        """Analyze collected traffic data for anomalies"""
        while self.is_running:
            try:
                # Check for port scanning
                for ip, stats in self.traffic_stats.items():
                    if len(stats['ports']) > self.alert_thresholds['port_scan']:
                        self._add_alert('port_scan', ip, f"Detected port scanning activity from {ip}")
                    
                    # Check for brute force attempts
                    failed_auth = sum(1 for port in stats['ports'] 
                                    if port in [21, 22, 23, 3389] and 
                                    stats['ports'][port] > self.alert_thresholds['brute_force'])
                    if failed_auth > 0:
                        self._add_alert('brute_force', ip, f"Detected potential brute force attempts from {ip}")
                
                # Save traffic data periodically
                self._save_traffic_data()
                
                # Reset statistics every minute
                time.sleep(60)
                self.traffic_stats.clear()
                
            except Exception as e:
                logging.error(f"Error analyzing traffic: {e}")
                time.sleep(1)

    def _check_syn_flood(self, src_ip: str):
        """Check for SYN flood attack"""
        syn_count = sum(1 for conn in self.traffic_stats[src_ip]['connections'].values() 
                       if conn > self.alert_thresholds['syn_flood'])
        if syn_count > 0:
            self._add_alert('syn_flood', src_ip, f"Detected potential SYN flood from {src_ip}")

    def _check_dns_amplification(self, src_ip: str):
        """Check for DNS amplification attack"""
        dns_count = self.traffic_stats[src_ip]['protocols'].get(17, 0)
        if dns_count > self.alert_thresholds['dns_amplification']:
            self._add_alert('dns_amplification', src_ip, f"Detected potential DNS amplification from {src_ip}")

    def _add_alert(self, alert_type: str, source_ip: str, message: str):
        """Add security alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'source_ip': source_ip,
            'message': message,
            'severity': self._get_alert_severity(alert_type)
        }
        self.alerts.append(alert)
        logging.warning(f"Security Alert: {message}")
        
        # Send alert to dashboard
        socketio.emit('alert', alert)

    def _get_alert_severity(self, alert_type: str) -> str:
        """Get alert severity level"""
        critical_alerts = {'syn_flood', 'dns_amplification'}
        warning_alerts = {'port_scan', 'brute_force'}
        
        if alert_type in critical_alerts:
            return 'critical'
        elif alert_type in warning_alerts:
            return 'warning'
        else:
            return 'info'

    def _save_traffic_data(self):
        """Save traffic data to file"""
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'traffic_stats': dict(self.traffic_stats),
                'alerts': self.alerts
            }
            
            with open(self.traffic_data_file, 'w') as f:
                json.dump(data, f, indent=4)
            
            logging.info("Traffic data saved successfully")
        except Exception as e:
            logging.error(f"Error saving traffic data: {e}")

    def get_alerts(self) -> List[Dict]:
        """Get current security alerts"""
        return list(self.alerts)

    def get_traffic_stats(self) -> Dict:
        """Get current traffic statistics"""
        return dict(self.traffic_stats)

    def update_time_window(self, minutes: int):
        """Update time window for statistics"""
        self.time_window = minutes
        logging.info(f"Updated time window to {minutes} minutes")

# Flask routes
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@socketio.on('update_filter')
def handle_filter_update(data):
    analyzer.update_time_window(int(data['time_window']))

# Example usage
if __name__ == "__main__":
    try:
        # Initialize the analyzer
        analyzer = TrafficAnalyzer()
        
        # Get available interfaces
        if platform.system() == "Windows":
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            print("Available interfaces:")
            for i, iface in enumerate(interfaces):
                print(f"{i+1}. {iface['name']} - {iface['description']}")
            
            # Let user choose interface
            choice = input("\nEnter interface number to monitor (or press Enter for default): ")
            interface = interfaces[int(choice)-1]['name'] if choice else None
        else:
            from scapy.arch import get_if_list
            interfaces = get_if_list()
            print("Available interfaces:")
            for i, iface in enumerate(interfaces):
                print(f"{i+1}. {iface}")
            
            # Let user choose interface
            choice = input("\nEnter interface number to monitor (or press Enter for default): ")
            interface = interfaces[int(choice)-1] if choice else None
        
        # Start monitoring
        print("\nStarting network traffic monitoring...")
        if analyzer.start_monitoring(interface):
            print("Monitoring started successfully")
            print("Starting web dashboard...")
            socketio.run(app, host='0.0.0.0', port=5000, debug=False)
        
    except Exception as e:
        print(f"\nError: {e}") 