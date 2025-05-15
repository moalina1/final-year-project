import logging
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Optional
import threading
import time
import os
from collections import deque
from traffic_analyzer import TrafficAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('alert_system.log'),
        logging.StreamHandler()
    ]
)

class AlertSystem:
    def __init__(self, config_file: str = 'alert_config.json'):
        self.config_file = config_file
        self.config = self._load_config()
        self.traffic_analyzer = TrafficAnalyzer()
        self.alert_history = deque(maxlen=1000)  # Keep last 1000 alerts
        self.is_running = False
        self.notification_thread = None

    def _load_config(self) -> Dict:
        """Load alert system configuration"""
        default_config = {
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'recipients': []
            },
            'alert_thresholds': {
                'critical': 5,    # Number of critical alerts before notification
                'warning': 10,    # Number of warning alerts before notification
                'info': 20        # Number of info alerts before notification
            },
            'notification_interval': 300,  # Seconds between notifications
            'blacklist': [],      # List of IP addresses to ignore
            'whitelist': []       # List of trusted IP addresses
        }

        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    # Update default config with loaded values
                    default_config.update(config)
            return default_config
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return default_config

    def start_monitoring(self, interface: str = None):
        """Start the alert system"""
        try:
            self.is_running = True
            
            # Start traffic analyzer
            if not self.traffic_analyzer.start_monitoring(interface):
                raise Exception("Failed to start traffic analyzer")
            
            # Start notification thread
            self.notification_thread = threading.Thread(target=self._monitor_alerts)
            self.notification_thread.daemon = True
            self.notification_thread.start()
            
            logging.info("Alert system started successfully")
            return True
        except Exception as e:
            logging.error(f"Error starting alert system: {e}")
            return False

    def stop_monitoring(self):
        """Stop the alert system"""
        self.is_running = False
        self.traffic_analyzer.stop_monitoring()
        logging.info("Alert system stopped")

    def _monitor_alerts(self):
        """Monitor and process alerts"""
        alert_counts = {
            'critical': 0,
            'warning': 0,
            'info': 0
        }
        last_notification = datetime.now()

        while self.is_running:
            try:
                # Get new alerts from traffic analyzer
                alerts = self.traffic_analyzer.get_alerts()
                
                for alert in alerts:
                    # Skip if alert is already in history
                    if alert in self.alert_history:
                        continue
                    
                    # Add to history
                    self.alert_history.append(alert)
                    
                    # Update alert counts
                    alert_type = self._classify_alert(alert['type'])
                    alert_counts[alert_type] += 1
                
                # Check if notification threshold reached
                current_time = datetime.now()
                time_since_last = (current_time - last_notification).total_seconds()
                
                if time_since_last >= self.config['notification_interval']:
                    # Check if any threshold reached
                    for level, threshold in self.config['alert_thresholds'].items():
                        if alert_counts[level] >= threshold:
                            self._send_notification(alert_counts)
                            alert_counts = {k: 0 for k in alert_counts}
                            last_notification = current_time
                            break
                
                time.sleep(1)
                
            except Exception as e:
                logging.error(f"Error in alert monitoring: {e}")
                time.sleep(5)

    def _classify_alert(self, alert_type: str) -> str:
        """Classify alert severity"""
        critical_alerts = {'syn_flood', 'dns_amplification'}
        warning_alerts = {'port_scan', 'brute_force'}
        
        if alert_type in critical_alerts:
            return 'critical'
        elif alert_type in warning_alerts:
            return 'warning'
        else:
            return 'info'

    def _send_notification(self, alert_counts: Dict[str, int]):
        """Send notification about alerts"""
        try:
            if not self.config['email']['enabled']:
                return
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = self.config['email']['username']
            msg['To'] = ', '.join(self.config['email']['recipients'])
            msg['Subject'] = 'Security Alert Notification'
            
            # Create email body
            body = "Security Alert Summary:\n\n"
            for level, count in alert_counts.items():
                if count > 0:
                    body += f"{level.capitalize()} alerts: {count}\n"
            
            body += "\nRecent Alerts:\n"
            for alert in list(self.alert_history)[-5:]:  # Last 5 alerts
                body += f"\n[{alert['timestamp']}] {alert['message']}"
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(self.config['email']['smtp_server'], 
                            self.config['email']['smtp_port']) as server:
                server.starttls()
                server.login(self.config['email']['username'],
                           self.config['email']['password'])
                server.send_message(msg)
            
            logging.info("Notification email sent successfully")
            
        except Exception as e:
            logging.error(f"Error sending notification: {e}")

    def get_alert_history(self) -> List[Dict]:
        """Get alert history"""
        return list(self.alert_history)

    def update_config(self, new_config: Dict):
        """Update alert system configuration"""
        try:
            self.config.update(new_config)
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            logging.info("Configuration updated successfully")
        except Exception as e:
            logging.error(f"Error updating configuration: {e}")

# Example usage
if __name__ == "__main__":
    try:
        # Initialize the alert system
        alert_system = AlertSystem()
        
        # Configure email notifications (optional)
        email_config = {
            'email': {
                'enabled': True,
                'username': 'your_email@gmail.com',
                'password': 'your_app_password',
                'recipients': ['recipient@example.com']
            }
        }
        alert_system.update_config(email_config)
        
        # Start monitoring
        print("Starting alert system...")
        if alert_system.start_monitoring():
            print("Alert system started successfully")
            print("Press Ctrl+C to stop monitoring")
            
            try:
                while True:
                    # Display recent alerts
                    alerts = alert_system.get_alert_history()
                    if alerts:
                        print("\nRecent Alerts:")
                        for alert in alerts[-5:]:  # Show last 5 alerts
                            print(f"[{alert['timestamp']}] {alert['message']}")
                    
                    time.sleep(5)
                    
            except KeyboardInterrupt:
                print("\nStopping alert system...")
                alert_system.stop_monitoring()
        
    except Exception as e:
        print(f"\nError: {e}") 