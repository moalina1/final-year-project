from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import threading
import time
import json
from datetime import datetime
from typing import Dict, List
import os
from alert_system import AlertSystem
from traffic_analyzer import TrafficAnalyzer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this in production
socketio = SocketIO(app)

class SecurityDashboard:
    def __init__(self):
        self.alert_system = AlertSystem()
        self.traffic_analyzer = TrafficAnalyzer()
        self.is_running = False
        self.update_thread = None
        self.dashboard_data = {
            'alerts': [],
            'traffic_stats': {},
            'top_ports': [],
            'top_protocols': [],
            'attack_types': {},
            'timeline': []
        }

    def start(self, interface: str = None):
        """Start the dashboard and monitoring systems"""
        try:
            self.is_running = True
            
            # Start alert system and traffic analyzer
            if not self.alert_system.start_monitoring(interface):
                raise Exception("Failed to start alert system")
            
            # Start data update thread
            self.update_thread = threading.Thread(target=self._update_dashboard_data)
            self.update_thread.daemon = True
            self.update_thread.start()
            
            return True
        except Exception as e:
            print(f"Error starting dashboard: {e}")
            return False

    def stop(self):
        """Stop the dashboard and monitoring systems"""
        self.is_running = False
        self.alert_system.stop_monitoring()
        if self.update_thread:
            self.update_thread.join()

    def _update_dashboard_data(self):
        """Update dashboard data periodically"""
        while self.is_running:
            try:
                # Get latest alerts
                alerts = self.alert_system.get_alert_history()
                self.dashboard_data['alerts'] = alerts[-10:]  # Last 10 alerts
                
                # Get traffic statistics
                traffic_stats = self.traffic_analyzer.get_traffic_stats()
                self.dashboard_data['traffic_stats'] = traffic_stats
                
                # Calculate top ports
                port_counts = {}
                for ip, stats in traffic_stats.items():
                    for port, count in stats['ports'].items():
                        port_counts[port] = port_counts.get(port, 0) + count
                self.dashboard_data['top_ports'] = sorted(
                    port_counts.items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:10]
                
                # Calculate top protocols
                protocol_counts = {}
                for ip, stats in traffic_stats.items():
                    for proto, count in stats['protocols'].items():
                        protocol_counts[proto] = protocol_counts.get(proto, 0) + count
                self.dashboard_data['top_protocols'] = sorted(
                    protocol_counts.items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:5]
                
                # Calculate attack types
                attack_counts = {}
                for alert in alerts:
                    attack_type = alert['type']
                    attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
                self.dashboard_data['attack_types'] = attack_counts
                
                # Update timeline
                timeline_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'alerts': len(alerts),
                    'traffic': sum(stats['packets'] for stats in traffic_stats.values())
                }
                self.dashboard_data['timeline'].append(timeline_entry)
                if len(self.dashboard_data['timeline']) > 60:  # Keep last 60 entries
                    self.dashboard_data['timeline'] = self.dashboard_data['timeline'][-60:]
                
                # Emit update to connected clients
                socketio.emit('dashboard_update', self.dashboard_data)
                
                time.sleep(1)  # Update every second
                
            except Exception as e:
                print(f"Error updating dashboard data: {e}")
                time.sleep(5)

# Initialize dashboard
dashboard = SecurityDashboard()

@app.route('/')
def index():
    """Render the main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/data')
def get_dashboard_data():
    """Get current dashboard data"""
    return jsonify(dashboard.dashboard_data)

@app.route('/api/config', methods=['GET', 'POST'])
def handle_config():
    """Handle dashboard configuration"""
    if request.method == 'POST':
        try:
            new_config = request.json
            dashboard.alert_system.update_config(new_config)
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})
    else:
        return jsonify(dashboard.alert_system.config)

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Create dashboard template
    with open('templates/dashboard.html', 'w') as f:
        f.write('''
<!DOCTYPE html>
<html>
<head>
    <title>Network Security Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.socket.io/4.0.1/socket.io.min.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        .card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .alerts {
            grid-column: 1 / -1;
        }
        .alert {
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
        }
        .critical { background-color: #ffebee; border-left: 4px solid #f44336; }
        .warning { background-color: #fff3e0; border-left: 4px solid #ff9800; }
        .info { background-color: #e3f2fd; border-left: 4px solid #2196f3; }
        h2 { margin-top: 0; }
        canvas { width: 100% !important; height: 300px !important; }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="card alerts">
            <h2>Recent Alerts</h2>
            <div id="alerts-container"></div>
        </div>
        
        <div class="card">
            <h2>Traffic Overview</h2>
            <canvas id="traffic-chart"></canvas>
        </div>
        
        <div class="card">
            <h2>Top Ports</h2>
            <canvas id="ports-chart"></canvas>
        </div>
        
        <div class="card">
            <h2>Attack Types</h2>
            <canvas id="attacks-chart"></canvas>
        </div>
        
        <div class="card">
            <h2>Protocol Distribution</h2>
            <canvas id="protocols-chart"></canvas>
        </div>
    </div>

    <script>
        // Initialize charts
        const trafficCtx = document.getElementById('traffic-chart').getContext('2d');
        const portsCtx = document.getElementById('ports-chart').getContext('2d');
        const attacksCtx = document.getElementById('attacks-chart').getContext('2d');
        const protocolsCtx = document.getElementById('protocols-chart').getContext('2d');

        const trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: { labels: [], datasets: [{ label: 'Traffic', data: [] }] },
            options: { responsive: true }
        });

        const portsChart = new Chart(portsCtx, {
            type: 'bar',
            data: { labels: [], datasets: [{ label: 'Connections', data: [] }] },
            options: { responsive: true }
        });

        const attacksChart = new Chart(attacksCtx, {
            type: 'doughnut',
            data: { labels: [], datasets: [{ data: [] }] },
            options: { responsive: true }
        });

        const protocolsChart = new Chart(protocolsCtx, {
            type: 'pie',
            data: { labels: [], datasets: [{ data: [] }] },
            options: { responsive: true }
        });

        // Connect to WebSocket
        const socket = io();
        
        socket.on('dashboard_update', function(data) {
            // Update alerts
            const alertsContainer = document.getElementById('alerts-container');
            alertsContainer.innerHTML = data.alerts.map(alert => `
                <div class="alert ${alert.type}">
                    [${new Date(alert.timestamp).toLocaleTimeString()}] ${alert.message}
                </div>
            `).join('');

            // Update traffic chart
            trafficChart.data.labels = data.timeline.map(t => new Date(t.timestamp).toLocaleTimeString());
            trafficChart.data.datasets[0].data = data.timeline.map(t => t.traffic);
            trafficChart.update();

            // Update ports chart
            portsChart.data.labels = data.top_ports.map(p => `Port ${p[0]}`);
            portsChart.data.datasets[0].data = data.top_ports.map(p => p[1]);
            portsChart.update();

            // Update attacks chart
            attacksChart.data.labels = Object.keys(data.attack_types);
            attacksChart.data.datasets[0].data = Object.values(data.attack_types);
            attacksChart.update();

            // Update protocols chart
            protocolsChart.data.labels = data.top_protocols.map(p => `Protocol ${p[0]}`);
            protocolsChart.data.datasets[0].data = data.top_protocols.map(p => p[1]);
            protocolsChart.update();
        });
    </script>
</body>
</html>
        ''')
    
    # Start the dashboard
    if dashboard.start():
        print("Dashboard started successfully")
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    else:
        print("Failed to start dashboard") 