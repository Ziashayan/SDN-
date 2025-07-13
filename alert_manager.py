import os
import json
import time
import logging
import threading
from collections import deque
from datetime import datetime

class AlertManager:
    def __init__(self, alert_file='alerts.json'):
        self.logger = logging.getLogger('AlertManager')
        self.alert_file = alert_file
        self.alerts = deque(maxlen=100)
        self.realtime_alerts = deque(maxlen=20)
        self.compromised_hosts = {}
        self.lock = threading.Lock()
        self.alert_duration = 3600  # 1 hour in seconds
        self.socketio = None
        
    def set_socketio(self, socketio):
        self.socketio = socketio
        
    def add_security_alert(self, attack_type, src_ip, dst_ip, probability, switch_mac=None):
        """Add a security alert with real-time notification"""
        timestamp = time.time()
        alert = {
            'type': 'security',
            'attack_type': attack_type,
            'src': src_ip,
            'dst': dst_ip,
            'probability': probability,
            'timestamp': timestamp,
            'expire_time': timestamp + self.alert_duration,
            'message': f"{attack_type} attack from {src_ip} to {dst_ip}",
            'is_realtime': True
        }
        
        with self.lock:
            self.alerts.append(alert)
            self.realtime_alerts.append(alert)
            
        # Emit real-time alert via WebSocket
        if self.socketio:
            try:
                self.socketio.emit('real_time_alert', alert)
                self.logger.debug(f"WebSocket alert emitted: {attack_type}")
            except Exception as e:
                self.logger.error(f"WebSocket emit error: {str(e)}")
        
        self.logger.warning(f"Security alert added: {attack_type} from {src_ip}")
        return alert
    def add_ips_action(self, attack_type, src_ip, dst_ip, action):
        """Log IPS actions taken"""
        alert = {
            'type': 'ips',
            'timestamp': time.time(),
            'attack_type': attack_type,
            'src': src_ip,
            'dst': dst_ip,
            'action': action,
            'message': f"{action} applied for {attack_type} attack"
        }
        self.alerts.append(alert)
        self._save_alert(alert)
        
        # Emit real-time alert
        if self.socketio:
            self.socketio.emit('ips_action', alert)

    def add_qos_alert(self, level, message):
        """Add a QoS alert"""
        timestamp = time.time()
        alert = {
            'type': 'qos',
            'level': level,
            'timestamp': timestamp,
            'expire_time': timestamp + self.alert_duration,
            'message': message,
            'is_realtime': False
        }
        
        with self.lock:
            self.alerts.append(alert)
        self.logger.warning(f"QoS alert added: {message}")
        return alert

    def add_compromised_host(self, ip, attack_type):
        """Add a compromised host"""
        with self.lock:
            self.compromised_hosts[ip] = {
                'ip': ip,
                'attack_type': attack_type,
                'timestamp': time.time()
            }
        self.logger.warning(f"Compromised host added: {ip} ({attack_type})")
        return self.compromised_hosts[ip]

    def get_realtime_alerts(self):
        """Get real-time alerts and clear the queue"""
        with self.lock:
            alerts = list(self.realtime_alerts)
            self.realtime_alerts.clear()
        return alerts

    def get_alerts(self, max_alerts=50):
        current_time = time.time()
        valid_alerts = []
        
        with self.lock:
            # Remove expired alerts
            self.alerts = deque(
                [a for a in self.alerts if a['expire_time'] > current_time],
                maxlen=100
            )
            
            # Return the most recent alerts
            valid_alerts = list(self.alerts)[-max_alerts:][::-1]
        
        return valid_alerts

    def get_security_alerts(self, max_count=10):
        """Get security alerts only"""
        return [a for a in self.get_alerts() if a.get('type') == 'security'][:max_count]

    def get_compromised_hosts(self):
        """Get list of compromised hosts"""
        with self.lock:
            return list(self.compromised_hosts.values())

    def save_alerts(self):
        """Save alerts to file"""
        try:
            with self.lock:
                data = {
                    'alerts': list(self.alerts),
                    'compromised_hosts': self.compromised_hosts,
                    'timestamp': time.time()
                }
                
                with open(self.alert_file, 'w') as f:
                    json.dump(data, f, indent=2)
                    
            self.logger.info("Alerts saved to file")
        except Exception as e:
            self.logger.error(f"Error saving alerts: {str(e)}")

    def load_alerts(self):
        """Load alerts from file"""
        if not os.path.exists(self.alert_file):
            return
            
        try:
            with open(self.alert_file) as f:
                data = json.load(f)
                self.alerts = deque(data.get('alerts', []), maxlen=100)
                self.compromised_hosts = data.get('compromised_hosts', {})
                
            self.logger.info("Alerts loaded from file")
        except Exception as e:
            self.logger.error(f"Error loading alerts: {str(e)}")