import os
import logging
import time
import json
import numpy as np
from collections import defaultdict
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, arp
from sklearn.preprocessing import LabelEncoder
from ids_model import IDSModel

class IDSManager:
    # Constants for feature processing
    REQUIRED_FEATURES = 41
    REAL_TIME_FEATURES = [
        'proto', 'service', 'state', 'sbytes', 'dbytes', 
        'sttl', 'sload', 'dload', 'sinpkt', 'dinpkt',
        'sjit', 'djit', 'swin', 'dwin', 'tcprtt'
    ]
    
    # Protocol mappings
    PROTOCOL_MAP = {
        'tcp': 6, 'udp': 17, 'icmp': 1, 'other': -1
    }
    
    SERVICE_MAP = {
        'http': 80, 'https': 443, 'ssh': 22, 'smtp': 25,
        'dns': 53, 'ftp': 21, 'telnet': 23, 'pop3': 110,
        'imap': 143, 'smtps': 465, 'imaps': 993, 'pop3s': 995,
        'other': 0
    }
    
    STATE_MAP = {
        'REQ': 1, 'RSP': 2, 'SYN': 3, 'ACK': 4, 'FIN': 5,
        'RST': 6, 'ESTAB': 7, 'OTHER': 0
    }

    def __init__(self, model_path=None):
        self.logger = logging.getLogger('IDSManager')
        self.model = IDSModel(model_path)
        
        # Attack type mapping
        self.attack_types = {
            0: 'Normal',
            1: 'Generic',
            2: 'Exploits',
            3: 'Fuzzers',
            4: 'DoS',
            5: 'Reconnaissance',
            6: 'Analysis',
            7: 'Backdoor',
            8: 'Shellcode',
            9: 'Worms'
        }
        
        # Attack statistics
        self.attack_stats = defaultdict(lambda: {
            'count': 0, 
            'first_seen': 0, 
            'last_seen': 0,
            'last_source': ''
        })
        
        self.logger.info("IDS Manager initialized")

    def _predict_from_features(self, features):
        """Predict from features with robust handling"""
        try:
            # Create feature vector in predefined order
            input_features = []
            for feature in self.REAL_TIME_FEATURES:
                value = features.get(feature, 0)
                
                # Handle categorical conversions
                if feature == 'proto' and isinstance(value, str):
                    value = self.PROTOCOL_MAP.get(value.lower(), -1)
                elif feature == 'service' and isinstance(value, str):
                    value = self.SERVICE_MAP.get(value.lower(), 0)
                elif feature == 'state' and isinstance(value, str):
                    value = self.STATE_MAP.get(value.upper(), 0)
                
                input_features.append(value)
            
            # Pad to required features with zeros
            padded_features = np.zeros(self.REQUIRED_FEATURES)
            padded_features[:len(input_features)] = input_features
            
            # Reshape for scaler
            input_array = padded_features.reshape(1, -1)
            
            # Scale features
            scaled_features = self.model.scaler.transform(input_array)
            
            # Make prediction
            prediction = self.model.model.predict(scaled_features)[0]
            proba = self.model.model.predict_proba(scaled_features)[0].max()
            
            attack_type = self.attack_types.get(prediction, 'Unknown')
            return attack_type, proba, features
        except Exception as e:
            self.logger.error(f"Prediction error: {str(e)}")
            return 'Normal', 0.0, features
            
    def analyze_packet(self, pkt, features):
        """Analyze packet with robust error handling"""
        try:
            # If features are provided, use them directly
            if features:
                return self._predict_from_features(features)
            
            # Otherwise, extract features from packet
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            arp_pkt = pkt.get_protocol(arp.arp)
        
            # Skip ARP and non-IP packets if no features provided
            if arp_pkt or not ip_pkt:
                return 'Normal', 0.0, {}
        
            # Extract basic features
            features = {
                'proto': self._get_proto_name(ip_pkt.proto),
                'sbytes': len(pkt.data),
                'src_ip': ip_pkt.src,
                'dst_ip': ip_pkt.dst,
                'sttl': ip_pkt.ttl,
                'dttl': 64,  # Default destination TTL
            }
        
            # TCP-specific features
            if tcp_pkt:
                features.update({
                    'service': self._get_service_name(tcp_pkt.dst_port),
                    'sport': tcp_pkt.src_port,
                    'dport': tcp_pkt.dst_port,
                    'state': self._get_tcp_state(tcp_pkt),
                    'swin': tcp_pkt.window_size,
                    'syn_count': 1 if tcp_pkt.bits & tcp.TCP_SYN else 0,
                    'ack_count': 1 if tcp_pkt.bits & tcp.TCP_ACK else 0,
                })
            # UDP-specific features
            elif udp_pkt:
                features.update({
                    'service': self._get_service_name(udp_pkt.dst_port),
                    'sport': udp_pkt.src_port,
                    'dport': udp_pkt.dst_port,
                })
            # ICMP-specific features
            elif icmp_pkt:
                features.update({
                    'service': 'icmp',
                    'type': icmp_pkt.type,
                    'code': icmp_pkt.code,
                })
        
            # Add DoS detection heuristic
            features['is_dos_suspect'] = int(
                features.get('syn_count', 0) > 10 and 
                features.get('ack_count', 0) == 0
            )
        
            return self._predict_from_features(features)
            
        except Exception as e:
            self.logger.error(f"Packet analysis error: {str(e)}")
            return 'Normal', 0.0, {}
    
    # ... rest of the file remains the same ...
    def get_attack_statistics(self):
        """Get attack statistics with timestamps"""
        now = time.time()
        # Filter attacks from the last 10 minutes
        recent_attacks = {k: v for k, v in self.attack_stats.items() 
                         if now - v['last_seen'] <= 600}
        
        # Calculate distribution
        total = sum(data['count'] for data in recent_attacks.values())
        distribution = {}
        
        for attack_type, data in recent_attacks.items():
            distribution[attack_type] = {
                'count': data['count'],
                'percentage': (data['count'] / total * 100) if total > 0 else 0,
                'last_seen': data['last_seen'],
                'last_source': data['last_source']
            }
        
        return {
            'total': total,
            'distribution': distribution,
            'timestamp': now
        }
    
    def update_attack_stats(self, attack_type, source_ip):
        """Update attack statistics with timestamp and source"""
        if attack_type == 'Normal':
            return
            
        now = time.time()
        if attack_type not in self.attack_stats:
            self.attack_stats[attack_type] = {
                'count': 0, 
                'first_seen': now, 
                'last_seen': now,
                'last_source': source_ip
            }
        
        self.attack_stats[attack_type]['count'] += 1
        self.attack_stats[attack_type]['last_seen'] = now
        self.attack_stats[attack_type]['last_source'] = source_ip

    def needs_training(self):
        return self.model.needs_training()
    
    def train(self, training_file, testing_file):
        return self.model.train(training_file, testing_file)
    
    def get_model_info(self):
        return self.model.get_model_info()
    
    def _get_service_name(self, port):
        """Convert port number to service name"""
        services = {
            80: 'http', 443: 'https', 22: 'ssh', 25: 'smtp',
            53: 'dns', 21: 'ftp', 23: 'telnet', 110: 'pop3',
            143: 'imap', 465: 'smtps', 993: 'imaps', 995: 'pop3s'
        }
        return services.get(port, 'other')
    
    def _get_proto_name(self, protocol_num):
        """Convert protocol number to name"""
        protocols = {6: 'tcp', 17: 'udp', 1: 'icmp'}
        return protocols.get(protocol_num, 'other')
    
    def _get_tcp_state(self, tcp_pkt):
        """Determine TCP connection state"""
        bits = tcp_pkt.bits
        if bits & tcp.TCP_SYN:
            return 'SYN' if not (bits & tcp.TCP_ACK) else 'SYN_ACK'
        elif bits & tcp.TCP_FIN:
            return 'FIN'
        elif bits & tcp.TCP_RST:
            return 'RST'
        elif bits & tcp.TCP_ACK:
            return 'ACK'
        return 'ESTAB'

    def save_state(self, file_path):
        """Save current IDS state to file"""
        state = {
            'attack_stats': dict(self.attack_stats),
            'model_info': self.get_model_info()
        }
        try:
            with open(file_path, 'w') as f:
                json.dump(state, f, indent=2)
            self.logger.info(f"IDS state saved to {file_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving state: {str(e)}")
            return False

    def load_state(self, file_path):
        """Load IDS state from file"""
        try:
            if not os.path.exists(file_path):
                self.logger.warning("State file not found")
                return False
                
            with open(file_path, 'r') as f:
                state = json.load(f)
            
            # Load attack statistics
            self.attack_stats.clear()
            for k, v in state.get('attack_stats', {}).items():
                self.attack_stats[k] = v
            
            self.logger.info(f"IDS state loaded from {file_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error loading state: {str(e)}")
            return False