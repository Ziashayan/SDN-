import os
import json
import time
import logging
from collections import defaultdict
from ryu.lib.packet import packet, ipv4, tcp, udp, icmp

class QoSManager:
    def __init__(self, logger=None, alert_manager=None):
        self.bandwidth_thresholds = {
            'critical': 1000,  # 1 Gbps
            'warning': 500     # 500 Mbps
        }
        self.logger = logger or logging.getLogger('QoSManager')
        self.alert_manager = alert_manager
        self._initialize_data_structures()
        self._setup_paths()
        self.load_config()
        self.last_update = time.time()
        
    def _initialize_data_structures(self):
        self.traffic_stats = defaultdict(lambda: {
            'bytes': 0,
            'packets': 0,
            'normal': 0,
            'abnormal': 0,
            'last_updated': 0
        })
        
        self.bandwidth_stats = defaultdict(dict)
        self.qos_policies = {}
        self.classification_rules = []
        self.prev_stats = defaultdict(dict)
        
    def _setup_paths(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(current_dir))
        self.stats_file = os.path.join(project_root, "qos_stats.json")
        
    def load_config(self):
        try:
            config_file = os.path.join(os.path.dirname(__file__), "qos_config.json")
            if os.path.exists(config_file):
                with open(config_file) as f:
                    config = json.load(f)
                    self.qos_policies = config.get('policies', {})
                    self.classification_rules = config.get('rules', [])
                    self.logger.info("Loaded QoS configuration")
            else:
                self.logger.warning("QoS config file not found, using defaults")
                self._create_default_config()
        except Exception as e:
            self.logger.error(f"Error loading QoS config: {str(e)}")
            self._create_default_config()
    
    def record_traffic(self, category, packet_length, is_normal=True):
        if category not in self.qos_policies:
            self.logger.warning(f"Recording traffic for unknown category: {category}")
            return
            
        # Update the stats for this category
        self.traffic_stats[category]['bytes'] += packet_length
        self.traffic_stats[category]['packets'] += 1
        if is_normal:
            self.traffic_stats[category]['normal'] += 1
        else:
            self.traffic_stats[category]['abnormal'] += 1
        self.traffic_stats[category]['last_updated'] = time.time()

    def get_realtime_traffic_stats(self):
        """Get real-time traffic classification stats"""
        now = time.time()
        total_bytes = 0
        total_packets = 0
        normal_bytes = 0
        normal_packets = 0
        abnormal_bytes = 0
        abnormal_packets = 0
        
        # Calculate totals
        for category, data in self.traffic_stats.items():
            total_bytes += data['bytes']
            total_packets += data['packets']
            
            if data.get('is_normal', True):
                normal_bytes += data['bytes']
                normal_packets += data['packets']
            else:
                abnormal_bytes += data['bytes']
                abnormal_packets += data['packets']
        
        # Calculate percentages
        normal_percentage = (normal_bytes / total_bytes * 100) if total_bytes > 0 else 0
        abnormal_percentage = (abnormal_bytes / total_bytes * 100) if total_bytes > 0 else 0
        
        return {
            'by_category': {
                'normal': {
                    'bytes': normal_bytes,
                    'packets': normal_packets,
                    'percentage': normal_percentage
                },
                'abnormal': {
                    'bytes': abnormal_bytes,
                    'packets': abnormal_packets,
                    'percentage': abnormal_percentage
                }
            },
            'normal_vs_abnormal': {
                'normal': normal_percentage,
                'abnormal': abnormal_percentage
            },
            'timestamp': now
        }

    def get_realtime_bandwidth_stats(self):
        """Get real-time bandwidth utilization stats"""
        now = time.time()
        total_rx = 0
        total_tx = 0
        per_node_stats = {}
        
        for dpid, ports in self.bandwidth_stats.items():
            per_node_stats[dpid] = {}
            for port, stats in ports.items():
                rx = stats.get('rx_rate', 0)
                tx = stats.get('tx_rate', 0)
                per_node_stats[dpid][port] = {
                    'rx_rate': rx,
                    'tx_rate': tx
                }
                total_rx += rx
                total_tx += tx
        
        return {
            'by_switch': per_node_stats,
            'overall': {
                'rx': total_rx,
                'tx': total_tx,
                'total': total_rx + total_tx
            },
            'timestamp': now
        }
    
    def _create_default_config(self):
        self.qos_policies = {
            'voip': {'priority': 7, 'max_bw': 30},
            'video': {'priority': 6, 'max_bw': 40},
            'critical': {'priority': 5, 'max_bw': 20},
            'default': {'priority': 1, 'max_bw': 10}
        }
        
        self.classification_rules = [
            {'category': 'voip', 'protocol': 'udp', 'port_range': (5060, 5080)},
            {'category': 'video', 'protocol': 'udp', 'port_range': (40000, 50000)},
            {'category': 'critical', 'protocol': 'tcp', 'dst_port': 22}
        ]
    
    def classify_traffic(self, pkt):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return 'default', None
            
        for rule in self.classification_rules:
            if self._matches_rule(ip_pkt, pkt, rule):
                return rule['category'], ip_pkt
                
        return 'default', ip_pkt
    
    def _matches_rule(self, ip_pkt, pkt, rule):
        if rule.get('protocol'):
            if rule['protocol'] == 'tcp' and not pkt.get_protocol(tcp.tcp):
                return False
            if rule['protocol'] == 'udp' and not pkt.get_protocol(udp.udp):
                return False
        
        if rule.get('port_range'):
            min_port, max_port = rule['port_range']
            transport = pkt.get_protocol(tcp.tcp) or pkt.get_protocol(udp.udp)
            if not transport or not (min_port <= transport.dst_port <= max_port):
                return False
                
        if rule.get('dst_port'):
            transport = pkt.get_protocol(tcp.tcp) or pkt.get_protocol(udp.udp)
            if not transport or transport.dst_port != rule['dst_port']:
                return False
                
        return True
    
    def update_bandwidth_utilization(self, datapath, port_stats):
        dpid = str(datapath.id)
        current_time = time.time()
    
        if dpid not in self.bandwidth_stats:
            self.bandwidth_stats[dpid] = {}
    
        prev_stats = self.prev_stats.get(dpid, {})
    
        for stat in port_stats:
            port_no = stat.port_no
            if port_no == datapath.ofproto.OFPP_LOCAL:
                continue
                
            port_key = str(port_no)
            
            # Initialize if first time
            if port_key not in prev_stats:
                prev_stats[port_key] = {
                    'rx_bytes': stat.rx_bytes,
                    'tx_bytes': stat.tx_bytes,
                    'timestamp': current_time
                }
                # Set initial rates to zero
                self.bandwidth_stats[dpid][port_key] = {
                    'rx_bytes': stat.rx_bytes,
                    'tx_bytes': stat.tx_bytes,
                    'rx_rate': 0.0,
                    'tx_rate': 0.0,
                    'timestamp': current_time
                }
                continue
            
            prev = prev_stats[port_key]
            prev_time = prev.get('timestamp', current_time)
            
            time_diff = max(0.1, current_time - prev_time)
            
            rx_bytes_diff = stat.rx_bytes - prev['rx_bytes']
            tx_bytes_diff = stat.tx_bytes - prev['tx_bytes']
            
            rx_rate = (rx_bytes_diff * 8) / time_diff / 1e6  # Mbps
            tx_rate = (tx_bytes_diff * 8) / time_diff / 1e6   # Mbps
            
            self.bandwidth_stats[dpid][port_key] = {
                'rx_bytes': stat.rx_bytes,
                'tx_bytes': stat.tx_bytes,
                'rx_rate': rx_rate,
                'tx_rate': tx_rate,
                'timestamp': current_time
            }
            
            # Update previous stats
            prev_stats[port_key] = {
                'rx_bytes': stat.rx_bytes,
                'tx_bytes': stat.tx_bytes,
                'timestamp': current_time
            }
            
            # Generate alerts if thresholds exceeded
            if self.alert_manager:
                if rx_rate > self.bandwidth_thresholds['critical'] or tx_rate > self.bandwidth_thresholds['critical']:
                    self.alert_manager.add_qos_alert('critical', 
                        f"Port {port_no} on switch {dpid} utilization: "
                        f"RX {rx_rate:.1f}Mbps / TX {tx_rate:.1f}Mbps")
                elif rx_rate > self.bandwidth_thresholds['warning'] or tx_rate > self.bandwidth_thresholds['warning']:
                    self.alert_manager.add_qos_alert('warning', 
                        f"Port {port_no} on switch {dpid} utilization: "
                        f"RX {rx_rate:.1f}Mbps / TX {tx_rate:.1f}Mbps")
    
        self.prev_stats[dpid] = prev_stats
    
        if current_time - self.last_update > 5:
            self.save_stats()
            self.last_update = current_time

    def save_stats(self):
        stats = self.get_stats()
        
        try:
            with open(self.stats_file, 'w') as f:
                json.dump(stats, f, indent=2)
            self.logger.info("Saved QoS statistics")
        except Exception as e:
            self.logger.error(f"Error saving QoS stats: {str(e)}")

    def get_stats(self):
        total_bytes = sum(cat['bytes'] for cat in self.traffic_stats.values()) if self.traffic_stats else 0
        
        traffic_data = {}
        for category, data in self.traffic_stats.items():
            percentage = (data['bytes'] / total_bytes * 100) if total_bytes > 0 else 0
            normal_percentage = (data['normal'] / data['packets'] * 100) if data['packets'] > 0 else 0
            abnormal_percentage = (data['abnormal'] / data['packets'] * 100) if data['packets'] > 0 else 0
            
            traffic_data[category] = {
                'bytes': data['bytes'],
                'packets': data['packets'],
                'percentage': round(percentage, 2),
                'normal_percentage': round(normal_percentage, 2),
                'abnormal_percentage': round(abnormal_percentage, 2)
            }
        
        return {
            'by_category': traffic_data,
            'by_switch': {k: dict(v) for k, v in self.bandwidth_stats.items()},
            'policies': self.qos_policies,
            'timestamp': time.time()
        }
    
    def create_qos_rule(self, datapath, category, match, actions):
        if category not in self.qos_policies:
            self.logger.warning(f"Unknown QoS category: {category}")
            return
            
        priority = self.qos_policies[category]['priority']
        parser = datapath.ofproto_parser
        
        if 'max_bw' in self.qos_policies[category]:
            self._add_meter(datapath, category)
            
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, 
            actions
        )]
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            flags=datapath.ofproto.OFPFF_SEND_FLOW_REM
        )
        
        datapath.send_msg(mod)
        self.logger.info(f"Created QoS rule for {category} traffic")
    
    def _add_meter(self, datapath, category):
        max_bw = self.qos_policies[category]['max_bw']
        parser = datapath.ofproto_parser
        
        bands = [
            parser.OFPMeterBandDrop(rate=int(max_bw * 1000), burst_size=0)
        ]
        
        meter_mod = parser.OFPMeterMod(
            datapath=datapath,
            command=datapath.ofproto.OFPMC_ADD,
            flags=datapath.ofproto.OFPMF_KBPS,
            meter_id=self._get_meter_id(category),
            bands=bands
        )
        
        datapath.send_msg(meter_mod)
    
    def _get_meter_id(self, category):
        return {
            'voip': 1,
            'video': 2,
            'critical': 3,
            'default': 4
        }.get(category, 4)
    
    def limit_bandwidth(self, dpid, port, max_bps=100000):
        # Implementation for bandwidth limiting
        self.logger.info(f"Limiting bandwidth on dpid={dpid} port={port} to {max_bps} bps")
        # Actual implementation would send OpenFlow meter mod messages
    
    def should_drop(self, category, dpid):
        if category not in self.qos_policies:
            return False
            
        if dpid in self.bandwidth_stats:
            total_bw = 0
            for port_stats in self.bandwidth_stats[dpid].values():
                total_bw += port_stats.get('tx_rate', 0) + port_stats.get('rx_rate', 0)
            
            max_bw = self.qos_policies[category]['max_bw']
            if total_bw > max_bw:
                return True
                
        return False