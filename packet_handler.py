#!/usr/bin/env python

import os
import sys
import logging
import time
import threading
import traceback
import numpy as np
from collections import defaultdict, deque
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp
from ryu.lib.packet import ether_types
import ipaddress
import tensorflow as tf
from tensorflow.keras.models import load_model

class PacketHandler:
    def __init__(self, topo_manager, alert_manager=None, ids_manager=None, qos_manager=None, controller=None):
        self.topo = topo_manager
        self.alert_manager = alert_manager
        self.ids_manager = ids_manager
        self.qos_manager = qos_manager
        self.controller = controller
        self._configure_logging()
        self.installed_flows = defaultdict(dict)
        self.flow_timeout = 30
        self.packet_count = 0
        self.normal_packets = 0
        self.abnormal_packets = 0
        self.data_lock = threading.Lock()
        self.last_analysis_time = 0
        self.analysis_interval = 0.1
        self.syn_count = defaultdict(int)
        self.last_syn_reset = time.time()
        
        # Deep Learning Model
        self.dl_model = self._load_dl_model()
        self.feature_window = deque(maxlen=10)  # Store last 10 packets for sequence analysis
        
        # Enhanced IPS Configuration
        self.enable_ips = True
        self.ips_thresholds = {
            'syn_flood': 100,   # Packets/sec
            'port_scan': 50,    # Unique ports/sec
            'dns_amplification': 100  # DNS responses/sec
        }
        self.ips_blocked_flows = {}
        self.ips_blocked_macs = {}
        self.redirect_ip = "8.8.8.8"
        self.block_duration = 300
        self.attack_counters = defaultdict(lambda: defaultdict(int))
        self.last_counter_reset = time.time()
        self.flow_max_age = 5
        self.flow_cleanup_interval = 15
        self.last_flow_cleanup = time.time()
        
        # Feature extraction configuration
        self.feature_mapping = {
            'proto': {'tcp': 0, 'udp': 1, 'icmp': 2, 'other': 3},
            'state': {'SYN': 0, 'ACK': 1, 'FIN': 2, 'RST': 3, 'ESTAB': 4, 'OTHER': 5}
        }
        
        self.default_features = {
            'proto': 'other',
            'sbytes': 0,
            'src': '00:00:00:00:00:00',
            'dst': '00:00:00:00:00:00',
            'src_ip': '0.0.0.0',
            'dst_ip': '0.0.0.0',
            'sttl': 64,
            'sport': 0,
            'dport': 0,
            'state': 'OTHER'
        }

    def _configure_logging(self):
        """Configure logging settings"""
        self.logger = logging.getLogger('PacketHandler')
        self.logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        file_handler = logging.FileHandler('packet_handler.log')
        file_handler.setFormatter(formatter)
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def _load_dl_model(self):
        """Load the pre-trained deep learning model"""
        try:
            model_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'models',
                'cnn_lstm_ids_model.h5'
            )
            
            if os.path.exists(model_path):
                self.logger.info(f"Loading deep learning model from {model_path}")
                return load_model(model_path)
            else:
                self.logger.error("Deep learning model not found!")
                return None
        except Exception as e:
            self.logger.error(f"Error loading DL model: {str(e)}")
            return None

    def _extract_dl_features(self, pkt, features):
        """Extract features for deep learning model"""
        try:
            # Basic features
            dl_features = [
                features.get('sbytes', 0),
                features.get('dbytes', 0),
                features.get('sttl', 64),
                features.get('sport', 0),
                features.get('dport', 0),
                self.feature_mapping['proto'].get(features.get('proto', 'other'), 3),
                self.feature_mapping['state'].get(features.get('state', 'OTHER'), 5)
            ]
            
            # Protocol-specific features
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                dl_features.extend([
                    tcp_pkt.window_size,
                    1 if tcp_pkt.bits & tcp.TCP_SYN else 0,
                    1 if tcp_pkt.bits & tcp.TCP_ACK else 0,
                    1 if tcp_pkt.bits & tcp.TCP_FIN else 0,
                    1 if tcp_pkt.bits & tcp.TCP_RST else 0
                ])
            else:
                dl_features.extend([0, 0, 0, 0, 0])
            
            # Pad to 12 features
            while len(dl_features) < 12:
                dl_features.append(0)
                
            return dl_features
        except Exception as e:
            self.logger.error(f"Feature extraction error: {str(e)}")
            return [0] * 12

    def _predict_with_dl(self, features):
        """Make prediction using deep learning model"""
        if not self.dl_model:
            return 'Normal', 0.0
            
        try:
            # Add to feature window
            self.feature_window.append(features)
            
            # Create sequence for LSTM (10 packets)
            sequence = list(self.feature_window)
            while len(sequence) < 10:
                sequence.insert(0, [0] * 12)  # Pad with zeros
                
            # Reshape for model (1 sample, 10 timesteps, 12 features)
            input_data = np.array([sequence], dtype=np.float32)
            
            # Make prediction
            prediction = self.dl_model.predict(input_data, verbose=0)
            class_idx = np.argmax(prediction[0])
            confidence = np.max(prediction[0])
            
            # Map to attack types
            attack_types = {
                0: 'Normal',
                1: 'DoS',
                2: 'Probe',
                3: 'R2L',
                4: 'U2R',
                5: 'Generic'
            }
            
            return attack_types.get(class_idx, 'Normal'), confidence
        except Exception as e:
            self.logger.error(f"DL prediction error: {str(e)}")
            return 'Normal', 0.0

    def switch_features_handler(self, ev):
        """Handle switch features reply"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install default table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)
        self.logger.info(f"Switch connected: dpid={datapath.id}")

    def install_flow(self, datapath, eth_src, eth_dst, out_port):
        """Install a flow entry for bidirectional communication"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Forward flow (src -> dst)
        match = parser.OFPMatch(eth_src=eth_src, eth_dst=eth_dst)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=10,
            match=match,
            instructions=inst,
            idle_timeout=self.flow_timeout,
            hard_timeout=self.flow_timeout * 2
        )
        datapath.send_msg(mod)
        self.logger.debug(f"Flow installed: {eth_src}->{eth_dst} out:{out_port}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle incoming packets with comprehensive attack detection and IPS"""
        try:
            # Extract packet information
            msg = ev.msg
            datapath = msg.datapath
            in_port = msg.match['in_port']
            pkt = packet.Packet(msg.data)
            pkt_id = self.packet_count
            self.packet_count += 1
            
            # Log basic packet info
            self.logger.info(f"[Pkt-{pkt_id}] Packet received on dpid={datapath.id} port={in_port}")
            
            # Parse protocol layers
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            arp_pkt = pkt.get_protocol(arp.arp)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            
            # Update topology MAC-port mapping
            if eth_pkt:
                self.topo.add_switch_port(datapath.id, eth_pkt.src, in_port)
                self.logger.debug(f"[Pkt-{pkt_id}] Updated MAC {eth_pkt.src} on port {in_port}")
            
            # Periodic flow cleanup
            current_time = time.time()
            if current_time - self.last_flow_cleanup > self.flow_cleanup_interval:
                self.clean_old_flows()
                self.last_flow_cleanup = current_time

            # Extract features for analysis
            features = self.default_features.copy()
            is_malicious = False
            attack_type = "Normal"
            probability = 0.0
            
            if eth_pkt:
                features.update({
                    'src': eth_pkt.src,
                    'dst': eth_pkt.dst,
                    'sbytes': len(pkt.data)
                })
                
                if arp_pkt:
                    features.update({
                        'proto': 'arp',
                        'src_ip': arp_pkt.src_ip,
                        'dst_ip': arp_pkt.dst_ip,
                        'opcode': arp_pkt.opcode
                    })
                elif ip_pkt:
                    features.update({
                        'proto': self._get_proto_name(ip_pkt.proto),
                        'src_ip': ip_pkt.src,
                        'dst_ip': ip_pkt.dst,
                        'sttl': ip_pkt.ttl
                    })
                    
                    if tcp_pkt:
                        features.update({
                            'sport': tcp_pkt.src_port,
                            'dport': tcp_pkt.dst_port,
                            'state': self._get_tcp_state(tcp_pkt)
                        })
            
            # Detect attacks with deep learning model
            dl_features = self._extract_dl_features(pkt, features)
            dl_attack_type, dl_probability = self._predict_with_dl(dl_features)
            
            if dl_attack_type != 'Normal':
                attack_type = dl_attack_type
                probability = dl_probability
                is_malicious = True
                self.abnormal_packets += 1
                self.logger.warning(
                    f"[Pkt-{pkt_id}] DL detected: {attack_type} "
                    f"from {features.get('src_ip', features['src'])} "
                    f"(confidence: {probability:.2%})"
                )
                
                if self.alert_manager:
                    src = features.get('src_ip', features['src'])
                    dst = features.get('dst_ip', features['dst'])
                    self.alert_manager.add_security_alert(
                        attack_type, 
                        src, 
                        dst, 
                        probability,
                        datapath.id,
                        "dl"
                    )
            else:
                self.normal_packets += 1
            
            # Detect advanced attacks with heuristics
            self.detect_advanced_attacks(
                ip_pkt, tcp_pkt, udp_pkt, 
                datapath.id, in_port, pkt_id, len(msg.data)
            )
            
            # IPS Handling - Apply prevention if malicious traffic detected
            if self.enable_ips and is_malicious:
                self.apply_ips_actions(
                    features, attack_type, probability,
                    datapath, msg, pkt, pkt_id  # Added pkt parameter here
                )
                return
            
            # ARP Processing with Spoofing Detection
            if arp_pkt:
                self.logger.info(f"[Pkt-{pkt_id}] ARP packet detected")
                
                # Detect ARP spoofing
                known_mac = self.topo.get_mac_for_ip(arp_pkt.src_ip)
                if known_mac and known_mac.lower() != eth_pkt.src.lower():
                    self.logger.warning(
                        f"[Pkt-{pkt_id}] ARP spoofing detected! "
                        f"IP {arp_pkt.src_ip} claimed by {eth_pkt.src} (real: {known_mac})"
                    )
                    
                    # Generate security alert
                    if self.alert_manager:
                        self.alert_manager.add_security_alert(
                            'ARP Spoofing',
                            arp_pkt.src_ip,
                            arp_pkt.dst_ip,
                            1.0,  # 100% confidence
                            datapath.id
                        )
                
                # Process ARP request/reply
                self.handle_arp(datapath, in_port, pkt, eth_pkt, msg.data, pkt_id)
                return
            
            # IP Packet Processing
            if ip_pkt:
                self.logger.info(f"[Pkt-{pkt_id}] IP packet: {ip_pkt.src} -> {ip_pkt.dst}")
                
                # Update host topology mapping
                self.topo.add_host_attachment(datapath.id, in_port, eth_pkt.src, ip_pkt.src)
                
                # Handle specific protocols
                if icmp_pkt:
                    self.handle_icmp(datapath, in_port, eth_pkt, ip_pkt, icmp_pkt, msg.data, pkt_id)
                elif tcp_pkt or udp_pkt:
                    self.route_ip_packet(datapath, in_port, ip_pkt, msg.data, pkt_id)
                return
            
            # Flood unknown packet types
            self.flood_packet(datapath, in_port, msg.data, pkt_id)
            
        except Exception as e:
            self.logger.error(f"Packet processing error: {str(e)}")
            self.logger.debug(traceback.format_exc())

    def detect_advanced_attacks(self, ip_pkt, tcp_pkt, udp_pkt, dpid, in_port, pkt_id, packet_length):
        """Detect advanced attack patterns"""
        if not ip_pkt:
            return
            
        src_ip = ip_pkt.src
        current_time = time.time()
        
        # Reset counters every second
        if current_time - self.last_counter_reset > 1.0:
            self.attack_counters.clear()
            self.last_counter_reset = current_time
        
        # SYN Flood detection
        if tcp_pkt and tcp_pkt.bits & tcp.TCP_SYN and not (tcp_pkt.bits & tcp.TCP_ACK):
            self.attack_counters[src_ip]['syn'] += 1
            if self.attack_counters[src_ip]['syn'] > self.ips_thresholds['syn_flood']:
                self.logger.warning(f"[Pkt-{pkt_id}] SYN Flood detected from {src_ip}")
                self.apply_ips_action(
                    src_ip, "SYN Flood", "rate_limit", 
                    dpid, in_port, self.attack_counters[src_ip]['syn']
                )
        
        # Port Scan detection
        if tcp_pkt or udp_pkt:
            port = tcp_pkt.dst_port if tcp_pkt else udp_pkt.dst_port
            
            if 'ports' not in self.attack_counters[src_ip]:
                self.attack_counters[src_ip]['ports'] = set()
            
            self.attack_counters[src_ip]['ports'].add(port)
            
            if len(self.attack_counters[src_ip]['ports']) > self.ips_thresholds['port_scan']:
                self.logger.warning(f"[Pkt-{pkt_id}] Port Scan detected from {src_ip}")
                self.apply_ips_action(
                    src_ip, "Port Scan", "block", 
                    dpid, in_port, len(self.attack_counters[src_ip]['ports'])
                )
        
        # DNS Amplification detection - FIXED
        if udp_pkt and udp_pkt.src_port == 53 and packet_length > 512:
            # Use victim's IP (destination) for tracking
            victim_ip = ip_pkt.dst
            self.attack_counters[victim_ip]['dns_resp'] += 1
            
            if self.attack_counters[victim_ip]['dns_resp'] > self.ips_thresholds['dns_amplification']:
                self.logger.warning(f"[Pkt-{pkt_id}] DNS Amplification towards {victim_ip}")
                self.apply_ips_action(
                    victim_ip, 
                    "DNS Amplification", 
                    "alert", 
                    dpid, 
                    in_port, 
                    self.attack_counters[victim_ip]['dns_resp']
                )

    def apply_ips_action(self, target_ip, attack_type, action, dpid, port, count):
        """Apply IPS mitigation actions"""
        if action == "block":
            self._add_blocked_flow(target_ip, "any")
            self.logger.critical(f"BLOCKED {target_ip} for {attack_type}")
        elif action == "rate_limit":
            if self.qos_manager:
                self.qos_manager.limit_bandwidth(
                    dpid, port, max_bps=100000  # Limit to 100 Kbps
                )
        elif action == "alert":
            self.logger.critical(f"ALERT: {attack_type} targeting {target_ip}")
            # No automated mitigation for DNS amplification
            
        # Send alert
        if self.alert_manager:
            self.alert_manager.add_ips_action(
                attack_type,
                target_ip,
                "N/A",
                f"{action} applied (count: {count})",
                dpid
            )

    def apply_ips_actions(self, features, attack_type, probability, datapath, msg, pkt, pkt_id):
        """Apply IPS actions based on detection - FIXED SIGNATURE"""
        # 1. Check if MAC is blocked
        if features['src'] in self.ips_blocked_macs:
            if time.time() < self.ips_blocked_macs[features['src']]:
                self.logger.info(f"[Pkt-{pkt_id}] Blocked MAC: {features['src']}")
                self.drop_packet(datapath, msg.buffer_id)
                return
            else:
                # Block expired, remove from tracking
                del self.ips_blocked_macs[features['src']]
        
        # 2. Handle ARP Spoofing specifically
        if attack_type == 'ARP Spoofing':
            self.logger.warning(f"[Pkt-{pkt_id}] Applying IPS for ARP Spoofing: {features['src']}")
            # Block attacker MAC
            self.ips_blocked_macs[features['src']] = time.time() + self.block_duration
            self._install_block_mac_flow(datapath, features['src'])
            self.drop_packet(datapath, msg.buffer_id)
            
            # Get IP associated with MAC for alerting
            attacker_ip = self.topo.get_ip_for_mac(features['src']) or "Unknown"
            if self.alert_manager:
                self.alert_manager.add_ips_action(
                    "ARP Spoofing",
                    attacker_ip,
                    features.get('dst_ip', 'N/A'),
                    f"Blocked MAC {features['src']} for {self.block_duration} seconds",
                    datapath.id
                )
            return
        
        # 3. Handle IP-based attacks
        if 'src_ip' in features and 'dst_ip' in features:
            src_ip = features.get('src_ip')
            dst_ip = features.get('dst_ip')
            
            if self._is_flow_blocked(src_ip, dst_ip):
                self.logger.info(f"[Pkt-{pkt_id}] Blocked flow: {src_ip}->{dst_ip}")
                self.drop_packet(datapath, msg.buffer_id)
                return
            
            # Apply IPS actions: redirect and block
            self.logger.warning(
                f"[Pkt-{pkt_id}] Applying IPS actions for attack: "
                f"{src_ip} -> {dst_ip}"
            )
            
            self._install_redirect_flow(datapath, src_ip, dst_ip)
            self._install_block_flow(datapath, src_ip, dst_ip)
            self._add_blocked_flow(src_ip, dst_ip)
            
            # Redirect the current malicious packet - FIXED CALL
            self._redirect_packet(datapath, pkt, msg, pkt_id)
            
            if self.alert_manager:
                self.alert_manager.add_ips_action(
                    attack_type,
                    src_ip,
                    dst_ip,
                    f"Blocked traffic for {self.block_duration} seconds (prob: {probability:.2%})",
                    datapath.id
                )
            return

    # ------------------------ IPS Functionality ------------------------ #
    
    def _is_flow_blocked(self, src_ip, dst_ip):
        """Check if a flow is currently blocked by IPS"""
        flow_key = (src_ip, dst_ip)
        current_time = time.time()
        
        if flow_key in self.ips_blocked_flows:
            if current_time < self.ips_blocked_flows[flow_key]:
                return True
            else:
                # Block expired, remove
                del self.ips_blocked_flows[flow_key]
        return False

    def _add_blocked_flow(self, src_ip, dst_ip):
        """Add a flow to the blocked flows tracker"""
        flow_key = (src_ip, dst_ip)
        self.ips_blocked_flows[flow_key] = time.time() + self.block_duration
        self.logger.warning(f"IPS blocked flow: {src_ip} -> {dst_ip} for {self.block_duration} seconds")

    def _install_redirect_flow(self, datapath, src_ip, dst_ip):
        """Install flow rule to redirect traffic to safe server"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Match on source and destination IP
        match = parser.OFPMatch(
            eth_type=0x0800,  # IPv4
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )
        
        # Actions: rewrite destination IP and MAC
        actions = [
            parser.OFPActionSetField(ipv4_dst=self.redirect_ip),
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)
        ]
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=1000,  # Higher priority than normal flows
            match=match,
            instructions=inst,
            hard_timeout=self.block_duration
        )
        datapath.send_msg(mod)
        self.logger.warning(f"Installed redirect flow: {src_ip}->{dst_ip} to {self.redirect_ip}")

    def _install_block_flow(self, datapath, src_ip, dst_ip):
        """Install flow rule to block traffic after redirect period"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(
            eth_type=0x0800,  # IPv4
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )
        
        # No actions = drop packet
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=1000,  # Higher priority than normal flows
            match=match,
            instructions=[],
            hard_timeout=self.block_duration
        )
        datapath.send_msg(mod)
        self.logger.warning(f"Installed block flow: {src_ip}->{dst_ip}")

    def _install_block_mac_flow(self, datapath, src_mac):
        """Install flow rule to block traffic from a specific MAC"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(eth_src=src_mac)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=1000,  # High priority
            match=match,
            instructions=[],
            hard_timeout=self.block_duration
        )
        datapath.send_msg(mod)
        self.logger.warning(f"Installed MAC block flow: {src_mac}")

    def _redirect_packet(self, datapath, pkt, msg, orig_pkt_id=None):
        """Redirect the current packet to safe server - FIXED VERSION"""
        try:
            # Extract Ethernet and IP layers
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            
            if not eth_pkt or not ip_pkt:
                self.logger.warning("Cannot redirect non-IP packet")
                return
            
            # Find router for safe server
            router_ip = self.topo.find_router_for_ip(self.redirect_ip)
            if not router_ip:
                self.logger.error("No router found for redirect IP")
                return
                
            # Get router MAC
            router_mac = self.topo.get_mac_for_ip(router_ip)
            if not router_mac:
                self.logger.error("No MAC found for router")
                return
            
            # Create new packet with modified destination
            new_pkt = packet.Packet()
            
            # Copy Ethernet header with new destination MAC
            new_eth = ethernet.ethernet(
                ethertype=eth_pkt.ethertype,
                dst=router_mac,
                src=eth_pkt.src
            )
            
            # Copy IP header with new destination IP
            new_ip = ipv4.ipv4(
                src=ip_pkt.src,
                dst=self.redirect_ip,
                proto=ip_pkt.proto,
                ttl=ip_pkt.ttl
            )
            
            # Add payload (transport layer + data)
            new_pkt.add_protocol(new_eth)
            new_pkt.add_protocol(new_ip)
            
            # Add transport protocol if exists
            transport_proto = None
            for proto in pkt.protocols:
                if isinstance(proto, (tcp.tcp, udp.udp, icmp.icmp)):
                    transport_proto = proto
                    new_pkt.add_protocol(proto)
                    break
            
            # Serialize the new packet
            new_pkt.serialize()
            
            # Get output port for the router
            out_port = self.topo.get_port_for_mac(datapath.id, router_mac)
            
            # If port not found, use flooding
            if out_port is None:
                self.logger.warning("Router port not found, flooding redirected packet")
                self.flood_packet(datapath, datapath.ofproto.OFPP_FLOOD, new_pkt.data, orig_pkt_id)
            else:
                # Send to switch
                self.send_packet(datapath, out_port, new_pkt.data, pkt_id=orig_pkt_id)
            
            log_msg = f"Redirected packet to safe server {self.redirect_ip} via router {router_ip}"
            if orig_pkt_id is not None:
                log_msg = f"[Pkt-{orig_pkt_id}] " + log_msg
            self.logger.info(log_msg)
            
        except Exception as e:
            self.logger.error(f"Packet redirection failed: {str(e)}")
            self.logger.debug(traceback.format_exc())

    # ------------------------ Core Packet Handling ------------------------ #
    
    def clean_old_flows(self):
        """Remove old flows to ensure packets continue to be analyzed"""
        for dpid, switch in self.topo.switches.items():
            if 'datapath' in switch and switch['status'] == 'active':
                dp = switch['datapath']
                ofproto = dp.ofproto
                parser = dp.ofproto_parser
                
                # Request flow statistics
                req = parser.OFPFlowStatsRequest(
                    dp,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    cookie=0,
                    cookie_mask=0,
                    match=None
                )
                dp.send_msg(req)
                
        self.logger.info("Flow cleanup initiated")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Handle flow stats reply to remove old flows"""
        try:
            current_time = time.time()
            body = ev.msg.body
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            for stat in body:
                # Calculate flow age
                flow_age = current_time - stat.duration_sec
                
                if flow_age > self.flow_max_age:
                    # Skip default controller flow
                    if stat.priority == 0:
                        continue
                        
                    self.logger.debug(f"Removing old flow (age: {flow_age:.1f}s): {stat.match}")
                    
                    mod = parser.OFPFlowMod(
                        datapath=datapath,
                        cookie=stat.cookie,
                        cookie_mask=0xffffffffffffffff,
                        table_id=stat.table_id,
                        command=ofproto.OFPFC_DELETE,
                        out_port=ofproto.OFPP_ANY,
                        out_group=ofproto.OFPG_ANY,
                        match=stat.match,
                    )
                    datapath.send_msg(mod)
        except Exception as e:
            self.logger.error(f"Flow stats handler error: {str(e)}")

    def handle_arp(self, datapath, in_port, pkt, eth_pkt, raw_data, pkt_id):
        arp_pkt = pkt.get_protocol(arp.arp)
        if not arp_pkt:
            return

        if arp_pkt.opcode == arp.ARP_REQUEST:
            self.handle_arp_request(datapath, in_port, eth_pkt, arp_pkt, raw_data, pkt_id)
        elif arp_pkt.opcode == arp.ARP_REPLY:
            self.logger.info(f"[Pkt-{pkt_id}] ARP reply from {arp_pkt.src_ip}")
            self.topo.update_arp_table(arp_pkt.src_ip, eth_pkt.src)

    def handle_arp_request(self, datapath, in_port, eth_pkt, arp_pkt, raw_data, pkt_id):
        target_ip = arp_pkt.dst_ip
        src_ip = arp_pkt.src_ip
        
        self.logger.info(f"[Pkt-{pkt_id}] ARP request: Who has {target_ip}? Tell {src_ip}")

        # 1. Check if target is a router interface
        router_mac = self.topo.get_router_mac(target_ip)
        if router_mac:
            self.logger.info(f"[Pkt-{pkt_id}] Target is router interface: {target_ip}")
            self.send_arp_reply(
                datapath, in_port, 
                router_mac, target_ip,
                eth_pkt.src, src_ip, pkt_id
            )
            return

        # 2. Check if target is a known host
        dst_mac = self.topo.get_mac_for_ip(target_ip)
        if dst_mac:
            self.logger.info(f"[Pkt-{pkt_id}] Target is known host: {target_ip}")
            self.send_arp_reply(
                datapath, in_port,
                dst_mac, target_ip,
                eth_pkt.src, src_ip, pkt_id
            )
            return

        # 3. Check if in same subnet
        src_net = self.topo.find_network_for_ip(src_ip)
        dst_net = self.topo.find_network_for_ip(target_ip)
        
        self.logger.debug(f"[Pkt-{pkt_id}] Subnet check: {src_ip} ({src_net}) -> {target_ip} ({dst_net})")
        
        if src_net == dst_net:
            # Same subnet, direct delivery
            self.logger.info(f"[Pkt-{pkt_id}] Same subnet ({src_net}), flooding ARP")
            self.flood_packet(datapath, in_port, raw_data, pkt_id)
            return
        
        # 4. Different subnet: send to source's default gateway
        router_ip = self.topo.find_router_for_ip(src_ip)
        router_mac = self.topo.get_mac_for_ip(router_ip) if router_ip else None
        if router_mac:
            self.send_arp_reply(
                datapath, in_port,
                router_mac, router_ip,
                eth_pkt.src, src_ip, pkt_id
            )
            return

        # 5. Fallback - flood
        self.logger.warning(f"[Pkt-{pkt_id}] No router found, flooding")
        self.flood_packet(datapath, in_port, raw_data, pkt_id)

    def send_arp_reply(self, datapath, in_port, src_mac, src_ip, dst_mac, dst_ip, pkt_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=dst_mac,
            src=src_mac
        ))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip
        ))
        pkt.serialize()

        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data
        )
        datapath.send_msg(out)
        self.logger.info(f"[Pkt-{pkt_id}] ARP reply sent: {src_ip} is at {src_mac}")

    def handle_icmp(self, datapath, in_port, eth_pkt, ip_pkt, icmp_pkt, raw_data, pkt_id):
        if icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
            self.handle_icmp_echo(datapath, in_port, eth_pkt, ip_pkt, icmp_pkt, raw_data, pkt_id)
        else:
            self.route_ip_packet(datapath, in_port, ip_pkt, raw_data, pkt_id)

    def handle_icmp_echo(self, datapath, in_port, eth_pkt, ip_pkt, icmp_pkt, raw_data, pkt_id):
        router_mac = self.topo.get_router_mac(ip_pkt.dst)
        if router_mac:
            self.send_icmp_reply(datapath, in_port, eth_pkt, ip_pkt, icmp_pkt, router_mac, pkt_id)
            return
        
        self.forward_to_host(datapath, in_port, ip_pkt.dst, raw_data, pkt_id, src_ip=ip_pkt.src)

    def send_icmp_reply(self, datapath, in_port, eth_pkt, ip_pkt, icmp_pkt, router_mac, pkt_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        icmp_reply = icmp.icmp(
            type_=icmp.ICMP_ECHO_REPLY,
            code=0,
            csum=0,
            data=icmp_pkt.data
        )
        
        ip_reply = ipv4.ipv4(
            proto=ip_pkt.proto,
            src=ip_pkt.dst,
            dst=ip_pkt.src,
            ttl=64
        )
        
        eth_reply = ethernet.ethernet(
            ethertype=eth_pkt.ethertype,
            dst=eth_pkt.src,
            src=router_mac
        )
        
        pkt = packet.Packet()
        pkt.add_protocol(eth_reply)
        pkt.add_protocol(ip_reply)
        pkt.add_protocol(icmp_reply)
        pkt.serialize()
        
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data
        )
        datapath.send_msg(out)
        self.logger.info(f"[Pkt-{pkt_id}] ICMP reply sent to {ip_pkt.src}")

    def route_ip_packet(self, datapath, in_port, ipv4_pkt, raw_data, pkt_id):
        dst_ip = ipv4_pkt.dst
        
        # 1. Check if destination is directly reachable
        dst_mac = self.topo.get_mac_for_ip(dst_ip)
        if dst_mac:
            self.forward_to_host(datapath, in_port, dst_ip, raw_data, pkt_id, src_ip=ipv4_pkt.src)
            return
            
        # 2. Check if destination in same subnet as source
        src_net = self.topo.find_network_for_ip(ipv4_pkt.src)
        dst_net = self.topo.find_network_for_ip(dst_ip)
        
        if src_net == dst_net:
            self.forward_to_host(datapath, in_port, dst_ip, raw_data, pkt_id, src_ip=ipv4_pkt.src)
            return
            
        # 3. Different subnet: send to source's default gateway
        router_ip = self.topo.find_router_for_ip(ipv4_pkt.src)
        router_mac = self.topo.get_mac_for_ip(router_ip) if router_ip else None
        if router_mac:
            self.forward_to_router_mac(datapath, router_mac, raw_data, pkt_id)
            self.logger.info(f"[Pkt-{pkt_id}] Routing via {router_ip} to {dst_ip}")
            return

        # 4. Fallback - flood
        self.logger.warning(f"[Pkt-{pkt_id}] No router found for {ipv4_pkt.src}")
        self.flood_packet(datapath, in_port, raw_data, pkt_id)

    def forward_to_host(self, datapath, in_port, dst_ip, raw_data, pkt_id, src_ip=None):
        dpid = datapath.id
        dst_mac = self.topo.get_mac_for_ip(dst_ip)
        
        if not dst_mac:
            self.logger.warning(f"[Pkt-{pkt_id}] MAC for {dst_ip} not found, flooding")
            self.flood_packet(datapath, in_port, raw_data, pkt_id)
            return
        
        out_port = self.topo.get_port_for_mac(dpid, dst_mac)
        if out_port is not None:
            self.send_packet(datapath, out_port, raw_data, pkt_id)
            
            # Install bidirectional flows
            if src_ip:
                src_mac = self.topo.get_mac_for_ip(src_ip)
                if src_mac:
                    # Forward flow (src -> dst)
                    self.install_flow(
                        datapath, 
                        eth_src=src_mac, 
                        eth_dst=dst_mac, 
                        out_port=out_port
                    )
                    
                    # Reverse flow (dst -> src)
                    self.install_flow(
                        datapath, 
                        eth_src=dst_mac, 
                        eth_dst=src_mac, 
                        out_port=in_port
                    )
            return
        else:
            self.logger.warning(f"[Pkt-{pkt_id}] Port for MAC {dst_mac} not found on dpid={dpid}, flooding")
            self.flood_packet(datapath, in_port, raw_data, pkt_id)
    
    def forward_to_router_mac(self, datapath, router_mac, raw_data, pkt_id):
        dpid = datapath.id
        out_port = self.topo.get_port_for_mac(dpid, router_mac)
        if out_port is not None:
            self.send_packet(datapath, out_port, raw_data, pkt_id)
        else:
            self.logger.warning(f"[Pkt-{pkt_id}] Port for router MAC {router_mac} not found on dpid={dpid}, flooding")
            self.flood_packet(datapath, datapath.ofproto.OFPP_FLOOD, raw_data, pkt_id)

    def flood_packet(self, datapath, in_port, data, pkt_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
        self.logger.debug(f"[Pkt-{pkt_id}] Flooding packet")

    def send_packet(self, datapath, out_port, data, pkt_id=None):
        """Send packet with optional packet ID for logging"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
        
        if pkt_id is not None:
            self.logger.debug(f"[Pkt-{pkt_id}] Packet sent to port {out_port}")
        else:
            self.logger.debug(f"Packet sent to port {out_port}")
    
    def drop_packet(self, datapath, buffer_id):
        """Explicitly drop a packet"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        if buffer_id != ofproto.OFP_NO_BUFFER:
            actions = []
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=buffer_id,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=None
            )
            datapath.send_msg(out)
    
    # ------------------------ Utility Methods ------------------------ #
    
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