#!/usr/bin/env python

import os
import sys
import logging
import time
import threading
import csv
import traceback
from datetime import datetime
from ryu.base import app_manager
from ryu.controller import ofp_event
from web.app import start_web_server, set_controller  
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.lib import hub

# Calculate paths
current_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(os.path.dirname(current_dir))
controller_dir = os.path.dirname(current_dir)
sys.path.extend([project_dir, controller_dir, current_dir])

# Import modules with error handling
try:
    from topology_manager import TopologyManager
    from packet_handler import PacketHandler
    from qos_manager import QoSManager
    from alert_manager import AlertManager
    from ids_manager import IDSManager
    from web.app import start_web_server, set_controller
except ImportError as e:
    logging.error(f"Import error: {str(e)}")
    raise

class RouterController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(RouterController, self).__init__(*args, **kwargs)
        self.real_time_data = {
            'ids': {'total': 0, 'normal': 0, 'abnormal': 0, 'attacks': {}},
            'bandwidth': {},
            'alerts': []  # Initialize alerts list
        }
        self._configure_logging()
        self.connected = False
        self.last_connection_check = 0
        
        # Initialize connection status
        self.connection_status = {'status': 'disconnected', 'timestamp': time.time()}
        
        self.real_time_data = {
            'ids': {'total': 0, 'normal': 0, 'abnormal': 0, 'attacks': {}},
            'bandwidth': {},
            'alerts': []
        }
        
        # Attack archive
        self.attack_archive = []
        self.attack_archive_file = os.path.join(project_dir, "attack_archive.csv")
        self._init_attack_archive()
        
        try:
            self.logger.info("Initializing SDN Controller...")
            
            # Initialize core components
            self.alert_manager = AlertManager()
            self.topo_manager = TopologyManager(self.alert_manager)
            self.ids_manager = IDSManager()
            self.qos_manager = QoSManager(logger=self.logger, alert_manager=self.alert_manager)
            
            # Set QoS manager in topology manager
            self.topo_manager.set_qos_manager(self.qos_manager)
            
            # Initialize packet handler
            self.pkt_handler = PacketHandler(
                topo_manager=self.topo_manager,
                alert_manager=self.alert_manager,
                ids_manager=self.ids_manager,
                qos_manager=self.qos_manager,
                controller=self  # Pass controller reference
            )
            
            # Start periodic tasks
            self.monitor_thread = hub.spawn(self._monitor_system)
            self.data_thread = hub.spawn(self._collect_real_time_data)
            
            # Start web server
            self._start_web_server()
            
            self.logger.info("SDN Controller initialized with full capabilities")
            
        except Exception as e:
            self.logger.exception(f"Initialization error: {str(e)}")
            self.stop()
    
    def set_socketio(self, socketio):
        """Set SocketIO instance for alert manager"""
        self.socketio = socketio
        if self.alert_manager:
            self.alert_manager.set_socketio(socketio)
        else:
            self.logger.warning("Alert manager not initialized when setting SocketIO")
        
    def _configure_logging(self):
        """Configure logging settings"""
        self.logger = logging.getLogger('RouterController')
        self.logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # File handler
        file_handler = logging.FileHandler('controller.log')
        file_handler.setFormatter(formatter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        self.logger.propagate = False
        
    def _init_attack_archive(self):
        """Initialize attack archive file with headers"""
        if not os.path.exists(self.attack_archive_file):
            with open(self.attack_archive_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'attack_type', 'src_ip', 'dst_ip', 
                    'probability', 'switch_mac', 'traffic_volume'
                ])
    
    def _archive_attack(self, attack_type, src_ip, dst_ip, probability, switch_mac, traffic_volume):
        """Archive attack to CSV file"""
        timestamp = datetime.now().isoformat()
        with open(self.attack_archive_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp, attack_type, src_ip, dst_ip, 
                probability, switch_mac, traffic_volume
            ])
        self.logger.info(f"Archived attack: {attack_type} from {src_ip}")
        
    def _start_web_server(self):
        """Start the web server in a separate thread"""
        try:
            self.logger.info("Starting web server thread")
            
            # Set global controller reference
            set_controller(self)
            
            web_thread = threading.Thread(
                target=start_web_server,
                daemon=True
            )
            web_thread.start()
            self.logger.info("Web server started successfully")
        except Exception as e:
            self.logger.exception("Failed to start web server")
        
    def _monitor_system(self):
        """Monitor system components periodically"""
        while True:
            try:
                # Check network connectivity
                self.connected = self.topo_manager.is_network_connected()
                self.topo_manager.connected = self.connected
                self.connection_status = {
                    'status': 'connected' if self.connected else 'disconnected',
                    'timestamp': time.time()
                }
                
                # Collect statistics
                self._collect_switch_stats()
                
                # Train IDS if needed
                if self.ids_manager.needs_training():
                    self._train_ids_model()
                
                # Save alerts
                self.alert_manager.save_alerts()
                
                hub.sleep(5)  # Reduced from 10 to 5 seconds
            except Exception as e:
                self.logger.error(f"Monitoring error: {str(e)}")
                hub.sleep(30)
                
    def _collect_real_time_data(self):
        """Collect real-time IDS, bandwidth and alerts data"""
        while True:
            try:
                # Update IDS stats
                self.real_time_data['ids'] = {
                    'total': self.pkt_handler.packet_count,
                    'normal': self.pkt_handler.normal_packets,
                    'abnormal': self.pkt_handler.abnormal_packets,
                    'attacks': self.ids_manager.get_attack_statistics() if self.ids_manager else {}
                }
                
                # Update bandwidth stats
                bandwidth_stats = {}
                for dpid, switch in self.topo_manager.switches.items():
                    if 'datapath' in switch and switch['status'] == 'active':
                        dpid_str = str(dpid)
                        bandwidth_stats[dpid_str] = {}
                        if dpid_str in self.qos_manager.bandwidth_stats:
                            for port, stats in self.qos_manager.bandwidth_stats[dpid_str].items():
                                bandwidth_stats[dpid_str][port] = {
                                    'rx_rate': stats.get('rx_rate', 0),
                                    'tx_rate': stats.get('tx_rate', 0)
                                }
                
                self.real_time_data['bandwidth'] = bandwidth_stats
                
                # Update real-time alerts
                if self.alert_manager:
                    alerts = self.alert_manager.get_realtime_alerts()
                    self.real_time_data['alerts'] = alerts
                    
                    # Archive and log new alerts
                    for alert in alerts:
                        if alert.get('type') == 'security':
                            self.logger.warning(
                                f"Real-time alert: {alert.get('attack_type', 'Unknown')} "
                                f"from {alert.get('src', 'N/A')} to {alert.get('dst', 'N/A')} "
                                f"(prob: {alert.get('probability', 0):.2%})"
                            )
                            # Archive security alerts
                            self._archive_attack(
                                alert['attack_type'],
                                alert['src'],
                                alert['dst'],
                                alert.get('probability', 0),
                                alert.get('switch_mac', 'N/A'),
                                alert.get('traffic_volume', 0)
                            )
                
                hub.sleep(1)  # Collect data every second
                
            except Exception as e:
                self.logger.error(f"Real-time data collection error: {str(e)}")
                self.logger.debug(traceback.format_exc())
                hub.sleep(5)
                
    def _collect_switch_stats(self):
        """Collect statistics from all switches"""
        for dpid, switch in self.topo_manager.switches.items():
            if 'datapath' in switch and switch['status'] == 'active':
                self._request_port_stats(switch['datapath'])
    
    def _request_port_stats(self, datapath):
        """Request port statistics from switch"""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            req = parser.OFPPortStatsRequest(
                datapath,
                0,
                ofproto.OFPP_ANY
            )
            datapath.send_msg(req)
        except Exception as e:
            self.logger.error(f"Stats request error: {str(e)}")
    
    def _train_ids_model(self):
        try:
            controller_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(controller_dir)
            datasets_dir = os.path.join(project_root, "datasets")
        
            training_file = os.path.join(datasets_dir, "UNSW_NB15_training-set.csv")
            testing_file = os.path.join(datasets_dir, "UNSW_NB15_testing-set.csv")
        
        # Create directory if doesn't exist
            os.makedirs(datasets_dir, exist_ok=True)
        
            if not os.path.exists(training_file):
                self.logger.error(f"Training file not found: {training_file}")
            # Provide download instructions
                self.logger.info("Download datasets from: https://research.unsw.edu.au/projects/unsw-nb15-dataset")
                return False
        # ... rest of the code
                
            training_success = self.ids_manager.train(
                training_file=training_file,
                testing_file=testing_file
            )
            
            if training_success:
                self.logger.info("IDS training completed successfully")
            else:
                self.logger.error("IDS training failed")
        except Exception as e:
            self.logger.error(f"IDS training error: {str(e)}")
            self.logger.debug(traceback.format_exc())
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
      self.pkt_handler.flow_stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.pkt_handler.switch_features_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self.pkt_handler.packet_in_handler(ev)
    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        self.qos_manager.update_bandwidth_utilization(ev.msg.datapath, ev.msg.body)
    
    @set_ev_cls(event.EventSwitchEnter, CONFIG_DISPATCHER)
    @set_ev_cls(event.EventSwitchLeave, CONFIG_DISPATCHER)
    def switch_change_handler(self, ev):
        self.topo_manager.handle_switch_event(ev)
    
    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_change_handler(self, ev):
        self.topo_manager.handle_link_event(ev)
    
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        self.topo_manager.handle_port_status(ev)
    @set_ev_cls(event.EventSwitchEnter, CONFIG_DISPATCHER)
    @set_ev_cls(event.EventSwitchLeave, CONFIG_DISPATCHER)
    def switch_change_handler(self, ev):
        self.topo_manager.handle_switch_event(ev)
    
    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_change_handler(self, ev):
        self.topo_manager.handle_link_event(ev)
    
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        self.topo_manager.handle_port_status(ev)

if __name__ == '__main__':
    app_manager.run_app()