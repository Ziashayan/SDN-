import os
import sys
import logging
import time
import threading
import csv
import traceback
from datetime import datetime
from flask_socketio import SocketIO
from flask import Flask, render_template, jsonify, send_from_directory
from flask_socketio import SocketIO
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.lib import hub

# Calculate paths
current_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(os.path.dirname(current_dir))
controller_dir = os.path.dirname(current_dir)
sys.path.extend([project_dir, controller_dir, current_dir])

# Configure logging
logger = logging.getLogger('SDNController')
logger.setLevel(logging.INFO)

# Clear existing handlers
for handler in logger.handlers[:]:
    logger.removeHandler(handler)

# Create formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# File handler
file_handler = logging.FileHandler('controller.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Import modules
try:
    from topology_manager import TopologyManager
    from packet_handler import PacketHandler
    from qos_manager import QoSManager
    from alert_manager import AlertManager
    from ids_manager import IDSManager
except ImportError as e:
    logger.error(f"Critical import error: {str(e)}")
    logger.error(traceback.format_exc())
    sys.exit(1)

# Create Flask application instance
app = Flask(__name__, template_folder='templates', static_folder='static')
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# Global controller reference
controller_instance = None

def set_controller(controller):
    global controller_instance
    controller_instance = controller

def get_ryu_app():
    return controller_instance

# SocketIO Events
@socketio.on('connect')
def handle_connect():
    logger.info("WebSocket client connected")

# Flask Routes
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/topology')
def topology_view():
    return render_template('topology.html')

@app.route('/ids-monitoring')
def ids_monitoring():
    return render_template('ids-monitoring.html')

@app.route('/api/network-stats')
def network_stats():
    ryu_app = get_ryu_app()
    if not ryu_app:
        return jsonify({"error": "Controller not ready", "connected": False})
    
    try:
        stats = ryu_app.topo_manager.get_network_stats()
        compromised_hosts = ryu_app.alert_manager.get_compromised_hosts() or []
        stats['compromised_hosts'] = len(compromised_hosts)
        stats['connected'] = ryu_app.connected
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Network stats error: {str(e)}")
        return jsonify({"error": "Internal server error", "connected": False})

@app.route('/api/connection-status')
def connection_status():
    ryu_app = get_ryu_app()
    return jsonify({"connected": ryu_app.connected if ryu_app else False})

@app.route('/api/qos')
def qos_stats():
    ryu_app = get_ryu_app()
    if not ryu_app:
        return jsonify({})
    
    try:
        return jsonify(ryu_app.qos_manager.get_stats())
    except Exception as e:
        logger.error(f"QoS stats error: {str(e)}")
        return jsonify({})

@app.route('/api/topology')
def topology_data():
    ryu_app = get_ryu_app()
    if not ryu_app:
        return jsonify({'nodes': [], 'edges': [], 'connected': False})
    
    try:
        topology = ryu_app.topo_manager.get_topology()
        return jsonify({
            'nodes': topology.get('nodes', []),
            'edges': topology.get('edges', []),
            'routing_table': topology.get('routing_table', []),
            'connected': ryu_app.connected
        })
    except Exception as e:
        logger.error(f"Topology data error: {str(e)}")
        return jsonify({'nodes': [], 'edges': [], 'connected': False})

@app.route('/api/alerts')
def alerts_list():
    ryu_app = get_ryu_app()
    if not ryu_app:
        return jsonify({'alerts': []})
    
    try:
        alerts = ryu_app.alert_manager.get_alerts() or []
        return jsonify({'alerts': alerts[:1000]})
    except Exception as e:
        logger.error(f"Alerts error: {str(e)}")
        return jsonify({'alerts': []})

@app.route('/api/security-status')
def security_status():
    ryu_app = get_ryu_app()
    if not ryu_app:
        return jsonify({'nodes': [], 'alerts': [], 'connected': False})
    
    try:
        topology = ryu_app.topo_manager.get_topology()
        nodes = topology.get('nodes', [])
        compromised_hosts = ryu_app.alert_manager.get_compromised_hosts() or []
        compromised_ips = [host['ip'] for host in compromised_hosts]
        
        alerts = ryu_app.alert_manager.get_security_alerts() or []
        
        attack_stats = ryu_app.ids_manager.get_attack_statistics() if ryu_app.ids_manager else {}
        
        formatted_nodes = []
        for node in nodes:
            is_compromised = node['type'] == 'host' and node.get('ip') in compromised_ips
            formatted_nodes.append({
                'id': node['id'],
                'type': node['type'],
                'ip': node.get('ip', ''),
                'mac': node.get('mac', ''),
                'status': node.get('status', 'unknown'),
                'is_compromised': is_compromised,
                'label': node.get('label', '')
            })
        
        return jsonify({
            'nodes': formatted_nodes,
            'alerts': alerts,
            'compromised_hosts': compromised_ips,
            'attack_distribution': attack_stats.get('distribution', {}),
            'total_attacks': attack_stats.get('total', 0),
            'connected': ryu_app.connected
        })
    except Exception as e:
        logger.error(f"Security status error: {str(e)}")
        return jsonify({
            'nodes': [],
            'alerts': [],
            'compromised_hosts': [],
            'attack_distribution': {},
            'connected': False
        })
    
@app.route('/api/ips/status')
def ips_status():
    ryu_app = get_ryu_app()
    if not ryu_app:
        return jsonify({})
    
    try:
        blocked_flows = []
        current_time = time.time()
        
        for (src, dst), expiry in ryu_app.pkt_handler.ips_blocked_flows.items():
            if current_time < expiry:
                blocked_flows.append({
                    'src': src,
                    'dst': dst,
                    'expires_in': int(expiry - current_time)
                })
        
        return jsonify({
            'blocked_flows': blocked_flows,
            'redirect_ip': ryu_app.pkt_handler.redirect_ip,
            'block_duration': ryu_app.pkt_handler.block_duration
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/ids/model-info')
def ids_model_info():
    ryu_app = get_ryu_app()
    if not ryu_app or not hasattr(ryu_app, 'ids_manager'):
        return jsonify({})
    
    try:
        return jsonify(ryu_app.ids_manager.get_model_info())
    except Exception as e:
        logger.error(f"IDS model info error: {str(e)}")
        return jsonify({})

@app.route('/topology-image')
def topology_image():
    ryu_app = get_ryu_app()
    if not ryu_app:
        return send_from_directory('static', 'empty-topology.png')
    
    try:
        image_path = ryu_app.topo_manager.visualize_topology()
        if image_path and os.path.exists(image_path):
            return send_from_directory(os.path.dirname(image_path), os.path.basename(image_path))
    except Exception as e:
        logger.error(f"Topology image error: {str(e)}")
    
    return send_from_directory('static', 'empty-topology.png')

@app.route('/api/ids/attack-stats')
def attack_stats():
    ryu_app = get_ryu_app()
    if not ryu_app or not hasattr(ryu_app, 'ids_manager'):
        return jsonify({})
    
    try:
        return jsonify(ryu_app.ids_manager.get_attack_statistics())
    except Exception as e:
        logger.error(f"Attack stats error: {str(e)}")
        return jsonify({})

# NEW REAL-TIME ENDPOINTS
@app.route('/api/real-time/ids')
def real_time_ids():
    ryu_app = get_ryu_app()
    if not ryu_app:
        return jsonify({})
    return jsonify(ryu_app.real_time_data.get('ids', {}))

@app.route('/api/real-time/bandwidth')
def real_time_bandwidth():
    ryu_app = get_ryu_app()
    if not ryu_app:
        return jsonify({})
    return jsonify(ryu_app.real_time_data.get('bandwidth', {}))

@app.route('/api/real-time/alerts')
def real_time_alerts():
    ryu_app = get_ryu_app()
    if not ryu_app:
        return jsonify({'alerts': []})
    
    try:
        alerts = ryu_app.alert_manager.get_realtime_alerts()
        return jsonify({'alerts': alerts, 'timestamp': time.time()})
    except Exception as e:
        logger.error(f"Real-time alerts error: {str(e)}")
        return jsonify({'alerts': []})

@app.route('/api/real-time/traffic')
def real_time_traffic():
    ryu_app = get_ryu_app()
    if not ryu_app:
        return jsonify({})
    return jsonify(ryu_app.qos_manager.get_realtime_traffic_stats() if ryu_app.qos_manager else {})

@app.route('/api/real-time/attacks')
def real_time_attacks():
    ryu_app = get_ryu_app()
    if not ryu_app or not hasattr(ryu_app, 'ids_manager'):
        return jsonify({'attacks': []})
    
    try:
        attacks = ryu_app.ids_manager.get_realtime_attack_stats()
        return jsonify(attacks)
    except Exception as e:
        logger.error(f"Real-time attacks error: {str(e)}")
        return jsonify({'attacks': []})

def start_web_server(host='0.0.0.0', port=8080):
    """Start the Flask web server with SocketIO"""
    logger.info(f"Starting web server on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=False, use_reloader=False)

class RouterController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = logger
        self.connected = False
        self.last_connection_check = 0
        self.real_time_data = {
            'ids': {'total': 0, 'normal': 0, 'abnormal': 0, 'attacks': {}},
            'bandwidth': {},
            'alerts': []
        }
        
        # Attack archive setup
        self.attack_archive_file = os.path.join(project_dir, "attack_archive.csv")
        self._init_attack_archive()
        
        try:
            self.logger.info("Initializing SDN Controller...")
            
            # Initialize core components
            self.alert_manager = AlertManager()
            self.topo_manager = TopologyManager(self.alert_manager)
            self.ids_manager = IDSManager()
            self.qos_manager = QoSManager(alert_manager=self.alert_manager)
            
            # Set QoS manager in topology manager
            self.topo_manager.set_qos_manager(self.qos_manager)
            
            # Pass SocketIO to AlertManager
            self.alert_manager.set_socketio(socketio)
            
            # Initialize packet handler
            self.pkt_handler = PacketHandler(
                topo_manager=self.topo_manager,
                alert_manager=self.alert_manager,
                ids_manager=self.ids_manager,
                qos_manager=self.qos_manager,
                controller=self
            )
            
            # Start periodic tasks
            self.monitor_thread = hub.spawn(self._monitor_system)
            self.data_thread = hub.spawn(self._collect_real_time_data)
            
            # Set global controller reference for web endpoints
            set_controller(self)
            
            # Start web server in a separate thread
            self.web_thread = threading.Thread(
                target=start_web_server,
                daemon=True,
                name="WebServerThread"
            )
            self.web_thread.start()
            self.logger.info("Web server started successfully")
            
            self.logger.info("SDN Controller initialized")
            
        except Exception as e:
            self.logger.exception(f"Initialization failed: {str(e)}")
            self.stop()
        
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
        
    def _monitor_system(self):
        """Monitor system components periodically"""
        while True:
            try:
                # Check network connectivity
                self.connected = self.topo_manager.is_network_connected()
                self.topo_manager.connected = self.connected
                
                # Collect statistics
                self._collect_switch_stats()
                
                # Train IDS if needed
                if self.ids_manager and self.ids_manager.needs_training():
                    self._train_ids_model()
                
                # Save alerts
                if self.alert_manager:
                    self.alert_manager.save_alerts()
                
                hub.sleep(5)
            except Exception as e:
                self.logger.error(f"Monitoring error: {str(e)}")
                hub.sleep(30)
                
    def _collect_real_time_data(self):
        """Collect real-time IDS, bandwidth and alerts data"""
        while True:
            try:
                # Update IDS stats
                if hasattr(self, 'pkt_handler'):
                    self.real_time_data['ids'] = {
                        'total': self.pkt_handler.packet_count,
                        'normal': self.pkt_handler.normal_packets,
                        'abnormal': self.pkt_handler.abnormal_packets,
                        'attacks': self.ids_manager.get_attack_statistics() if self.ids_manager else {}
                    }
                
                # Update bandwidth stats
                bandwidth_stats = {}
                if hasattr(self, 'topo_manager') and hasattr(self.topo_manager, 'switches'):
                    for dpid, switch in self.topo_manager.switches.items():
                        if 'datapath' in switch and switch['status'] == 'active':
                            dpid_str = str(dpid)
                            bandwidth_stats[dpid_str] = {}
                            if (hasattr(self, 'qos_manager') and 
                                hasattr(self.qos_manager, 'bandwidth_stats') and 
                                dpid_str in self.qos_manager.bandwidth_stats):
                                for port, stats in self.qos_manager.bandwidth_stats[dpid_str].items():
                                    bandwidth_stats[dpid_str][port] = {
                                        'rx_rate': stats.get('rx_rate', 0),
                                        'tx_rate': stats.get('tx_rate', 0)
                                    }
                
                self.real_time_data['bandwidth'] = bandwidth_stats
                
                # Update real-time alerts
                if hasattr(self, 'alert_manager'):
                    alerts = self.alert_manager.get_realtime_alerts()
                    self.real_time_data['alerts'] = alerts
                    
                    # Log new security alerts
                    for alert in alerts:
                        if alert.get('type') == 'security':
                            self.logger.warning(
                                f"Security alert: {alert.get('attack_type', 'Unknown')} "
                                f"from {alert.get('src', 'N/A')} to {alert.get('dst', 'N/A')} "
                                f"(prob: {alert.get('probability', 0):.2%})"
                            )
                
                hub.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Real-time data error: {str(e)}")
                hub.sleep(5)
                
    def _collect_switch_stats(self):
        """Collect statistics from all switches"""
        if not hasattr(self, 'topo_manager') or not hasattr(self.topo_manager, 'switches'):
            return
            
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
        """Train the IDS machine learning model"""
        if not hasattr(self, 'ids_manager'):
            return False
            
        try:
            controller_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(controller_dir)
            datasets_dir = os.path.join(project_root, "datasets")
            
            # Ensure datasets directory exists
            os.makedirs(datasets_dir, exist_ok=True)
            
            training_file = os.path.join(datasets_dir, "UNSW_NB15_training-set.csv")
            testing_file = os.path.join(datasets_dir, "UNSW_NB15_testing-set.csv")
        
            if not os.path.exists(training_file):
                self.logger.error(f"Training file not found: {training_file}")
                self.logger.info("Download datasets from: https://research.unsw.edu.au/projects/unsw-nb15-dataset")
                return False
                
            training_success = self.ids_manager.train(
                training_file=training_file,
                testing_file=testing_file
            )
            
            if training_success:
                self.logger.info("IDS training completed successfully")
                return True
            else:
                self.logger.error("IDS training failed")
                return False
        except Exception as e:
            self.logger.error(f"IDS training error: {str(e)}")
            return False

    # Event Handlers
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.pkt_handler.switch_features_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self.pkt_handler.packet_in_handler(ev)
    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        if hasattr(self, 'qos_manager'):
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

if __name__ == '__main__':
    app_manager.run_app()