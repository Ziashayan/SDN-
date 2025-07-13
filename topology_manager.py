import os
import json
import ipaddress
import random
import time
import logging
import threading
import hashlib
import traceback
from collections import defaultdict
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from ryu.topology import event

class TopologyManager:
    def __init__(self, alert_manager=None):
        self.alert_manager = alert_manager
        self._initialize_logging()
        self._initialize_data_structures()
        self._setup_paths()
        self.load_config()
        self._start_cleanup_thread()
        self._start_routing_thread()
        self.logger.info("Topology Manager initialized")
        self.compromised_hosts = {}
        self.qos_manager = None
        self.bandwidth_stats = {}
    
    def _initialize_logging(self):
        self.logger = logging.getLogger('TopologyManager')
        self.logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        file_handler = logging.FileHandler('topology.log')
        file_handler.setFormatter(formatter)
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def _initialize_data_structures(self):
        # Initialize data_lock FIRST
        self.data_lock = threading.Lock()
        
        self.mac_to_port = defaultdict(dict)
        self.arp_table = {}
        self.router_interfaces = {}
        self.hosts = {}
        self.switches = {}
        self.links = set()
        self.subnets = set()
        self.routes = {}
        self.update_callbacks = []
        self.last_packet = None
        
        self.host_timeout = 60
        self.router_timeout = 600
        self.switch_timeout = 30
        
        self.graph = nx.Graph()
        self.router_graph = nx.Graph()
        self.routing_table = {}
        self.graph_lock = threading.Lock()
        self.topology_hash = None
        self.switch_count = 0
        self.last_update_time = 0
        self.update_interval = 1
        self.last_routing_update = 0
        self.routing_update_interval = 10

    def is_network_connected(self):
        active_switches = sum(1 for s in self.switches.values() if s.get('status') == 'active')
        active_hosts = sum(1 for h in self.hosts.values() 
                           if time.time() - h['timestamp'] <= self.host_timeout)
        return active_switches > 0 and active_hosts > 1

    def set_qos_manager(self, qos_manager):
        self.qos_manager = qos_manager

    def _setup_paths(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(current_dir))
        
        self.topology_file = os.path.join(project_root, "topology_state.json")
        self.backup_dir = os.path.join(project_root, "backups")
        os.makedirs(self.backup_dir, exist_ok=True)
        
    def _start_cleanup_thread(self):
        self.cleanup_thread = threading.Thread(
            target=self.cleanup_expired_devices,
            daemon=True
        )
        self.cleanup_thread.start()
        self.logger.info("Device cleanup thread started")

    def _start_routing_thread(self):
        self.routing_thread = threading.Thread(
            target=self.update_routing_periodically,
            daemon=True
        )
        self.routing_thread.start()
        self.logger.info("Routing update thread started")

    def cleanup_expired_devices(self):
        while True:
            time.sleep(15)
            current_time = time.time()
        
            with self.data_lock:
                # Expired hosts
                expired_hosts = [ip for ip, host_info in self.hosts.items()
                                if current_time - host_info['timestamp'] > self.host_timeout]
                
                for ip in expired_hosts:
                    self.remove_host(ip)
                
                # Expired routers
                expired_routers = [ip for ip, rtr_info in self.router_interfaces.items()
                                if rtr_info.get('status') != 'configured' and
                                    current_time - rtr_info.get('last_seen', 0) > self.router_timeout]
                
                for ip in expired_routers:
                    self.remove_router(ip)
                
                # Old inactive switches
                expired_switches = [dpid for dpid, sw_info in self.switches.items()
                                   if sw_info.get('status') == 'inactive' and
                                      current_time - sw_info.get('last_seen', 0) > self.switch_timeout]
                
                for dpid in expired_switches:
                    self.remove_switch_completely(dpid)
                
                if expired_hosts or expired_routers or expired_switches:
                    self.logger.info(f"Removed: {len(expired_hosts)} hosts, {len(expired_routers)} routers, {len(expired_switches)} switches")
                    self.notify_update()

    def remove_host(self, ip):
        if ip in self.hosts:
            host_info = self.hosts[ip]
            
            if ip in self.arp_table:
                del self.arp_table[ip]
            
            if host_info.get('attached_to'):
                dpid, port = host_info['attached_to']
                if dpid in self.mac_to_port and host_info['mac'] in self.mac_to_port[dpid]:
                    del self.mac_to_port[dpid][host_info['mac']]
            
            host_node = f"host_{ip}"
            with self.graph_lock:
                if host_node in self.graph:
                    self.graph.remove_node(host_node)
            
            del self.hosts[ip]
            self.logger.info(f"Expired host removed: {ip}")
            self.notify_update()
            
    def remove_switch_completely(self, dpid):
        if dpid in self.switches:
            # Remove related links
            links_to_remove = [link for link in self.links 
                              if link[0] == dpid or link[2] == dpid]
            for link in links_to_remove:
                self.links.remove(link)
            
            # Remove from graph
            switch_node = f"switch_{dpid}"
            with self.graph_lock:
                if switch_node in self.graph:
                    # Remove all edges connected to this switch
                    for neighbor in list(self.graph.neighbors(switch_node)):
                        self.graph.remove_edge(switch_node, neighbor)
                    self.graph.remove_node(switch_node)
            
            # Remove MAC mapping
            if dpid in self.mac_to_port:
                del self.mac_to_port[dpid]
            
            del self.switches[dpid]
            self.logger.info(f"Switch completely removed: dpid={dpid}")
            self.switch_count = max(0, self.switch_count - 1)
            self.notify_update()

    def remove_router(self, ip):
        if ip in self.router_interfaces:
            router_info = self.router_interfaces[ip]
            
            if router_info['network'] in self.routes:
                del self.routes[router_info['network']]
            
            self.subnets.discard(router_info['network'])
            
            router_node = f"router_{ip}"
            with self.graph_lock:
                if router_node in self.graph:
                    self.graph.remove_node(router_node)
            
            del self.router_interfaces[ip]
            self.logger.warning(f"Expired router removed: {ip}")
            self.notify_update()

    def register_update_callback(self, callback):
        self.update_callbacks.append(callback)
        
    def notify_update(self):
        current_time = time.time()
        if current_time - self.last_update_time >= self.update_interval:
            self.save_topology_to_file()
            self.last_update_time = current_time
        for callback in self.update_callbacks:
            try:
                callback()
            except Exception as e:
                self.logger.error(f"Update callback error: {str(e)}")

    def save_topology_to_file(self):
        try:
            topology = self.get_topology()
            with open(self.topology_file, 'w') as f:
                json.dump(topology, f, indent=2)
            self.logger.debug("Topology state saved to file")
        except Exception as e:
            self.logger.error(f"Topology save error: {str(e)}")

    def load_config(self):
        try:
            # Use absolute path
            controller_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(controller_dir)
            config_file = os.path.join(project_root, "topology_config.json")
            
            self.logger.info(f"Loading router configuration from: {config_file}")
            
            if not os.path.exists(config_file):
                # Create default config if missing
                self.logger.warning("Config file not found, creating default")
                default_config = {
                    "routers": [{
                        "name": "DefaultRouter",
                        "interfaces": [{
                            "ip_range": "192.168.1.0/24",
                            "mac": "00:01:a3:2f:56:00"
                        }]
                    }]
                }
                with open(config_file, 'w') as f:
                    json.dump(default_config, f, indent=2)
            
            # Load config file
            with open(config_file) as f:
                config = json.load(f)
            
            with self.data_lock:
                self.router_interfaces = {}
                self.routes = {}
                self.subnets = set()
                
                for router in config.get("routers", []):
                    router_name = router.get("name", "UnnamedRouter")
                    for interface in router.get("interfaces", []):
                        ip_cidr = interface["ip_range"]
                        try:
                            network = ipaddress.IPv4Network(ip_cidr, strict=False)
                            gateway_ip = str(network.network_address + 1)
                            
                            router_mac = interface.get('mac')
                            if not router_mac:
                                router_mac = self.generate_mac()
                                self.logger.warning(f"Generated MAC {router_mac} for {gateway_ip}")
                            
                            self.router_interfaces[gateway_ip] = {
                                'mac': router_mac,
                                'network': str(network),
                                'status': 'configured',
                                'last_seen': time.time(),
                                'router_name': router_name
                            }
                            
                            self.routes[str(network)] = {
                                'mac': router_mac,
                                'interface_ip': gateway_ip
                            }
                            
                            self.subnets.add(str(network))
                            
                            self.arp_table[gateway_ip] = router_mac
                            
                            router_node = f"router_{gateway_ip}"
                            with self.graph_lock:
                                self.graph.add_node(
                                    router_node,
                                    type='router',
                                    ip=gateway_ip,
                                    mac=router_mac,
                                    network=str(network),
                                    status='configured',
                                    router_name=router_name,
                                    label=f"Router\n{router_name}\n{gateway_ip}"
                                )
                        except Exception as e:
                            self.logger.error(f"Router config error: {str(e)}")
                
                self.logger.info(f"Loaded: {len(self.router_interfaces)} router interfaces")
                self.logger.debug(f"Router interfaces: {list(self.router_interfaces.keys())}")
                self.logger.debug(f"Routes: {self.routes}")
                self.logger.debug(f"Subnets: {self.subnets}")
                
        except Exception as e:
            self.logger.error(f"Config error: {str(e)}")

    def generate_mac(self):
        return "02:00:" + ":".join(f"{random.randint(0, 255):02x}" for _ in range(4))

    def find_network_for_ip(self, ip):
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            best_network = None
            best_prefix_len = -1
            
            for subnet in self.subnets:
                network = ipaddress.IPv4Network(subnet, strict=False)
                if ip_obj in network:
                    if network.prefixlen > best_prefix_len:
                        best_prefix_len = network.prefixlen
                        best_network = network
            
            if best_network:
                return str(best_network)
                
            # Create /24 subnet for IP
            base = '.'.join(ip.split('.')[:-1])
            return f"{base}.0/24"
        except Exception as e:
            self.logger.error(f"Error finding network for IP {ip}: {str(e)}")
            return "0.0.0.0/0"

    def get_router_mac(self, ip):
        with self.data_lock:
            if ip in self.router_interfaces:
                return self.router_interfaces[ip]['mac']
            return None

    def get_port_for_mac(self, dpid, mac):
        with self.data_lock:
            if dpid in self.mac_to_port and mac in self.mac_to_port[dpid]:
                return self.mac_to_port[dpid][mac]
            return None

    def get_ip_for_mac(self, mac):
        """Get IP address associated with a MAC"""
        with self.data_lock:
            for ip, host_info in self.hosts.items():
                if host_info.get('mac', '').lower() == mac.lower():
                    return ip
            return None


    def handle_switch_event(self, ev):
        if isinstance(ev, event.EventSwitchEnter):
            self.add_switch(ev.switch.dp.id, ev.switch.dp)
            self.logger.info(f"Switch added. Total: {self.switch_count}")
        elif isinstance(ev, event.EventSwitchLeave):
            self.mark_switch_inactive(ev.switch.dp.id)
            self.logger.info(f"Switch removed. Total: {self.switch_count}")

    def add_switch(self, dpid, datapath):
        with self.graph_lock:
            # Only add if switch doesn't exist or is inactive
            if dpid not in self.switches or self.switches[dpid].get('status') != 'active':
                # Generate MAC address from DPID
                mac_parts = []
                for i in range(5, -1, -1):
                    byte = (dpid >> (i * 8)) & 0xFF
                    mac_parts.append(f"{byte:02x}")
                switch_mac = ":".join(mac_parts)
                
                self.switches[dpid] = {
                    'dpid': dpid,
                    'mac': switch_mac,
                    'datapath': datapath,
                    'ports': {},
                    'port_count': 0,
                    'status': 'active',
                    'last_seen': time.time(),
                    'timestamp': time.time()
                }
                
                switch_node = f"switch_{dpid}"
                if switch_node not in self.graph:
                    self.graph.add_node(
                        switch_node,
                        type='switch',
                        dpid=dpid,
                        mac=switch_mac,
                        label=f"Switch\n{dpid}\n{switch_mac}",
                        status='active',
                        port_count=0
                    )
                else:
                    # Update existing node status and MAC
                    self.graph.nodes[switch_node]['status'] = 'active'
                    self.graph.nodes[switch_node]['mac'] = switch_mac
                    self.graph.nodes[switch_node]['label'] = f"Switch\n{dpid}\n{switch_mac}"
                
                self.switch_count += 1
                self.logger.info(f"Switch added: dpid={dpid}, mac={switch_mac}")
                self.notify_update()

    def mark_switch_inactive(self, dpid):
        with self.graph_lock:
            if dpid in self.switches:
                self.switches[dpid]['status'] = 'inactive'
                self.switches[dpid]['last_seen'] = time.time()
                
                if f"switch_{dpid}" in self.graph:
                    self.graph.nodes[f"switch_{dpid}"]['status'] = 'inactive'
                
                self.logger.info(f"Switch marked inactive: dpid={dpid}")
                self.notify_update()

    def handle_link_event(self, ev):
        if isinstance(ev, event.EventLinkAdd):
            self.add_link(ev.link)
        elif isinstance(ev, event.EventLinkDelete):
            self.remove_link(ev.link)

    def add_link(self, link):
        src = link.src
        dst = link.dst
        link_key = (src.dpid, src.port_no, dst.dpid, dst.port_no)
        
        if link_key not in self.links:
            self.links.add(link_key)
            
            with self.graph_lock:
                src_node = f"switch_{src.dpid}"
                dst_node = f"switch_{dst.dpid}"
                
                if self.graph.has_edge(src_node, dst_node):
                    self.graph.remove_edge(src_node, dst_node)
                
                self.graph.add_edge(
                    src_node,
                    dst_node,
                    src_port=src.port_no,
                    dst_port=dst.port_no,
                    type='switch-link'
                )
            self.logger.info(f"Link added: {src.dpid}:{src.port_no} <-> {dst.dpid}:{dst.port_no}")
            self.notify_update()

    def remove_link(self, link):
        src = link.src
        dst = link.dst
        link_key = (src.dpid, src.port_no, dst.dpid, dst.port_no)
        
        if link_key in self.links:
            self.links.remove(link_key)
            
            with self.graph_lock:
                src_node = f"switch_{src.dpid}"
                dst_node = f"switch_{dst.dpid}"
                
                if self.graph.has_edge(src_node, dst_node):
                    self.graph.remove_edge(src_node, dst_node)
            self.logger.info(f"Link removed: {src.dpid}:{src.port_no} <-> {dst.dpid}:{dst.port_no}")
            self.notify_update()

    def clean_old_mac_entries(self, dpid, port, new_mac):
        if dpid not in self.switches:
            return
        
        old_mac = None
        if port in self.switches[dpid]['ports']:
            old_mac = self.switches[dpid]['ports'][port].get('mac')
        
        if old_mac and old_mac != new_mac:
            if dpid in self.mac_to_port and old_mac in self.mac_to_port[dpid]:
                del self.mac_to_port[dpid][old_mac]
                self.logger.info(f"Old MAC mapping removed: dpid={dpid}, mac={old_mac}")

        if dpid in self.mac_to_port and new_mac in self.mac_to_port[dpid]:
            current_port = self.mac_to_port[dpid][new_mac]
            if current_port != port:
                self.logger.warning(f"MAC moved from port {current_port} to {port}: {new_mac}")
                if current_port in self.switches[dpid]['ports']:
                    if self.switches[dpid]['ports'][current_port].get('mac') == new_mac:
                        del self.switches[dpid]['ports'][current_port]
                        self.logger.info(f"Old port entry removed: dpid={dpid}, port={current_port}")
                self.mac_to_port[dpid][new_mac] = port

    def add_switch_port(self, dpid, mac, port):
        try:
            self.logger.debug(f"Adding switch port: dpid={dpid}, port={port}, mac={mac}")
            
            # Only update if switch is active
            if dpid not in self.switches or self.switches[dpid].get('status') != 'active':
                self.logger.warning(f"Switch {dpid} is not active, skipping port update")
                return False
                
            self.clean_old_mac_entries(dpid, port, mac)
            
            current_mac = None
            if port in self.switches[dpid]['ports']:
                current_mac = self.switches[dpid]['ports'][port].get('mac')

            if current_mac != mac:
                with self.data_lock:
                    self.switches[dpid]['ports'][port] = {
                        'mac': mac,
                        'status': 'active',
                        'last_seen': time.time()
                    }
                    
                    if dpid not in self.mac_to_port:
                        self.mac_to_port[dpid] = {}
                        
                    self.mac_to_port[dpid][mac] = port
                    self.logger.info(f"Port updated: dpid={dpid}, port={port}, mac={mac}")
                    
                    with self.graph_lock:
                        if f"switch_{dpid}" in self.graph:
                            self.graph.nodes[f"switch_{dpid}"]['port_count'] = len(self.switches[dpid]['ports'])
                
                    self.notify_update()
                    return True
                
            return False
            
        except Exception as e:
            self.logger.error(f"Error adding switch port: {str(e)}")
            return False

    def handle_port_status(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        dpid = msg.datapath.id
        
        self.logger.info(f"Port status change: dpid={dpid} port={port_no} reason={reason}")
        
        if reason == msg.ofproto.OFPPR_ADD:
            self.add_switch_port(dpid, None, port_no)
        elif reason == msg.ofproto.OFPPR_DELETE:
            self.remove_switch_port(dpid, port_no)
        
        self.notify_update()

    def remove_switch_port(self, dpid, port):
        if dpid in self.switches and port in self.switches[dpid]['ports']:
            port_info = self.switches[dpid]['ports'][port]
            mac = port_info.get('mac')
            
            # Remove MAC mapping
            if mac and dpid in self.mac_to_port and mac in self.mac_to_port[dpid]:
                del self.mac_to_port[dpid][mac]
            
            # Remove port from switch
            del self.switches[dpid]['ports'][port]
            
            # Remove from graph
            for node in list(self.graph.nodes):
                if node.startswith(f"switch_{dpid}"):
                    for neighbor in list(self.graph.neighbors(node)):
                        if self.graph[node][neighbor].get('port') == port:
                            self.graph.remove_edge(node, neighbor)
            
            self.logger.info(f"Port removed: dpid={dpid} port={port}")
            return True
        return False

    def add_host_attachment(self, dpid, port, mac, ip):
        try:
            self.logger.info(f"Processing host attachment: {ip}@{mac} on dpid={dpid} port={port}")
            
            # Validate IP address
            ipaddress.ip_address(ip)
            
            # Check if this is a router interface
            for rtr_ip, rtr_info in list(self.router_interfaces.items()):
                if rtr_info['mac'].lower() == mac.lower():
                    rtr_info['status'] = 'active'
                    rtr_info['last_seen'] = time.time()
                    rtr_info['attached_to'] = (dpid, port)
                    self.logger.info(f"Router {rtr_ip} active on switch {dpid} port {port}")
                    self.update_router_in_graph(rtr_ip)
                    return
            
            # Check if this might be a router interface
            if ip.endswith('.1'):
                network = self.find_network_for_ip(ip)
                self.logger.info(f"Router interface identified: {ip} for network {network}")
                
                if ip not in self.router_interfaces:
                    self.router_interfaces[ip] = {
                        'mac': mac,
                        'network': network,
                        'status': 'detected',
                        'last_seen': time.time(),
                        'attached_to': (dpid, port)
                    }
                    self.routes[network] = {
                        'mac': mac,
                        'interface_ip': ip
                    }
                    self.subnets.add(network)
                    self.arp_table[ip] = mac
                    self.update_router_in_graph(ip)
                    return

            # Manage regular hosts
            with self.data_lock:
                changed = False
                if ip in self.hosts:
                    host_info = self.hosts[ip]
                    
                    if host_info['mac'] != mac:
                        host_info['mac'] = mac
                        changed = True
                        
                    if host_info.get('attached_to') != (dpid, port):
                        host_info['attached_to'] = (dpid, port)
                        changed = True
                        
                    host_info['timestamp'] = time.time()
                else:
                    self.hosts[ip] = {
                        'ip': ip,
                        'mac': mac,
                        'timestamp': time.time(),
                        'attached_to': (dpid, port),
                        'is_compromised': False
                    }
                    changed = True
                
                self.arp_table[ip] = mac
                
                with self.graph_lock:
                    host_node = f"host_{ip}"
                    
                    if host_node not in self.graph:
                        self.graph.add_node(
                            host_node,
                            type='host',
                            ip=ip,
                            mac=mac,
                            label=f"Host\n{ip}\n{mac}",
                            last_seen=time.time(),
                            is_compromised=False
                        )
                    
                    switch_node = f"switch_{dpid}"
                    if switch_node in self.graph:
                        for edge in list(self.graph.edges(host_node)):
                            self.graph.remove_edge(*edge)
                        
                        self.graph.add_edge(
                            switch_node,
                            host_node,
                            port=port,
                            type='host-link'
                        )
                
                if changed:
                    action = 'updated' if ip in self.hosts else 'added'
                    self.logger.info(f"Host {action}: {ip} on switch {dpid} port {port}")
                    self.notify_update()
            
        except ValueError as e:
            self.logger.error(f"Invalid IP address {ip}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error adding host attachment: {str(e)}")

    def update_router_in_graph(self, router_ip):
        if router_ip not in self.router_interfaces:
            return
            
        rtr_info = self.router_interfaces[router_ip]
        router_node = f"router_{router_ip}"
        attached_to = rtr_info.get('attached_to')
        status = rtr_info.get('status', 'configured')
        
        with self.graph_lock:
            if router_node not in self.graph:
                self.graph.add_node(
                    router_node,
                    type='router',
                    ip=router_ip,
                    mac=rtr_info['mac'],
                    network=rtr_info['network'],
                    status=status,
                    router_name=rtr_info.get('router_name', 'Unknown'),
                    label=f"Router\n{rtr_info.get('router_name', 'Unknown')}\n{router_ip}\n{rtr_info['mac']}"
                )
            else:
                self.graph.nodes[router_node]['status'] = status
                self.graph.nodes[router_node]['label'] = f"Router\n{rtr_info.get('router_name', 'Unknown')}\n{router_ip}\n{rtr_info['mac']}"
            
            if attached_to:
                dpid, port = attached_to
                switch_node = f"switch_{dpid}"
                
                # Remove old connections
                for neighbor in list(self.graph.neighbors(router_node)):
                    if self.graph[router_node][neighbor].get('type') == 'router-link':
                        self.graph.remove_edge(router_node, neighbor)
                
                # Add new connection
                if switch_node in self.graph:
                    self.graph.add_edge(
                        router_node,
                        switch_node,
                        port=port,
                        type='router-link'
                    )
        
        self.build_router_graph()
        self.calculate_routes()
        self.logger.info(f"Router updated in graph: {router_ip}")

    def update_arp_table(self, ip, mac):
        with self.data_lock:
            if self.arp_table.get(ip) != mac:
                self.arp_table[ip] = mac
                
                if ip in self.hosts:
                    self.hosts[ip]['mac'] = mac
                    self.hosts[ip]['timestamp'] = time.time()
                self.logger.debug(f"ARP updated: {ip} -> {mac}")

    def get_mac_for_ip(self, ip):
        with self.data_lock:
            if ip in self.router_interfaces:
                return self.router_interfaces[ip]['mac']
            
            if ip in self.hosts:
                return self.hosts[ip]['mac']
                
            return self.arp_table.get(ip)

    def get_port_for_mac(self, dpid, mac):
        with self.data_lock:
            if dpid in self.mac_to_port and mac in self.mac_to_port[dpid]:
                return self.mac_to_port[dpid][mac]
            return None

    def build_router_graph(self):
        with self.graph_lock:
            self.router_graph.clear()
            
            for ip, info in self.router_interfaces.items():
                self.router_graph.add_node(ip, **info)
            
            router_groups = defaultdict(list)
            for ip, info in self.router_interfaces.items():
                router_name = info.get('router_name', 'default')
                router_groups[router_name].append(ip)
            
            for router_name, interfaces in router_groups.items():
                if len(interfaces) > 1:
                    for i in range(len(interfaces)):
                        for j in range(i+1, len(interfaces)):
                            self.router_graph.add_edge(
                                interfaces[i], interfaces[j], 
                                cost=0, 
                                type='internal',
                                label=f"{router_name} internal"
                            )
            
            switch_router_map = defaultdict(list)
            for ip, info in self.router_interfaces.items():
                if 'attached_to' in info:
                    dpid, _ = info['attached_to']
                    switch_router_map[dpid].append(ip)
            
            for dpid, routers in switch_router_map.items():
                if len(routers) > 1:
                    for i in range(len(routers)):
                        for j in range(i+1, len(routers)):
                            if not self.router_graph.has_edge(routers[i], routers[j]):
                                self.router_graph.add_edge(
                                    routers[i], routers[j], 
                                    cost=1, 
                                    type='switch',
                                    label=f"Switch {dpid}"
                                )
            
            for (src_dpid, src_port, dst_dpid, dst_port) in self.links:
                src_routers = switch_router_map.get(src_dpid, [])
                dst_routers = switch_router_map.get(dst_dpid, [])
                
                for src_router in src_routers:
                    for dst_router in dst_routers:
                        if not self.router_graph.has_edge(src_router, dst_router):
                            self.router_graph.add_edge(
                                src_router, dst_router,
                                cost=1,
                                type='direct',
                                label=f"Link {src_dpid}-{dst_dpid}"
                            )
            
            self.logger.info(f"Router graph built with {len(self.router_graph.nodes)} nodes and {len(self.router_graph.edges)} edges")

    def update_routing_periodically(self):
        while True:
            time.sleep(self.routing_update_interval)
            self.build_router_graph()
            self.calculate_routes()
            self.logger.info("Routing table updated")

    def calculate_routes(self):
        if len(self.router_graph.nodes) < 2:
            self.logger.debug("Not enough nodes for routing calculation")
            return
            
        new_routing_table = {}
        
        for source in self.router_graph.nodes:
            try:
                paths = nx.single_source_dijkstra_path(self.router_graph, source)
                costs = nx.single_source_dijkstra_path_length(self.router_graph, source)
                
                for dest, path in paths.items():
                    if source == dest:
                        continue
                        
                    if len(path) > 1:
                        next_hop = path[1]
                    else:
                        next_hop = dest
                    
                    new_routing_table[(source, dest)] = {
                        'next_hop': next_hop,
                        'cost': costs[dest],
                        'path': path
                    }
            except Exception as e:
                self.logger.error(f"Routing calculation error: {str(e)}")
        
        self.routing_table = new_routing_table
        self.logger.info(f"Routing table updated with {len(new_routing_table)} entries")

    def get_route(self, src_router, dst_router):
        return self.routing_table.get((src_router, dst_router), {}).get('next_hop')

    def mark_compromised_host(self, ip, attack_type):
        with self.data_lock:
            if ip in self.hosts:
                self.hosts[ip]['is_compromised'] = True
                self.hosts[ip]['attack_type'] = attack_type
                self.logger.warning(f"Host marked as compromised: {ip} ({attack_type})")
                
                # Update graph
                host_node = f"host_{ip}"
                with self.graph_lock:
                    if host_node in self.graph:
                        self.graph.nodes[host_node]['is_compromised'] = True
                        self.graph.nodes[host_node]['attack_type'] = attack_type
                
                self.notify_update()
                
                if self.alert_manager:
                    self.alert_manager.add_compromised_host(ip, attack_type)

    def get_topology(self):
        topology = {
            'nodes': [],
            'edges': [],
            'routing_table': [],
            'stats': self.get_network_stats(),
            'timestamp': time.time()
        }
        
        for (src, dst), info in self.routing_table.items():
            topology['routing_table'].append({
                'source': src,
                'destination': dst,
                'next_hop': info['next_hop'],
                'cost': info['cost'],
                'path': info['path']
            })
        
        for ip, info in self.router_interfaces.items():
            status = info.get('status', 'configured')
            topology['nodes'].append({
                'id': f"router_{ip}",
                'type': 'router',
                'ip': ip,
                'mac': info['mac'],
                'network': info['network'],
                'status': status,
                'router_name': info.get('router_name', 'Unknown'),
                'label': f"Router\n{info.get('router_name', 'Unknown')}\n{ip}\n{info['mac']}",
            })
        
        for dpid, info in self.switches.items():
            port_details = []
            for port_id, port_info in info.get('ports', {}).items():
                port_details.append({
                    'port_id': port_id,
                    'mac': port_info.get('mac', ''),
                    'status': port_info.get('status', 'Unknown')
                })
            
            topology['nodes'].append({
                'id': f"switch_{dpid}",
                'type': 'switch',
                'dpid': dpid,
                'mac': info.get('mac', ''),
                'label': f"Switch\n{dpid}\n{info.get('mac', '')}",
                'status': info.get('status', 'Unknown'),
                'port_count': len(info.get('ports', {})),
                'ports': port_details,
                'last_seen': info.get('last_seen', 0)
            })
        
        current_time = time.time()
        for ip, info in self.hosts.items():
            if current_time - info['timestamp'] <= self.host_timeout:
                topology['nodes'].append({
                    'id': f"host_{ip}",
                    'type': 'host',
                    'ip': ip,
                    'mac': info.get('mac', 'Unknown'),
                    'label': f"Host\n{ip}\n{info.get('mac', 'Unknown')}",
                    'last_seen': info.get('timestamp', 0),
                    'is_compromised': info.get('is_compromised', False),
                    'attack_type': info.get('attack_type', '')
                })
        
        for (src_dpid, src_port, dst_dpid, dst_port) in self.links:
            topology['edges'].append({
                'source': f"switch_{src_dpid}",
                'target': f"switch_{dst_dpid}",
                'src_port': src_port,
                'dst_port': dst_port,
                'type': 'Switch Link'
            })
        
        for ip, info in self.hosts.items():
            if info.get('attached_to'):
                dpid, port = info['attached_to']
                topology['edges'].append({
                    'source': f"switch_{dpid}",
                    'target': f"host_{ip}",
                    'port': port,
                    'type': 'Host Link'
                })
        
        for ip, info in self.router_interfaces.items():
            if info.get('attached_to'):
                dpid, port = info['attached_to']
                topology['edges'].append({
                    'source': f"switch_{dpid}",
                    'target': f"router_{ip}",
                    'port': port,
                    'type': 'Router Link'
                })
        
        return topology

    def get_network_stats(self):
        active_routers = sum(1 for r in self.router_interfaces.values() 
                             if r.get('status') == 'active')
        
        active_switches = sum(1 for s in self.switches.values()
                              if s.get('status') == 'active')
        
        current_time = time.time()
        active_hosts = sum(1 for h in self.hosts.values()
                           if current_time - h['timestamp'] <= self.host_timeout)
        
        compromised_hosts = sum(1 for h in self.hosts.values()
                               if h.get('is_compromised', False))
        
        return {
            'routers': len(self.router_interfaces),
            'active_routers': active_routers,
            'switches': len(self.switches),
            'active_switches': active_switches,
            'hosts': len(self.hosts),
            'active_hosts': active_hosts,
            'compromised_hosts': compromised_hosts,
            'links': len(self.links),
            'nodes': len(self.graph.nodes),
            'edges': len(self.graph.edges),
            'switch_count': self.switch_count
        }

    def visualize_topology(self, output_path='topology.png'):
        try:
            plt.figure(figsize=(12, 8))
            plt.axis('off')
            
            with self.graph_lock:
                pos = nx.spring_layout(self.graph, k=0.5, iterations=50, seed=42)
                
                node_colors = []
                node_sizes = []
                node_labels = {}
                
                for node, data in self.graph.nodes(data=True):
                    node_type = data.get('type', 'unknown')
                    status = data.get('status', 'unknown')
                    
                    if node_type == 'router':
                        if status == 'active':
                            node_colors.append('#4CAF50')  # Green
                        else:
                            node_colors.append('#FF6B6B')  # Red
                        node_sizes.append(800)
                        node_labels[node] = data.get('label', node)
                    elif node_type == 'switch':
                        if status == 'active':
                            node_colors.append('#4ECDC4')  # Turquoise
                        else:
                            node_colors.append('#AAAAAA')  # Gray for inactive
                        node_sizes.append(600)
                        node_labels[node] = data.get('label', node)
                    elif node_type == 'host':
                        if data.get('is_compromised', False):
                            node_colors.append('#FF5252')  # Light red
                        else:
                            node_colors.append('#FFD166')  # Yellow
                        node_sizes.append(400)
                        node_labels[node] = data.get('label', node)
                    else:
                        node_colors.append('#999999')  # Gray
                        node_sizes.append(300)
                        node_labels[node] = node
                
                nx.draw_networkx_nodes(
                    self.graph, pos,
                    node_size=node_sizes,
                    node_color=node_colors,
                    alpha=0.9,
                    edgecolors='black',
                    linewidths=1
                )
                
                # Calculate edge widths based on traffic
                edge_widths = []
                for u, v, data in self.graph.edges(data=True):
                    bandwidth = 0
                    if data.get('type') == 'switch-link' and self.qos_manager:
                        try:
                            src_dpid = int(u.split('_')[1])
                            src_port = data.get('src_port')
                            dst_dpid = int(v.split('_')[1])
                            dst_port = data.get('dst_port')
                            
                            if src_dpid and src_port:
                                src_stats = self.qos_manager.bandwidth_stats.get(str(src_dpid), {}).get(str(src_port), {})
                                src_bw = src_stats.get('rx_rate', 0) + src_stats.get('tx_rate', 0)
                            
                            if dst_dpid and dst_port:
                                dst_stats = self.qos_manager.bandwidth_stats.get(str(dst_dpid), {}).get(str(dst_port), {})
                                dst_bw = dst_stats.get('rx_rate', 0) + dst_stats.get('tx_rate', 0)
                            
                            bandwidth = min(src_bw, dst_bw) if src_bw and dst_bw else 0
                        except:
                            pass
                    
                    # Scale bandwidth to line width (1-10)
                    width = 1 + min(bandwidth / 100, 9)  # 100 Mbps = max width
                    edge_widths.append(width)
                
                nx.draw_networkx_edges(
                    self.graph, pos,
                    width=edge_widths,
                    alpha=0.6,
                    edge_color='#555555'
                )
                
                nx.draw_networkx_labels(
                    self.graph, pos,
                    labels=node_labels,
                    font_size=9,
                    font_weight='bold'
                )
                
                edge_labels = {}
                for (u, v, data) in self.graph.edges(data=True):
                    if 'port' in data:
                        edge_labels[(u, v)] = f"Port: {data['port']}"
                    elif 'src_port' in data and 'dst_port' in data:
                        edge_labels[(u, v)] = f"{data['src_port']}↔{data['dst_port']}"
                
                nx.draw_networkx_edge_labels(
                    self.graph, pos,
                    edge_labels=edge_labels,
                    font_size=8,
                    bbox=dict(alpha=0.8)
                )
                
                stats = self.get_network_stats()
                plt.title(
                    f"Network Topology\n"
                    f"Routers: {stats['active_routers']}/{stats['routers']} | "
                    f"Switches: {stats['active_switches']}/{stats['switches']} | "
                    f"Hosts: {stats['active_hosts']}/{stats['hosts']} | "
                    f"Compromised: {stats['compromised_hosts']} | "
                    f"Links: {stats['links']}",
                    fontsize=12
                )
            
            plt.tight_layout()
            plt.savefig(output_path, format='png', dpi=100, bbox_inches='tight')
            plt.close()
            return output_path
        except Exception as e:
            self.logger.error(f"Visualization error: {str(e)}")
            return None
    
    def calculate_topology_hash(self):
        topology_data = json.dumps(self.get_topology(), sort_keys=True)
        return hashlib.md5(topology_data.encode()).hexdigest()

