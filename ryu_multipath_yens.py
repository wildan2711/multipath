from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import in_proto
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.lib import hub
from ryu.lib import ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event

from collections import defaultdict
from operator import itemgetter

import os
import random
import time

# Cisco Reference bandwidth = 1 Gbps
REFERENCE_BW = 10000000

DEFAULT_BW = 10000000

MAX_PATHS = float('Inf')

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        self.arp_table = {}
        self.switches = []
        self.hosts = {}
        self.multipath_group_ids = {}
        self.group_ids = []
        self.adjacency = defaultdict(dict)
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: DEFAULT_BW))

        # Fake addresses only known to the controller
        self.controller_ip = "10.0.0.100"
        self.controller_mac = "dd:dd:dd:dd:dd:df"
        self.ping_mac = "de:dd:dd:dd:de:dd"
        self.ping_ip = "10.0.0.99"
        self.delay = defaultdict(lambda: defaultdict(lambda: 0))

        self.replied = []

    def monitor_link(self, s1, s2):
        '''
            Monitors link latency between two switches.
            Sends ping packet every 0.5 second.
        '''
        while True:
            self.send_ping_packet(s1, s2)

            hub.sleep(0.5)

        self.logger.info('Stop monitoring link %s %s' % (s1.dpid, s2.dpid))

    def monitor_link_controller(self, s1):
        '''
            Monitors link latency between two switches.
            Sends ping packet every 0.5 second.
        '''
        while True:
            self.send_ping_packet_controller(s1)

            hub.sleep(0.5)


    def send_ping_packet_controller(self, s1):
        '''
            Send a ping/ICMP packet between two switches.
            Uses ryu's packet library.
            Uses a fake MAC and IP address only known to controller.
        '''
        datapath = s1
        dst_mac = self.ping_mac
        dst_ip = self.ping_ip
        out_port = datapath.ofproto.OFPP_CONTROLLER
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_IP,
                                           src=self.controller_mac,
                                           dst=dst_mac))
        pkt.add_protocol(ipv4.ipv4(proto=in_proto.IPPROTO_ICMP,
                                   src=self.controller_ip,
                                   dst=dst_ip))
        echo_payload = '%s;%s;%f' % (s1.id, 0, time.time())
        payload = icmp.echo(data=echo_payload)
        pkt.add_protocol(icmp.icmp(data=payload))
        pkt.serialize()

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            data=pkt.data,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions
        )

        datapath.send_msg(out)

    def send_ping_packet(self, s1, s2):
        '''
            Send a ping/ICMP packet between two switches.
            Uses ryu's packet library.
            Uses a fake MAC and IP address only known to controller.
        '''
        datapath = self.datapath_list[int(s1.dpid)]
        dst_mac = self.ping_mac
        dst_ip = self.ping_ip
        out_port = s1.port_no
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_IP,
                                           src=self.controller_mac,
                                           dst=dst_mac))
        pkt.add_protocol(ipv4.ipv4(proto=in_proto.IPPROTO_ICMP,
                                   src=self.controller_ip,
                                   dst=dst_ip))
        echo_payload = '%s;%s;%f' % (s1.dpid, s2.dpid, time.time())
        payload = icmp.echo(data=echo_payload)
        pkt.add_protocol(icmp.icmp(data=payload))
        pkt.serialize()

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            data=pkt.data,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions
        )

        datapath.send_msg(out)

    def ping_packet_handler(self, pkt):
        '''
            Handler function when ping packet arrives.
            Extracts the data from the packet and calculates the latency.
        '''
        icmp_packet = pkt.get_protocol(icmp.icmp)
        echo_payload = icmp_packet.data
        payload = echo_payload.data
        info = payload.split(';')
        s1 = info[0]
        s2 = info[1]
        latency = (time.time() - float(info[2])) * 1000  # in ms
        # print "s%s to s%s latency = %f ms" % (s1, s2, latency)
        self.delay[int(s1)][int(s2)] = latency
    
    def minimum_distance(self, distance, Q):
        min = float('Inf')
        node = 0
        for v in Q:
            if distance[v] < min:
                min = distance[v]
                node = v
        return node

    def path(self, previous, node_start, node_end):
        r=[]
        p=node_end
        r.append(p)
        q=previous[p]
        while q is not None:
            if q == node_start:
                r.append(q)
                break
            p=q
            r.append(p)
            q=previous[p]
    
        r.reverse()
        if node_start==node_end:
            path=[node_start]
        else:
            path=r
        return r
    
    def dijkstra(self,graph, node_start, node_end=None):
        distances = {}     
        previous = {}  
    
        distances = defaultdict(lambda: float('Inf'))
        previous = defaultdict(lambda: None)
    
        distances[node_start]=0
        Q=set(switches)
    
        while len(Q)>0:
            u = minimum_distance(distances, Q)
            Q.remove(u)  
    
            for p in switches:
                if graph[u][p]!=None:
                    w = delay[u][p] 
                    if distances[u] + w < distances[p]:
                        distances[p] = distances[u] + w
                        previous[p] = u
    
        if node_end:
            return {'cost': distances[node_end],
                    'path': path(previous, node_start, node_end)}
        else:
            return (distances, previous)
    
    def get_paths(self, src,dst,first_port,final_port,max_k=2):
        print "YenKSP is called"
        print "src=",src," dst=",dst, " first_port=", first_port, " final_port=", final_port, " max_k=", max_k 
        adjacency2=defaultdict(lambda:defaultdict(lambda:None))
        
        distances, previous = dijkstra(self.adjacency,src)
        A = [{'cost': distances[dst],
                'path': path(previous, src, dst)}]
        B = []
        #print "distances=", distances
        #print  "previous=", previous
        #print "A=", A
        
        if not A[0]['path']: return A
        
        try:
            for k in range(1, max_k):
                adjacency2=copy.deepcopy(self.adjacency)
                #print "k=", k, " adjacency2=", adjacency2
                for i in range(0, len(A[-1]['path']) - 1):
                    node_spur = A[-1]['path'][i]
                    path_root = A[-1]['path'][:i+1]
                #print "node_spur=", node_spur, " path_root=", path_root
            
                    for path_k in A:
                        curr_path = path_k['path']
                #print "curr_path=", curr_path, " i=", i
                        if len(curr_path) > i and path_root == curr_path[:i+1]:
                            adjacency2[curr_path[i]][curr_path[i+1]]=None
                #print "link[", curr_path[i],"][", curr_path[i+1], "] is removed"
                
                    path_spur = dijkstra(adjacency2, node_spur, dst)
            #print "path_spur=", path_spur
        
                    if path_spur['path']:
                        path_total = path_root[:-1] + path_spur['path']
                #print "path_total=", path_total
                        dist_total = distances[node_spur] + path_spur['cost']
                #print "dist_total=", path_total
                        potential_k = {'cost': dist_total, 'path': path_total}
                #print "potential_k=", potential_k
        
                        if not (potential_k in B):
                            B.append(potential_k)
                #print "B=", B
        
                if len(B):
                    B = sorted(B, key=itemgetter('cost'))
                #print "after sorting, B=", B
                    A.append(B[0])
                    B.pop(0)
            #print "after poping out the first element, B=", B, " A=", A
                else:
                    break
        except:
            pass
    
        tmp=[]
        print "YenKSP->"
        for path_k in A:
            print path_k
            tmp.append(path_k)
    
        return map(lambda x: x['path'], A)

    def get_link_cost(self, s1, s2):
        '''
        Get the link cost between two switches 
        '''
        e1 = self.adjacency[s1][s2]
        e2 = self.adjacency[s2][s1]
        bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
        ew = REFERENCE_BW/bl
        return ew

    def get_path_cost(self, path):
        '''
        Get the path cost
        '''
        cost = 0
        for i in range(len(path) - 1):
            cost += self.get_link_cost(path[i], path[i+1])
        return cost

    def get_optimal_paths(self, src, dst):
        '''
        Get the n-most optimal paths according to MAX_PATHS
        '''
        paths = self.get_paths(src, dst)
        paths_count = len(paths) if len(
            paths) < MAX_PATHS else MAX_PATHS
        return sorted(paths, key=lambda x: self.get_path_cost(x))[0:(paths_count)]

    def add_ports_to_paths(self, paths, first_port, last_port):
        '''
        Add the ports that connects the switches for all paths
        '''
        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = self.adjacency[s1][s2]
                p[s1] = (in_port, out_port)
                in_port = self.adjacency[s2][s1]
            p[path[-1]] = (in_port, last_port)
            paths_p.append(p)
        return paths_p

    def generate_openflow_gid(self):
        '''
        Returns a random OpenFlow group id
        '''
        n = random.randint(0, 2**32)
        while n in self.group_ids:
            n = random.randint(0, 2**32)
        return n


    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        computation_start = time.time()
        paths = self.get_paths(src, dst)
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path))
            print path, "cost = ", pw[len(pw) - 1]
        sum_of_pw = sum(pw)
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        switches_in_paths = set().union(*paths)

        for node in switches_in_paths:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            ports = defaultdict(list)
            actions = []
            i = 0

            for path in paths_with_ports:
                if node in path:
                    in_port = path[node][0]
                    out_port = path[node][1]
                    if (out_port, pw[i]) not in ports[in_port]:
                        ports[in_port].append((out_port, pw[i]))
                i += 1

            for in_port in ports:

                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_src=ip_src, 
                    ipv4_dst=ip_dst
                )
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )

                out_ports = ports[in_port]
                print out_ports 

                if len(out_ports) > 1:
                    group_id = None
                    group_new = False

                    if (node, src, dst) not in self.multipath_group_ids:
                        group_new = True
                        self.multipath_group_ids[
                            node, src, dst] = self.generate_openflow_gid()
                    group_id = self.multipath_group_ids[node, src, dst]

                    buckets = []
                    # print "node at ",node," out ports : ",out_ports
                    for port, weight in out_ports:
                        bucket_weight = int(round((1 - weight/sum_of_pw) * 10))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                watch_port=port,
                                watch_group=ofp.OFPG_ANY,
                                actions=bucket_action
                            )
                        )

                    if group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id,
                            buckets
                        )
                        dp.send_msg(req)
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                            group_id, buckets)
                        dp.send_msg(req)

                    actions = [ofp_parser.OFPActionGroup(group_id)]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)

                elif len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)
        print "Path installation finished in ", time.time() - computation_start 
        return paths_with_ports[0][src][1]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # print "Adding flow ", match, actions
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        print "switch_features_handler is called"
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        for p in ev.msg.body:
            self.bandwidths[switch.id][p.port_no] = p.curr_speed

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        # avoid broadcast from LLDP
        if eth.ethertype == 35020:
            return

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if dst == self.ping_mac:
            # ping packet arrives
            self.ping_packet_handler(pkt)
            return

        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        if arp_pkt:
            # print dpid, pkt
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                h1 = self.hosts[src]
                h2 = self.hosts[dst]
                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]
                    out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                    self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse

        print pkt

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, event):
        switch = event.switch.dp
        ofp_parser = switch.ofproto_parser

        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch

            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)
            hub.spawn(self.monitor_link_controller, switch)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, event):
        print event
        switch = event.switch.dp.id
        if switch in self.switches:
            del self.switches[switch]
            del self.datapath_list[switch]
            del self.adjacency[switch]

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, event):
        s1 = event.link.src
        s2 = event.link.dst
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no
        hub.spawn(self.monitor_link, s1, s2)

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, event):
        return
