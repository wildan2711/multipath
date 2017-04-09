from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, arp, ipv6
from ryu.lib.packet import ether_types
from ryu.lib import mac, hub, ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from collections import defaultdict
from requests import get
from subprocess import check_output
from thread import start_new_thread
from operator import itemgetter
import logging
import socket
import time
import os
import shlex
import json
import re
import random

from datetime import datetime

byte = defaultdict(lambda: 0)
clock = defaultdict(lambda: 0)
thr = defaultdict(lambda: defaultdict(lambda: 0))

# switches
switches = defaultdict(dict)

# myhost[srcmac]->(switch, port)
mymac = {}

topology_map = defaultdict(dict)

min_route = defaultdict(dict)

# adjacency map [sw1][sw2]->port from sw1 to sw2
adjacency = defaultdict(dict)

multipath_group_ids = {}

group_ids = []

# Reference bandwidth = 1 Gbps
REFERENCE_BW = 10000000

# Switch capacity = 100 Gbps
SWITCH_CAPACITY = 100000000000

MAX_EXTRA_SWITCH = 1

MAX_PATHS = 3

# Ip address of sFlow collector
collector = '127.0.0.1'

def getIfInfo(ip):
    '''
    Get interface name of ip address (collector)
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ip, 0))
    ip = s.getsockname()[0]
    ifconfig = check_output(['ifconfig'])
    ifs = re.findall(r'^(\S+).*?inet addr:(\S+).*?', ifconfig, re.S | re.M)
    for entry in ifs:
        if entry[1] == ip:
            return entry

def init_sflow(ifname, collector, sampling, polling):
    '''
    Initialise sFlow for monitoring traffic
    '''
    cmd = shlex.split('ip link show')
    out = check_output(cmd)
    info = re.findall('(\d+): ((s[0-9]+)-eth([0-9]+))', out)

    sflow = 'ovs-vsctl -- --id=@sflow create sflow agent=%s target=\\"%s\\" sampling=%s polling=%s --' % (
        ifname, collector, sampling, polling)

    for ifindex, ifname, switch, port in info:
        if int(switch[1:]) in switches:
            switches[int(switch[1:])]['ports'][int(port)] = {
                'ifindex' : ifindex,
                'ifname' : ifname,
                'bandwidth' : 10000000
            }
            sflow += ' -- set bridge %s sflow=@sflow' % switch

    print sflow
    os.system(sflow)

    hub.spawn_after(0.1, measure_link)

def measure_link():
    '''
    Measure outgoing traffic per second for all switch ports
    '''
    while True:
        try:
            for switch in switches:
                for port in switches[switch]['ports']:
                    url = 'http://' + collector + ':8008/metric/' + \
                        collector + '/' + switches[switch]['ports'][port]['ifindex'] + \
                        '.ifoutoctets/json'
                    r = get(url)
                    response = r.json()
                    # print response
                        # Bps to Kbps
                    thr[switch][port] = response[0]['metricValue'] * 8 / 1000
                    # print switch,thr[switch]
        except:
            pass
        hub.sleep(1)


def path_cost(route):
    cost = 0
    for s, p in route:
        for i in thr[s]:
            cost += thr[s][i]
    return cost


def measure_path(thread):
    while True:
        for src in topology_map.keys():
            for dst in topology_map[src].keys():
                try:
                    min_route[src][dst] = min(
                        topology_map[src][dst], key=path_cost)
                except KeyError:
                    pass
        time.sleep(0.1)

def get_paths(src, dst):
    '''
    Get all paths from src to dst using DFS algorithm    
    '''
    paths = []
    stack = [(src, [src])]
    while stack:
        (node, path) = stack.pop()
        for next in set(adjacency[node].keys()) - set(path):
            if next is dst:
                paths.append(path + [next])
            else:
                stack.append((next, path + [next]))
    print "Available paths from ", src, " to ", dst, " : ", paths
    return paths

def get_link_cost(s1, s2):
    '''
    Get the link cost between two switches 
    '''
    traffic = 0
    e1 = adjacency[s1][s2]
    e2 = adjacency[s2][s1]
    bl = min(switches[s1]['ports'][e1]['bandwidth'], switches[s2]['ports'][e2]['bandwidth'])
    print bl, thr[s2][e1]
    ew = REFERENCE_BW/(bl - thr[s2][e1])
    return ew

def get_path_cost(path):
    '''
    Get the path cost
    '''
    cost = 0
    for i in range(len(path)-1):
        cost += get_link_cost(path[i], path[i+1])
    return cost

def get_optimal_paths(src, dst):
    '''
    Get the n-most optimal paths according to MAX_PATHS
    '''
    paths = get_paths(src, dst)
    paths_count = len(paths) if len(
        paths) < MAX_PATHS else MAX_PATHS
    return sorted(paths, key=lambda x: get_path_cost(x))[0:(paths_count)]

def add_ports_to_paths(paths, first_port, last_port):
    '''
    Add the ports that connects the switches for all paths
    '''
    paths_p = []
    for path in paths:
        p = {}
        in_port = first_port
        for s1, s2 in zip(path[:-1], path[1:]):
            out_port = adjacency[s1][s2]
            p[s1] = (in_port, out_port)
            in_port = adjacency[s2][s1]
        p[path[-1]] = (in_port, last_port)
        paths_p.append(p)
    return paths_p

def generate_openflow_gid():
    '''
    Returns a random OpenFlow group id
    '''
    n = random.randint(0, 2**32)
    while n in group_ids:
        n = random.randint(0, 2**32)
    return n


class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        self.arp_table = {}
        self.sw = {}

    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst, mac_src, mac_dst):
        computation_start = time.time()
        if src is dst: # if destination is in the same switch
            paths = [[src]]
        else:
            paths = get_optimal_paths(src, dst)
        pw = []
        for path in paths:
            pw.append(get_path_cost(path))
            print path, "cost = ", pw[len(pw) - 1]
        sum_of_pw = sum(pw)
        paths_with_ports = add_ports_to_paths(paths, first_port, last_port)
        switches_in_paths = set().union(*paths)

        for node in switches_in_paths:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            ports = {}
            actions = []
            i = 0

            for path in paths_with_ports:
                if node in path:
                    in_port = path[node][0]
                    out_port = path[node][1]
                    if in_port in ports:
                        ports[in_port].append((out_port, pw[i]))
                    else:
                        ports[in_port] = [(out_port, pw[i])]
                i += 1

            for in_port in ports:

                match_ip = ofp_parser.OFPMatch(
                    in_port=in_port, 
                    eth_type=0x0800, 
                    ipv4_src=ip_src, 
                    ipv4_dst=ip_dst
                )
                match_arp = ofp_parser.OFPMatch(
                    in_port=in_port, 
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )

                out_ports = ports[in_port]

                if len(out_ports) > 1:
                    group_id = None
                    group_new = False

                    if (node, src, dst) not in multipath_group_ids:
                        group_new = True
                        multipath_group_ids[
                            node, src, dst] = generate_openflow_gid()
                    group_id = multipath_group_ids[node, src, dst]

                    buckets = []
                    # print "node at ",node," out ports : ",out_ports
                    for port, weight in out_ports:
                        bucket_weight = 0
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                watch_port=port,
                                watch_group=ofp.OFPG_ANY,
                                actions=bucket_action
                            )
                        )
                    # If GROUP Was new, we send a GROUP_ADD
                    if group_new:
                        # print 'GROUP_ADD for %s from %s to %s GROUP_ID %d out_rules %s' % (node, src, dst, group_id, buckets)

                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id,
                            buckets
                        )
                        dp.send_msg(req)

                    # If the GROUP already existed, we send a GROUP_MOD to
                    # eventually adjust the buckets with current link
                    # utilization
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_FF,
                            group_id, buckets)
                        dp.send_msg(req)
                        # print 'GROUP_MOD for %s from %s to %s GROUP_ID %d out_rules %s' % (node, src, dst, group_id, buckets)

                    actions = [ofp_parser.OFPActionGroup(group_id)]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)

                # Sending OUTPUT Rules
                elif len(out_ports) == 1:
                    # print 'Match for %s from %s to %s out_ports %d' % (node, src, dst, out_ports[0])
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)
        print "Path installation finished in ", time.time() - computation_start 

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
        try:
            for p in ev.msg.body:
                if p.port_no in switches[switch.id]['ports']:
                    switches[switch.id]['ports'][p.port_no]["bandwidth"] = p.curr_speed
        # Resend request if reply arrives while initializing
        except RuntimeError: 
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)
        print switches

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
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if src not in mymac.keys():
            mymac[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        if dst in mymac.keys():
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
                if arp_pkt:
                    ip_src = arp_pkt.src_ip  
                    ip_dst = arp_pkt.dst_ip  
                    self.install_paths(mymac[src][0], mymac[src][1], mymac[dst][
                                        0], mymac[dst][1], ip_src, ip_dst, src, dst)
                    self.install_paths(mymac[dst][0], mymac[dst][1], mymac[src][
                                        0], mymac[src][1], ip_dst, ip_src, dst, src)
                    self.arp_table[ip_src] = src
                    self.arp_handler(msg)

        # if dst is mac.BROADCAST_STR:
        #     self.arp_handler(msg)

        # print pkt

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

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
        if switch.id not in switches:
            switches[switch.id]['ports'] = defaultdict(dict)
            switches[switch.id]['capacity'] = SWITCH_CAPACITY # 100 Gbps
            self.datapath_list[switch.id] = switch
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

        if switches:
            (ifname, agent) = getIfInfo(collector)
            logging.getLogger("requests").setLevel(logging.WARNING)
            logging.getLogger("urllib3").setLevel(logging.WARNING)
            init_sflow(ifname, collector, 10, 10)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, event):
        print event
        switch = event.switch.dp.id
        if switch in switches:
            del switches[switch]
            del self.datapath_list[switch]
            del adjacency[switch]

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, event):
        s1 = event.link.src
        s2 = event.link.dst
        adjacency[s1.dpid][s2.dpid] = s1.port_no
        adjacency[s2.dpid][s1.dpid] = s2.port_no

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, event):
        return

    def arp_handler(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth:
            eth_dst = eth.dst
            eth_src = eth.src

        # Break the loop for avoiding ARP broadcast storm
        if eth_dst == mac.BROADCAST_STR:  # and arp_pkt:
            arp_dst_ip = arp_pkt.dst_ip
            arp_src_ip = arp_pkt.src_ip

            if (datapath.id, arp_src_ip, arp_dst_ip) in self.sw:
                # packet come back at different port.
                if self.sw[(datapath.id, arp_src_ip, arp_dst_ip)] != in_port:
                    datapath.send_packet_out(in_port=in_port, actions=[])
                    return True
            else:
                # self.sw.setdefault((datapath.id, eth_src, arp_dst_ip), None)
                self.sw[(datapath.id, arp_src_ip, arp_dst_ip)] = in_port
                print self.sw
                self.mac_to_port.setdefault(datapath.id, {})
                self.mac_to_port[datapath.id][eth_src] = in_port

        # Try to reply arp request
        if arp_pkt:
            if arp_pkt.opcode == arp.ARP_REQUEST:
                hwtype = arp_pkt.hwtype
                proto = arp_pkt.proto
                hlen = arp_pkt.hlen
                plen = arp_pkt.plen
                arp_src_ip = arp_pkt.src_ip
                arp_dst_ip = arp_pkt.dst_ip
                if arp_dst_ip in self.arp_table:
                    actions = [parser.OFPActionOutput(in_port)]
                    ARP_Reply = packet.Packet()

                    ARP_Reply.add_protocol(ethernet.ethernet(
                        ethertype=eth.ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    ARP_Reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    ARP_Reply.serialize()

                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=ARP_Reply.data)
                    datapath.send_msg(out)
                    print "ARP_Reply"
                    return True
        return False
