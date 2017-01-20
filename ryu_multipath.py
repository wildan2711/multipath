from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, arp
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
switches = []

switch_info = defaultdict(dict)

# myhost[srcmac]->(switch, port)
mymac = {}

topology_map = defaultdict(dict)

min_route = defaultdict(dict)

# adjacency map [sw1][sw2]->port from sw1 to sw2
adjacency = defaultdict(dict)

multipath_group_ids = {}

group_ids = []

collector = '127.0.0.1'

MAX_EXTRA_SWITCH = 1

MAX_PATHS = 2

# get interface name of ip address (collector)


def getIfInfo(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ip, 0))
    ip = s.getsockname()[0]
    ifconfig = check_output(['ifconfig'])
    ifs = re.findall(r'^(\S+).*?inet addr:(\S+).*?', ifconfig, re.S | re.M)
    for entry in ifs:
        if entry[1] == ip:
            return entry


def measure_link(thread):
    # every second, we measure the incoming bytes for each port of the switch
    while True:
        for switch in switches:
            for ifindex in switch_info[switch]['ifindex']:
                url = 'http://' + collector + ':8008/metric/' + \
                    collector + '/' + ifindex + '.ifoutoctets/json'
                r = get(url)
                response = r.json()
                # print response
                try:
                    thr[switch][ifindex] = response[0]['metricValue']
                except KeyError:
                    pass
                # print switch,thr[switch]
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
    # Depth-first search, find all paths from src to dst
    try:
        if topology_map[src][dst]:
            return
    except KeyError:
        paths = []
        stack = [(src, [src])]
        while stack:
            (node, path) = stack.pop()
            for next in set(adjacency[node].keys()) - set(path):
                if next is dst:
                    paths.append(path + [next])
                else:
                    stack.append((next, path + [next]))
        topology_map[src][dst] = paths
        print "Jalur yg tersedia dari ", src, " ", dst, " : ", topology_map[src][dst]


def get_link_cost(s1, s2):
    return


def get_optimal_paths(src, dst):
    get_paths(src, dst)
    paths_count = len(topology_map[src][dst]) if len(
        topology_map[src][dst]) < MAX_PATHS else MAX_PATHS
    return sorted(topology_map[src][dst], key=lambda x: len(x))[0:(paths_count)]


def add_ports_to_paths(paths, first_port, last_port):
    # Add the ports that connects the switches for all paths
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

    # Handy function that lists all attributes in the given object
    def ls(self, obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))

    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst, mac_src, mac_dst):
        # print src," ", dst," ", last_port," ", mac_src," ", mac_dst
        paths = get_optimal_paths(src, dst)
        paths_with_ports = add_ports_to_paths(paths, first_port, last_port)
        print paths_with_ports
        switches_in_paths = set().union(*paths)

        for node in switches_in_paths:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            ports = {}
            actions = []

            for path in paths_with_ports:
                if node in path:
                    in_port = path[node][0]
                    out_port = path[node][1]
                    if in_port in ports:
                        ports[in_port].append(out_port)
                    else:
                        ports[in_port] = [out_port]

            for in_port in ports:

                match_ip = ofp_parser.OFPMatch(
                    in_port=in_port, eth_type=0x0800, ipv4_src=ip_src, ipv4_dst=ip_dst)
                match_arp = ofp_parser.OFPMatch(
                    in_port=in_port, 
                    eth_type=0x0806, 
                    arp_sha=mac_src, 
                    arp_tha=mac_dst
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
                    for port in out_ports:
                        bucket_weight = 50
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                actions=bucket_action
                            )
                        )
                    # If GROUP Was new, we send a GROUP_ADD
                    if group_new:
                        print 'GROUP_ADD for %s from %s to %s GROUP_ID %d out_rules %s' % (node, src, dst, group_id, buckets)

                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id,
                            buckets
                        )
                        dp.send_msg(req)

                    # If the GROUP already existed, we send a GROUP_MOD to
                    # eventually adjust the buckets with current link
                    # utilization
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                            group_id, buckets)
                        dp.send_msg(req)
                        print 'GROUP_MOD for %s from %s to %s GROUP_ID %d out_rules %s' % (node, src, dst, group_id, buckets)

                    actions = [ofp_parser.OFPActionGroup(group_id)]

                    inst = [ofp_parser.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS, actions)]
                    mod_ip = ofp_parser.OFPFlowMod(
                        datapath=dp, match=match_ip, idle_timeout=0, hard_timeout=0,
                        priority=32768, instructions=inst)
                    mod_arp = ofp_parser.OFPFlowMod(
                        datapath=dp, match=match_arp, idle_timeout=0, hard_timeout=0,
                        priority=1, instructions=inst)
                    dp.send_msg(mod_ip)
                    dp.send_msg(mod_arp)

                    # Sending OUTPUT Rules
                elif len(out_ports) == 1:
                    print 'Match for %s from %s to %s out_ports %d' % (node, src, dst, out_ports[0])
                    actions = [ofp_parser.OFPActionOutput(out_ports[0])]

                    inst = [ofp_parser.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS, actions)]
                    mod_ip = ofp_parser.OFPFlowMod(
                        datapath=dp, match=match_ip, idle_timeout=0, hard_timeout=0,
                        priority=32768, instructions=inst)
                    mod_arp = ofp_parser.OFPFlowMod(
                        datapath=dp, match=match_arp, idle_timeout=0, hard_timeout=0,
                        priority=1, instructions=inst)
                    dp.send_msg(mod_ip)
                    dp.send_msg(mod_arp)

    def _request_port_stats(self, switch):
        '''
        Request port statistic to a switch
        '''
        self.logger.debug(
            'Request port stats for dp %s at t: %f',
            switch.dp.id, time.time()
        )
        ofproto = switch.dp.ofproto
        parser = switch.dp.ofproto_parser
        req = parser.OFPPortStatsRequest(switch.dp, 0, ofproto.OFPP_ANY)
        switch.dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        '''
        Handles a PORT STATS response from a switch
        '''
        ports = ev.msg.body
        port_stats_reply_time = time.time()

        # Calculate switch-controller RTT
        switch = self.topo_shape.dpid_to_switch[ev.msg.datapath.id]
        switch.calculate_delay_to_controller(port_stats_reply_time)

        sorted_port_table = sorted(ports, key=lambda l: l.port_no)
        for stat in sorted_port_table:
            if stat.port_no not in switch.ports:
                continue
            port = switch.ports[stat.port_no]
            utilization = stat.tx_bytes + stat.rx_bytes

            if port.last_request_time:
                timedelta = port_stats_reply_time - port.last_request_time
                datadelta = utilization - port.last_utilization_value

                utilization_bps = datadelta / timedelta
                port.capacity = port.max_capacity - utilization_bps
                self.logger.debug('p %d s %s utilization %f real_capacity %f',
                                  stat.port_no, switch, datadelta, port.capacity)

            port.last_request_time = port_stats_reply_time
            port.last_utilization_value = utilization

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        print "Adding flow ", match, actions
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

        global switches

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # avoid broadcast from LLDP
        if eth.ethertype == 35020:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if src not in mymac.keys():
            mymac[src] = (dpid, in_port)
            # print "mymac=", mymac

        if dst in mymac.keys():
            if dst in self.mac_to_port[dpid]:
                print pkt
                out_port = self.mac_to_port[dpid][dst]
                arp_pkt = pkt.get_protocol(arp.arp)
                if arp_pkt:
                    ip_src = arp_pkt.src_ip  # if arp_pkt else ip_pkt.src
                    ip_dst = arp_pkt.dst_ip  # if arp_pkt else ip_pkt.dst
                    if ip_src and ip_dst not in self.arp_table:
                        self.arp_table[ip_src] = src
                        self.arp_table[ip_dst] = dst
                        self.install_paths(mymac[src][0], mymac[src][1], mymac[dst][
                                           0], mymac[dst][1], ip_src, ip_dst, src, dst)
                        self.install_paths(mymac[dst][0], mymac[dst][1], mymac[src][
                                           0], mymac[src][1], ip_dst, ip_src, dst, src)
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    def init_sflow(self, ifname, collector, sampling, polling):
        cmd = shlex.split('ip link show')
        out = check_output(cmd)
        info = re.findall('(\d+): ((s[0-9]+)-eth[0-9]+)', out)

        sflow = 'ovs-vsctl -- --id=@sflow create sflow agent=%s target=\\"%s\\" sampling=%s polling=%s --' % (
            ifname, collector, sampling, polling)

        for ifindex, ifname, switch in info:
            switch_info[int(switch[1:])]['ifindex'].append(ifindex)
            switch_info[int(switch[1:])]['ifname'].append(ifname)
            sflow += ' -- set bridge %s sflow=@sflow' % switch

        # print sflow
        os.system(sflow)

        # hub.spawn_after(1, measure_link)

        # print switch_info
        #start_new_thread(measure_link, ("thread_measure_link",))

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        global switches, mymac
        if switches == 4:
            return
        switch_list = get_switch(self.topology_api_app, None)
        for switch in switch_list:
            if switch.dp.id not in switches:
                switches.append(switch.dp.id)
                switch_info[switch.dp.id]['ifindex'] = []
                switch_info[switch.dp.id]['ifname'] = []
                self.datapath_list[switch.dp.id] = switch.dp
        # print "self.datapath_list=", self.datapath_list
        print "switches=", switches

        links_list = get_link(self.topology_api_app, None)
        mylinks = [(link.src.dpid, link.dst.dpid, link.src.port_no,
                    link.dst.port_no) for link in links_list]
        for s1, s2, port1, port2 in mylinks:
            adjacency[s1][s2] = port1
            adjacency[s2][s1] = port2

        if switches:
            print adjacency
            (ifname, agent) = getIfInfo(collector)
            logging.getLogger("get").setLevel(logging.WARNING)
            self.init_sflow(ifname, collector, 10, 10)

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
        if eth_dst == mac.BROADCAST_STR and arp_pkt:
            arp_dst_ip = arp_pkt.dst_ip

            if (datapath.id, eth_src, arp_dst_ip) in self.sw:
                if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    datapath.send_packet_out(in_port=in_port, actions=[])
                    return True
            else:
                self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port

        # Try to reply arp request
        if arp_pkt:
            hwtype = arp_pkt.hwtype
            proto = arp_pkt.proto
            hlen = arp_pkt.hlen
            plen = arp_pkt.plen
            opcode = arp_pkt.opcode
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip

            if opcode == arp.ARP_REQUEST:
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
                    return True
        return False
