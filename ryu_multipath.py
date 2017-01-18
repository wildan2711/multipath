from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import mac
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

MAX_PATHS = 3

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
        time.sleep(1)


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
        print "Jalur yg tersedia dari ",src, " ",dst," : ", topology_map[src][dst]

def get_optimal_paths(src, dst):
    get_paths(src, dst)
    paths_count = len(topology_map[src][dst]) if len(topology_map[src][dst]) < 3 else 3
    return sorted(topology_map[src][dst], key=lambda x: len(x))[0:(paths_count)]

def add_ports_to_paths(paths, last_port):
    # Add the ports that connects the switches for all paths
    paths_p = []
    for path in paths:
        p = {}
        for s1, s2 in zip(path[:-1], path[1:]):
            p[s1] = adjacency[s1][s2]
        p[path[-1]] = last_port
        paths_p.append(p)
    return paths_p

def get_least_cost_route(src, dst, first_port, last_port):
    # print src, dst, first_port, last_port
    if src is dst:
        return [(dst, first_port, last_port)]
    try:
        if adjacency[src][dst]:
            return [(src, first_port, adjacency[src][dst])] + [(dst, adjacency[dst][src], last_port)]
    except KeyError:
        pass
    # generate all paths from src to dst
    get_paths(src, dst)
    r = topology_map[src][dst]
    route_costs = [{'route': [], 'cost':0} for k in range(len(r))]
    for i in range(len(r)):
        route_costs[i]['route'] = r[i]
        for s, fp, lp in r[i]:
            # get the total cost of every interface for switch
            for ifindex in thr[s]:
                route_costs[i]['cost'] += thr[s][ifindex]
    print route_costs
    if not route_costs[0]['route']:
        del route_costs[0]
    min_route = min(route_costs, key=itemgetter('cost'))
    if min_route['cost'] == 0:
        min_route = min(route_costs, key=lambda x: len(x['route']))
    first = (src, first_port, adjacency[src][min_route['route'][0][0]])
    last = (dst, adjacency[dst][min_route['route'][-1][0]], last_port)
    return [first] + min_route['route'] + [last]

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

    # Handy function that lists all attributes in the given object
    def ls(self, obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))

    def install_paths(self, src, dst, last_port, mac_src, mac_dst):
        # print src," ", dst," ", last_port," ", mac_src," ", mac_dst
        paths = get_optimal_paths(src, dst)
        paths_with_ports = add_ports_to_paths(paths, last_port)
        print paths_with_ports
        switches_in_paths = set().union(*paths)

        for node in switches_in_paths:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser
            match = ofp_parser.OFPMatch(eth_src=mac_src, eth_dst=mac_dst)

            out_ports = set()
            actions = []

            for path in paths_with_ports:
                if node in path:
                    out_ports.add(path[node])

            if len(out_ports) > 1:
                group_id = None
                group_new = False

                if (node, src, dst) not in multipath_group_ids:
                    group_new = True
                    multipath_group_ids[node, src, dst] = generate_openflow_gid()
                group_id = multipath_group_ids[node, src, dst]

                buckets = []
                print "node at ",node," out ports : ",out_ports
                for port in out_ports:
                    bucket_weight = 10
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

                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                mod = ofp_parser.OFPFlowMod(
                    datapath=dp, match=match, idle_timeout=0, hard_timeout=0,
                    priority=1, instructions=inst)
                dp.send_msg(mod)

                    # Sending OUTPUT Rules
            elif len(out_ports) == 1:
                # print 'Match for %s from %s to %s out_ports %d' % (node, src, dst, out_ports[0])
                actions = [ofp_parser.OFPActionOutput(list(out_ports)[0])]

                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                mod = ofp_parser.OFPFlowMod(
                    datapath=dp, match=match, idle_timeout=0, hard_timeout=0,
                    priority=1, instructions=inst)
                dp.send_msg(mod)



    def install_path(self, p, ev, src_mac, dst_mac):
        # print "install_path is called"
        # print "p=", p, " src_mac=", src_mac, " dst_mac=", dst_mac
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for sw, in_port, out_port in p:
            match = parser.OFPMatch(
                in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            datapath = self.datapath_list[sw]
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, idle_timeout=0, hard_timeout=0,
                priority=1, instructions=inst)
            datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print "switch_features_handler is called"
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Re
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # print "eth.ethertype=", eth.ethertype

        # avodi broadcast from LLDP
        if eth.ethertype == 35020:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        if src not in mymac.keys():
            mymac[src] = (dpid,  in_port)
            # print "mymac=", mymac

        if dst in mymac.keys() and mymac[src][0] != mymac[dst][0]:
            self.install_paths(mymac[src][0], mymac[dst][0], mymac[dst][1], src, dst)
        else:
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]

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

        print sflow
        os.system(sflow)

        # print switch_info
        #start_new_thread(measure_link, ("thread_measure_link",))

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        global switches
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

