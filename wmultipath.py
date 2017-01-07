from pyretic.lib.corelib import*
from pyretic.lib.std import *
from multiprocessing import Lock
from pyretic.lib.query import *
from collections import defaultdict
from requests import get
from subprocess import check_output
from thread import start_new_thread
import time
import os
import shlex
import json
import re

from datetime import datetime

byte = defaultdict(lambda: 0)
clock = defaultdict(lambda: 0)
thr = defaultdict(lambda: defaultdict(lambda: 0))

# switches
switches = []

switch_info = defaultdict(dict)

# myhost[srcmac]->(switch, port)
myhost = {}

topology_map = defaultdict(dict)

min_route = defaultdict(dict)

# adjacency map [sw1][sw2]->port from sw1 to sw2
adjacency = defaultdict(dict)

collector = '127.0.0.1'

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
                response = json.loads(r.content)
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
        # Add the ports that connects the switches for all paths
        paths_p = []
        for path in paths:
            r = []
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = adjacency[s1][s2]
                r.append((s1, out_port))
            paths_p.append(r)
        topology_map[src][dst] = paths_p
        print "Jalur yg tersedia : ", topology_map[src][dst]


def get_least_cost_route(src, dst, final_port):
    if src is dst:
        return [(dst, final_port)]
    # generate all paths from src to dst
    get_paths(src, dst)
    r = topology_map[src][dst]
    route_costs = [{'route': [], 'cost':0} for k in range(len(r))]
    for i in range(len(r)):
        route_costs[i]['route'] = r[i]
        for s, p in r[i]:
            # get the total cost of every interface for switch
            for ifindex in thr[s]:
                route_costs[i]['cost'] += thr[s][ifindex]
    print route_costs
    min_route = min(route_costs, key=lambda x: x['cost'])
    if min_route['cost'] == 0:
        min_route = min(route_costs, key=lambda x: len(x['route']))
    return min_route['route'] + [(dst, final_port)]


class find_route(DynamicPolicy):

    def __init__(self):
        super(find_route, self).__init__()
        self.flood = flood()
        self.set_initial_state()

    def set_initial_state(self):
        self.query = packets(1, ['srcmac','dstmac', 'srcip', 'dstip', 'protocol', 'ethtype', 'srcport', 'dstport'])
        self.query.register_callback(self.myroute)
        self.forward = self.flood
        self.update_policy()

    def set_network(self, network):
        self.set_initial_state()

    def update_policy(self):
        self.policy = self.forward + self.query

    def myroute(self, pkt):
        # print pkt['srcmac'], pkt['dstmac'], pkt['srcip'], pkt['dstip']
        if (pkt['srcmac'] not in myhost.keys()) or (pkt['dstmac'] not in myhost.keys()):
            return
        
        path = get_least_cost_route(myhost[pkt['srcmac']][0], myhost[pkt['dstmac']][0], myhost[pkt['dstmac']][1])

        print "Jalur terbaik : ", path
		
        if pkt['protocol'] == 1:
            r1 = parallel([(match(switch=a, srcip=pkt['srcip'], dstip=pkt['dstip']) >> fwd(b))
                        for a, b in path])
            self.forward = if_(
                        match(dstip=pkt['dstip'], srcip=pkt['srcip']), r1, self.forward)
        else:
            r1 = parallel([(match(switch=a,ethtype=pkt['ethtype'],srcip=pkt['srcip'],dstip=pkt['dstip'], protocol=pkt['protocol'], srcport=pkt['srcport'],dstport=pkt['dstport']) >> fwd(b)) for a,b in p1])
            self.forward = if_(match(ethtype=pkt['ethtype'],dstip=pkt['dstip'],srcip=pkt['srcip'], protocol=pkt['protocol'], srcport=pkt['srcport'],dstport=pkt['dstport']),r1,self.forward)
        self.update_policy()

def find_host():
    q = packets(1, ['srcmac'])
    q.register_callback(mymac_learner)
    return q


def mymac_learner(pkt):
    # print pkt['srcmac'], pkt['dstmac'], pkt['switch'], pkt['inport']

    if pkt['srcmac'] not in myhost.keys():
        myhost[pkt['srcmac']] = (pkt['switch'], pkt['inport'])


class find_switch(DynamicPolicy):

    def __init__(self):
        self.last_topology = None
        self.lock = Lock()
        super(find_switch, self).__init__()

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
        start_new_thread(measure_link, ("thread_measure_link",))
        # start_new_thread(measure_path,("thread_measure_path",))

    def set_network(self, network):
        with self.lock:
            for dpid in network.switch_list():
                if dpid not in switches:
                    switches.append(dpid)
                switch_info[dpid]['ifindex'] = []
                switch_info[dpid]['ifname'] = []
            for (s1, s2, data) in network.topology.edges(data=True):
                adjacency[s1][s2] = data[s1]
                adjacency[s2][s1] = data[s2]
            self.last_topology = network.topology

            if switches:
                print switches
                (ifname, agent) = getIfInfo(collector)
                self.init_sflow(ifname, collector, 10, 10)


def main():
    return (find_switch() + find_host() + find_route())
