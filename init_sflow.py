from requests import get
from subprocess import check_output
from operator import itemgetter
import logging
import socket
import time
import os
import re
import shlex

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
        sflow += ' -- set bridge %s sflow=@sflow' % switch

    print sflow
    os.system(sflow)

(ifname, agent) = getIfInfo(collector)
init_sflow(ifname, collector, 10, 10)