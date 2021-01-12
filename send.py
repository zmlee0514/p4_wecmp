#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.fields import *

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class WECMP(Packet):
    name = "WECMP"
    fields_desc = [ BitField("src_sw_id", 0, 8),
                    BitField("selected_path_id", 0, 8),
                    BitField("tag_path_id", 0, 8),
                    BitField("max_utilization", 0, 8)]
    def mysummary(self):
        return self.sprintf("src_sw_id=%src_sw_id%, selected_path_id=%selected_path_id%, tag_path_id=%tag_path_id%, max_utilization=%max_utilization%")

bind_layers(Ether, WECMP, type=0x1234)
bind_layers(WECMP, IP)

def main():

    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff') / WECMP(src_sw_id=15, selected_path_id=0, tag_path_id=0, max_utilization=0)
    pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=49152) / sys.argv[2]
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
