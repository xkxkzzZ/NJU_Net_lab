#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard import llnetbase

class ForwardingTableEntry:
    def __init__(self, dest, mask, gateway, interface):
        self.dest = dest
        self.mask = mask
        self.gateway = gateway
        self.interface = interface
        self.prefixnet = IPv4Network("{}/{}".format(dest, mask), strict=False)
    
    def __lt__(self, other):
        return self.prefixnet.prefixlen > other.prefixnet.prefixlen

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.interfaces = self.net.interfaces()
        self.ip_list = [interface.ipaddr for interface in self.interfaces]
        self.arp_table = {}
        self.forwarding_table = []
        self.build_forwarding_table()
        self.waiting_packet = {} # ip - packet_list
        self.waiting_ip = {} # ip - (time, retries)

    def build_forwarding_table(self):
        for interface in self.interfaces:
            self.forwarding_table.append(ForwardingTableEntry(interface.ipaddr, interface.netmask, None, interface.name))
        with open("forwarding_table.txt") as f:
            for line in f:
                dest, mask, gateway, interface = line.strip().split()
                self.forwarding_table.append(ForwardingTableEntry(dest, mask, gateway, interface))
        self.forwarding_table.sort()
    
    def get_forwarding_entry(self, ipaddr):
        for entry in self.forwarding_table:
            if ipaddr in entry.prefixnet: # match
                return entry
        return None

    def handle_ipv4_packet(self, recv):
        timestamp, ifaceName, packet = recv
        ipv4 = packet.get_header(IPv4)
        eth = packet.get_header(Ethernet)
        dst_ip = ipv4.dst
        if len(eth) + ipv4.total_length != packet.size():
            return
        if dst_ip in self.ip_list:
            return
        entry = self.get_forwarding_entry(dst_ip)
        if entry is None:
            return        
        
        next_hop_ip = dst_ip if entry.gateway is None else ip_address(entry.gateway)
        next_hop_mac = self.arp_table.get(next_hop_ip)

        if next_hop_mac is not None:
            packet[Ethernet].src = self.net.interface_by_name(entry.interface).ethaddr
            packet[Ethernet].dst = next_hop_mac
            packet[IPv4].ttl -= 1
            self.net.send_packet(entry.interface, packet)

        else:
            if next_hop_ip not in self.waiting_ip.keys():
                self.waiting_ip[next_hop_ip] = (time.time(), 1)
                arp_request = create_ip_arp_request(self.net.interface_by_name(entry.interface).ethaddr,self.net.interface_by_name(entry.interface).ipaddr,next_hop_ip)
                self.net.send_packet(entry.interface, arp_request)
            if next_hop_ip not in self.waiting_packet.keys():
                self.waiting_packet[next_hop_ip] = []
            self.waiting_packet[next_hop_ip].append(packet)
           

    def handle_arp_packet(self, recv):
        timestamp, ifaceName, packet = recv
        arp = packet.get_header(Arp)
        eth = packet.get_header(Ethernet)
        src_ip = arp.senderprotoaddr
        src_mac = arp.senderhwaddr
        dst_ip = arp.targetprotoaddr
        if dst_ip not in self.ip_list:
            return
        
        if arp.operation == ArpOperation.Request:
            self.arp_table[src_ip] = src_mac
            arp_reply = create_ip_arp_reply(self.net.interface_by_ipaddr(dst_ip).ethaddr, src_mac, dst_ip, src_ip)
            self.net.send_packet(ifaceName, arp_reply)

        elif arp.operation == ArpOperation.Reply:
            if eth.src == 'ff:ff:ff:ff:ff:ff':
                return 
            self.arp_table[src_ip] = src_mac
            if src_ip in self.waiting_ip.keys():
                for packet in self.waiting_packet[src_ip]:
                    packet[Ethernet].src = self.net.interface_by_name(ifaceName).ethaddr
                    packet[Ethernet].dst = src_mac
                    packet[IPv4].ttl -= 1
                    self.net.send_packet(ifaceName, packet)
                del self.waiting_packet[src_ip]
                del self.waiting_ip[src_ip]
        
    def handle_timeout(self):
        for ip in list(self.waiting_ip.keys()):
            timestamp = self.waiting_ip[ip][0]
            retries = self.waiting_ip[ip][1]
            if time.time() - timestamp > 1:
                if retries >= 5:
                    del self.waiting_ip[ip]
                    del self.waiting_packet[ip]
                else:
                    self.waiting_ip[ip] = (time.time(), retries + 1)
                    arp_request = create_ip_arp_request(
                        self.net.interface_by_name(self.get_forwarding_entry(ip).interface).ethaddr,
                        self.net.interface_by_name(self.get_forwarding_entry(ip).interface).ipaddr,
                        ip
                    )
                    self.net.send_packet(self.get_forwarding_entry(ip).interface, arp_request)


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        arp = packet.get_header(Arp)
        eth = packet.get_header(Ethernet)
        ipv4 = packet.get_header(IPv4)

        if eth.dst != self.net.interface_by_name(ifaceName).ethaddr and eth.dst != 'ff:ff:ff:ff:ff:ff':
            return
        if eth.ethertype != EtherType.ARP and eth.ethertype != EtherType.IPv4:
            return

        if arp:
            self.handle_arp_packet(recv)
            return
        if ipv4:
            self.handle_ipv4_packet(recv)
            return
        

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.handle_timeout()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
