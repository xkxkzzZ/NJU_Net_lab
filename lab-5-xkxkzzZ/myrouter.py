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
    
icmp_error_types = {ICMPType.DestinationUnreachable, ICMPType.SourceQuench,
                ICMPType.Redirect, ICMPType.TimeExceeded, ICMPType.ParameterProblem}

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

    def make_icmp_error(self, origpkt, icmptype, src_ip, dst_ip, icmpcode = 0):
        log_info("Making ICMP error")
        del origpkt[Ethernet]
        eth = Ethernet()
        icmp = ICMP()
        icmp.icmptype = icmptype
        icmp.icmpcode = icmpcode
        icmp.icmpdata.data = origpkt.to_bytes()[:28]
        ipv4 = IPv4()
        ipv4.protocol = IPProtocol.ICMP
        ipv4.src = src_ip
        ipv4.dst = dst_ip
        ipv4.ttl = 64
        pkt = eth + ipv4 + icmp
        return pkt

    def send_icmp_error(self, packet, fromintf, icmptype, icmpcode, intfchoice = False):
        icmp = packet.get_header(ICMP)
        ipv4 = packet.get_header(IPv4)
        if icmp and icmp.icmptype in icmp_error_types:
            log_info("icmp.icmptype: {}, return".format(icmp.icmptype))
            return
        entry = self.get_forwarding_entry(ipv4.src)
        if entry is None: return
        if not intfchoice:
            errpacket = self.make_icmp_error(packet, icmptype, 
                self.net.interface_by_name(entry.interface).ipaddr, ipv4.src, icmpcode)
        else:
            errpacket = self.make_icmp_error(packet, icmptype, 
                self.net.interface_by_name(fromintf).ipaddr, ipv4.src, icmpcode)
        self.send_out(ipv4.src, entry.interface, errpacket, fromintf)

    def forwarding(self, packet, fromintf):
        log_info("Forwarding packet:{}".format(packet))
        ipv4 = packet.get_header(IPv4)
        icmp = packet.get_header(ICMP)
        dst_ip = ipv4.dst
        entry = self.get_forwarding_entry(dst_ip)
        if entry is None:
            log_info("Sending ICMP Destination Unreachable")
            self.send_icmp_error(packet, fromintf, ICMPType.DestinationUnreachable, 0)
            return
        
        elif ipv4.ttl <= 1:
            log_info("Sending ICMP Time Exceeded")
            self.send_icmp_error(packet, fromintf, ICMPType.TimeExceeded, 0)
            return
        
        else:
            log_info("entry.interface: {}".format(entry.interface))
            next_hop_ip = dst_ip if entry.gateway is None else ip_address(entry.gateway)
            self.send_out(next_hop_ip, entry.interface, packet, fromintf)

    
    def send_out(self, ip, interface, packet, fromintf):
        log_info("Sending out packet:{}".format(packet))
        log_info("on interface:{}".format(interface))
        mac = self.arp_table.get(ip)
        if mac is not None:
            log_info("mac is known")
            packet[Ethernet].src = self.net.interface_by_name(interface).ethaddr
            packet[Ethernet].dst = mac
            packet[IPv4].ttl -= 1
            log_info("sending packet: {}".format(packet))
            log_info("on interface: {}".format(interface))
            self.net.send_packet(interface, packet)
        else:
            log_info("mac is unknown")
            if ip not in self.waiting_ip.keys():
                self.waiting_ip[ip] = (time.time(), 0)
            if ip not in self.waiting_packet.keys():
                self.waiting_packet[ip] = []
            self.waiting_packet[ip].append((packet, fromintf))

    def make_icmp_reply(self, request_packet):
        ipv4 = request_packet.get_header(IPv4)
        icmp = request_packet.get_header(ICMP)
        icmp_header = ICMP()
        icmp_header.icmptype = ICMPType.EchoReply
        icmp_header.icmpdata.sequence = icmp.icmpdata.sequence
        icmp_header.icmpdata.identifier = icmp.icmpdata.identifier
        icmp_header.icmpdata.data = icmp.icmpdata.data
        ipv4_header = IPv4()
        ipv4_header.src = ipv4.dst
        ipv4_header.dst = ipv4.src
        ipv4_header.protocol = IPProtocol.ICMP
        ipv4_header.ttl = 64
        eth_header = Ethernet()
        reply_packet = eth_header + ipv4_header + icmp_header
        return reply_packet

    def handle_ipv4_packet(self, recv):
        timestamp, ifaceName, packet = recv
        log_info("Handling IPv4 packet{}".format(packet))
        ipv4 = packet.get_header(IPv4)
        eth = packet.get_header(Ethernet)
        icmp = packet.get_header(ICMP)
        dst_ip = ipv4.dst
        if len(eth) + ipv4.total_length != packet.size():
            return
                
        if dst_ip in self.ip_list:
            log_info("there is a packet for me")
            if icmp:
                if icmp.icmptype == ICMPType.EchoRequest:
                    log_info("Received ICMP Echo Request")
                    reply = self.make_icmp_reply(packet) 
                    self.forwarding(reply, ifaceName)
                    return 
                else:
                    return
            else: 
                log_info("Sending ICMP Destination Unreachable")
                errpacket = self.make_icmp_error(packet, ICMPType.DestinationUnreachable, self.net.interface_by_name(ifaceName).ipaddr, ipv4.src, icmpcode=3)
                self.forwarding(errpacket, None)
                return
            
        else:
            log_info("there is a packet for other")
            self.forwarding(packet, ifaceName)


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
            log_info("Received ARP request")
            self.arp_table[src_ip] = src_mac
            arp_reply = create_ip_arp_reply(self.net.interface_by_ipaddr(dst_ip).ethaddr, src_mac, dst_ip, src_ip)
            self.net.send_packet(ifaceName, arp_reply)

        elif arp.operation == ArpOperation.Reply:
            log_info("Received ARP reply")
            if eth.src == 'ff:ff:ff:ff:ff:ff':
                return 
            self.arp_table[src_ip] = src_mac
            if src_ip in self.waiting_ip.keys():
                for packet, fromintf in self.waiting_packet[src_ip]:
                    self.forwarding(packet, fromintf)
                del self.waiting_packet[src_ip]
                del self.waiting_ip[src_ip]
        
    def handle_timeout(self):
        for ip in list(self.waiting_ip.keys()):
            timestamp = self.waiting_ip[ip][0]
            retries = self.waiting_ip[ip][1]
            if time.time() - timestamp > 1:
                if retries >= 5:
                    entry = self.get_forwarding_entry(ip)
                    for packet, fromintf in self.waiting_packet[ip]:
                        self.send_icmp_error(packet, fromintf, ICMPType.DestinationUnreachable, 1, True)
                    del self.waiting_ip[ip]
                    del self.waiting_packet[ip]
                else:
                    self.waiting_ip[ip] = (time.time(), retries + 1)
                    entry = self.get_forwarding_entry(ip)
                    arp_request = create_ip_arp_request(
                        self.net.interface_by_name(entry.interface).ethaddr,
                        self.net.interface_by_name(entry.interface).ipaddr,
                        ip
                    )
                    log_info("arp_request: {}".format(arp_request))
                    self.net.send_packet(entry.interface, arp_request)


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        arp = packet.get_header(Arp)
        eth = packet.get_header(Ethernet)
        ipv4 = packet.get_header(IPv4)

        if eth.dst != self.net.interface_by_name(ifaceName).ethaddr and eth.dst != 'ff:ff:ff:ff:ff:ff':
            return
        if eth.ethertype != EtherType.ARP and eth.ethertype != EtherType.IPv4:
            return
        log_info("--------------------------------------------------------")

        if arp:
            log_info("Received ARP packet")
            self.handle_arp_packet(recv)
            return
        if ipv4:
            log_info("Received IPv4 packet")
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
