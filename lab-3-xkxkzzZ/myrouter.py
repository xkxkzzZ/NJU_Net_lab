#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.interfaces = self.net.interfaces()
        self.arp_table = {}

    def handle_arp_packet(self, recv):
        timestamp, ifaceName, packet = recv
        arp = packet.get_header(Arp)
        self.arp_table[arp.senderprotoaddr] = arp.senderhwaddr
        log_info("arp_table: {}".format(self.arp_table))
        for interface in self.interfaces:
            if(arp.targetprotoaddr == interface.ipaddr):
                arp_reply = create_ip_arp_reply(interface.ethaddr, arp.senderhwaddr, interface.ipaddr, arp.senderprotoaddr)
                self.net.send_packet(ifaceName, arp_reply)
                return


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp = packet.get_header(Arp)
        if arp:
            self.handle_arp_packet(recv)
            return
        

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
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
