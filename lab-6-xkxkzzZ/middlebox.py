#!/usr/bin/env python3

import time
import threading
from random import randint

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import random

blaster_eth = EthAddr("10:00:00:00:00:01")
middlebox_eth0 = EthAddr("40:00:00:00:00:01")
middlebox_eth1 = EthAddr("40:00:00:00:00:02")
blastee_eth = EthAddr("20:00:00:00:00:01")
blaster_ip = IPv4Address("192.168.100.1")
middlebox_ip0 = IPv4Address("192.168.100.2")
middlebox_ip1 = IPv4Address("192.168.200.2")
blastee_ip = IPv4Address("192.168.200.1")


class Middlebox:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate="0.19"
    ):
        self.net = net
        self.dropRate = float(dropRate)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        if not packet.has_header(IPv4):
            log_info("Received non-IPv4 packet")
            return
        seq_num = int.from_bytes(packet[RawPacketContents].data[:4], 'big')
        if fromIface == "middlebox-eth0": # Received from blaster
            if random() < self.dropRate:
                log_info(f"Drop packet {seq_num}")
                return
            log_info(f"Forwarding packet {seq_num}")
            packet[Ethernet].src = middlebox_eth1
            packet[Ethernet].dst = blastee_eth
            self.net.send_packet("middlebox-eth1", packet)
        elif fromIface == "middlebox-eth1": # Received from blastee
            packet[Ethernet].src = middlebox_eth0
            packet[Ethernet].dst = blaster_eth
            log_info(f"Forwarding ACK {seq_num}")
            self.net.send_packet("middlebox-eth0", packet)
        else:
            log_info("Oops :))")

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=3.0)
            except NoPackets:
                continue
            except Shutdown:
                break
            
            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()
