#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *

blaster_eth = EthAddr("10:00:00:00:00:01")
middlebox_eth0 = EthAddr("40:00:00:00:00:01")
middlebox_eth1 = EthAddr("40:00:00:00:00:02")
blastee_eth = EthAddr("20:00:00:00:00:01")
blaster_ip = IPv4Address("192.168.100.1")
middlebox_ip0 = IPv4Address("192.168.100.2")
middlebox_ip1 = IPv4Address("192.168.200.2")
blastee_ip = IPv4Address("192.168.200.1")



class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp = "192.168.100.1",
            num = "10"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasterIp = IPv4Address(blasterIp)
        if(self.blasterIp != blaster_ip):
            log_info(f"Blaster IP is {self.blasterIp} and should be {blaster_ip}")
        self.num = int(num) # Number of packets to receive
        self.recv_num = 0
        self.recved = [False] * (self.num + 1)

    def create_ack(self, packet, seq_num):
        eth = Ethernet(src=blastee_eth, dst=middlebox_eth1, ethertype=EtherType.IPv4)
        ip = IPv4(src=blastee_ip, dst=blaster_ip, protocol=IPProtocol.UDP, ttl=64)
        udp = UDP()
        blaster_payload = packet[RawPacketContents].data.ljust(8, b'\0')
        payload = blaster_payload[:8]
        raw_data = struct.pack('!I8s', seq_num, payload)  
        raw_packet = RawPacketContents(raw_data)
        ack = eth + ip + udp + raw_packet
        return ack

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        seq_num = int.from_bytes(packet[RawPacketContents].data[:4], 'big')
        log_info(f"Received packet {seq_num}")
        ack = self.create_ack(packet, seq_num)
        self.net.send_packet("blastee-eth0", ack)
        if not self.recved[seq_num]:
            self.recved[seq_num] = True
            self.recv_num += 1
        

    def start(self):
        '''A running daemon of the blastee.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                if self.recv_num == self.num:
                    break
                continue
            except Shutdown:
                break
            
            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
