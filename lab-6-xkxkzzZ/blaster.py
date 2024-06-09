#!/usr/bin/env python3

import time
from random import randint
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


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp="192.168.200.1",
            num="10",
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasteeIp = IPv4Address(blasteeIp)
        if(self.blasteeIp != blastee_ip):
            log_info(f"Blastee IP is {self.blasteeIp} and should be {blastee_ip}")
        self.num = int(num) # Number of packets to send
        self.length = int(length) # Length of the payload
        self.senderWindow = int(senderWindow) 
        self.timeout = int(timeout) # Coarse timeout value in milliseconds
        self.recvTimeout = int(recvTimeout)
        self.lhs = 1 # Left hand side of the window
        self.rhs = 0 # Right hand side of the window
        self.lhs_time = time.time()
        self.acked = [False] * (self.num + 1)
        self.acked_num = 0
        self.begin_time = 0
        self.end_time = 0
        self.timeout_num = 0
        self.resend_num = 0

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        seq_num = int.from_bytes(packet[RawPacketContents].data[:4], 'big')
        log_info(f"Received ACK{seq_num}")
        if(seq_num < self.lhs or seq_num > self.rhs):
            return
        if(not self.acked[seq_num]):
            self.acked[seq_num] = True
            self.acked_num += 1
            if(seq_num == self.lhs):
                while(self.lhs <= self.num and self.acked[self.lhs]):
                    self.lhs += 1
                    if self.lhs == self.num + 1:
                        self.end_time = time.time()
                self.lhs_time = time.time()
            # if(self.rhs <= self.num):
            #     self.rhs += 1
            #     pkt = self.create_packet(self.rhs)
            #     self.net.send_packet("blaster-eth0", pkt)


    def create_packet(self, seq_num):
        eth = Ethernet(src=blaster_eth, dst=middlebox_eth0, ethertype=EtherType.IPv4)
        ip = IPv4(src=blaster_ip, dst=self.blasteeIp, protocol=IPProtocol.UDP, ttl=64)
        udp = UDP()
        payload = bytes([randint(0, 255) for _ in range(self.length)])
        length = len(payload)
        raw_data = struct.pack('!IH', seq_num, length) + payload 
        raw_packet = RawPacketContents(raw_data)
        pkt = eth + ip + udp + raw_packet
        return pkt

    def handle_no_packet(self):
        # log_info(f"lhs: {self.lhs}, rhs: {self.rhs}")
        log_info(f"{list(range(self.lhs, self.rhs + 1))}")
        self.handle_timeout()
        if self.rhs < self.num and self.rhs - self.lhs + 1 < self.senderWindow:
            self.rhs += 1
            if self.rhs == 1:
                self.begin_time = time.time()
            pkt = self.create_packet(self.rhs)
            log_info(f"Sending packet{self.rhs}")
            self.net.send_packet("blaster-eth0", pkt)
        
        
    def handle_timeout(self):
        if(time.time() - self.lhs_time > self.timeout/1000.0):
            log_info("Timeout")
            self.timeout_num += 1
            for i in range(self.lhs, self.rhs + 1):
                if(not self.acked[i]):
                    pkt = self.create_packet(i)
                    log_info(f"Resending packet{i}")
                    self.net.send_packet("blaster-eth0", pkt)
                    self.resend_num += 1
        

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                # recv = self.net.recv_packet(timeout=1.0)
                recv = self.net.recv_packet(timeout=self.recvTimeout/1000.0)
            except NoPackets:
                if self.acked_num == self.num:
                    break
                self.handle_no_packet()
                continue
            except Shutdown:
                break
            self.handle_packet(recv)


        self.shutdown()

    def shutdown(self):
        self.net.shutdown()
        log_info("---------------------------------------------")
        log_info(f"Blaster finished sending {self.num} packets")
        # log_info(f"begin_time: {self.begin_time}") 
        # log_info(f"end_time: {self.end_time}")
        log_info(f"Total time (in seconds): {self.end_time - self.begin_time}")
        log_info(f"Number of resends: {self.resend_num}")
        log_info(f"Number of timeouts: {self.timeout_num}")
        log_info(f"Throughput (Bps): {(self.num + self.resend_num) * self.length / (self.end_time - self.begin_time)}")
        log_info(f"Goodput (Bps):{self.num * self.length / (self.end_time - self.begin_time)}")
        log_info("---------------------------------------------")


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
