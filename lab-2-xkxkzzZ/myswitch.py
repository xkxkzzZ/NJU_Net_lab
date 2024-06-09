'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    # dictionary to store the interface associated with the source address of the packet
    mac_table = {}
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        
        # record interface associated with source address of arriving packet
        mac_table[eth.src] = fromIface
        

        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            #search for the output port for the destination
            if eth.dst in mac_table:
                log_info(f"Sending packet on {mac_table[eth.dst]}")
                net.send_packet(mac_table[eth.dst], packet)
            else:
                #if dont know, flood
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
