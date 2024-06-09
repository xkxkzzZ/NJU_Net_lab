

import switchyard
from switchyard.lib.userlib import *

import heapq

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    max_size = 5
    mac_table = [] # [traffic, mac, interface]

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
        
        for tuple in mac_table:
            if tuple[1] == eth.src:
                break
        else:
            if len(mac_table) >= max_size:
                heapq.heappop(mac_table)
            heapq.heappush(mac_table, [0, eth.src, fromIface])


        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            #search for the output port for the destination
            for tuple in mac_table:
                if tuple[1] == eth.dst:
                    tuple[0] += 1
                    log_info(f"Sending packet {packet} to {tuple[2]}")
                    net.send_packet(tuple[2], packet)
                    break
            
            else:   #if dont know, flood
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
