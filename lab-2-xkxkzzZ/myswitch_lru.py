
import switchyard
from switchyard.lib.userlib import *
from collections import deque

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    mac_table = deque(maxlen=5)

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
        for pair in mac_table:
            if pair[0] == eth.src:
                mac_table.remove(pair)
                break
        mac_table.append([eth.src, fromIface])

                
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            #search for the output port for the destination
            for pair in mac_table:
                if pair[0] == eth.dst: # if know update and send
                    mac_table.remove(pair)
                    mac_table.append(pair)
                    log_info(f"Sending packet {packet} to {pair[1]}")
                    net.send_packet(pair[1], packet)
                    break
            
            else:   #if dont know, flood
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
