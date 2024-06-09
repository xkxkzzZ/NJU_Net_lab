
import switchyard
from switchyard.lib.userlib import *
from time import time

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    '''
        Your switch may have a table like:
        MAC Address          Interface      Timestamp
        ab:cd:ef:fe:cd:ba   interface-0    123456.123456
    '''

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
        mac_table[eth.src] = [fromIface, time()]

        # delete entries older than 10 seconds
        for key in list(mac_table):
            if time() - mac_table[key][1] > 10:
                del mac_table[key]
                
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            #search for the output port for the destination
            if eth.dst in mac_table: # if know
                log_info(f"Sending packet on {mac_table[eth.dst][0]}")
                net.send_packet(mac_table[eth.dst][0], packet)
            else:
                #if dont know, flood
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
