import os
os.sys.path.append('/home/jaidev/.local/bin/scapy')

from scapy.all import *


def craft_packet():
    src_ip = "20.20.20.20"
    dst_ip = "100.100.100.100"
    src_port = 11
    dst_port = 80
    packet = IP(dst=dst_ip,src=src_ip)/TCP(sport=src_port,dport=dst_port,flags="S")
    print("Raw Packet: ")
    print(packet)
    print()
    print("Packet: ")
    packet.show()
    tcp = srloop(packet, count=3)
    return tcp

packet = craft_packet()
print(packet)