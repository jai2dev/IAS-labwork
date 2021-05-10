def read_packet(filename):
    f = open(filename, "r")
    hexdump = f.readline().strip()
    print("Hexdump: \n", hexdump,"\n\nPacket info:")
    hd = ' '.join(hexdump[i:i + 2] for i in range(0, len(hexdump), 2)) 
    hd = list(hd)
    hexdump = []
    for i in hd:
        if i == ' ':
            continue
        hexdump.append(i)
    f.close()
    return hexdump

def get_firewall_policy(sip, dip, sp, dp, acl):
    src_ip = sip.split('.')
    dest_ip = dip.split('.')
    for i in acl:
        if sip == i[0] or i[0] == "Any":
            if dip == i[2] or i[2] == "Any":
                if i[1] == "Any" or sp == int(i[1]):
                    if i[3] == "Any" or dp == int(i[3]):
                        return i[4]
                    else:
                        continue
                else:
                    continue
            else:
                ip = i[2].split('.')
                f = False
                for x in range(4):
                    if ip[x] == dest_ip[x] or ip[x] == "*":
                        continue
                    else:
                        f = True
                    if f:
                        break 
                if f:
                    continue
                else:
                    if i[1] == "Any" or sp == int(i[1]):
                        if i[3] == "Any" or dp == int(i[3]):
                            return i[4]
                        else:
                            continue
                    else:
                        continue
        else:
            ip = i[0].split('.')
            f = False
            for y in range(4):
                if ip[y] == src_ip[y] or ip[y] == "*":
                    continue
                else:
                    f = True
                if f:
                    break
            if f:
                continue
            else:
                if dip == i[2] or i[2] == "Any":
                    if i[1] == "Any" or sp == int(i[1]):
                        if i[3] == "Any" or dp == int(i[3]):
                            return i[4]
                        else:
                            continue
                    else:
                        continue
                else:
                    ip = i[2].split('.')
                    f = False
                    for x in range(4):
                        if ip[x] == dest_ip[x] or ip[x] == "*":
                            continue
                        else:
                            f = True
                        if f:
                            break 
                    if f:
                        continue
                    else:
                        if i[1] == "Any" or sp == int(i[1]):
                            if i[3] == "Any" or dp == int(i[3]):
                                return i[4]
                            else:
                                continue
                        else:
                            continue
    return "Deny"



def get_mac(l):
    mac = ""
    for i in range(len(l)):
        mac = mac + l[i]
        if i % 2 == 1:
            mac = mac + ":"
    return mac[:len(mac)-1]

def get_hex_str(l):
    s = "".join(l)
    return s

def get_ethernet_header(hexdump):
    dest_mac_add = hexdump[:12]
    src_mac_add = hexdump[12:24]
    eth_type = hexdump[24:28]

    ethernet_header = []
    ethernet_header.append(dest_mac_add)
    ethernet_header.append(src_mac_add)
    ethernet_header.append(eth_type)

    return ethernet_header

def display_ethernet_header(eth, out):
    print("Ethernet Header: ")
    mac = eth[0]
    mac_dest = get_mac(mac)
    mac = eth[1]
    mac_src = get_mac(mac)
    print("Desination MAC address: ", mac_dest)
    print("Source MAC address: ", mac_src)
    print("Ethernet Type: ", get_hex_str(eth[2]))
    if eth[2] == ['0', '8', '0', '0']:
        print("IP Packet")
    elif  eth[2] == ['0', '8', '0', '6']:
        print("ARP Packet") 
    else:
        print("Packet type not recognised")

    print()
    return None

def get_ip_4(l):
    ip = ""
    p1 = "" + l[0] + l[1]
    p2 = "" + l[2] + l[3]
    p3 = "" + l[4] + l[5]
    p4 = "" + l[6] + l[7]
    ip1 = int(p1, 16)
    ip2 = int(p2, 16)
    ip3 = int(p3, 16)
    ip4 = int(p4, 16)
    ip = ip + str(ip1) + "." + str(ip2) + "." + str(ip3) + "." + str(ip4)
    return ip

def get_dec(l):
    p = "".join(l)
    p = int(p, 16)
    return p


def display_ip_header(iph, acl):
    print("IP Header: ")
    print("Version: ", int(iph[0][0]))
    if iph[0] == ['4']:
        print("IPv4 Version")
    elif iph[0] == ['6']:
        print("IPv6 Version")
    print("IP Header Length: ", iph[1][0])
    if iph[0] == ['4']:
        print("( ", int(iph[1][0])*4, " bytes )")
    elif iph[0] == ['6']:
        print("( ", int(iph[1][0])*4, " ? bytes )") 
    print("Type of Service: ", iph[2][0])
    print("Explicit Congestion Notification: ", iph[3][0])
    print("IP Packet Length: ", get_hex_str(iph[4]))
    print("( ", get_dec(iph[4]), " bytes )")
    print("Identification: ", get_hex_str(iph[5]))
    print("Fragment offset: ", get_hex_str(iph[6]))
    print("Time to Live: ", get_hex_str(iph[7]))
    print("Protocol: ", get_hex_str(iph[8]))
    print("Header Checksum: ", get_hex_str(iph[9]))
    sip = get_ip_4(iph[10])
    dip = get_ip_4(iph[11])
    print("Source IP Address: ", sip)
    print("Destination IP Address: ", dip)
    print()
    if iph[8] == ['1', '1']:
        print("UDP Protocol:")
        sp = get_dec(iph[12][0])
        dp = get_dec(iph[12][1])
        l = get_dec(iph[12][2])
        chsum = iph[12][3]
        print("Source Port: ", sp)
        print("Destination Port: ", dp)
        print("Length: ", l)
        print("Checksum: ",get_hex_str(chsum))
        print()
        firewall_policy = get_firewall_policy(sip, dip, sp, dp, acl)
        if firewall_policy == "Allow":
            print("Packet Allowed!")
        else:
            print("Packet Denied!")

    elif iph[8] == ['0', '6']:
        print("TCP Protocol:")
        sp = get_dec(iph[12][0])
        dp = get_dec(iph[12][1])
        print("Source Port: ", sp)
        print("Destination Port: ", dp)
        print("Sequence Number: ", get_hex_str(iph[12][2]))
        print("Acknowledgement Number: ", get_hex_str(iph[12][3]))
        print("Checksum: ", get_hex_str(iph[12][7]))
        print()
        firewall_policy = get_firewall_policy(sip, dip, sp, dp, acl)
        if firewall_policy == "Allow":
            print("Packet Allowed!")
        else:
            print("Packet Denied!")
    
    elif iph[8] == ['0', '1']:
        print("ICMP Protocol")

    else:
        print("Protocol not coded here")
    print() 


def parse_ip(hexdump, start, acl):
    version = hexdump[start:start+1]
    ihl = hexdump[start+1:start+2]
    dscp = hexdump[start+2:start+3]
    ecn = hexdump[start+3:start+4]
    tot_length = hexdump[start+4:start+8]
    start = start + 8
    identification = hexdump[start:start+4]
    fragment = hexdump[start+4:start+8]
    start = start + 8
    time_to_live = hexdump[start:start+2]
    protocol = hexdump[start+2:start+4]
    header_checksum = hexdump[start+4:start+8] 
    start = start + 8
    src_address =  hexdump[start:start+8]
    start = start + 8
    dest_address =  hexdump[start:start+8]
    start = start + 8

    udp_header = []
    tcp_header = []
    
    if protocol == ['1', '1']:
        udp_src_port = hexdump[start:start+4]
        udp_dest_port = hexdump[start+4:start+8]
        udp_length = hexdump[start+8:start+12]
        udp_checksum = hexdump[start+12:start+16]
        udp_header.append(udp_src_port)
        udp_header.append(udp_dest_port)
        udp_header.append(udp_length)
        udp_header.append(udp_checksum)

    elif protocol == ['0', '6']:
        tcp_src_port = hexdump[start:start+4]
        tcp_dest_port = hexdump[start+4:start+8]
        tcp_seq_no = hexdump[start+8:start+16]
        tcp_ack_no = hexdump[start+16:start+24]
        tcp_seg_len = hexdump[start+24:start+26]
        tcp_cwr = hexdump[start+26:start+28]
        tcp_window_size = hexdump[start+28:start+32]
        tcp_checksum = hexdump[start+32:start+36]
        tcp_urgent_pointer = hexdump[start+36:start+40]

        tcp_header.append(tcp_src_port)
        tcp_header.append(tcp_dest_port)
        tcp_header.append(tcp_seq_no)
        tcp_header.append(tcp_ack_no)
        tcp_header.append(tcp_seg_len)
        tcp_header.append(tcp_cwr)
        tcp_header.append(tcp_window_size)
        tcp_header.append(tcp_checksum)
        tcp_header.append(tcp_checksum)
        tcp_header.append(tcp_urgent_pointer)

    else:
        print("not tcp/udp header")

    ip_header = []
    ip_header.append(version)
    ip_header.append(ihl)
    ip_header.append(dscp)
    ip_header.append(ecn)
    ip_header.append(tot_length)
    ip_header.append(identification)
    ip_header.append(fragment)
    ip_header.append(time_to_live)
    ip_header.append(protocol)
    ip_header.append(header_checksum)
    ip_header.append(src_address)
    ip_header.append(dest_address)
    if protocol == ['1', '1']:
        ip_header.append(udp_header)
    elif protocol == ['0', '6']:
        ip_header.append(tcp_header)

    display_ip_header(ip_header, acl)


def display_arp_header(ah, acl):
    print("ARP:")
    print("Hardware Type: ", get_hex_str(ah[0]))
    if ah[0] == ['0', '0', '0', '1']:
        print("( Ethernet (1) )")
    print("Protocol Type: ", get_hex_str(ah[1]))
    if ah[1] == ['0', '8', '0', '0']:
        print("IPv4 Protocol")
    print("Hardware Size: ", get_hex_str(ah[2]))
    print("Protocol Size: ", get_hex_str(ah[3]))
    print("Opcode: ", get_hex_str(ah[4]))
    print("Sender MAC address: ", get_mac(ah[5]))
    print("Target MAC address: ", get_mac(ah[7]))
    if ah[1] == ['0', '8', '0', '0']:
        print("Sender IP address: ", get_ip_4(ah[6]))
        print("Target IP address:", get_ip_4(ah[8]))
        print()
        firewall_policy = get_firewall_policy(get_ip_4(ah[6]), get_ip_4(ah[8]), None, None, acl)
        if firewall_policy == "Allow":
            print("Packet Allowed!")
        else:
            print("Packet Denied!")
    else:
        print("Sender IP address: ", ah[6])
        print("Target IP address:", ah[8])

    print()


def parse_arp(hexdump, start, acl):
    hardware_type = hexdump[start:start+4]
    protocol = hexdump[start+4:start+8]
    hardware_size = hexdump[start+8:start+10]
    protocol_size = hexdump[start+10:start+12]
    opcode = hexdump[start+12:start+16]
    sender_mac = hexdump[start+16:start+28]
    sender_ip = hexdump[start+28:start+36]
    target_mac = hexdump[start+36:start+48]
    target_ip = hexdump[start+48:start+56]

    arp_header = []
    arp_header.append(hardware_type)
    arp_header.append(protocol)
    arp_header.append(hardware_size)
    arp_header.append(protocol_size)
    arp_header.append(opcode)
    arp_header.append(sender_mac)
    arp_header.append(sender_ip)
    arp_header.append(target_mac)
    arp_header.append(target_ip)

    display_arp_header(arp_header, acl)


def get_acl():
    f = open("ACL-File.csv", "r")
    lines = f.readlines()
    lines = lines[2:8]
    
    for i in range(6):
        line = lines[i]
        line = line.split(',')
        line = line[1:]
        line[4] = line[4][:len(line[4])-1]
        lines[i] = line
    
    return lines
    


def main():
    filename = "hexdump.txt" 
    hexdump = read_packet(filename)
    acl = get_acl()
    print()
    ethernet_header = get_ethernet_header(hexdump)
    display_ethernet_header(ethernet_header, None)
    if ethernet_header[2] == ['0', '8', '0', '0']:
        parse_ip(hexdump, 28, acl)
    elif ethernet_header[2] == ['0', '8', '0', '6']:
        parse_arp(hexdump, 28, acl)
    else:
        print("Code not written for the given protocol")

if __name__ == '__main__':
    
    print()
    print()
    main()