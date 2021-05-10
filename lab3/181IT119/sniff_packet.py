from scapy.all import *
from codecs import encode
from binascii import hexlify

def main():
    packets = sniff(filter="host 100.100.100.100",count=1)
    print("Packets sniffed: ", packets)
    packet = (str(packets[0]))
    packet = (packet)[2:len(packet)-1]
    print("Raw Packet Sniffed: ", packet)
    hexdump = str((hexlify(encode(packet.encode().decode('unicode_escape'),"raw_unicode_escape"))))
    f=open("hexdump.txt","w")
    f.write(hexdump[2:len(hexdump)-1])

if __name__ == '__main__':
	main()


