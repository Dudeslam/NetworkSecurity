#!/usr/bin/env python

# ### 2. Throttling TCP connections

# For this part, you will need to have some familiarity with the TCP protocol to write low-level networking code using a library. 
# Suggestions again are the `libnet/libpcap` library in the C programming language or the equivalent `Scapy` package in Python.

# The objective of this task is to slow down or interrupt TCP connections by forcing retransmission of packets. 
# An illustrative example of such an approach is the `tcpnice` program in the `dsniff` package which reduces windows advertised to artificially decrease bandwidth.
#  We will adopt two different approaches: send 3 ACK packets to simulate packet loss and force retransmission; send a TCP reset packet to drop the connection altogether.

# You will implement a tool that receives a source and destination IP addresses to listen for TCP connections and what approach for throttling should be used. 
# The tool should be executed in a third node with access to the traffic.
#  Whenever such a packet is captured, RST or 3 ACK packets should be sent back to the origin and/or destination.

# For the experimental setup, you can try using virtual machines, or leveraging the VM used for practical exercises as a malicious node to interfere with
#  connections between the host machine and another device.
# Collect experimental evidence of the malicious behavior through Wireshark,
#  and screenshots of the time taken to transmit a file using a file transfer (FTP or SSH) to show that it is indeed slower or interrupted when under attack.
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

import socket 
from socket import *
from struct import *
import sys
import ctypes
import binascii
import getmac
import textwrap

#Run this script in CMD with admin


def ethernet_head(raw_data):
    dest, src, prototype = unpack('! 6s 6s H' , raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = htons(prototype)
    data = raw_data[:14]
    return dest_mac, src_mac, proto, data

# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Returns properly formatted IPv4 address
def ipv4(self, addr):
    return '.'.join(map(str, addr))

def ipv4_head(raw_data):
 version_header_length = raw_data[0]
 version = version_header_length >> 4
 header_length = (version_header_length & 15) * 4
 ttl, proto, src, target = unpack('! 8x B B 2x 4s 4s', raw_data[:20])
 data = raw_data[header_length:]
 src = get_ip(src)
 target = get_ip(target)

 return version, header_length, ttl, proto, src, target, data


def get_ip(addr):
 return '.'.join(map(str, addr))

def tcp_head( raw_data):
 (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = unpack( '! H H L L H', raw_data[:14])
 offset = (offset_reserved_flags >> 12) * 4
 flag_urg = (offset_reserved_flags & 32) >> 5
 flag_ack = (offset_reserved_flags & 16) >> 4
 flag_psh = (offset_reserved_flags & 8) >> 3
 flag_rst = (offset_reserved_flags & 4) >> 2
 flag_syn = (offset_reserved_flags & 2) >> 1
 flag_fin = offset_reserved_flags & 1
 data = raw_data[offset:]
 return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def main():
    print("Starting Program")
    s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    while True:
        packet, addr = s.recvfrom(65565)
        eth = ethernet_head(packet)
        print('Destination: {}, Source {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))
        # IPv4
        if eth.proto == 8:
            ipv4 = ipv4(eth.data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

            # ICMP
            if ipv4.proto == 1:
                icmp = icmp(ipv4.data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                print(TAB_2 + 'ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp.data))

            # TCP
            elif ipv4.proto == 6:
                tcp = tcp(ipv4.data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                if len(tcp.data) > 0:

                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = http(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp.data))

            # UDP
            elif ipv4.proto == 17:
                udp = udp(ipv4.data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

            # Other IPv4
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, ipv4.data))

        else:
            print('Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, eth.data))


if __name__ == "__main__":
    main()
