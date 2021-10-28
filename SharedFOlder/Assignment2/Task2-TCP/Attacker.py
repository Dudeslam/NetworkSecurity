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
import struct
import sys
import ctypes
import scapy.all as scapy

#Run this script in CMD with admin

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False



def recvPacket():
    print("Hello Packet")
    s = socket(AF_INET, SOCK_RAW, htons(0x0800))
    hostname = gethostname()
    host = gethostbyname(hostname)
    print('IP: {}'.format(host))
    # addr = getaddrinfo('localhost', 8080)
    # print(addr)

    
    # s.bind(("eth0", htons(0x0800)))
    

    while True:
        packet = s.recvfrom(2048)

if is_admin():
    recvPacket()
else:
    recvPacket()
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

