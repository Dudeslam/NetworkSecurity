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

from ctypes import sizeof
import socket 
from socket import *
from struct import *
import sys
from typing import Counter
from scapy import sessions
import scapy.all as scapy
from scapy.all import conf
from scapy.layers.inet import IP, TCP
import time
import re

#Run this script in CMD with admin

def contains_192(s):
    if ("192." in s):
        return s

def cleanlist(listof):
    retList = []
 
    for x in listof:
        rSuffix = x.replace(':', ' ').replace('>', ' ').split()
        for y in rSuffix:
            if("192." in y):
                if (y in retList):
                    pass
                else:
                    retList.append(y)
        

        
        # rSuffix.remove("https")
        # retList.append(filter(contains_192, rSuffix))
    return retList

             

        
        

def GetList(filter):
    packet = scapy.sniff(filter=filter,
      session=sessions.IPSession,  # defragment on-the-flow
    #   prn=lambda x: x.summary(),
      count=100)
    ListOfIP = []
    retList = []

    for x in range(0,100):
        if ("192." in packet[x][1].getlayer(IP).summary()):
            AddThis = str(packet[x][1].getlayer(IP).summary())
            ListOfIP.append(AddThis)
    retList = cleanlist(ListOfIP)
            
    return retList

def _input(message, input_type=int):
    while True:
        try:
                return input_type (input(message))
        except:pass

def main():
    i = 0
    j = 0
    print("Getting List\n")
    IPList = GetList("tcp")
    IPList2 = IPList
    src = 0
    dst = 0
    n = len(IPList)
    while not input("Enter to Continue \n"):
        print("IP adresses:")
        for x in IPList:
            i += 1
            print("[{}] ".format(i) + x)

        val = _input("Choose Source\n")
        print(val)
        if val <= n & val > 0:
            src = IPList[_input(val)-1]
            print(IPList.pop(val))

        for x in IPList:
            j += 1
            print("[{}] ".format(i) + x)

        val = _input("Choose Destination")
        if val <= n-1 & val > 0:
            dst = IPList[_input(val)-1]
        break

    print("This is src {}".format(src))
    print("This is dst {}".format(dst))

    print("end")



if __name__ == "__main__":
    main()
